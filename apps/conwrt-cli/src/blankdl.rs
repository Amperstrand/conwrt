//! `conwrt blankdl` — ZTE ipq40xx blank-download flash fence + trigger.
//!
//! `fence`   the hardened TFTP serving daemon (Rust port of
//!           scripts/zte-blankdl-flashd.py; serve ONE pinned image to the
//!           bootloader's volume-not-found recovery, exit on the fin
//!           packet).
//! `trigger` the device-side half of the recovery: verify the specimen
//!           (MAC gate), stage the session-proven UBI trigger image,
//!           sha256-verify at the target BEFORE writing, `mtd erase` +
//!           `mtd write`, read back and verify, probe the device alive —
//!           then (optionally) reboot into the fence's flash window.
//!
//! Safety model mirrors `zycast`: payload magic gate, flash mutex,
//! specimen attestation, and the Irreversible Write Discipline from
//! AGENTS.md as code — reuse the proven artifact, verify before write,
//! read back after, probe before reboot.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// Parsed `conwrt blankdl` arguments (fence mode).
pub struct FenceArgs {
    /// Image path, optionally `path#sha256:<hex>`.
    pub image: String,
    /// Pinned sha256 (required unless the path carries `#sha256:`).
    pub expect_sha256: Option<String>,
    /// Bind address (default: the protocol's fixed server address).
    pub bind: String,
    /// Bind port.
    pub port: u16,
    /// Give up after this many seconds without a fin packet.
    pub timeout: f64,
    /// Log only — never answer anything.
    pub dry_run: bool,
    /// Write run.json + flash.log here.
    pub log_dir: Option<PathBuf>,
    /// Verify (or with --open-firewall, insert) the iptables INPUT rule
    /// that lets the bootloader's TFTP reach the fence. The hidden
    /// blocker of the 2026-11-10 recovery: netfilter drops UDP/69 by
    /// default and tcpdump sees the packets BEFORE the drop.
    pub firewall_iface: Option<String>,
    /// Insert the missing firewall rule instead of just reporting it.
    pub open_firewall: bool,
    /// Attest that a non-uImage payload is deliberate (research images).
    /// Without it the fence refuses to serve anything that is not a
    /// uImage — a sysupgrade tar, a squashfs, or a stray file served to
    /// the blank-download bootloader is a brick.
    pub allow_raw: bool,
}

/// Parsed `conwrt blankdl trigger` arguments.
pub struct TriggerArgs {
    /// Target as `user@host`.
    pub host: String,
    /// SSH identity file.
    pub identity: Option<PathBuf>,
    /// SSH port (jump hosts etc.).
    pub ssh_port: u16,
    /// Session-proven UBI trigger image (valid layout volumes, NO kernel
    /// volume) — the artifact class the 2026-11-08 unit-2 brick warned
    /// about: never synthesize, always transfer the proven file.
    pub trigger_image: PathBuf,
    /// The exact unit's MAC (the specimen gate — "flash the AP3915i" is
    /// ambiguous on a bench with four of them).
    pub expect_mac: String,
    /// MTD partition name (resolved BY NAME on the device, never by
    /// number — the numbering shifts between stock and OpenWrt).
    pub partition: String,
    /// Reboot into the fence window after a verified write (default:
    /// stop after the alive-probe so the fence can be armed first).
    pub reboot: bool,
    /// Print the commands, touch nothing.
    pub dry_run: bool,
}

pub fn run_fence(a: FenceArgs) -> ExitCode {
    match fence_inner(a) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("blankdl: {e}");
            ExitCode::from(1)
        }
    }
}

fn fence_inner(a: FenceArgs) -> Result<ExitCode, String> {
    // ---- image pinning -------------------------------------------------
    let (path, inline_sha) = match a.image.split_once("#sha256:") {
        Some((p, s)) => (p.to_owned(), Some(s.to_owned())),
        None => (a.image.clone(), None),
    };
    let expect = inline_sha
        .or(a.expect_sha256.clone())
        .ok_or_else(|| {
            "refusing to serve unpinned image: pass --expect-sha256 or \
             path#sha256:<hex>"
                .to_owned()
        })?;

    let bytes = std::fs::read(&path).map_err(|e| format!("read image {path}: {e}"))?;

    // ---- payload magic gate (zycast discipline) -------------------------
    // The blank-download bootloader writes whatever it is served into the
    // web+rootfs NAND regions. A uImage header is the shape of every
    // proven recovery image; anything else needs an explicit attestation.
    const UIMAGE_MAGIC: [u8; 4] = [0x27, 0x05, 0x19, 0x56];
    if !a.allow_raw && (bytes.len() < 4 || bytes[0..4] != UIMAGE_MAGIC) {
        return Err(
            "refusing to serve: payload does not carry the uImage magic \
             (27 05 19 56). The blank-download bootloader writes what it is \
             served into web+rootfs — a sysupgrade tar or arbitrary file is a \
             brick. If this is a deliberate raw payload, re-run with \
             --allow-raw."
                .into(),
        );
    }

    // ---- flash mutex -----------------------------------------------------
    // Two fences on the same port interleave answers to the same
    // bootloader — the transfer corrupts mid-flight. Fail fast with the
    // holder named. (Only the port WE will bind counts: a rehearsal on
    // :10691 does not conflict with a fence on :69.)
    let out = Command::new("sh")
        .args([
            "-c",
            &format!("ss -ulnp 2>/dev/null | grep ':{} ' || true", a.port),
        ])
        .output()
        .map_err(|e| format!("ss: {e}"))?;
    let s = String::from_utf8_lossy(&out.stdout);
    if !s.trim().is_empty() {
        return Err(format!(
            "flash-mutex: something is already bound to UDP/{}:\n{s}\
             two fences interleave answers to one bootloader — kill it first",
            a.port
        ));
    }

    // ---- firewall gate (the 2026-11-10 hidden blocker) -------------------
    if let Some(iface) = &a.firewall_iface {
        firewall_gate(iface, a.open_firewall)?;
    }

    let bind: IpAddr = a
        .bind
        .parse()
        .map_err(|e| format!("bad bind address {}: {e}", a.bind))?;
    if bind.to_string() != conwrt_protocols::blankdl::PROTO_BIND_IP {
        eprintln!(
            "blankdl: NON-STANDARD BIND {bind} — real blank-download clients \
             only talk to {} (dress rehearsal mode)",
            conwrt_protocols::blankdl::PROTO_BIND_IP
        );
    }

    let pinned = conwrt_blankdl::PinnedImage::from_bytes(bytes, Some(&expect), Some(Path::new(&path)))
        .map_err(|e| e.to_string())?;

    let mut cfg = conwrt_blankdl::FenceConfig::new(pinned);
    cfg.bind = bind;
    cfg.port = a.port;
    cfg.timeout = std::time::Duration::from_secs_f64(a.timeout.max(1.0));
    cfg.dry_run = a.dry_run;
    cfg.log_dir = a.log_dir;

    let (_outcome, exit) = conwrt_blankdl::serve(&cfg);
    Ok(ExitCode::from(u8::try_from(exit.exit_code()).unwrap_or(1)))
}

/// Check (and optionally insert) the iptables rule that admits the
/// bootloader's TFTP on the recovery interface. tcpdump sees packets
/// BEFORE netfilter — a fence that "works locally" can still be deaf.
fn firewall_gate(iface: &str, open: bool) -> Result<(), String> {
    let check = Command::new("iptables")
        .args(["-C", "INPUT", "-i", iface, "-p", "udp", "--dport", "69", "-j", "ACCEPT"])
        .output()
        .map_err(|e| format!("iptables check: {e} (is iptables installed?)"))?;
    if check.status.success() {
        eprintln!("blankdl: firewall OK — UDP/69 admitted on {iface}");
        return Ok(());
    }
    let rule = format!(
        "iptables -I INPUT -i {iface} -p udp --dport 69 -j ACCEPT"
    );
    if !open {
        return Err(format!(
            "firewall: UDP/69 is NOT admitted on {iface} — the bootloader's \
             TFTP requests will be silently dropped (the hidden blocker of the \
             2026-11-10 recovery). Fix: `{rule}` (or re-run with \
             --open-firewall)"
        ));
    }
    let rc = Command::new("sh")
        .args(["-c", &rule])
        .status()
        .map_err(|e| format!("iptables insert: {e}"))?;
    if !rc.success() {
        return Err(format!("firewall: inserting the rule failed: {rule}"));
    }
    eprintln!("blankdl: firewall rule inserted: {rule}");
    Ok(())
}

// ---------------------------------------------------------------------------
// trigger — the device-side half
// ---------------------------------------------------------------------------

pub fn run_trigger(a: TriggerArgs) -> ExitCode {
    match trigger_inner(&a) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("blankdl trigger: {e}");
            ExitCode::from(1)
        }
    }
}

/// One SSH exec to the target (identity, batch mode, strict timeouts).
fn ssh_exec(a: &TriggerArgs, cmd: &str) -> Result<String, String> {
    let mut c = Command::new("ssh");
    c.args([
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-p",
        &a.ssh_port.to_string(),
    ]);
    if let Some(id) = &a.identity {
        c.args(["-i", &id.display().to_string()]);
    }
    c.arg(&a.host).arg(cmd);
    let out = c.output().map_err(|e| format!("ssh exec: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "ssh command failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn scp_stage(a: &TriggerArgs, src: &Path, dst: &str) -> Result<(), String> {
    let mut c = Command::new("scp");
    c.args([
        "-O", // OpenWrt dropbear has no sftp-server — legacy SCP protocol
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-P",
        &a.ssh_port.to_string(),
    ]);
    if let Some(id) = &a.identity {
        c.args(["-i", &id.display().to_string()]);
    }
    c.arg(src).arg(format!("{}:{dst}", a.host));
    let rc = c.status().map_err(|e| format!("scp: {e}"))?;
    if !rc.success() {
        return Err(format!("scp {src:?} -> {dst} failed"));
    }
    Ok(())
}

fn trigger_inner(a: &TriggerArgs) -> Result<ExitCode, String> {
    let trigger_bytes =
        std::fs::read(&a.trigger_image).map_err(|e| format!("read trigger image: {e}"))?;
    let expect_sha = {
        use sha2::{Digest, Sha256};
        let mut s = String::new();
        for b in Sha256::digest(&trigger_bytes) {
            s.push_str(&format!("{b:02x}"));
        }
        s
    };
    eprintln!(
        "blankdl trigger: artifact {} ({} bytes, sha256 {})",
        a.trigger_image.display(),
        trigger_bytes.len(),
        expect_sha
    );

    // ---- 1. specimen gate: the MAC must match the exact unit ------------
    let mac = ssh_exec(a, "cat /sys/class/net/eth0/address")?;
    let mac = mac.trim().to_ascii_lowercase();
    let expect_mac = a.expect_mac.trim().to_ascii_lowercase();
    if mac != expect_mac {
        return Err(format!(
            "SPECIMEN GATE: device eth0 MAC {mac} != expected {expect_mac} — \
             wrong unit or wrong expectation. STOP (AGENTS: verify the \
             SPECIMEN, not just the model)"
        ));
    }
    eprintln!("blankdl trigger: specimen verified (eth0 {mac})");

    // ---- 2. resolve the partition BY NAME --------------------------------
    let part = &a.partition;
    let mtd = ssh_exec(a, &format!("grep ' \"{part}$' /proc/mtd || true"))?;
    if mtd.is_empty() {
        return Err(format!(
            "partition {part:?} not found in /proc/mtd — resolve by \
             name (numbering shifts between stock and OpenWrt)"
        ));
    }
    eprintln!("blankdl trigger: partition resolved: {}", mtd.replace('\n', "; "));

    // ---- 3. stage the artifact + verify sha AT THE TARGET ----------------
    // Reuse the proven artifact; never synthesize on-device (the 2026-11-08
    // unit-2 brick: zeros written instead of the proven UBI trigger).
    let remote_path = "/tmp/blankdl-trigger.img";
    if a.dry_run {
        eprintln!(
            "dry-run: would scp -O {} -> {}:{remote_path}",
            a.trigger_image.display(),
            a.host
        );
        return Ok(ExitCode::SUCCESS);
    }
    scp_stage(a, &a.trigger_image, remote_path)?;
    let remote_sha = ssh_exec(a, &format!("sha256sum {remote_path}"))?;
    let remote_sha = remote_sha
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if remote_sha != expect_sha {
        return Err(format!(
            "staged artifact sha mismatch at target: {remote_sha} != {expect_sha} — \
             aborting BEFORE any write"
        ));
    }
    eprintln!("blankdl trigger: artifact verified at target (sha256 match)");

    // ---- 4. erase fully, write, read back ---------------------------------
    // `mtd write` does NOT full-erase the partition — the unwritten blocks
    // keep their old contents (the first 2026-11-10 trigger attempt failed
    // exactly here: the old kernel volume survived).
    ssh_exec(
        a,
        &format!("mtd erase '{part}' && mtd write {remote_path} '{part}'"),
    )
    .map_err(|e| {
        format!(
            "mtd erase/write FAILED — do NOT reboot; the running OS is still \
             the recovery channel: {e}"
        )
    })?;
    eprintln!("blankdl trigger: mtd erase + write complete, verifying readback…");

    // Read back the written length and compare hashes. This verifies the
    // invariant the NEXT BOOT checks: a valid UBI layout WITHOUT a kernel
    // volume (recovery engages) rather than a dead partition (brick).
    let len = trigger_bytes.len();
    let readback = ssh_exec(
        a,
        &format!(
            "dd if=/dev/$(grep ' \\\"{part}\\\"$' /proc/mtd | cut -d: -f1 | sed 's/mtd/mtdblock/') bs=4096 count={} 2>/dev/null | sha256sum",
            len.div_ceil(4096),
        ),
    )?;
    let readback_sha = readback
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    // The readback covers whole 4K pages; compare by rehashing the padded
    // artifact the same way.
    let padded = {
        let mut v = trigger_bytes.clone();
        let pad = len.div_ceil(4096) * 4096 - len;
        v.extend(std::iter::repeat_n(0xff, pad)); // erased NAND reads 0xff
        use sha2::{Digest, Sha256};
        let mut s = String::new();
        for b in Sha256::digest(&v) {
            s.push_str(&format!("{b:02x}"));
        }
        s
    };
    if readback_sha != padded {
        return Err(format!(
            "READBACK MISMATCH: partition head hashes {readback_sha} != expected \
             {padded}. Do NOT reboot — the running OS is the recovery channel; \
             re-run the write or investigate before any power event."
        ));
    }
    eprintln!("blankdl trigger: readback verified (UBI layout, no kernel volume)");

    // ---- 5. probe alive before (and only then) reboot ---------------------
    let alive = ssh_exec(a, "echo alive")?;
    if alive != "alive" {
        return Err(format!(
            "alive-probe failed ({alive:?}) — the management channel died after \
             the write. Do NOT power-cycle blindly: the running OS may still be \
             reachable; re-probe before anything else."
        ));
    }
    eprintln!("blankdl trigger: device alive; trigger installed and verified");

    if a.reboot {
        // Detached reboot: the command must not hold the SSH session open
        // against the device's shutdown.
        ssh_exec(a, "setsid sh -c 'sleep 1 && reboot' >/dev/null 2>&1 & echo scheduled")?;
        eprintln!(
            "blankdl trigger: reboot scheduled — the fence must be armed on \
             {}:69 BEFORE the bootloader reaches its volume-not-found handler",
            conwrt_protocols::blankdl::PROTO_BIND_IP
        );
    } else {
        eprintln!(
            "blankdl trigger: done (no reboot). Arm the fence, then re-run with \
             --reboot or `ssh {} 'reboot'` when ready.",
            a.host
        );
    }
    Ok(ExitCode::SUCCESS)
}
