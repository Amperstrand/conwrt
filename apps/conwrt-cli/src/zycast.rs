//! `conwrt zycast` — multicast flash sender (Rust port of cmd/zycast).
//!
//! Thin CLI over `conwrt-zycast`: reads the image, prints the send plan,
//! runs the bounded multicast loops with progress lines mirroring the Go
//! reference's output.

use conwrt_zycast::protocol::{ImageType, chunk_count};
use conwrt_zycast::{SendConfig, send};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

/// Parsed `conwrt zycast` arguments.
pub struct ZycastArgs {
    /// Firmware image to multicast.
    pub image: PathBuf,
    /// Egress interface name.
    pub interface: String,
    /// Image type name (bootbase|rom|ras|romd|backup).
    pub image_type: String,
    /// Send loops.
    pub loops: u32,
    /// Inter-packet delay in milliseconds.
    pub delay_ms: u64,
    /// Multicast group address.
    pub group: String,
    /// Multicast port.
    pub port: u16,
    /// Operator attestation: target specimen verified (MAC/serial gate)
    /// and sibling units isolated. The multicast hits EVERY ZyXEL
    /// bootloader in its listen window on the segment — without this flag
    /// the command refuses to send.
    pub confirm_specimen: bool,
    /// Operator attestation: the payload is a non-RAS raw image sent
    /// deliberately (research payloads). Without it, kernel-slot sends
    /// must carry the ZyXEL RAS magic — a tar/sysupgrade container or any
    /// stray file is refused rather than flashed into bootloaders.
    pub allow_raw: bool,
}

/// CLI entry point.
pub fn run(a: ZycastArgs) -> ExitCode {
    match inner(a) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("zycast: {e}");
            ExitCode::from(1)
        }
    }
}

fn inner(a: ZycastArgs) -> Result<ExitCode, String> {
    // Lesson 2026-11-10 (36h dark-fleet arc): the bootloader poll-loop drops
    // chunks above reference pace — every 2ms (477 pkt/s) attempt failed,
    // every 98 pkt/s (10 ms) reference attempt succeeded. Clamp hard.
    if a.delay_ms < 10 {
        return Err("refusing: --delay-ms < 10 is above the bootloader's proven\n             receive pace (98 pkt/s reference; 477 pkt/s produced zero accepts\n             across every attempt — conwrt-bench docs/research/2026-11-10-*)".into());
    }
    // Flash-mutex (same arc): two concurrent senders interleave and no
    // bootloader can reconstruct either image; a looping sender traps units
    // in an accept-boot-reaccept flash-loop.
    if let Ok(dirs) = std::fs::read_dir("/proc") {
        for d in dirs.flatten() {
            let pid_s = d.file_name().to_string_lossy().to_string();
            if !pid_s.chars().all(|ch| ch.is_ascii_digit()) {
                continue;
            }
            if let Ok(cmd) = std::fs::read_to_string(format!("/proc/{}/cmdline", pid_s)) {
                let c = cmd.replace('\0', " ");
                let pid_self = std::process::id().to_string();
                let is_sender = (c.contains("zycast") && c.contains("--interface"))
                    || c.contains("/.cache/conwrt/zycast") || c.contains("conwrt-zycast-mips");
                if is_sender && pid_s != pid_self {
                    return Err(format!("flash-mutex: another zycast sender is live (pid {}): \n             {}\n             Kill it or coordinate via herdr before arming (bench lesson 2026-11-10)", pid_s, c.chars().take(80).collect::<String>()).into());
                }
            }
        }
    }

    if !a.confirm_specimen {
        return Err(
            "refusing to send: multicast flashes EVERY ZyXEL bootloader in its listen \
             window on this segment. Verify the target specimen (MAC/serial gate, AGENTS \
             \"Verify the SPECIMEN\") and isolate sibling units, then re-run with \
             --confirm-specimen."
                .into(),
        );
    }
    let ty: ImageType = a.image_type.parse()?;
    let group: Ipv4Addr = a
        .group
        .parse()
        .map_err(|e| format!("bad group address: {e}"))?;
    let image = std::fs::read(&a.image).map_err(|e| format!("read image: {e}"))?;
    // Payload magic gate: kernel-slot flashes must be ZyXEL RAS images
    // (0x8380_0000). A sysupgrade tar container ("sysu…"), a squashfs, or any
    // stray file flashed raw into a bootloader slot is a brick. Found live:
    // the Rust CLI happily accepted an ASU sysupgrade .bin as "type=ras"
    // (that field is the PARTITION selector, not a format check).
    if matches!(ty, ImageType::Ras | ImageType::Backup) && !a.allow_raw {
        const RAS_MAGIC: [u8; 4] = [0x83, 0x80, 0x00, 0x00];
        if image.len() < 4 || image[0..4] != RAS_MAGIC {
            return Err(
                "refusing to send: payload does not carry the ZyXEL RAS magic \
                 (83 80 00 00). Kernel-slot multicast of a non-RAS file (tar/sysupgrade \
                 container, squashfs, arbitrary data) bricks every listening unit. If \
                 this is a deliberate raw research payload, re-run with --allow-raw."
                    .into(),
            );
        }
    }
    // RE 2026-11-10 (Z-Loader stage-2, base 0x84024000, FINDINGS.md #167):
    // accept gates — HDR0-magic images validate model-ID + checksums;
    // non-HDR0 (8380xxxx) skip validation and write anyway. Model field at
    // image+0x11c must equal the flash model string ("7101" for NR7101).
    if matches!(ty, ImageType::Ras | ImageType::Backup) && !a.allow_raw {
        if image.len() > 0x120 && image.starts_with(b"HDR0") {
            let model = &image[0x11c..0x120];
            if model != b"7101" {
                return Err(format!(
                    "preflight (RE decode): HDR0 image model field @0x11c is {:02x?},\n             expected ASCII '7101' — the bootloader WILL refuse this\n             ('Wrong Model ID!! Skip upgrade.', silent without serial). Gate addr:\n             FUN_8402f248-0x8402f2bc.",
                    model
                ).into());
            }
        } else if !image.starts_with(&[0x83, 0x80, 0x00, 0x00]) {
            // neither class: warn-through but say what the bootloader will do
            eprintln!(
                "zycast: preflight note: image carries neither HDR0 nor the 8380-magic;\n          bootloader validation path undefined (RE FINDINGS §2)"
            );
        } else {
            eprintln!(
                "zycast: preflight note: 8380-class image — bootloader SKIPS model/checksum\n          validation and writes anyway (RE FINDINGS §2); ensure the image is trusted."
            );
        }
    }
    let chunks = chunk_count(image.len());
    let est = Duration::from_millis(chunks as u64 * a.delay_ms * a.loops as u64);
    println!("=== conwrt zycast (Rust) ===");
    println!(
        "image: {} ({} bytes, {chunks} chunks, type={ty})",
        a.image.display(),
        image.len()
    );
    println!("iface: {}, dst: {group}:{}", a.interface, a.port);
    println!("loops: {}, est send time: {est:?}", a.loops);
    let cfg = SendConfig {
        group,
        port: a.port,
        interface: a.interface,
        loops: a.loops,
        delay: Duration::from_millis(a.delay_ms),
    };
    let stats = send(&image, ty, &cfg, &mut |line| println!("[zycast] {line}"))
        .map_err(|e| e.to_string())?;
    println!(
        "[zycast] done: {} loops, {} packets in {:?}",
        stats.loops, stats.packets, stats.elapsed
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod magic_gate_tests {
    use super::*;

    fn args(image: &str, allow_raw: bool) -> ZycastArgs {
        ZycastArgs {
            image: image.into(),
            interface: "lo".into(),
            image_type: "ras".into(),
            loops: 1,
            delay_ms: 1000,
            group: "225.0.0.0".into(),
            port: 5631,
            confirm_specimen: true,
            allow_raw,
        }
    }

    #[test]
    fn tar_container_is_refused_for_kernel_slot() {
        let p = std::env::temp_dir().join("zycast-gate-test.tar");
        std::fs::write(&p, b"sysupgrade-zyxel_nr7101/\x00\x00\x00rest-of-tar").unwrap();
        let r = inner(args(p.to_str().unwrap(), false));
        assert!(r.is_err(), "tar must be refused");
        let msg = r.unwrap_err();
        assert!(
            msg.contains("RAS magic"),
            "message should name the check: {msg}"
        );
    }

    #[test]
    fn ras_magic_passes_gate() {
        // Gate check only: inner() will proceed past the magic test (and then
        // fail later on send or succeed); we assert it does NOT return the
        // magic-refusal error.
        let p = std::env::temp_dir().join("zycast-gate-test.ras");
        std::fs::write(&p, [0x83u8, 0x80, 0x00, 0x00].repeat(64)).unwrap();
        let r = inner(args(p.to_str().unwrap(), false));
        if let Err(e) = r {
            assert!(
                !e.contains("RAS magic"),
                "RAS payload must pass the magic gate"
            );
        }
    }

    #[test]
    fn allow_raw_overrides_the_gate() {
        let p = std::env::temp_dir().join("zycast-gate-test.raw");
        std::fs::write(&p, b"definitely-not-a-ras-image").unwrap();
        let r = inner(args(p.to_str().unwrap(), true));
        if let Err(e) = r {
            assert!(!e.contains("RAS magic"), "--allow-raw must bypass the gate");
        }
    }
}
