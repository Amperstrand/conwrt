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
    /// Expected RAS model-ID (hex string) — preflight vs the bootloader's
    /// flash-commit model gate (RE: field @img+0x11c, "%x" == flash model).
    pub expect_model: Option<String>,
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

fn enforce_flash_mutex() -> Result<(), String> {
    let out = std::process::Command::new("sh")
        .args(["-c", "ss -ulnp 2>/dev/null | grep -c ':5631 ' || true"])
        .output()
        .map_err(|e| e.to_string())?;
    if String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u32>()
        .unwrap_or(0)
        > 0
    {
        return Err("flash-mutex: a UDP/5631 sender is already live — interleaved streams flash-loop the target (2026-11-10 incident). Kill it first.".into());
    }
    Ok(())
}

fn inner(a: ZycastArgs) -> Result<ExitCode, String> {
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
        // Magic per the RE'd flash-commit gate (conwrt-bench
        // docs/research/2026-11-10-zloader-re-findings.md §2 [P]):
        // firmware images carry "HDR0", bootloader images "HDR4". (The
        // legacy 83 80 00 00 constant was from a different ZyXEL family;
        // NR7101 images would have tripped it — masked so far only
        // because real runs used --allow-raw.)
        const RAS_MAGICS: [[u8; 4]; 3] = [*b"HDR0", *b"HDR4", [0x83, 0x80, 0x00, 0x00]];
        if image.len() < 4 || !RAS_MAGICS.iter().any(|m| image.starts_with(m)) {
            return Err(
                "refusing to send: payload does not carry a ZyXEL RAS magic \
                 (HDR0/HDR4; or 83 80 00 00 legacy). Kernel-slot multicast of a non-RAS \
                 file (tar/sysupgrade container, squashfs, arbitrary data) bricks every \
                 listening unit. If this is a deliberate raw research payload, re-run \
                 with --allow-raw."
                    .into(),
            );
        }
    }
    enforce_flash_mutex()?;
    if a.delay_ms < 10 {
        return Err("pacing clamp (2026-11-10 lesson): <10ms (477pps class) never accepted — bootloader poll-loop drops chunks. Use the proven 10ms.".into());
    }
    // Model-ID preflight: the bootloader refuses mismatches AFTER
    // receiving the whole stream ("Wrong Model ID!! Skip upgrade." [P]);
    // refuse here, before any unit spends its listen window.
    if let Some(expected) = &a.expect_model {
        match conwrt_zycast::ras_model_id(&image) {
            Some(actual) => {
                let actual_hex = format!("{actual:x}");
                if &actual_hex != expected {
                    return Err(format!(
                        "refusing to send: image model-ID is {actual_hex}, expected \
                         {expected} — the bootloader's flash-commit gate would refuse it \
                         (\"Wrong Model ID!! Skip upgrade.\")"
                    ));
                }
            }
            None => {
                return Err(
                    "refusing to send: --expect-model given but the image carries no \
                     RAS header to check (no HDR0/HDR4 magic) — cannot attest the model"
                        .into(),
                );
            }
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
        expect_model: None,
    }
}

#[cfg(test)]
mod magic_gate_tests {
    use super::{args, inner};

    #[test]
    fn hdr0_image_passes_the_magic_gate() {
        // NR7101 reality: ZyXEL RAS files start "HDR0" (RE §2 [P]);
        // the old 83 80 00 00 constant would have refused them.
        let p = std::env::temp_dir().join("zycast-gate-test-ras.bin");
        let mut img = vec![0u8; 0x120];
        img[0..4].copy_from_slice(b"HDR0");
        std::fs::write(&p, &img).unwrap();
        // Interface "nonexistent-zycast-test" so a PASSING gate then fails
        // at socket-bind — proving we got past the magic check.
        let mut a = args(p.to_str().unwrap(), false);
        a.interface = "nonexistent-zycast-test".into();
        let msg = inner(a).unwrap_err();
        assert!(!msg.contains("RAS magic"), "HDR0 must pass: {msg}");
    }

    #[test]
    fn model_id_mismatch_is_refused_before_send() {
        let p = std::env::temp_dir().join("zycast-model-test.bin");
        let mut img = vec![0u8; 0x120];
        img[0..4].copy_from_slice(b"HDR0");
        img[0x11c..0x120].copy_from_slice(&0x0000_7101u32.to_be_bytes());
        std::fs::write(&p, &img).unwrap();
        let mut a = args(p.to_str().unwrap(), false);
        a.expect_model = Some("6101".into());
        let msg = inner(a).unwrap_err();
        assert!(
            msg.contains("model-ID is 7101") && msg.contains("expected 6101"),
            "message should state the mismatch: {msg}"
        );
    }

    #[test]
    fn model_id_match_proceeds_past_the_preflight() {
        let p = std::env::temp_dir().join("zycast-model-ok.bin");
        let mut img = vec![0u8; 0x120];
        img[0..4].copy_from_slice(b"HDR0");
        img[0x11c..0x120].copy_from_slice(&0x0000_7101u32.to_be_bytes());
        std::fs::write(&p, &img).unwrap();
        let mut a = args(p.to_str().unwrap(), false);
        a.expect_model = Some("7101".into());
        a.interface = "nonexistent-zycast-test".into();
        let msg = inner(a).unwrap_err();
        assert!(
            !msg.contains("model"),
            "matching model must not refuse: {msg}"
        );
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
    fn missing_confirm_specimen_refuses_before_anything_else() {
        // The MAC-gate must refuse BEFORE reading the image (fail closed,
        // no side effects) — regression guard for the bench doctrine
        // "multicast flashes EVERY listening ZyXEL bootloader".
        let mut a = args("/nonexistent/image.bin", true);
        a.confirm_specimen = false;
        let r = inner(a);
        let msg = r.expect_err("must refuse without --confirm-specimen");
        assert!(
            msg.contains("--confirm-specimen"),
            "message must name the flag: {msg}"
        );
        // It must not have progressed to file reading (the path doesn't
        // exist; a read attempt would produce a different error).
        assert!(!msg.contains("read image"), "refusal must precede file IO");
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

#[cfg(test)]
#[cfg(test)]
mod hardening_tests {
    // Corrected versions of the #680 tests: the RE (conwrt-bench
    // docs/research/2026-11-10-zloader-re-findings.md §2 [P]) specifies
    // ASCII "HDR0" as the file magic ("0RDH" bytes was a byte-order
    // misread of the LE word compare) and a NUMERIC u32 model-ID at
    // +0x11c (%x-printed == "7101" for NR7101), not ASCII.
    use super::*;

    #[test]
    fn plain_ras_magic_passes_unvalidated_class() {
        let mut img = vec![0xAAu8; 64];
        img[..4].copy_from_slice(&[0x83, 0x80, 0, 0]);
        // 83 80 legacy files skip bootloader validation and still write [P].
        let p = std::env::temp_dir().join("zycast-plain-ras.bin");
        std::fs::write(&p, &img).unwrap();
        let mut a = args(p.to_str().unwrap(), false);
        a.interface = "nonexistent-zycast-test".into();
        let msg = inner(a).unwrap_err();
        assert!(!msg.contains("RAS magic"), "83 80 must pass: {msg}");
    }

    #[test]
    fn hdr0_truncated_before_model_field_refused_when_model_expected() {
        let mut img = vec![0u8; 0x40];
        img[..4].copy_from_slice(b"HDR0");
        let p = std::env::temp_dir().join("zycast-trunc.bin");
        std::fs::write(&p, &img).unwrap();
        let mut a = args(p.to_str().unwrap(), false);
        a.expect_model = Some("7101".into());
        let msg = inner(a).unwrap_err();
        assert!(msg.contains("no RAS header"), "truncated HDR0: {msg}");
    }

    #[test]
    fn sub_10ms_pacing_is_refused() {
        // 2026-11-10 bench lesson (477pps class): the bootloader's poll
        // loop drops chunks at <10ms inter-packet delay.
        let p = std::env::temp_dir().join("zycast-pace.bin");
        std::fs::write(&p, b"\x83\x80\x00\x00rest").unwrap();
        let mut a = args(p.to_str().unwrap(), false);
        a.delay_ms = 1;
        let msg = inner(a).unwrap_err();
        assert!(msg.contains("pacing clamp"), "{msg}");
    }
}
