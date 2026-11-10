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

fn validate_image(image: &[u8]) -> Result<(), String> {
    // RE #167 (Z-Loader stage-2 decode): HDR0 ("0RDH") images are validated
    // by the bootloader (model-ID @+0x11c must equal "7101", header+data
    // checksums, size caps); plain-RAS (8380xxxx) images SKIP validation and
    // write anyway. Both classes are flash-legal; anything else is refused.
    let ok =
        image.len() > 4 && (image[0..4] == [0x30, 0x52, 0x44, 0x48] || image[0..2] == [0x83, 0x80]);
    if !ok {
        return Err("image pre-validation (RE #167): neither HDR0 nor RAS magic — bootloader will refuse/brick-class payload".into());
    }
    if image[0..4] == [0x30, 0x52, 0x44, 0x48] {
        if image.len() < 0x120 {
            return Err("HDR0 image truncated before model-ID field".into());
        }
        if &image[0x11c..0x11f] != b"710" {
            return Err(format!(
                "HDR0 model-ID gate (the 2026-11-10 refusal class): image model {:?} != flash model \"7101\" — bootloader drops silently (RE #167)",
                &image[0x11c..0x120]
            ));
        }
    }
    Ok(())
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
    if !a.allow_raw {
        validate_image(&image)?;
    }
    enforce_flash_mutex()?;
    if a.delay_ms < 10 {
        return Err("pacing clamp (2026-11-10 lesson): <10ms (477pps class) never accepted — bootloader poll-loop drops chunks. Use the proven 10ms.".into());
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
mod hardening_tests {
    use super::*;
    #[test]
    fn hdr0_wrong_model_refused_with_the_refusal_class_named() {
        let mut img = vec![0x30, 0x52, 0x44, 0x48];
        img.resize(0x120, 0);
        img[0x11c..0x120].copy_from_slice(b"7605");
        let e = validate_image(&img).unwrap_err();
        assert!(e.contains("model") && e.contains("710"), "{e}");
    }
    #[test]
    fn hdr0_nr7101_model_passes() {
        let mut img = vec![0x30, 0x52, 0x44, 0x48];
        img.resize(0x140, 0);
        img[0x11c..0x120].copy_from_slice(b"7101");
        assert!(validate_image(&img).is_ok());
    }
    #[test]
    fn hdr0_truncated_before_model_field_refused() {
        let mut img = vec![0u8; 0x40];
        img[..4].copy_from_slice(&[0x30, 0x52, 0x44, 0x48]);
        assert!(validate_image(&img).is_err());
    }
    #[test]
    fn plain_ras_magic_passes_unvalidated_class() {
        let mut img = vec![0xAAu8; 64];
        img[..4].copy_from_slice(&[0x83, 0x80, 0, 0]);
        assert!(validate_image(&img).is_ok()); // RE #167: writes without bootloader validation
    }
    #[test]
    fn garbage_refused() {
        assert!(validate_image(b"sysupgrade-zyxel_nr7101/ garbage").is_err());
    }
}
