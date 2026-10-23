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
    let ty: ImageType = a.image_type.parse()?;
    let group: Ipv4Addr = a
        .group
        .parse()
        .map_err(|e| format!("bad group address: {e}"))?;
    let image = std::fs::read(&a.image).map_err(|e| format!("read image: {e}"))?;
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
