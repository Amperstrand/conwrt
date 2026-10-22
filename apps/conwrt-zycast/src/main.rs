//! # conwrt-zycast — ZyXEL multicast flash sender (Rust port)
//!
//! Wire-compatible with the hardware-tested Go `cmd/zycast` sender:
//! streams a firmware image as UDP multicast packets that a ZyXEL
//! Z-Loader bootloader in its listen window reassembles and flashes.
//! Linux/OpenWrt only (SO_BINDTODEVICE egress binding).
//!
//! The sender is deliberately loop-bounded by default (3 loops). An
//! unbounded sender plus the bootloader's listen-on-every-boot behavior
//! is the documented infinite-reflash hazard — pass `--loops` explicitly
//! if you need more airtime, never `--loops 0` (unlimited) on a shared
//! bench segment.

use clap::Parser;
use conwrt_protocols::zycast::sender::{SendConfig, send};
use conwrt_protocols::zycast::{
    DEFAULT_GROUP, DEFAULT_LOOP_GAP_MS, DEFAULT_PACKET_DELAY_MS, DEFAULT_PORT, ImageType,
};
use std::io;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(
    name = "conwrt-zycast",
    version,
    about = "ZyXEL multicast flash sender (Rust port of cmd/zycast send)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Stream an image as zycast multicast.
    Send {
        /// Egress interface name (e.g. `lan`, `switch.1002`).
        #[arg(short = 'i', long)]
        iface: String,
        /// Multicast group address.
        #[arg(short = 'g', long, default_value = DEFAULT_GROUP)]
        group: Ipv4Addr,
        /// Multicast UDP port.
        #[arg(short = 'p', long, default_value_t = DEFAULT_PORT)]
        port: u16,
        /// Image type (target partition bitmap).
        #[arg(short = 't', long, default_value = "ras")]
        image_type: String,
        /// Stop after N complete loops (0 = unlimited — discouraged).
        #[arg(long, default_value_t = 3)]
        loops: u32,
        /// Inter-packet delay in milliseconds.
        #[arg(long, default_value_t = DEFAULT_PACKET_DELAY_MS)]
        delay_ms: u64,
        /// Pause between loops in milliseconds.
        #[arg(long, default_value_t = DEFAULT_LOOP_GAP_MS)]
        loop_gap_ms: u64,
        /// Hard runtime bound in seconds (0 = none).
        #[arg(long, default_value_t = 0)]
        timeout_secs: u64,
        /// Firmware image file.
        image: PathBuf,
    },
}

struct SendArgs {
    iface: String,
    group: Ipv4Addr,
    port: u16,
    image_type: String,
    loops: u32,
    delay_ms: u64,
    loop_gap_ms: u64,
    timeout_secs: u64,
    image: PathBuf,
}

fn main() {
    let Cli { command } = Cli::parse();
    match command {
        Command::Send {
            iface,
            group,
            port,
            image_type,
            loops,
            delay_ms,
            loop_gap_ms,
            timeout_secs,
            image,
        } => run_send(&SendArgs {
            iface,
            group,
            port,
            image_type,
            loops,
            delay_ms,
            loop_gap_ms,
            timeout_secs,
            image,
        }),
    }
}

fn run_send(args: &SendArgs) -> ! {
    let SendArgs {
        iface,
        group,
        port,
        image_type,
        loops,
        delay_ms,
        loop_gap_ms,
        timeout_secs,
        image: image_path,
    } = args;
    let (group, port, loops, delay_ms, loop_gap_ms, timeout_secs) = (
        *group,
        *port,
        *loops,
        *delay_ms,
        *loop_gap_ms,
        *timeout_secs,
    );
    let (image_type, image_path) = (image_type.as_str(), image_path.as_path());
    let Some(image_type) = ImageType::parse(image_type) else {
        eprintln!("unknown image type {image_type:?} (bootbase|rom|ras|romd|backup)");
        std::process::exit(2);
    };
    let image = match std::fs::read(image_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("cannot read {}: {e}", image_path.display());
            std::process::exit(2);
        }
    };
    if loops == 0 && timeout_secs == 0 {
        eprintln!(
            "refusing unbounded send (loops=0, timeout=0) — pick a loop count or a timeout; \
             an unbounded sender is the reflash-loop hazard (AGENTS.md)"
        );
        std::process::exit(2);
    }
    let cfg = SendConfig {
        group,
        port,
        iface: iface.to_string(),
        image_type,
        loops: if loops == 0 { None } else { Some(loops) },
        packet_delay: Duration::from_millis(delay_ms),
        loop_gap: Duration::from_millis(loop_gap_ms),
    };
    let chunks = conwrt_protocols::zycast::chunk_count(image.len());
    println!(
        "image: {} ({} bytes, {} chunks, type={image_type})",
        image_path.display(),
        image.len(),
        chunks
    );
    println!(
        "iface: {iface}, dst: {group}:{port}, loops: {}, delay: {delay_ms}ms, timeout: {timeout_secs}s",
        if loops == 0 {
            "unlimited".to_string()
        } else {
            loops.to_string()
        }
    );

    let started = Instant::now();
    let deadline = (timeout_secs > 0).then(|| started + Duration::from_secs(timeout_secs));
    let result = send(
        &image,
        &cfg,
        || deadline.is_some_and(|d| Instant::now() >= d),
        |loop_no, chunks| {
            let elapsed = started.elapsed().as_secs_f64();
            println!(
                "[zycast] loop {loop_no} complete ({chunks} chunks, {:.0} pkt/s, {elapsed:.0}s elapsed)",
                loop_no as f64 * chunks as f64 / elapsed.max(1e-9)
            );
        },
    );
    match result {
        Ok(stats) if stats.packets_sent > 0 => {
            println!(
                "[zycast] done: {} packets across {} loop(s) in {:.0}s",
                stats.packets_sent,
                stats.loops_completed,
                started.elapsed().as_secs_f64()
            );
            std::process::exit(0);
        }
        Ok(_) => {
            eprintln!("[zycast] sent nothing (timeout before first packet?)");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("[zycast] send failed: {e}");
            if e.kind() == io::ErrorKind::NotFound {
                eprintln!(
                    "       (unknown interface {iface:?}? SO_BINDTODEVICE needs the netdev name)"
                );
            }
            std::process::exit(1);
        }
    }
}
