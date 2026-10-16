//! Host twin of the F746 recovery POST (#226 slice 3): run the EXACT
//! executor wire path — `TransferState` window + `Multipart` framing +
//! `RecoveryPost` pump — from a laptop against a real router in U-Boot
//! recovery, no MCU needed. Validates wire behavior before the bench
//! leg touches hardware.
//!
//! The one-request contract binds the laptop exactly as it binds the
//! MCU (AGENTS.md): the POST is the first and only HTTP request — never
//! GET the recovery page first (probe by ARP only); a partial or failed
//! POST burns the recovery window and re-arming means power-cycling the
//! router back into recovery.
//!
//! Refuses to run without an explicit `--target` — no defaults, the
//! operator names the router on every invocation:
//!
//! ```text
//! cargo run -p conwrt-executor --example recovery-post -- \
//!     --target 192.168.0.1:80 --image openwrt.bin \
//!     [--field firmware] [--accept-pattern "Upgrade successfully!"]
//! ```

use std::net::{SocketAddr, TcpStream};

use conwrt_agent_proto::protocol::StreamChunk;
use conwrt_executor::multipart::{BOUNDARY_PREFIX, Multipart, UPLOAD_FIELD};
use conwrt_executor::transfer::TransferState;
use conwrt_executor::{HttpIo, PostError, PostOutcome, RecoveryPost, Verdict};

const USAGE: &str = "usage: recovery-post --target HOST:PORT --image PATH [--field NAME] [--accept-pattern PATTERN]";

/// Undrained window capacity — the F746 firmware profile, so the twin
/// reproduces the MCU's chunk/pump cadence.
const WINDOW: usize = 8 * 1024;
/// Controller chunk size (lock-step with the window).
const CHUNK: usize = 4 * 1024;
/// The transfer id a solo twin uses.
const TRANSFER_ID: u64 = 1;

struct Args {
    target: SocketAddr,
    image_path: String,
    field: String,
    accept_pattern: String,
}

fn parse_args() -> Result<Args, String> {
    let mut target: Option<String> = None;
    let mut image: Option<String> = None;
    let mut field = String::from(UPLOAD_FIELD);
    let mut accept_pattern = String::from(conwrt_executor::post::ACCEPT_PATTERN);

    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let value = argv.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--target" => target = Some(value),
            "--image" => image = Some(value),
            "--field" => field = value,
            "--accept-pattern" => accept_pattern = value,
            other => return Err(format!("unknown flag {other:?}")),
        }
    }

    // no defaults, ever: the operator names the router per invocation
    let Some(target) = target else {
        return Err(String::from(
            "--target is REQUIRED (explicit, no default — this POST burns a one-request recovery window)",
        ));
    };
    let Some(image_path) = image else {
        return Err(String::from("--image is REQUIRED"));
    };
    let target = target
        .parse()
        .map_err(|e| format!("--target {target:?} is not HOST:PORT ({e})"))?;
    Ok(Args {
        target,
        image_path,
        field,
        accept_pattern,
    })
}

/// WebKit-shaped boundary token: 16 hex chars from a time/pid-seeded
/// xorshift (browsers randomize per request; 1.x proved the shape, not
/// a fixed token).
fn boundary() -> String {
    let mut s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0x5eed_1234u32, |d| d.subsec_nanos() ^ d.as_secs() as u32)
        ^ std::process::id();
    let mut hex = String::with_capacity(16);
    for _ in 0..16 {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        hex.push(char::from_digit(s >> 28, 16).expect("nibble in range"));
    }
    format!("{BOUNDARY_PREFIX}{hex}")
}

/// Blocking std TCP as the pump's transport: the async surface is
/// driven to completion on first poll, so plain IO underneath is exact.
struct StdIo(TcpStream);

impl HttpIo for StdIo {
    type Error = std::io::Error;

    async fn write_all(&mut self, data: &[u8]) -> Result<(), std::io::Error> {
        std::io::Write::write_all(&mut self.0, data)
    }

    async fn read_response(&mut self, out: &mut Vec<u8>) -> Result<(), std::io::Error> {
        use std::io::Read;
        let mut buf = [0u8; 512];
        loop {
            match self.0.read(&mut buf) {
                Ok(0) => return Ok(()), // server FIN: verdict complete
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) => return Err(e),
            }
        }
    }
}

async fn run(
    io: &mut StdIo,
    mp: Multipart<'_>,
    image: &[u8],
    args: &Args,
) -> Result<PostOutcome, PostError> {
    let host = args.target.ip().to_string();
    let mut xfer = TransferState::new(TRANSFER_ID, WINDOW);
    let mut post =
        RecoveryPost::new(mp, &host, "/upload").with_accept_pattern(&args.accept_pattern);

    let mut sent = 0usize;
    while sent < image.len() {
        let end = (sent + CHUNK).min(image.len());
        xfer.accept(&StreamChunk {
            transfer_id: TRANSFER_ID,
            offset: sent as u64,
            total: Some(image.len() as u64),
            data: image[sent..end].to_vec(),
        })
        .expect("chunk fits: bounded by window math, drained every loop");
        if !post.committed() {
            post.start(io, &xfer).await?;
            eprintln!("POST head sent — point of no return for the one-request window");
        }
        post.pump(io, &mut xfer).await?;
        sent = end;
    }
    post.finish(io, &xfer).await
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(msg) => {
            eprintln!("error: {msg}\n{USAGE}");
            std::process::exit(2);
        }
    };
    let image = match std::fs::read(&args.image_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: reading {}: {e}", args.image_path);
            std::process::exit(2);
        }
    };
    if image.is_empty() {
        eprintln!(
            "error: {} is empty — a zero-byte POST still burns the recovery window",
            args.image_path
        );
        std::process::exit(2);
    }

    eprintln!("target         {}", args.target);
    eprintln!("image          {} ({} bytes)", args.image_path, image.len());
    eprintln!(
        "window         {WINDOW} bytes (F746 firmware profile), field {:?}, accept {:?}",
        args.field, args.accept_pattern
    );
    eprintln!(
        "one-request rule: this POST is the first and only HTTP request; a failure burns\n\
         the recovery window (re-arm = power-cycle the router into recovery)"
    );

    let stream = match TcpStream::connect(args.target) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: connect {}: {e}", args.target);
            std::process::exit(1);
        }
    };
    eprintln!("connected");
    let mut io = StdIo(stream);

    let boundary = boundary();
    let mp = Multipart {
        boundary: &boundary,
        field: &args.field,
        filename: "recovery.bin",
        image_len: image.len() as u64,
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("current-thread runtime");
    let outcome = rt.block_on(run(&mut io, mp, &image, &args));

    match outcome {
        Ok(outcome) => match outcome.verdict {
            Verdict::Accepted | Verdict::AcceptedHtml => {
                println!(
                    "verdict: {:?} ({} bytes uploaded)",
                    outcome.verdict, outcome.uploaded
                );
            }
            Verdict::Rejected { snippet } => {
                eprintln!(
                    "verdict: REJECTED — response body: {snippet:?} (window served; treat as a burn if unexplained)"
                );
                std::process::exit(1);
            }
            Verdict::NoResponse => {
                eprintln!(
                    "verdict: NO RESPONSE — the burned-window shape: the server already served or refused its one request"
                );
                std::process::exit(1);
            }
        },
        Err(e) => {
            eprintln!("POST failed: {e:?}");
            let burned = matches!(
                e,
                PostError::Write { .. } | PostError::Read | PostError::Incomplete { .. }
            );
            if burned {
                eprintln!(
                    "the recovery window is burned — re-arm by power-cycling the router into recovery"
                );
            }
            std::process::exit(1);
        }
    }
}
