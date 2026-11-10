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
//! Two-stage flows (#232 P1 4298093559): on GL.iNet models (MT3000) the
//! accepted upload only STORES the image — flashing starts when a GET
//! hits the model's `trigger_flash_endpoint` (`/result`), which blocks
//! until the flash completes (~360 s) and answers `success`. Pass
//! `--trigger /result` and the twin sends that second request on a
//! FRESH connection (the upload connection is `Connection: close`) and
//! only then reports success. Without `--trigger` the twin stops after
//! the upload verdict — do not use a two-stage model without it, or
//! the experiment reports completion while the image merely sits
//! uploaded.
//!
//! Refuses to run without an explicit `--target` — no defaults, the
//! operator names the router on every invocation:
//!
//! ```text
//! cargo run -p conwrt-executor --example recovery-post -- \
//!     --target 192.168.0.1:80 --image openwrt.bin \
//!     [--endpoint /upload] [--field firmware] \
//!     [--accept-pattern "Upgrade successfully!"] \
//!     [--trigger /result] [--yes]
//! ```
//!
//! The endpoint and field are flags because recovery httpds disagree
//! per model (e.g. glinet-gl-ar300m-lite: endpoint `/`, field
//! `nor__firmware`) — a POST to the wrong path burns the window just
//! the same. The confirmation gate prints the full identity (target,
//! image, sha256, endpoint, field) and requires a typed `yes` (or
//! `--yes`) before touching the network: nothing is sent, not even a
//! TCP connect, until the operator confirms the specimen behind the
//! target was verified (MAC/serial against the lab registry — the
//! AGENTS.md specimen gate is the operator's to run, the twin's to
//! demand acknowledgment of).
//!
//! Scope: this twin exists to exercise the MCU's exact wire path (the
//! executor state machines). It is NOT the D-Link COVR laptop
//! flashing procedure — that flow stays on real Chromium per the
//! AGENTS.md D-Link matrix.

use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use conwrt_agent_proto::protocol::StreamChunk;
use conwrt_executor::multipart::{BOUNDARY_PREFIX, Multipart, UPLOAD_FIELD};
use conwrt_executor::post::retain_verdict_bytes;
use conwrt_executor::transfer::TransferState;
use conwrt_executor::{HttpIo, PostError, PostOutcome, RecoveryPost, Verdict};

const USAGE: &str = "usage: recovery-post --target HOST:PORT --image PATH [--endpoint PATH] [--field NAME] [--accept-pattern PATTERN] [--trigger PATH] [--yes]";

/// Undrained window capacity — the F746 firmware profile, so the twin
/// reproduces the MCU's chunk/pump cadence.
const WINDOW: usize = 8 * 1024;
/// Controller chunk size (lock-step with the window).
const CHUNK: usize = 4 * 1024;
/// The transfer id a solo twin uses.
const TRANSFER_ID: u64 = 1;
/// Per-read response deadline (#232 P2 4298093594): the `HttpIo`
/// contract requires bounded reads (post.rs — the reference
/// `TcpHttpIo` uses 30 s per read; the Python uploader bounds the
/// whole POST at `curl -m 400`). A server that accepts but never
/// FINs must turn into a failed verdict, not a hung twin, after the
/// irreversible POST.
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Trigger-read deadline (#232 P1 4298093559): the trigger request
/// BLOCKS until the flash completes (`trigger_blocks_until_done` in
/// models/glinet-mt3000.json — ~360 s), so the 30 s upload-verdict
/// budget would fire mid-flash. Mirrors the Python twin's
/// `flash_time_seconds + 60` (scripts/flash/upload.py::trigger_flash).
const TRIGGER_READ_TIMEOUT: Duration = Duration::from_secs(420);

struct Args {
    target: SocketAddr,
    image_path: String,
    endpoint: String,
    field: String,
    accept_pattern: String,
    /// Two-stage flow: GET this path after an accepted upload to start
    /// the flash (models' `trigger_flash_endpoint`, e.g. MT3000 `/result`).
    trigger: Option<String>,
    assume_yes: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut target: Option<String> = None;
    let mut image: Option<String> = None;
    let mut endpoint = String::from("/upload");
    let mut field = String::from(UPLOAD_FIELD);
    let mut accept_pattern = String::from(conwrt_executor::post::ACCEPT_PATTERN);
    let mut trigger: Option<String> = None;
    let mut assume_yes = false;

    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        if flag == "--yes" {
            assume_yes = true;
            continue;
        }
        let value = argv.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--target" => target = Some(value),
            "--image" => image = Some(value),
            "--endpoint" => endpoint = value,
            "--field" => field = value,
            "--accept-pattern" => accept_pattern = value,
            "--trigger" => trigger = Some(value),
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
    if !endpoint.starts_with('/') {
        return Err(format!(
            "--endpoint {endpoint:?} must be an absolute path (models name it e.g. `/` or `/upload`)"
        ));
    }
    if let Some(path) = &trigger
        && !path.starts_with('/')
    {
        return Err(format!(
            "--trigger {path:?} must be an absolute path (the model's trigger_flash_endpoint, e.g. `/result`)"
        ));
    }
    Ok(Args {
        target,
        image_path,
        endpoint,
        field,
        accept_pattern,
        trigger,
        assume_yes,
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
struct StdIo {
    stream: TcpStream,
    read_timeout: Duration,
}

impl HttpIo for StdIo {
    type Error = std::io::Error;

    async fn write_all(&mut self, data: &[u8]) -> Result<(), std::io::Error> {
        std::io::Write::write_all(&mut self.stream, data)
    }

    async fn read_response(&mut self, out: &mut Vec<u8>) -> Result<(), std::io::Error> {
        use std::io::Read;
        // The HttpIo bounded-read contract (#232 P2 4298093594): the
        // deadline expires as WouldBlock/TimedOut, which surfaces on
        // the error path as PostError::Read — failed verdict, burned
        // window, no manual termination needed.
        self.stream.set_read_timeout(Some(self.read_timeout))?;
        let mut buf = [0u8; 512];
        loop {
            match self.stream.read(&mut buf) {
                Ok(0) => return Ok(()), // server FIN: verdict complete
                // same bounded retention as the firmware: the twin
                // reproduces the MCU's read behavior exactly
                Ok(n) => {
                    retain_verdict_bytes(out, &buf[..n]);
                }
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
        RecoveryPost::new(mp, &host, &args.endpoint).with_accept_pattern(&args.accept_pattern);

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

/// Stage two of the GL.iNet two-stage flow (#232 P1 4298093559):
/// after an ACCEPTED upload verdict, GET the model's
/// `trigger_flash_endpoint` on a fresh connection — the trigger starts
/// the actual flash and blocks until it completes, so the read budget
/// is [`TRIGGER_READ_TIMEOUT`], not the 30 s upload-verdict one.
async fn send_trigger(
    target: SocketAddr,
    host: &str,
    endpoint: &str,
) -> Result<conwrt_executor::TriggerVerdict, PostError> {
    let stream = TcpStream::connect(target).map_err(|_| PostError::Write { op: "trigger" })?;
    let mut io = StdIo {
        stream,
        read_timeout: TRIGGER_READ_TIMEOUT,
    };
    conwrt_executor::TriggerRequest::new(host, endpoint)
        .trigger(&mut io)
        .await
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

    let sha256 = {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(&image);
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };

    eprintln!("target         {}", args.target);
    eprintln!(
        "endpoint       {} (must match the model's upload_endpoint)",
        args.endpoint
    );
    eprintln!("image          {} ({} bytes)", args.image_path, image.len());
    eprintln!("sha256         {sha256}");
    eprintln!(
        "window         {WINDOW} bytes (F746 firmware profile), field {:?}, accept {:?}",
        args.field, args.accept_pattern
    );
    if let Some(path) = &args.trigger {
        eprintln!(
            "trigger        {path} (two-stage flow: upload stores, GET {path} flashes; the GET blocks up to {} s)",
            TRIGGER_READ_TIMEOUT.as_secs()
        );
    }
    eprintln!(
        "one-request rule: this POST is the first and only HTTP request; a failure burns\n\
         the recovery window (re-arm = power-cycle the router into recovery){}",
        if args.trigger.is_some() {
            " — the trigger GET is the documented\n         second request, sent only after an accepted upload"
        } else {
            ""
        }
    );

    if !args.assume_yes {
        eprintln!(
            "confirm the identity pair above: the SPECIMEN behind {} was verified\n\
             (MAC/serial against the lab registry — AGENTS.md specimen gate), and this\n\
             image is the right firmware for that exact unit.",
            args.target
        );
        eprint!("type `yes` to burn the window, anything else aborts: ");
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .expect("read confirmation");
        if answer.trim() != "yes" {
            eprintln!("aborted before any network IO — the recovery window is intact");
            std::process::exit(2);
        }
    }

    let stream = match TcpStream::connect(args.target) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: connect {}: {e}", args.target);
            std::process::exit(1);
        }
    };
    eprintln!("connected");
    let mut io = StdIo {
        stream,
        read_timeout: READ_TIMEOUT,
    };

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
                // #232 P1 4298093559: on two-stage models an accepted
                // upload means STORED, not flashing — the run is not a
                // success until the trigger verdict says the flash ran
                // (or was already consumed). The trigger is NEVER sent
                // after a rejected/no-response upload: it would flash
                // whatever stale image the server holds.
                let Some(trigger_path) = args.trigger.clone() else {
                    return;
                };
                let host = args.target.ip().to_string();
                match rt.block_on(send_trigger(args.target, &host, &trigger_path)) {
                    Ok(conwrt_executor::TriggerVerdict::Success) => {
                        println!("trigger: flash completed ('success' from {trigger_path})");
                    }
                    Ok(conwrt_executor::TriggerVerdict::InProgress) => {
                        println!(
                            "trigger: 'Update in progress' — the flash has started, answer came early"
                        );
                    }
                    Ok(conwrt_executor::TriggerVerdict::NoResponse) => {
                        // The lenient 1.x shape (upload.py::trigger_flash):
                        // an empty trigger answer often means it was
                        // already consumed — warn, do not fail the run.
                        eprintln!(
                            "trigger: EMPTY response from {trigger_path} — the flash may have been consumed already; verify boot on the wire"
                        );
                    }
                    Ok(conwrt_executor::TriggerVerdict::Rejected { snippet }) => {
                        eprintln!(
                            "trigger: REJECTED — response body: {snippet:?} (image uploaded but flash not confirmed started)"
                        );
                        std::process::exit(1);
                    }
                    Err(PostError::Read) => {
                        // A deadline expiry after 420 s is the
                        // "flash may still be in progress" lenient shape
                        // (upload.py treats its curl timeout the same).
                        eprintln!(
                            "trigger: read deadline expired — the flash may still be in progress; verify boot on the wire"
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "trigger failed: {e:?} — image uploaded but flash not confirmed started"
                        );
                        std::process::exit(1);
                    }
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// #232 P2 4298093594: the twin's own HttpIo impl must honor the
    /// trait's bounded-read contract (post.rs) — a server that accepts
    /// and then never FINs must produce a transport error within the
    /// deadline, not hang the twin after the irreversible POST. The
    /// outer recv_timeout is the red shape: pre-fix, the blocking read
    /// never returns.
    #[test]
    fn read_response_is_bounded_against_a_mute_server() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        // Accept, hold the socket open, never write, never FIN.
        let server = std::thread::spawn(move || {
            let (_conn, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_secs(1));
        });

        let stream = TcpStream::connect(addr).unwrap();
        let mut io = StdIo {
            stream,
            read_timeout: Duration::from_millis(250),
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("current-thread runtime");
            let mut out = Vec::new();
            let result = rt.block_on(async { io.read_response(&mut out).await });
            let _ = tx.send(result);
        });

        match rx.recv_timeout(Duration::from_secs(3)) {
            Ok(Err(e)) => assert!(
                matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ),
                "deadline expiry must surface as the read-timeout kind, got {e:?}"
            ),
            Ok(Ok(())) => panic!("a mute server must not read as a complete verdict"),
            Err(recv_timeout) => panic!(
                "read_response never returned against a mute server \
                 ({recv_timeout}): StdIo lacks the contract's read deadline"
            ),
        }
        reader.join().unwrap();
        server.join().unwrap();
    }

    /// #232 P1 4298093559 — the MT3000 two-stage flow, end to end over
    /// real sockets: connection 1 takes the multipart POST and answers
    /// the GL.iNet `<size> <md5>` upload verdict; connection 2 must be
    /// the trigger `GET /result`, answered with `success`. The red
    /// shape is compile-level: pre-fix, the twin had no trigger path —
    /// an accepted upload verdict WAS the success exit.
    #[test]
    fn two_stage_upload_then_trigger_gets_result_before_success() {
        use std::io::{Read, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            // Stage 1: drain the upload POST until the multipart
            // footer tail, answer the GL.iNet size-md5 shape.
            let (mut conn, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = conn.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                seen.extend_from_slice(&buf[..n]);
                if seen.ends_with(b"--\r\n") {
                    break; // multipart footer tail: body complete
                }
            }
            assert!(
                seen.starts_with(b"POST /upload HTTP/1.1\r\n"),
                "upload first"
            );
            conn.write_all(b"4194304 0d7e2f8d5c3b1a9f6e4d2c8b7a6f5e3d")
                .unwrap();
            drop(conn);

            // Stage 2: the trigger — a SECOND connection carrying the
            // model's trigger_flash_endpoint as a GET.
            let (mut conn, _) = listener.accept().unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 512];
            loop {
                let n = conn.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&buf[..n]);
                if req.ends_with(b"\r\n\r\n") {
                    break; // request head complete
                }
            }
            let first_line = String::from_utf8_lossy(&req).into_owned();
            let first_line = first_line.lines().next().unwrap_or_default().to_string();
            conn.write_all(b"success").unwrap();
            drop(conn);
            first_line
        });

        let stream = TcpStream::connect(addr).unwrap();
        let mut io = StdIo {
            stream,
            read_timeout: Duration::from_secs(5),
        };
        let image = vec![0xA5u8; 8 * 1024];
        let args = Args {
            target: addr,
            image_path: "test-image".into(),
            endpoint: "/upload".into(),
            field: "firmware".into(),
            accept_pattern: "Upgrade successfully!".into(),
            trigger: Some("/result".into()),
            assume_yes: true,
        };
        let boundary = String::from("----WebKitFormBoundary0123456789abcdef");
        let mp = Multipart {
            boundary: &boundary,
            field: &args.field,
            filename: "recovery.bin",
            image_len: image.len() as u64,
        };
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("current-thread runtime");
        let outcome = rt.block_on(run(&mut io, mp, &image, &args)).unwrap();
        assert_eq!(outcome.verdict, Verdict::Accepted, "size-md5 shape accepts");

        let host = addr.ip().to_string();
        let verdict = rt
            .block_on(send_trigger(addr, &host, "/result"))
            .expect("trigger completes");
        assert_eq!(verdict, conwrt_executor::TriggerVerdict::Success);

        let trigger_line = server.join().unwrap();
        assert_eq!(
            trigger_line, "GET /result HTTP/1.1",
            "the second request must be the trigger GET, got {trigger_line:?}"
        );
    }
}
