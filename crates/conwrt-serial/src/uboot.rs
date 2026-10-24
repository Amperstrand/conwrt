//! U-Boot serial flash stage: BREAK-reboot ladder, `loady` + YMODEM
//! transfer, verification gates, explicit-address `bootm`.
//!
//! Proven on the bench GS1900-8HP (RTL8382M, U-Boot 2011.12.39239)
//! 2026-10-23: BREAK+sysrq-b through a live wedge-tick storm, space-bar
//! autoboot interrupt (bootdelay 1 s — keep pressing through the DRAM
//! calibration phase, which can exceed 30 s on warm reboot), `loady`
//! YMODEM at 115200 (10.4 KiB/s sustained), U-Boot's `## Total Size`
//! line as the byte-count gate, `iminfo` as the header-integrity gate,
//! and explicit-address `bootm` (a bare `bootm` uses the stock
//! `b4100000` boot address, NOT the loady target).
//!
//! Safety: every write here is RAM-only. The only flash write in the
//! recipe is a later `sysupgrade` of a sha-verified image from inside
//! the booted initramfs — never from this module.

use std::time::{Duration, Instant};

use crate::io::ConsoleIo;
use crate::io::open_break_port;
use crate::recovery::{BreakIo, SysrqKey, send_sysrq};

/// The RTL838x U-Boot prompt banner we press SPACE through bootdelay for.
pub const UBOOT_PROMPT: &[u8] = b"RTL838x#";
/// Default GS1900/RTL838x RAM load address for `loady`.
pub const DEFAULT_LOAD_ADDR: &str = "0x84f00000";

/// Failure modes of the U-Boot loady stage. Every variant leaves the
/// device in a safe state (RAM-only writes; flash untouched).
#[derive(Debug)]
pub enum UbootError {
    /// Serial transport failure.
    Io(String),
    /// The BREAK ladder never reached the U-Boot prompt.
    NoPrompt,
    /// The YMODEM transfer failed (invitation, frame retries, or CAN).
    TransferFailed(String),
    /// U-Boot's `Total Size` line did not match the sent byte count —
    /// `bootm` was withheld.
    SizeGate {
        /// Size the loader reported (None = no Total Size line found).
        got: Option<u64>,
        /// The exact byte count we sent.
        want: u64,
    },
    /// `iminfo` did not verify the image header — `bootm` withheld.
    IminfoBad,
    /// `bootm` produced no kernel output within the wait window.
    BootFailed,
}

impl std::fmt::Display for UbootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UbootError::Io(e) => write!(f, "serial io: {e}"),
            UbootError::NoPrompt => write!(
                f,
                "no U-Boot prompt (BREAK ladder exhausted; DRAM calibration can take >30s)"
            ),
            UbootError::TransferFailed(e) => write!(f, "ymodem transfer failed: {e}"),
            UbootError::SizeGate { got, want } => {
                write!(
                    f,
                    "size gate: loader reported {got:?}, expected {want} — NOT booting"
                )
            }
            UbootError::IminfoBad => write!(f, "iminfo did not verify the image header"),
            UbootError::BootFailed => write!(f, "bootm produced no kernel output"),
        }
    }
}
impl std::error::Error for UbootError {}

fn read_for(io: &mut dyn ConsoleIo, secs: f64, sink: &mut Vec<u8>) -> usize {
    let deadline = Instant::now() + Duration::from_secs_f64(secs.max(0.05));
    let mut n = 0;
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline {
        match io.read(&mut buf) {
            Ok(0) => {}
            Ok(k) => {
                sink.extend_from_slice(&buf[..k]);
                n += k;
            }
            Err(_) => break,
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    n
}

fn write_line(io: &mut dyn ConsoleIo, line: &str) -> Result<(), UbootError> {
    io.write_all_bytes(format!("{line}\n").as_bytes())
        .map_err(|e| UbootError::Io(e.to_string()))
}

/// BREAK+sysrq-b reboot, then press SPACE through the bootdelay (and the
/// slow warm-reboot DRAM phase) until the `RTL838x#` prompt appears.
pub fn break_to_prompt(io: &mut dyn BreakIo, ladder_secs: f64) -> Result<(), UbootError> {
    // sysrq needs the BREAK-capable view; the probing helpers only need
    // ConsoleIo — re-coerce per phase so the borrows never overlap.
    {
        let cio: &mut dyn ConsoleIo = io as &mut dyn ConsoleIo;
        // plain probe first (box may already sit at the prompt)
        let _ = cio.write_all_bytes(b"\r");
        let mut sink = Vec::new();
        read_for(cio, 2.0, &mut sink);
        if sink.windows(UBOOT_PROMPT.len()).any(|w| w == UBOOT_PROMPT) {
            return Ok(());
        }
    }
    send_sysrq(io, SysrqKey::Reboot).map_err(|e| UbootError::Io(format!("sysrq: {e}")))?;
    let deadline = Instant::now() + Duration::from_secs_f64(ladder_secs.max(10.0));
    while Instant::now() < deadline {
        let cio: &mut dyn ConsoleIo = io as &mut dyn ConsoleIo;
        let _ = cio.write_all_bytes(b"  ");
        let mut sink = Vec::new();
        read_for(cio, 0.8, &mut sink);
        if sink.windows(UBOOT_PROMPT.len()).any(|w| w == UBOOT_PROMPT) {
            // settle, then draw a clean prompt
            std::thread::sleep(Duration::from_millis(400));
            let _ = cio.write_all_bytes(b"\r");
            let mut t = Vec::new();
            read_for(cio, 1.5, &mut t);
            return Ok(());
        }
    }
    Err(UbootError::NoPrompt)
}

// ---- YMODEM (single-file batch) -------------------------------------
// Frame control bytes (YMODEM/XMODEM, standard values).

/// Start of a 128-byte header/data frame.
pub const SOH: u8 = 0x01;
/// Start of a 1024-byte data frame.
pub const STX: u8 = 0x02;
/// End-of-transmission marker.
pub const EOT: u8 = 0x04;
/// Receiver acknowledgement.
pub const ACK: u8 = 0x06;
/// Receiver/sender cancel.
pub const CAN: u8 = 0x18;
/// 'C' — the CRC-mode invitation the receiver polls.
pub const C_INVITE: u8 = 0x43;

/// CRC16/XMODEM (CCITT, poly 0x1021, init 0) of a frame payload.
pub fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// Build one YMODEM frame (start + seq + complement + padded payload +
/// CRC16 big-endian). Pure function — unit-testable against known bytes.
pub fn build_frame(blkno: u8, payload: &[u8], use_1k: bool) -> Vec<u8> {
    let frame_len = if use_1k { 1024 } else { 128 };
    let mut padded = payload.to_vec();
    padded.resize(frame_len, 0x1a);
    let mut frame = Vec::with_capacity(frame_len + 5);
    frame.push(if use_1k { STX } else { SOH });
    frame.push(blkno);
    frame.push(!blkno);
    frame.extend_from_slice(&padded);
    frame.extend_from_slice(&crc16_xmodem(&padded).to_be_bytes());
    frame
}

fn read_byte(io: &mut dyn ConsoleIo, timeout: f64) -> Option<u8> {
    let deadline = Instant::now() + Duration::from_secs_f64(timeout.max(0.1));
    let mut b = [0u8; 1];
    while Instant::now() < deadline {
        if let Ok(1) = io.read(&mut b) {
            return Some(b[0]);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    None
}

fn send_frame(io: &mut dyn ConsoleIo, frame: &[u8], tries: u8) -> Result<(), UbootError> {
    let mut attempt = 0;
    while attempt < tries {
        io.write_all_bytes(frame)
            .map_err(|e| UbootError::Io(e.to_string()))?;
        match read_byte(io, 10.0) {
            Some(ACK) => return Ok(()),
            Some(CAN) => return Err(UbootError::TransferFailed("receiver CANcelled".into())),
            other => {
                eprintln!("ymodem frame retry {attempt} (rx {other:?})");
            }
        }
        attempt += 1;
    }
    Err(UbootError::TransferFailed("frame retries exhausted".into()))
}

/// Drive `loady <addr>` and YMODEM-send `image` named `name`.
/// Returns after the loader's end-of-batch handshake.
pub fn loady_ymodem(
    io: &mut dyn ConsoleIo,
    addr: &str,
    name: &str,
    image: &[u8],
    mut progress: impl FnMut(u64, u64),
) -> Result<(), UbootError> {
    write_line(io, &format!("loady {addr}"))?;
    // wait for the C invitation (the loader polls C ~1/s)
    let mut invited = false;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Some(C_INVITE) = read_byte(io, 5.0) {
            invited = true;
            break;
        }
    }
    if !invited {
        return Err(UbootError::TransferFailed(
            "no YMODEM invitation (C)".into(),
        ));
    }

    // block 0: name\0size\0 (128-byte frame). The handshake after it is
    // loader-dependent — U-Boot may send C BEFORE ACK, so accept either
    // order (bench lesson 2026-10-23: strict ACK-then-C aborts wrongly).
    let header = format!("{name}\0{}\0", image.len());
    send_frame(io, &build_frame(0, header.as_bytes(), false), 10)?;
    let mut got_c = false;
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        match read_byte(io, 5.0) {
            Some(C_INVITE) => {
                got_c = true;
                break;
            }
            Some(ACK) => {}
            Some(other) => eprintln!("block0 handshake byte {other:#x}"),
            None => {}
        }
    }
    if !got_c {
        return Err(UbootError::TransferFailed("no C after block 0".into()));
    }

    let mut sent: u64 = 0;
    let mut blkno: u8 = 1;
    while (sent as usize) < image.len() {
        let end = ((sent as usize) + 1024).min(image.len());
        send_frame(
            io,
            &build_frame(blkno, &image[sent as usize..end], true),
            10,
        )?;
        sent = end as u64;
        blkno = blkno.wrapping_add(1);
        progress(sent, image.len() as u64);
    }

    // EOT dance, then the terminating null block-0
    for _ in 0..10 {
        io.write_all_bytes(&[EOT])
            .map_err(|e| UbootError::Io(e.to_string()))?;
        if let Some(ACK) = read_byte(io, 10.0) {
            break;
        }
    }
    let _ = read_byte(io, 3.0);
    send_frame(io, &build_frame(0, b"", false), 5)
}

/// U-Boot's `## Total Size = N Bytes` after loady — the byte-count gate.
pub fn parse_total_size(loader_output: &[u8]) -> Option<u64> {
    let text = String::from_utf8_lossy(loader_output);
    let idx = text.rfind("Total Size")?;
    let rest = &text[idx..];
    // U-Boot prints either "Total Size = N Bytes" or
    // "Total Size = 0xHEX = N Bytes" — take the digit run that ends at
    // " Bytes" (the hex form's leading digits must not win).
    let bytes_at = rest.find(" Bytes")?;
    let head = &rest[..bytes_at];
    let start = head
        .rfind(|c: char| !c.is_ascii_digit())
        .map(|i| i + 1)
        .unwrap_or(0);
    head[start..].trim_start_matches('=').trim().parse().ok()
}

/// Full stage: BREAK ladder -> optional command prologue -> loady+YMODEM
/// -> size gate -> iminfo gate -> (optionally) bootm <addr>.
///
/// RAM-only by construction; see the module docs for the safety model.
pub fn loady_stage_on(
    io: &mut dyn ConsoleIo,
    addr: &str,
    name: &str,
    image: &[u8],
    prologue: &[String],
    boot: bool,
) -> Result<(), UbootError> {
    let mut early = Vec::new();
    for cmd in prologue {
        write_line(io, cmd)?;
        read_for(io, 2.5, &mut early);
    }

    let mut transcript = early;
    loady_ymodem(io, addr, name, image, |s, t| {
        if s % (128 * 1024) == 0 || s == t {
            eprintln!("ymodem {s}/{t}");
        }
    })?;
    read_for(io, 4.0, &mut transcript);

    // Settle + fresh line before ANY post-transfer command (bench lesson
    // 2026-10-23, twice): the YMODEM end-batch padding echoes back into
    // the next command line ("Unknown command '\x1a..iminfo'", and a
    // bare bootm at the stock address). Drain, then a lone newline to
    // draw a clean prompt, before iminfo/bootm.
    std::thread::sleep(Duration::from_millis(500));
    io.write_all_bytes(b"\n")
        .map_err(|e| UbootError::Io(e.to_string()))?;
    read_for(io, 1.5, &mut transcript);

    let want = image.len() as u64;
    match parse_total_size(&transcript) {
        Some(got) if got == want => {}
        other => return Err(UbootError::SizeGate { got: other, want }),
    }

    write_line(io, &format!("iminfo {addr}"))?;
    let mut info = Vec::new();
    read_for(io, 4.0, &mut info);
    if !info.windows(2).any(|w| w == b"OK") {
        return Err(UbootError::IminfoBad);
    }

    if boot {
        // A bare `bootm` uses the stock boot address — always pass ours.
        write_line(io, &format!("bootm {addr}"))?;
        let mut boot_out = Vec::new();
        read_for(io, 150.0, &mut boot_out);
        let alive = boot_out.windows(6).any(|w| w == b"OpenWrt")
            || boot_out.windows(6).any(|w| w == b"BusyBox")
            || boot_out.windows(5).any(|w| w == b"login");
        if !alive {
            return Err(UbootError::BootFailed);
        }
    }
    Ok(())
}

/// Port-opening convenience wrapper (the CLI entry): open the port,
/// BREAK-ladder to the prompt, run the gated loady stage on it.
pub fn flash_stage_loady(
    port_spec: &str,
    baud: u32,
    addr: &str,
    name: &str,
    image: &[u8],
    prologue: &[String],
    boot: bool,
) -> Result<(), UbootError> {
    let mut io = open_break_port(port_spec, baud, Duration::from_millis(200))
        .map_err(|e| UbootError::Io(e.to_string()))?;
    break_to_prompt(io.as_mut(), 90.0)?;
    loady_stage_on(io.as_mut(), addr, name, image, prologue, boot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc16_matches_xmodem_reference() {
        // Reference vector: CRC-16/XMODEM("123456789") = 0x31C3
        assert_eq!(crc16_xmodem(b"123456789"), 0x31c3);
        assert_eq!(crc16_xmodem(b""), 0x0000);
    }

    #[test]
    fn frame_layout_128() {
        let f = build_frame(0, b"img.bin\x006529354\x00", false);
        assert_eq!(f.len(), 133); // SOH + seq + comp + 128 + crc16
        assert_eq!(f[0], SOH);
        assert_eq!(f[1], 0);
        assert_eq!(f[2], 0xFF);
        // exact header bytes, 0x1A padding to 128
        assert_eq!(&f[3..11], b"img.bin\0");
        assert_eq!(&f[11..19], b"6529354\0");
        assert!(f[19..131].iter().all(|&b| b == 0x1a));
        let crc = crc16_xmodem(&f[3..131]);
        assert_eq!(&f[131..133], &crc.to_be_bytes());
    }

    #[test]
    fn frame_layout_1k_seq_wraps() {
        let f = build_frame(1, &[0xAB; 1024], true);
        assert_eq!(f.len(), 1029); // STX + seq + comp + 1024 + crc16
        assert_eq!(f[0], STX);
        assert_eq!(f[1], 1);
        assert_eq!(f[2], 0xFE);
        // wrap-around numbering (block 256 -> byte 0x00, complement 0xFF)
        let g = build_frame(0, &[0xCD; 1024], true);
        assert_eq!(g[1], 0);
        assert_eq!(g[2], 0xFF);
    }

    #[test]
    fn total_size_parser_handles_loader_line() {
        let out = b"## Ready for binary (ymodem) download to 0x84F00000 at 115200 bps...\r\nC\r\n## Total Size = 0x00639c4a = 6529354 Bytes = 6376.3 KiB\r\nRTL838x#";
        assert_eq!(parse_total_size(out), Some(6_529_354));
        // also decimal-only form
        assert_eq!(
            parse_total_size(b"Total Size = 6529354 Bytes"),
            Some(6_529_354)
        );
        assert_eq!(parse_total_size(b"nothing here"), None);
    }

    #[test]
    fn total_size_parser_takes_last_occurrence() {
        let out = b"Total Size = 10 Bytes\r\nnoise\r\nTotal Size = 20 Bytes";
        assert_eq!(parse_total_size(out), Some(20));
    }
}
