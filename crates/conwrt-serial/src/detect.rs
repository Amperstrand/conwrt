//! Device detection over the serial console: attach, classify what the
//! box is (U-Boot prompt / Linux shell / booting / silent), and when a
//! prompt is reachable, collect the device card — banner fingerprint,
//! U-Boot environment, kernel release, OpenWrt release, MTD/flash
//! layout — as structured JSON. The "look before you flash" leg of the
//! rescue doctrine: know the target before any write.

use std::time::{Duration, Instant};

use serde::Serialize;

use crate::io::{ConsoleIo, open_port};

/// What the console shows right now.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ConsoleClass {
    /// U-Boot prompt banner visible (e.g. RTL838x#).
    UbootPrompt,
    /// Linux shell prompt visible (root@...).
    LinuxShell,
    /// Boot text streaming (kernel/init messages).
    Booting,
    /// Nothing at all — wedged, hard-locked, or powered off.
    Silent,
}

/// Collected identity + flash layout of the attached device.
#[derive(Debug, Clone, Serialize, PartialEq, Default)]
pub struct DeviceCard {
    /// What the console showed at attach.
    pub class: Option<ConsoleClass>,
    /// U-Boot version banner, when at the U-Boot prompt.
    pub uboot_banner: Option<String>,
    /// Vendor board model from the U-Boot env.
    pub board_model: Option<String>,
    /// Kernel release, when at a Linux shell.
    pub kernel: Option<String>,
    /// DISTRIB_DESCRIPTION, when at a Linux shell.
    pub openwrt_release: Option<String>,
    /// /proc/mtd lines — the flash layout to verify images against.
    pub mtd_layout: Vec<String>,
    /// U-Boot bootcmd (how the box boots).
    pub bootcmd: Option<String>,
    /// U-Boot console baud rate.
    pub baudrate: Option<String>,
    /// U-Boot client IP.
    pub ipaddr: Option<String>,
    /// U-Boot TFTP server IP.
    pub serverip: Option<String>,
    /// Raw transcript of the probe commands (evidence).
    pub probe_transcript: String,
}

fn read_secs(io: &mut dyn ConsoleIo, secs: f64, sink: &mut Vec<u8>) -> usize {
    let deadline = Instant::now() + Duration::from_secs_f64(secs.max(0.05));
    let mut n = 0;
    let mut buf = [0u8; 4096];
    while Instant::now() < deadline {
        match io.read(&mut buf) {
            Ok(k) if k > 0 => {
                sink.extend_from_slice(&buf[..k]);
                n += k;
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => break,
            _ => {}
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    n
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && hay.len() >= needle.len()
        && hay.windows(needle.len()).any(|w| w == needle)
}

fn last_line_matching(text: &str, prefix: &str) -> Option<String> {
    text.lines()
        .rev()
        .find(|l| l.contains(prefix))
        .map(|l| l.trim().to_string())
}

/// Classify the console from a read window (pure — unit-testable).
pub fn classify(window: &[u8]) -> ConsoleClass {
    let text = String::from_utf8_lossy(window);
    let t = text.trim_end();
    let last = t.rsplit('\n').next().unwrap_or("");
    if last.contains('#') && last.contains("RTL838") {
        return ConsoleClass::UbootPrompt;
    }
    if last.starts_with("root@") || last.contains("root@") && last.ends_with('#') {
        return ConsoleClass::LinuxShell;
    }
    if window.is_empty() {
        return ConsoleClass::Silent;
    }
    if text.contains("Starting kernel")
        || text.contains("Linux version")
        || text.contains("init:")
        || text.contains("Calibrating delay loop")
        || text.contains("U-Boot 2011")
    {
        return ConsoleClass::Booting;
    }
    ConsoleClass::Silent
}

/// Probe the console and, when a prompt answers, collect the device
/// card. Read-only: no state on the box changes (printenv/version/mtd
/// listings only).
pub fn detect(port_spec: &str, baud: u32, probe_secs: f64) -> std::io::Result<DeviceCard> {
    let mut io = open_port(port_spec, baud, Duration::from_millis(200))
        .map_err(|e| std::io::Error::other(format!("open {port_spec}: {e}")))?;
    // framing doctrine (audit R3): tcp:// is a RAW relay per io.rs;
    // only telnet:// endpoints negotiate — injecting IAC bytes into a
    // raw bridge is console garbage
    if port_spec.starts_with("telnet://") {
        let _ = io.write_all_bytes(&[0xFF, 0xFB, 0x00, 0xFF, 0xFD, 0x00]);
    }
    let mut card = DeviceCard::default();
    let mut all = Vec::new();

    // poke and classify
    let _ = io.write_all_bytes(b"\r\n");
    read_secs(io.as_mut(), probe_secs, &mut all);
    let class = classify(&all);
    card.class = Some(class.clone());
    card.probe_transcript = String::from_utf8_lossy(&all).to_string();

    let run_cmd = |io: &mut Box<dyn ConsoleIo>, all: &mut Vec<u8>, cmd: &str| {
        let _ = io.write_all_bytes(format!("{cmd}\n").as_bytes());
        read_secs(io.as_mut(), 2.5, all);
    };

    match class {
        ConsoleClass::UbootPrompt => {
            let before = all.len();
            run_cmd(&mut io, &mut all, "printenv");
            let env = String::from_utf8_lossy(&all[before..]).to_string();
            card.board_model = last_line_matching(&env, "boardmodel");
            card.bootcmd = last_line_matching(&env, "bootcmd=");
            card.baudrate = last_line_matching(&env, "baudrate=");
            card.ipaddr = last_line_matching(&env, "ipaddr=");
            card.serverip = last_line_matching(&env, "serverip=");
            let b = last_line_matching(&env, "U-Boot");
            card.uboot_banner = b;
        }
        ConsoleClass::LinuxShell => {
            let before = all.len();
            run_cmd(&mut io, &mut all, "uname -r");
            let u = String::from_utf8_lossy(&all[before..]).to_string();
            card.kernel = u
                .lines()
                .find(|l| l.starts_with("6.") || l.starts_with("5."))
                .map(|l| l.to_string());
            let before = all.len();
            run_cmd(
                &mut io,
                &mut all,
                ". /etc/openwrt_release; echo $DISTRIB_DESCRIPTION",
            );
            let o = String::from_utf8_lossy(&all[before..]).to_string();
            card.openwrt_release = o
                .lines()
                .find(|l| l.contains("OpenWrt"))
                .map(|l| l.trim().to_string());
            let before = all.len();
            run_cmd(&mut io, &mut all, "cat /proc/mtd");
            let m = String::from_utf8_lossy(&all[before..]).to_string();
            card.mtd_layout = m
                .lines()
                .filter(|l| l.starts_with("mtd"))
                .map(|l| l.trim().to_string())
                .collect();
        }
        _ => {}
    }
    Ok(card)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_uboot_vs_linux_vs_silent() {
        assert_eq!(classify(b"noise\r\nRTL838x# "), ConsoleClass::UbootPrompt);
        assert_eq!(classify(b"\r\nroot@OpenWrt:~# "), ConsoleClass::LinuxShell);
        assert_eq!(classify(b""), ConsoleClass::Silent);
        assert_eq!(
            classify(b"[    0.000000] Linux version 6.12.112...\r\n"),
            ConsoleClass::Booting
        );
    }

    #[test]
    fn card_serializes() {
        let c = DeviceCard {
            class: Some(ConsoleClass::LinuxShell),
            kernel: Some("6.12.112".into()),
            openwrt_release: Some("OpenWrt 25.12.6".into()),
            mtd_layout: vec!["mtd0: 00040000 00010000 \"u-boot\"".into()],
            ..Default::default()
        };
        let j = serde_json::to_string(&c).unwrap();
        assert!(j.contains("linux_shell"));
        assert!(j.contains("u-boot"));
    }
}
