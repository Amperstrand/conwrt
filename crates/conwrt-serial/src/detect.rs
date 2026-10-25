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

/// Profile fingerprint match result (SWUpdate compat-gate pattern).
#[derive(Debug, Clone, Serialize, PartialEq, Default)]
pub struct ProfileMatch {
    /// Profile name that matched, e.g. "zyxel/gs1900-8hp".
    pub profile: String,
    /// Which fingerprints hit: uboot_prompt / boot_signature / shell_prompt.
    pub matched_on: Vec<String>,
    /// Fingerprints checked but not seen in the probe window.
    pub not_seen: Vec<String>,
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
    /// Best profile match when profiles were supplied.
    pub matched_profile: Option<ProfileMatch>,
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

/// Match a probe window against candidate profiles (pure — testable).
/// Scores by which fingerprints appear in the window; the profile with
/// the most hits wins; ties reject (ambiguous).
pub fn match_profiles(
    window: &[u8],
    profiles: &[crate::profile::DeviceProfile],
) -> Option<ProfileMatch> {
    let text = String::from_utf8_lossy(window);
    let mut best: Option<(usize, ProfileMatch)> = None;
    let mut ambiguous = false;
    for p in profiles {
        let mut matched_on = Vec::new();
        let mut not_seen = Vec::new();
        let prompt = &p.console.uboot_prompt;
        if !prompt.is_empty() {
            if text.contains(prompt.as_str()) {
                matched_on.push("uboot_prompt".to_string());
            } else {
                not_seen.push("uboot_prompt".to_string());
            }
        }
        for sig in &p.console.boot_signatures {
            if text.contains(sig.as_str()) {
                matched_on.push(format!("signature:{sig}"));
            } else {
                not_seen.push(format!("signature:{sig}"));
            }
        }
        if !p.console.shell_prompt.is_empty() {
            if text.contains(p.console.shell_prompt.as_str()) {
                matched_on.push("shell_prompt".to_string());
            } else {
                not_seen.push("shell_prompt".to_string());
            }
        }
        if !matched_on.is_empty() {
            let score = matched_on.len();
            match &best {
                Some((s, _)) if *s == score => ambiguous = true,
                Some((s, _)) if *s > score => {}
                _ => {
                    best = Some((
                        score,
                        ProfileMatch {
                            profile: p.profile.clone(),
                            matched_on,
                            not_seen,
                        },
                    ));
                    ambiguous = false;
                }
            }
        }
    }
    if ambiguous {
        None
    } else {
        best.map(|(_, m)| m)
    }
}

/// Probe the console and, when a prompt answers, collect the device
/// card. Read-only: no state on the box changes (printenv/version/mtd
/// listings only).
pub fn detect(port_spec: &str, baud: u32, probe_secs: f64) -> std::io::Result<DeviceCard> {
    detect_with_profiles(port_spec, baud, probe_secs, &[])
}

/// detect + profile fingerprint matching: the card carries the best
/// profile match (or None when no candidate fits / ambiguous).
pub fn detect_with_profiles(
    port_spec: &str,
    baud: u32,
    probe_secs: f64,
    profile_search_path: &[std::path::PathBuf],
) -> std::io::Result<DeviceCard> {
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
    if !profile_search_path.is_empty() {
        let names = crate::profile::list_profiles(profile_search_path);
        let mut boards: Vec<crate::profile::DeviceProfile> = Vec::new();
        for n in names.keys() {
            // board profiles first (skip */-base family files)
            if n.ends_with("-base") {
                continue;
            }
            match crate::profile::DeviceProfile::load(n, profile_search_path) {
                Ok(p) => boards.push(p),
                Err(e) => eprintln!("conwrt: profile {n:?} failed to load: {e}"),
            }
        }
        if let Some(m) = match_profiles(&all, &boards) {
            card.matched_profile = Some(m);
        } else {
            // boards tie-rejected (e.g. a bare "root@OpenWrt" shell
            // prompt is shared across a family) — fall back to the
            // HONEST family-level match against the base profiles
            let mut families: Vec<crate::profile::DeviceProfile> = Vec::new();
            for n in names.keys() {
                if n.ends_with("-base") {
                    match crate::profile::DeviceProfile::load(n, profile_search_path) {
                        Ok(p) => families.push(p),
                        Err(e) => eprintln!("conwrt: profile {n:?} failed to load: {e}"),
                    }
                }
            }
            card.matched_profile = match_profiles(&all, &families);
        }
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
    fn profile_matching_picks_the_right_board() {
        let dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/profiles");
        let gs =
            crate::profile::DeviceProfile::load("zyxel/gs1900-8hp", std::slice::from_ref(&dir))
                .unwrap();
        let dl =
            crate::profile::DeviceProfile::load("dlink/dgs-1210-16", std::slice::from_ref(&dir))
                .unwrap();
        // a Realtek-style boot window matches the gs1900 (its prompt)
        let window = b"DRAM is set\r\nU-Boot 2011.12\r\nRTL838x# ";
        let m = match_profiles(window, &[gs.clone(), dl.clone()]).expect("match");
        assert_eq!(m.profile, "zyxel/gs1900-8hp");
        assert!(m.matched_on.contains(&"uboot_prompt".to_string()));
        // the D-Link window matches the dlink (ESC banner, its prompt)
        let window2 = b"Hit Esc key to stop autoboot\r\nu-boot># ";
        let m2 = match_profiles(window2, &[gs, dl]).expect("match2");
        assert_eq!(m2.profile, "dlink/dgs-1210-16");
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
