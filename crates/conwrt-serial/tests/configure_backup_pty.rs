//! Configure + backup integration against a STATEFUL mock OpenWrt shell
//! riding a real pty pair — the Rust twins of running
//! `scripts/serial-configure.py` and `scripts/serial-backup.py` against
//! a device. No `/dev/ttyUSB` and no host serial port is ever opened.
//!
//! The mock keeps real uci/dropbear/mtd state, so the flows under test
//! exercise genuine device-side feedback. Every incoming line is first
//! stripped of the RC-marker tail the driver appends (` &&
//! echo __RC0__ || echo __RC1__`) — exactly what the device shell sees
//! after parsing its own command line — before value extraction:
//!
//! * `set_lan_ip` — the uci set/commit/ifup steps store the address and
//!   the readback verification reads the STORED value (happy path), or
//!   a mock mode that accepts-but-ignores the set pins the
//!   `IpVerifyMismatch` guard.
//! * `install_authorized_key` — the echo line lands in the mock's
//!   authorized_keys; the driver's `wc -c` gate compares against the
//!   REAL stored length (a truncating mock mode pins
//!   `KeySizeMismatch`).
//! * `dump_partition` — the mock serves BusyBox-style wrapped base64
//!   of its own partition bytes; exact round-trip plus a 90% truncation
//!   (rejected, file NOT written) pin the Python thresholds.

use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsFd;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use base64::Engine as _;
use nix::pty::openpty;
use nix::sys::termios::{cfmakeraw, tcgetattr, tcsetattr};
use nix::unistd::ttyname;

use conwrt_serial::SerialConsole;
use conwrt_serial::backup::{
    BackupError, BackupSelection, Partition, dump_partition, list_partitions, select_targets,
};
use conwrt_serial::configure::{
    ConfigureError, install_authorized_key, set_lan_ip, set_password_auth, show_firmware,
};

/// Mock device behavior toggles.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct MockMode {
    /// `uci set` replies OK but does not store — readback mismatches.
    ignore_uci_set: bool,
    /// authorized_keys loses a byte — the wc -c gate must refuse.
    truncate_key: bool,
    /// serve only the first 90% of the partition base64 lines.
    truncate_dump_90: bool,
}

#[derive(Debug, Default)]
struct DeviceState {
    lan_ip: Option<String>,
    password_auth: Option<String>,
    authorized_keys: Option<String>,
}

struct MockOpenWrt {
    state: Arc<Mutex<DeviceState>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockOpenWrt {
    fn spawn(master: std::fs::File, mode: MockMode) -> Self {
        let state = Arc::new(Mutex::new(DeviceState::default()));
        let shared = Arc::clone(&state);
        let handle = thread::spawn(move || device_shell(master, mode, shared));
        Self {
            state,
            handle: Some(handle),
        }
    }

    fn join(mut self) -> DeviceState {
        let handle = self.handle.take().expect("handle");
        handle.join().expect("device shell");
        let mut state = self.state.lock().unwrap();
        std::mem::take(&mut *state)
    }
}

const PROC_MTD: &str = "dev:    size   erasesize  name\n\
                        mtd0: 00030000 00010000 \"u-boot\"\n\
                        mtd2: 00080000 00010000 \"Factory\"\n";

/// The RC tail the console driver appends to every `run` command.
const RC_TAIL: &str = " && echo __RC0__ || echo __RC1__";

fn device_shell(master: std::fs::File, mode: MockMode, state: Arc<Mutex<DeviceState>>) {
    let mut writer = master.try_clone().expect("clone master");
    let mut reader = BufReader::new(master);
    // deterministic "Factory" contents
    let factory: Vec<u8> = (0..0x0008_0000u64).map(|i| (i % 251) as u8).collect();
    let factory_b64 = base64::engine::general_purpose::STANDARD.encode(&factory);
    let mut lines: Vec<&str> = Vec::new();
    for chunk in factory_b64.as_bytes().chunks(76) {
        lines.push(std::str::from_utf8(chunk).expect("b64 ascii"));
    }
    if mode.truncate_dump_90 {
        lines.truncate(lines.len() * 90 / 100);
    }
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        // the device shell parses ITS command; the RC tail is part of
        // the same line but never part of any value
        let cmd = line.split(RC_TAIL).next().unwrap_or("").trim();
        if cmd.is_empty() || cmd == "\u{3}" {
            continue;
        }
        let reply = |w: &mut std::fs::File, text: &str| {
            let _ = w.write_all(format!("{text}__RC0__\r\n").as_bytes());
        };
        let quoted_value = |prefix: &str| -> String {
            let rest = &cmd[prefix.len()..];
            rest.split('\'').next().unwrap_or("").to_string()
        };
        if let Some(prefix) = cmd.strip_prefix("uci set network.lan.ipaddr='") {
            let _ = prefix;
            if !mode.ignore_uci_set {
                state.lock().unwrap().lan_ip = Some(quoted_value("uci set network.lan.ipaddr='"));
            }
            reply(&mut writer, "");
        } else if cmd.starts_with("uci commit network") || cmd.starts_with("ifup lan") {
            reply(&mut writer, "");
        } else if cmd.starts_with("uci get network.lan.ipaddr") {
            let ip = state
                .lock()
                .unwrap()
                .lan_ip
                .clone()
                .unwrap_or_else(|| "192.168.1.1".to_string());
            reply(&mut writer, &format!("{ip}\r\n"));
        } else if let Some(_prefix) =
            cmd.strip_prefix("uci set dropbear.@dropbear[0].PasswordAuth='")
        {
            if !mode.ignore_uci_set {
                state.lock().unwrap().password_auth =
                    Some(quoted_value("uci set dropbear.@dropbear[0].PasswordAuth='"));
            }
            reply(&mut writer, "");
        } else if cmd.starts_with("uci commit dropbear")
            || cmd.starts_with("/etc/init.d/dropbear restart")
            || cmd.starts_with("mkdir -p /etc/dropbear")
            || cmd.starts_with("chmod 600 /etc/dropbear/authorized_keys")
        {
            reply(&mut writer, "");
        } else if cmd.starts_with("echo '") && cmd.contains("' > /etc/dropbear/authorized_keys") {
            let key = &cmd["echo '".len()..]
                .split("' > /etc/dropbear/authorized_keys")
                .next()
                .unwrap_or("");
            // BusyBox echo appends the newline — the on-device file is
            // key + \n (the wc -c gate compares against exactly that)
            state.lock().unwrap().authorized_keys = Some(format!("{key}\n"));
            reply(&mut writer, "");
        } else if cmd.starts_with("wc -c /etc/dropbear/authorized_keys") {
            let stored = state.lock().unwrap().authorized_keys.clone();
            match stored {
                Some(key) => {
                    let len = if mode.truncate_key {
                        key.len() - 1
                    } else {
                        key.len()
                    };
                    reply(
                        &mut writer,
                        &format!("{len} /etc/dropbear/authorized_keys\r\n"),
                    );
                }
                None => {
                    let _ = writer.write_all(b"can't open\r\n__RC1__\r\n");
                }
            }
        } else if cmd.starts_with("cat /etc/openwrt_release") {
            reply(
                &mut writer,
                "DISTRIB_ID='OpenWrt'\r\nDISTRIB_RELEASE='24.10.2'\r\nDISTRIB_TARGET='ramips/mt7621'\r\n",
            );
        } else if cmd.starts_with("cat /proc/mtd") {
            reply(&mut writer, &PROC_MTD.replace('\n', "\r\n"));
        } else if cmd.starts_with("cat /dev/mtd2 | base64") {
            let payload = lines.join("\r\n");
            reply(&mut writer, &format!("{payload}\r\n"));
        }
    }
}

fn pty_parts() -> (std::fs::File, String) {
    let pair = openpty(None, None).expect("openpty");
    let mut term = tcgetattr(&pair.slave).expect("tcgetattr slave");
    cfmakeraw(&mut term);
    tcsetattr(
        pair.slave.as_fd(),
        nix::sys::termios::SetArg::TCSANOW,
        &term,
    )
    .expect("setraw slave");
    let slave_path = ttyname(&pair.slave).expect("ttyname slave");
    drop(pair.slave);
    (
        std::fs::File::from(pair.master),
        slave_path.display().to_string(),
    )
}

fn open_console(slave_path: &str) -> SerialConsole {
    SerialConsole::with_baud(slave_path, 115_200, Duration::from_millis(20))
        .expect("open pty slave")
}

const T: Duration = Duration::from_secs(5);

#[test]
fn set_lan_ip_happy_path_stores_and_verifies() {
    let (master, slave_path) = pty_parts();
    let device = MockOpenWrt::spawn(master, MockMode::default());
    let mut console = open_console(&slave_path);
    set_lan_ip(&mut console, "192.168.5.1", T).expect("set_lan_ip");
    thread::sleep(Duration::from_millis(100));
    drop(console);
    let state = device.join();
    assert_eq!(state.lan_ip.as_deref(), Some("192.168.5.1"));
}

#[test]
fn set_lan_ip_readback_mismatch_is_a_typed_error() {
    let (master, slave_path) = pty_parts();
    let device = MockOpenWrt::spawn(
        master,
        MockMode {
            ignore_uci_set: true,
            ..MockMode::default()
        },
    );
    let mut console = open_console(&slave_path);
    let err = set_lan_ip(&mut console, "192.168.5.1", T).unwrap_err();
    thread::sleep(Duration::from_millis(100));
    drop(console);
    device.join();
    match err {
        ConfigureError::IpVerifyMismatch { requested, actual } => {
            assert_eq!(requested, "192.168.5.1");
            assert_eq!(actual, "192.168.1.1");
        }
        other => panic!("expected IpVerifyMismatch, got {other:?}"),
    }
}

#[test]
fn password_auth_toggles_dropbear_state() {
    let (master, slave_path) = pty_parts();
    let device = MockOpenWrt::spawn(master, MockMode::default());
    let mut console = open_console(&slave_path);
    set_password_auth(&mut console, true, T).expect("enable");
    set_password_auth(&mut console, false, T).expect("disable");
    thread::sleep(Duration::from_millis(100));
    drop(console);
    let state = device.join();
    assert_eq!(state.password_auth.as_deref(), Some("off"));
}

#[test]
fn install_key_round_trips_and_wc_gate_refuses_truncation() {
    let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleHexKey operator@bench";
    let key_file = std::env::temp_dir().join(format!("conwrt-key-{}.pub", std::process::id()));
    std::fs::write(&key_file, format!("{key}\n")).unwrap();

    let (master, slave_path) = pty_parts();
    let device = MockOpenWrt::spawn(master, MockMode::default());
    let mut console = open_console(&slave_path);
    let installed = install_authorized_key(&mut console, &key_file, T).expect("install");
    thread::sleep(Duration::from_millis(100));
    drop(console);
    let state = device.join();
    assert_eq!(installed, key.len() + 1, "wc counts the echo newline");
    assert_eq!(state.authorized_keys.as_deref(), Some(&*format!("{key}\n")));

    let (master, slave_path) = pty_parts();
    let device = MockOpenWrt::spawn(
        master,
        MockMode {
            truncate_key: true,
            ..MockMode::default()
        },
    );
    let mut console = open_console(&slave_path);
    let err = install_authorized_key(&mut console, &key_file, T).unwrap_err();
    thread::sleep(Duration::from_millis(100));
    drop(console);
    device.join();
    assert!(
        matches!(err, ConfigureError::KeySizeMismatch { .. }),
        "got {err:?}"
    );
    let _ = std::fs::remove_file(&key_file);
}

#[test]
fn show_firmware_returns_filtered_release_block() {
    let (master, slave_path) = pty_parts();
    let device = MockOpenWrt::spawn(master, MockMode::default());
    let mut console = open_console(&slave_path);
    let fw = show_firmware(&mut console, T).expect("firmware");
    thread::sleep(Duration::from_millis(100));
    drop(console);
    device.join();
    assert!(fw.contains("DISTRIB_RELEASE='24.10.2'"), "{fw}");
    assert!(
        !fw.contains("cat /etc/openwrt_release"),
        "echo must be filtered: {fw}"
    );
}

#[test]
fn backup_lists_selects_and_dumps_factory_exactly() {
    let (master, slave_path) = pty_parts();
    let device = MockOpenWrt::spawn(master, MockMode::default());
    let mut console = open_console(&slave_path);
    let partitions = list_partitions(&mut console, T).expect("list");
    let targets = select_targets(&partitions, &BackupSelection::FactoryDefault).unwrap();
    assert_eq!(targets.len(), 1);
    let out_dir = std::env::temp_dir().join(format!("conwrt-backup-{}", std::process::id()));
    let mut progress_calls = 0;
    let outcome = dump_partition(&mut console, &targets[0], &out_dir, |got, total| {
        progress_calls += 1;
        assert!(got <= total);
    })
    .expect("dump");
    thread::sleep(Duration::from_millis(100));
    drop(console);
    device.join();

    assert_eq!(outcome.bytes, 0x0008_0000);
    assert_eq!(outcome.size_mismatch, None);
    assert_eq!(outcome.partition.name, "Factory");
    assert!(progress_calls >= 1);
    let dumped = std::fs::read(&outcome.path).expect("dump file");
    let expected: Vec<u8> = (0..0x0008_0000u64).map(|i| (i % 251) as u8).collect();
    assert_eq!(dumped.len(), expected.len());
    assert_eq!(dumped, expected, "Factory dump must be byte-exact");
    assert!(Path::new(&outcome.path).exists());
    let _ = std::fs::remove_dir_all(&out_dir);
}

#[test]
fn backup_truncated_90_percent_is_rejected_without_file() {
    let (master, slave_path) = pty_parts();
    let device = MockOpenWrt::spawn(
        master,
        MockMode {
            truncate_dump_90: true,
            ..MockMode::default()
        },
    );
    let mut console = open_console(&slave_path);
    let partition = Partition {
        device: "mtd2".to_string(),
        size: 0x0008_0000,
        name: "Factory".to_string(),
    };
    let out_dir = std::env::temp_dir().join(format!("conwrt-backup-trunc-{}", std::process::id()));
    let err = dump_partition(&mut console, &partition, &out_dir, |_, _| {}).unwrap_err();
    thread::sleep(Duration::from_millis(100));
    drop(console);
    device.join();
    match err {
        BackupError::Incomplete { got, expected, .. } => {
            assert_eq!(expected, 0x0008_0000);
            // truncation is at 76-char line granularity (~57 B), so the
            // captured size lands near, not exactly on, 90%
            assert!(
                got >= expected * 89 / 100 && got < expected,
                "got {got}, expected ~90% of {expected}"
            );
        }
        other => panic!("expected Incomplete, got {other:?}"),
    }
    assert!(
        !out_dir.join("factory.bin").exists(),
        "incomplete dump must NOT be written"
    );
    let _ = std::fs::remove_dir_all(&out_dir);
}
