//! Serial configuration of an OpenWrt device — the Rust port of
//! `scripts/serial-configure.py` (parity-matrix §5), built on the
//! [`crate::console`] RC-marker driver.
//!
//! When network access is unavailable (wrong IP, no SSH, broken
//! firmware), these typed operations configure the device over the
//! serial console: LAN IP change (with uci readback verification),
//! password auth enable/disable, SSH authorized-key install (with an
//! on-device `wc -c` byte check), config/firmware inspection, and
//! arbitrary commands.
//!
//! Python parity notes:
//!
//! * The Python tool's `send_and_read` (write, sleep, drain, filter)
//!   is replaced by [`SerialConsole::run`] RC-marker collection — the
//!   #412 command-FIFO semantics: each command's reply is delimited by
//!   its `__RC0__`/`__RC1__` marker instead of a guessed 2 s sleep.
//!   Wire bytes of the uci/dropbear/init.d commands are identical.
//! * [`filter_reply`] ports the Python reply filter verbatim (strip
//!   the echoed command, `root@` prompt lines, and `^C` noise) for
//!   real-device output where the tty echoes the typed line.

use std::path::Path;

use thiserror::Error;

use crate::collect::{CmdOutcome, RC_FAIL, RC_OK};
use crate::console::{PortOpener, SerialConsole, Sleeper};
use crate::io::ConsoleError;

/// Dropbear uci selector for password auth (Python parity).
pub const DROPBEAR_AUTH_SELECT: &str = "dropbear.@dropbear[0].PasswordAuth";

/// Why a configure operation failed. Messages are operator-safe.
#[derive(Debug, Error)]
pub enum ConfigureError {
    /// Transport failure.
    #[error(transparent)]
    Console(#[from] ConsoleError),
    /// A uci/dropbear/init.d step did not complete with rc 0.
    #[error("configure step {step:?} failed (rc {rc}): {output}")]
    StepFailed {
        /// Which logical step failed (e.g. `"uci set network.lan.ipaddr"`).
        step: &'static str,
        /// The collected rc (1 = `__RC1__`, 2 = timeout).
        rc: u8,
        /// Collected console output.
        output: String,
    },
    /// The readback of `network.lan.ipaddr` differs from the requested
    /// address — the setting did not take.
    #[error("LAN IP readback mismatch: set {requested}, device reports {actual}")]
    IpVerifyMismatch {
        /// The address that was requested.
        requested: String,
        /// What `uci get network.lan.ipaddr` returned.
        actual: String,
    },
    /// The authorized-key file could not be read on the host.
    #[error("cannot read key file {path}: {source}")]
    KeyFile {
        /// The host path that failed.
        path: String,
        /// The underlying read error.
        #[source]
        source: std::io::Error,
    },
    /// The on-device `wc -c /etc/dropbear/authorized_keys` reply could
    /// not be parsed to a byte count.
    #[error("could not parse device wc -c reply: {output:?}")]
    WcUnparseable {
        /// The raw collected console output.
        output: String,
    },
    /// The installed key's on-device byte count differs from the host
    /// key text — the write was truncated or mangled.
    #[error("authorized_keys size mismatch: wrote {written}, device reports {reported}")]
    KeySizeMismatch {
        /// Bytes the host sent (key text without trailing newline).
        written: usize,
        /// The device's `wc -c` count.
        reported: usize,
    },
}

fn step(outcome: CmdOutcome, step_name: &'static str) -> Result<String, ConfigureError> {
    if outcome.rc != 0 {
        return Err(ConfigureError::StepFailed {
            step: step_name,
            rc: outcome.rc,
            output: outcome.output,
        });
    }
    Ok(outcome.output)
}

/// Python `send_and_read`'s line filter, adapted to the RC-marker
/// transport: drop empty lines, the echoed command line, `root@`
/// prompt lines, `^C` noise, and the driver's own `__RC` marker lines
/// (Python replies carried no markers — on this driver they are
/// plumbing, never device content). Pure.
#[must_use]
pub fn filter_reply(reply: &str, command: &str) -> String {
    let lines: Vec<&str> = reply
        .lines()
        .map(str::trim)
        .filter(|l| {
            !l.is_empty()
                && *l != RC_OK
                && *l != RC_FAIL
                && !l.contains(command)
                && !l.contains("root@")
                && !l.starts_with("^C")
        })
        .collect();
    lines.join("\n")
}

/// `cat /etc/openwrt_release` — firmware banner block.
///
/// # Errors
/// [`ConfigureError::Console`] on transport failure; the command's own
/// failure (missing file on a non-OpenWrt device) surfaces as
/// [`ConfigureError::StepFailed`].
pub fn show_firmware<S: Sleeper, O: PortOpener>(
    console: &mut SerialConsole<S, O>,
    timeout: std::time::Duration,
) -> Result<String, ConfigureError> {
    let out = console.run("cat /etc/openwrt_release", timeout)?;
    step(out, "cat /etc/openwrt_release").map(|s| filter_reply(&s, "cat /etc/openwrt_release"))
}

/// `uci show network.lan` — the LAN network config block.
///
/// # Errors
/// As [`show_firmware`].
pub fn show_network_config<S: Sleeper, O: PortOpener>(
    console: &mut SerialConsole<S, O>,
    timeout: std::time::Duration,
) -> Result<String, ConfigureError> {
    let out = console.run("uci show network.lan", timeout)?;
    step(out, "uci show network.lan").map(|s| filter_reply(&s, "uci show network.lan"))
}

/// `uci show dropbear` — the SSH daemon config block.
///
/// # Errors
/// As [`show_firmware`].
pub fn show_dropbear_config<S: Sleeper, O: PortOpener>(
    console: &mut SerialConsole<S, O>,
    timeout: std::time::Duration,
) -> Result<String, ConfigureError> {
    let out = console.run("uci show dropbear", timeout)?;
    step(out, "uci show dropbear").map(|s| filter_reply(&s, "uci show dropbear"))
}

/// Set the LAN IP (`uci set/commit network` + `ifup lan`), then VERIFY
/// by reading `network.lan.ipaddr` back — a mismatch is a typed error,
/// not a warning (upgrading the Python flow's print-only check).
///
/// # Errors
/// [`ConfigureError::StepFailed`] for any uci/ifup step;
/// [`ConfigureError::IpVerifyMismatch`] when the readback differs;
/// [`ConfigureError::Console`] on transport failure.
pub fn set_lan_ip<S: Sleeper, O: PortOpener>(
    console: &mut SerialConsole<S, O>,
    ip: &str,
    timeout: std::time::Duration,
) -> Result<(), ConfigureError> {
    step(
        console.run(&format!("uci set network.lan.ipaddr='{ip}'"), timeout)?,
        "uci set network.lan.ipaddr",
    )?;
    step(
        console.run("uci commit network", timeout)?,
        "uci commit network",
    )?;
    step(console.run("ifup lan", timeout)?, "ifup lan")?;
    let readback = console.run("uci get network.lan.ipaddr", timeout)?;
    let readback = step(readback, "uci get network.lan.ipaddr")?;
    let actual = filter_reply(&readback, "uci get network.lan.ipaddr");
    if actual != ip {
        return Err(ConfigureError::IpVerifyMismatch {
            requested: ip.to_string(),
            actual,
        });
    }
    Ok(())
}

/// Enable or disable dropbear password auth (`uci set/commit` +
/// init.d restart). `false` = key-only login.
///
/// # Errors
/// [`ConfigureError::StepFailed`] for any step;
/// [`ConfigureError::Console`] on transport failure.
pub fn set_password_auth<S: Sleeper, O: PortOpener>(
    console: &mut SerialConsole<S, O>,
    enabled: bool,
    timeout: std::time::Duration,
) -> Result<(), ConfigureError> {
    let value = if enabled { "on" } else { "off" };
    step(
        console.run(
            &format!("uci set {DROPBEAR_AUTH_SELECT}='{value}'"),
            timeout,
        )?,
        "uci set dropbear PasswordAuth",
    )?;
    step(
        console.run("uci commit dropbear", timeout)?,
        "uci commit dropbear",
    )?;
    step(
        console.run("/etc/init.d/dropbear restart", timeout)?,
        "dropbear restart",
    )?;
    Ok(())
}

/// Install an SSH public key: `mkdir -p /etc/dropbear`, single
/// `echo 'KEY' > authorized_keys` (the Python wire format — the key
/// text carries no single quotes, so the quoting is safe), `chmod 600`,
/// then a receiver-side `wc -c` byte-count check (the #405 rule: the
/// write is only accepted when the DEVICE's count matches the host's).
///
/// NB: an RSA public key line (~500+ chars) exceeds the 200-char
/// script-line lint budget — this path sends the raw line exactly like
/// the Python tool (proven on the bench with ed25519 keys); long-key
/// chunking stays with [`crate::console::SerialConsole::send_script`].
///
/// # Errors
/// [`ConfigureError::KeyFile`] when the host file cannot be read;
/// [`ConfigureError::StepFailed`] for device steps;
/// [`ConfigureError::WcUnparseable`] / [`ConfigureError::KeySizeMismatch`]
/// for the verification; [`ConfigureError::Console`] on transport.
pub fn install_authorized_key<S: Sleeper, O: PortOpener>(
    console: &mut SerialConsole<S, O>,
    key_path: &Path,
    timeout: std::time::Duration,
) -> Result<usize, ConfigureError> {
    let key = std::fs::read_to_string(key_path).map_err(|source| ConfigureError::KeyFile {
        path: key_path.display().to_string(),
        source,
    })?;
    let key = key.trim();
    step(
        console.run("mkdir -p /etc/dropbear", timeout)?,
        "mkdir -p /etc/dropbear",
    )?;
    step(
        console.run(
            &format!("echo '{key}' > /etc/dropbear/authorized_keys"),
            timeout,
        )?,
        "write authorized_keys",
    )?;
    step(
        console.run("chmod 600 /etc/dropbear/authorized_keys", timeout)?,
        "chmod authorized_keys",
    )?;
    verify_key_size(console, key, timeout)
}

/// The `wc -c` verification shared by the install paths. Returns the
/// verified byte count.
fn verify_key_size<S: Sleeper, O: PortOpener>(
    console: &mut SerialConsole<S, O>,
    key: &str,
    timeout: std::time::Duration,
) -> Result<usize, ConfigureError> {
    let wc = console.run("wc -c /etc/dropbear/authorized_keys", timeout)?;
    let wc = step(wc, "wc -c authorized_keys")?;
    let reported = parse_wc_bytes(&filter_reply(&wc, "wc -c /etc/dropbear/authorized_keys"))
        .ok_or(ConfigureError::WcUnparseable { output: wc })?;
    let written = key.len();
    if reported != written {
        return Err(ConfigureError::KeySizeMismatch { written, reported });
    }
    Ok(reported)
}

/// Extract the byte count from a `wc -c /path` reply line
/// (`  123 /etc/dropbear/authorized_keys`). Pure.
#[must_use]
pub fn parse_wc_bytes(reply: &str) -> Option<usize> {
    for line in reply.lines() {
        if line.contains("/etc/dropbear/authorized_keys") {
            if let Some(first) = line.split_whitespace().next() {
                if let Ok(n) = first.parse::<usize>() {
                    return Some(n);
                }
            }
        }
    }
    None
}

/// Run one arbitrary shell command and return its filtered reply
/// (Python `--command`).
///
/// # Errors
/// [`ConfigureError::StepFailed`] when the command itself fails (rc 1);
/// [`ConfigureError::Console`] on transport failure.
pub fn run_command<S: Sleeper, O: PortOpener>(
    console: &mut SerialConsole<S, O>,
    command: &str,
    timeout: std::time::Duration,
) -> Result<String, ConfigureError> {
    let out = console.run(command, timeout)?;
    step(out, "command").map(|s| filter_reply(&s, command))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_strips_echo_prompt_and_ctrl_c() {
        let reply = "uci get network.lan.ipaddr\r\n192.168.5.1\r\nroot@OpenWrt:~# \r\n^C\r\n";
        assert_eq!(
            filter_reply(reply, "uci get network.lan.ipaddr"),
            "192.168.5.1"
        );
    }

    #[test]
    fn filter_strips_rc_marker_lines() {
        let reply = "192.168.5.1\r\n__RC0__\r\n";
        assert_eq!(
            filter_reply(reply, "uci get network.lan.ipaddr"),
            "192.168.5.1"
        );
    }

    #[test]
    fn filter_keeps_unrelated_root_marker_lines_out() {
        // a line merely containing root@ is prompt noise, Python parity
        let reply = "value1\nsomething root@ else\nvalue2";
        assert_eq!(filter_reply(reply, "cmd"), "value1\nvalue2");
    }

    #[test]
    fn filter_empty_reply_is_empty_string() {
        assert_eq!(filter_reply("", "cmd"), "");
    }

    #[test]
    fn wc_parse_extracts_count() {
        assert_eq!(
            parse_wc_bytes("  141 /etc/dropbear/authorized_keys\r\n"),
            Some(141)
        );
        assert_eq!(parse_wc_bytes("no numbers here"), None);
        assert_eq!(parse_wc_bytes("abc /etc/dropbear/authorized_keys"), None);
    }

    #[test]
    fn dropbear_selector_is_python_exact() {
        assert_eq!(DROPBEAR_AUTH_SELECT, "dropbear.@dropbear[0].PasswordAuth");
    }
}
