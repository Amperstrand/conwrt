//! Authenticated fingerprint gathering over the SSH provider — read-only
//! exec of well-known identity files (see `conwrt_core::fingerprint`).

use conwrt_core::fingerprint::{FingerprintReport, OpenwrtRelease, parse_openwrt_release};

use crate::ssh::{ExecOutput, SshError, SshSession};

const RELEASE_FILE: &str = "/etc/openwrt_release";
const BOARD_NAME_FILE: &str = "/tmp/sysinfo/board_name";
const HOSTNAME_FILE: &str = "/proc/sys/kernel/hostname";

/// Gather the authenticated device fingerprint: OpenWrt release, board
/// name, hostname. Every source is optional — a stock device answers the
/// exec but has no `/etc/openwrt_release`, which is itself signal.
///
/// # Errors
/// Only transport-level SSH failures propagate (`SshError`); per-file
/// absence (non-zero exit / empty output) is recorded as `None`.
pub async fn fingerprint(session: &SshSession) -> Result<FingerprintReport, SshError> {
    let mut report = FingerprintReport::default();

    if let Ok(output) = session.exec(&format!("cat {RELEASE_FILE}")).await {
        if let Some(release) = release_from(&output) {
            report.release = Some(release);
        } else {
            report.notes.push(format!(
                "{RELEASE_FILE} absent or unparseable — not OpenWrt, or very old"
            ));
        }
    }

    if let Ok(output) = session.exec(&format!("cat {BOARD_NAME_FILE}")).await {
        if let Some(board) = text_from(&output) {
            report.board_name = Some(board);
        }
    }

    if let Ok(output) = session.exec(&format!("cat {HOSTNAME_FILE}")).await {
        if let Some(hostname) = text_from(&output) {
            report.hostname = Some(hostname);
        }
    }

    Ok(report)
}

fn succeeded(output: &ExecOutput) -> bool {
    output.exit_code.unwrap_or(1) == 0
}

fn text_from(output: &ExecOutput) -> Option<String> {
    if !succeeded(output) {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() { None } else { Some(text) }
}

fn release_from(output: &ExecOutput) -> Option<OpenwrtRelease> {
    if !succeeded(output) {
        return None;
    }
    parse_openwrt_release(&String::from_utf8_lossy(&output.stdout))
}
