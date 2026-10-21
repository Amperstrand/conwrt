//! Persistent host-key trust for the CLI (known-hosts file).
//!
//! The engine's [`MemoryTrustStore`] is, by design, single-session: the
//! CLI owns cross-invocation persistence. Without it every connection
//! is TOFU-first-use, so the changed-key refusal can never protect a
//! later `--execute` (review finding on `apply`): a spoofed endpoint
//! would receive credentials on first contact and again after rotation.
//!
//! Store format — one entry per line, OpenSSH-flavored simplicity:
//!
//! ```text
//! # host algo fingerprint
//! 192.168.1.1:22 ssh-ed25519 SHA256:abc…
//! ```
//!
//! Lines are whitespace-separated; blank lines and `#` comments are
//! skipped; malformed lines are ignored (never fatal — a corrupt store
//! must not lock the operator out, it just degrades to first-use).

use std::io::Write;
use std::path::{Path, PathBuf};

use conwrt_core::ssh::{HostKeyView, MemoryTrustStore};

/// Resolve the known-hosts path from the environment (pure, testable).
///
/// Precedence: `CONWRT_KNOWN_HOSTS`, then `$XDG_STATE_HOME/conwrt`,
/// then `~/.local/state/conwrt`.
#[must_use]
pub fn known_hosts_path_from(
    env_override: Option<&str>,
    xdg_state: Option<&str>,
    home: &str,
) -> PathBuf {
    if let Some(p) = env_override.filter(|s| !s.is_empty()) {
        return PathBuf::from(p);
    }
    let state = xdg_state
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(home).join(".local").join("state"));
    state.join("conwrt").join("known_hosts")
}

/// The known-hosts path for this invocation.
#[must_use]
pub fn known_hosts_path() -> PathBuf {
    known_hosts_path_from(
        std::env::var("CONWRT_KNOWN_HOSTS").ok().as_deref(),
        std::env::var("XDG_STATE_HOME").ok().as_deref(),
        &std::env::var("HOME").unwrap_or_else(|_| "/".into()),
    )
}

/// Load the store from disk; a missing file is an empty store.
#[must_use]
pub fn load(path: &Path) -> MemoryTrustStore {
    let mut store = MemoryTrustStore::new();
    let Ok(text) = std::fs::read_to_string(path) else {
        return store;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        if let (Some(host), Some(algo), Some(fp)) = (parts.next(), parts.next(), parts.next()) {
            store.remember(
                host,
                &HostKeyView {
                    key_algo: algo.into(),
                    fingerprint: fp.into(),
                },
            );
        }
    }
    store
}

/// Append `key` for `host` unless already recorded.
///
/// Returns `Ok(true)` when a NEW entry was written, `Ok(false)` when it
/// was already known. Errors are I/O only — the caller decides whether
/// to warn (trust decisions already happened in-memory).
pub fn remember_host_key(path: &Path, host: &str, key: &HostKeyView) -> std::io::Result<bool> {
    let existing = load(path);
    if existing.entries(host).iter().any(|k| k == key) {
        return Ok(false);
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut line = String::new();
    line.push_str(host);
    line.push(' ');
    line.push_str(&key.key_algo);
    line.push(' ');
    line.push_str(&key.fingerprint);
    line.push('\n');
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?
        .write_all(line.as_bytes())?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(algo: &str, fp: &str) -> HostKeyView {
        HostKeyView {
            key_algo: algo.into(),
            fingerprint: fp.into(),
        }
    }

    #[test]
    fn path_precedence() {
        let p = known_hosts_path_from(Some("/tmp/kh"), Some("/xdg"), "/home/op");
        assert_eq!(p, PathBuf::from("/tmp/kh"));
        let p = known_hosts_path_from(None, Some("/xdg"), "/home/op");
        assert_eq!(p, PathBuf::from("/xdg/conwrt/known_hosts"));
        let p = known_hosts_path_from(None, None, "/home/op");
        assert_eq!(p, PathBuf::from("/home/op/.local/state/conwrt/known_hosts"));
        let p = known_hosts_path_from(Some(""), None, "/home/op"); // empty = unset
        assert_eq!(p, PathBuf::from("/home/op/.local/state/conwrt/known_hosts"));
    }

    #[test]
    fn roundtrip_and_dedup() {
        let dir = std::env::temp_dir().join(format!("conwrt-kh-{}", std::process::id()));
        let path = dir.join("known_hosts");
        let _ = std::fs::remove_file(&path);

        let k1 = key("ssh-ed25519", "SHA256:aaa");
        let k2 = key("rsa-sha2-256", "SHA256:bbb");
        assert!(remember_host_key(&path, "h:22", &k1).unwrap());
        assert!(remember_host_key(&path, "h:22", &k2).unwrap());
        assert!(!remember_host_key(&path, "h:22", &k1).unwrap(), "dedup");

        let store = load(&path);
        let mut got = store.entries("h:22");
        got.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        assert_eq!(got, vec![k1.clone(), k2]);
        assert!(store.entries("other:22").is_empty());

        // changed-key detection works across "invocations"
        let reloaded = load(&path);
        assert!(reloaded.entries("h:22").contains(&k1));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn malformed_lines_are_skipped_not_fatal() {
        let dir = std::env::temp_dir().join(format!("conwrt-kh-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("known_hosts");
        std::fs::write(
            &path,
            "# comment\n\nonly-one-token\nh:22 ssh-ed25519 SHA256:ccc extra tokens\n",
        )
        .unwrap();
        let store = load(&path);
        assert_eq!(store.entries("h:22").len(), 1);
        assert_eq!(store.entries("only-one-token").len(), 0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn missing_file_is_empty_store() {
        let store = load(Path::new("/nonexistent/conwrt/known_hosts"));
        assert!(store.entries("h:22").is_empty());
    }
}
