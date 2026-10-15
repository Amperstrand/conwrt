//! Persistent host-key trust store (#125): the file-backed twin of
//! [`conwrt_core::ssh::MemoryTrustStore`].
//!
//! File format — one entry per line, fingerprints only (never key
//! material), so the file is safe to persist, diff, and print:
//!
//! ```text
//! <host> <key-algo> <SHA256-fingerprint>
//! 127.0.0.1:2322 ssh-ed25519 SHA256:nkf0e8cF1...
//! ```
//!
//! Default path: `$CONWRT_KNOWN_HOSTS`, else `~/.config/conwrt/known_hosts`
//! (the OpenSSH mental model, conwrt-scoped). Concurrent access: an
//! exclusive lock file (`<path>.lock`, O_EXCL with bounded retry, stale
//! takeover after a timeout) guards the read-merge-write; the write itself
//! is temp-file + atomic rename, so a crashed writer can never tear the
//! store. Worst case under lock contention is last-writer-wins *per
//! remember()*, never a corrupted file.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use conwrt_core::ssh::{HostKeyView, TrustStore};

/// How long [`FileTrustStore::remember`] waits for the lock before
/// taking over a stale one (a crashed holder cannot release).
const LOCK_WAIT: Duration = Duration::from_secs(3);
/// Retry cadence while waiting for the lock.
const LOCK_RETRY: Duration = Duration::from_millis(25);

/// File-backed TOFU store.
pub struct FileTrustStore {
    path: PathBuf,
}

impl std::fmt::Debug for FileTrustStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Path only: contents are fingerprints, but a store mid-write is
        // nobody's business and logs stay lean.
        f.debug_struct("FileTrustStore")
            .field("path", &self.path)
            .finish()
    }
}

/// A held exclusive lock file. Removing it on drop is the release.
struct LockGuard {
    path: PathBuf,
}

impl LockGuard {
    fn acquire(lock_path: &Path) -> std::io::Result<Self> {
        let deadline = Instant::now() + LOCK_WAIT;
        loop {
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(lock_path)
            {
                Ok(_) => {
                    return Ok(Self {
                        path: lock_path.to_path_buf(),
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if Instant::now() >= deadline {
                        // Stale holder (crashed process). Take over: the
                        // atomic-rename write below means a racing writer
                        // can lose an entry but never corrupt the store.
                        let _ = fs::remove_file(lock_path);
                        continue;
                    }
                    std::thread::sleep(LOCK_RETRY);
                }
                Err(e) => return Err(e),
            }
        }
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl FileTrustStore {
    /// Store backed by an explicit file (creates nothing until the first
    /// `remember`).
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// `$CONWRT_KNOWN_HOSTS`, else `~/.config/conwrt/known_hosts`.
    #[must_use]
    pub fn default_path() -> PathBuf {
        if let Ok(p) = std::env::var("CONWRT_KNOWN_HOSTS") {
            return PathBuf::from(p);
        }
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        Path::new(&home)
            .join(".config")
            .join("conwrt")
            .join("known_hosts")
    }

    fn parse(contents: &str) -> Vec<(String, HostKeyView)> {
        let mut out = Vec::new();
        for line in contents.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            let mut parts = line.split_whitespace();
            let (Some(host), Some(algo), Some(fp)) = (parts.next(), parts.next(), parts.next())
            else {
                continue; // malformed lines are skipped, never fatal
            };
            out.push((
                host.to_string(),
                HostKeyView {
                    key_algo: algo.to_string(),
                    fingerprint: fp.to_string(),
                },
            ));
        }
        out
    }

    fn read_entries(&self) -> Vec<(String, HostKeyView)> {
        match fs::read_to_string(&self.path) {
            Ok(contents) => Self::parse(&contents),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => {
                // An unreadable store behaves as empty: connections then
                // re-ask for trust rather than silently trusting nothing
                // forever. Surface in-band via Strict/TOFU as usual.
                let _ = e;
                Vec::new()
            }
        }
    }
}

impl FileTrustStore {
    /// Rewrite the store without `host`'s lines (lock-guarded, atomic).
    fn forget_impl(&mut self, host: &str) {
        if !self.path.exists() {
            return;
        }
        let lock_path = {
            let mut s = self.path.as_os_str().to_os_string();
            s.push(".lock");
            PathBuf::from(s)
        };
        let _lock = match LockGuard::acquire(&lock_path) {
            Ok(g) => g,
            Err(_) => return,
        };
        let kept: Vec<_> = self
            .read_entries()
            .into_iter()
            .filter(|(h, _)| h != host)
            .collect();
        let tmp_path = {
            let mut s = self.path.as_os_str().to_os_string();
            s.push(".tmp");
            PathBuf::from(s)
        };
        let Ok(mut tmp) = File::create(&tmp_path) else {
            return;
        };
        for (h, k) in &kept {
            let _ = writeln!(tmp, "{} {} {}", h, k.key_algo, k.fingerprint);
        }
        let _ = tmp.sync_all();
        let _ = fs::rename(&tmp_path, &self.path);
    }
}

impl TrustStore for FileTrustStore {
    fn entries(&self, host: &str) -> Vec<HostKeyView> {
        self.read_entries()
            .into_iter()
            .filter(|(h, _)| h == host)
            .map(|(_, k)| k)
            .collect()
    }

    fn remember(&mut self, host: &str, key: &HostKeyView) {
        if let Some(parent) = self.path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let lock_path = {
            let mut s = self.path.as_os_str().to_os_string();
            s.push(".lock");
            PathBuf::from(s)
        };
        let _lock = match LockGuard::acquire(&lock_path) {
            Ok(g) => g,
            Err(_) => return, // store unavailable: skip, never panic mid-auth
        };

        let mut entries = self.read_entries();
        if entries.iter().any(|(h, k)| {
            h == host && k.key_algo == key.key_algo && k.fingerprint == key.fingerprint
        }) {
            return;
        }
        entries.push((host.to_string(), key.clone()));

        let tmp_path = {
            let mut s = self.path.as_os_str().to_os_string();
            s.push(".tmp");
            PathBuf::from(s)
        };
        let Ok(mut tmp) = File::create(&tmp_path) else {
            return;
        };
        for (h, k) in &entries {
            let _ = writeln!(tmp, "{} {} {}", h, k.key_algo, k.fingerprint);
        }
        let _ = tmp.sync_all();
        let _ = fs::rename(&tmp_path, &self.path);
    }

    fn forget(&mut self, host: &str) {
        self.forget_impl(host);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use conwrt_core::ssh::HostKeyView;

    fn key(algo: &str, fp: &str) -> HostKeyView {
        HostKeyView {
            key_algo: algo.into(),
            fingerprint: fp.into(),
        }
    }

    #[test]
    fn roundtrip_remember_then_entries() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = FileTrustStore::new(dir.path().join("known_hosts"));
        store.remember("h:22", &key("ssh-ed25519", "SHA256:aaa"));
        assert_eq!(
            store.entries("h:22"),
            vec![key("ssh-ed25519", "SHA256:aaa")]
        );
        assert!(store.entries("other:22").is_empty());
    }

    #[test]
    fn persists_across_instances_and_dedupes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let mut a = FileTrustStore::new(&path);
        a.remember("h:22", &key("ssh-ed25519", "SHA256:aaa"));
        a.remember("h:22", &key("ssh-ed25519", "SHA256:aaa")); // dedupe
        a.remember("h:22", &key("rsa-sha2-256", "SHA256:bbb")); // second algo

        let b = FileTrustStore::new(&path);
        assert_eq!(b.entries("h:22").len(), 2);

        let mut c = FileTrustStore::new(&path);
        c.remember("h2:22", &key("ssh-ed25519", "SHA256:ccc"));
        let d = FileTrustStore::new(&path);
        assert_eq!(d.entries("h:22").len(), 2);
        assert_eq!(d.entries("h2:22").len(), 1);
    }

    #[test]
    fn file_holds_fingerprints_only_and_survives_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let mut store = FileTrustStore::new(&path);
        store.remember("h:22", &key("ssh-ed25519", "SHA256:aaa"));
        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "h:22 ssh-ed25519 SHA256:aaa\n");

        fs::write(
            &path,
            "# comment line\nh:22 ssh-ed25519 SHA256:aaa\n\ngarbage\n",
        )
        .unwrap();
        let store = FileTrustStore::new(&path);
        assert_eq!(store.entries("h:22").len(), 1);
    }

    #[test]
    fn absent_file_is_empty_not_error() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileTrustStore::new(dir.path().join("nope"));
        assert!(store.entries("h:22").is_empty());
    }

    #[test]
    fn concurrent_remembers_do_not_lose_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let path = std::sync::Arc::new(path);
        let mut handles = Vec::new();
        for i in 0..8 {
            let path = std::sync::Arc::clone(&path);
            handles.push(std::thread::spawn(move || {
                let mut s = FileTrustStore::new((*path).clone());
                for j in 0..10 {
                    s.remember(
                        &format!("host{i}-{j}:22"),
                        &key("ssh-ed25519", &format!("SHA256:{i}{j}aaaa")),
                    );
                }
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
        let store = FileTrustStore::new((*path).clone());
        for i in 0..8 {
            for j in 0..10 {
                assert_eq!(
                    store.entries(&format!("host{i}-{j}:22")).len(),
                    1,
                    "lost host{i}-{j}"
                );
            }
        }
    }

    #[test]
    fn forget_removes_only_that_host_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let mut store = FileTrustStore::new(&path);
        store.remember("h1:22", &key("ssh-ed25519", "SHA256:aaa"));
        store.remember("h2:22", &key("ssh-ed25519", "SHA256:bbb"));
        store.forget("h1:22");
        assert!(store.entries("h1:22").is_empty());
        assert_eq!(store.entries("h2:22").len(), 1);
        // Absent host: no-op, other entries intact, no error.
        store.forget("never-seen:22");
        assert_eq!(store.entries("h2:22").len(), 1);
        // Persists across instances.
        let reopened = FileTrustStore::new(&path);
        assert!(reopened.entries("h1:22").is_empty());
        assert_eq!(reopened.entries("h2:22").len(), 1);
    }

    #[test]
    fn forget_on_absent_file_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = FileTrustStore::new(dir.path().join("nope"));
        store.forget("h:22"); // must not panic or create the file
        assert!(store.entries("h:22").is_empty());
    }

    #[test]
    fn stale_lock_is_taken_over() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let lock_path = {
            let mut s = path.as_os_str().to_os_string();
            s.push(".lock");
            PathBuf::from(s)
        };
        fs::write(&lock_path, "held by a dead process").unwrap();
        let mut store = FileTrustStore::new(&path);
        let start = Instant::now();
        store.remember("h:22", &key("ssh-ed25519", "SHA256:aaa"));
        assert!(start.elapsed() >= LOCK_WAIT, "must wait before takeover");
        assert_eq!(store.entries("h:22").len(), 1);
        assert!(!lock_path.exists(), "lock released after write");
    }
}
