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
//! exclusive `flock(2)` on a persistent sidecar (`<path>.lock`) guards
//! the read-merge-write; the write itself is temp-file + atomic rename,
//! so a crashed writer can never tear the store. The kernel both
//! enforces exclusion and reclaims a crashed holder's lock (fd close),
//! so there are no timeouts, no stale takeover, and no lost entries
//! under contention (#406).

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use conwrt_core::ssh::{HostKeyView, TrustStore, TrustStoreError};

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

/// Acquires the exclusive `flock(2)` on the persistent sidecar file and
/// returns the RAII guard (drop = release).
///
/// Determinism (#406): mutual exclusion is enforced by the kernel, which
/// also owns liveness — a holder that crashes has the lock reclaimed when
/// its fd closes. There is no timeout that can expire against a merely
/// slow holder (the old O_EXCL scheme deposed slow holders after 3s and
/// lost whole write batches), no stale takeover, and no polling. `flock`
/// is per open-file-description, so separate `open()`s inside one
/// process contend exactly like separate processes. The sidecar is never
/// unlinked: the lock's identity is its inode, and removing it would let
/// two openers hold "the lock" on different inodes.
fn acquire_lock(lock_path: &Path) -> std::io::Result<nix::fcntl::Flock<File>> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    // Blocking LOCK_EX: queues behind the current holder and returns
    // only with the lock held — the release→acquire happens-before edge
    // is the kernel's, not the scheduler's.
    nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusive)
        .map_err(|(_, errno)| std::io::Error::from(errno))
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

    fn parse(contents: &str) -> Result<Vec<(String, HostKeyView)>, String> {
        let mut out = Vec::new();
        for line in contents.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            // Blank and comment lines are fine; a NON-empty line without
            // the `host algo fingerprint` shape is corruption — dropping
            // it silently would un-pin that host and let TOFU hand
            // credentials to a replacement (Codex P1 on #207).
            let (Some(host), Some(algo), Some(fp)) = (parts.next(), parts.next(), parts.next())
            else {
                return Err(line.to_string());
            };
            out.push((
                host.to_string(),
                HostKeyView {
                    key_algo: algo.to_string(),
                    fingerprint: fp.to_string(),
                },
            ));
        }
        Ok(out)
    }

    fn read_entries(&self) -> Result<Vec<(String, HostKeyView)>, TrustStoreError> {
        match fs::read_to_string(&self.path) {
            Ok(contents) => Self::parse(&contents).map_err(TrustStoreError::Malformed),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            // An unreadable store must NOT behave as empty: TOFU would
            // auto-accept the presented key and send credentials to a
            // possible replacement host (Codex P1 on #207). Fail closed.
            Err(_) => Err(TrustStoreError::Unreadable),
        }
    }
}

impl FileTrustStore {
    /// Rewrite the store without `host`'s lines (lock-guarded, atomic).
    /// Persistence failures are errors, not silent no-ops (Codex P1 on
    /// #207): the operator asked for a relearn and must learn it failed.
    fn forget_impl(&mut self, host: &str) -> Result<(), TrustStoreError> {
        if !self.path.exists() {
            return Ok(());
        }
        let lock_path = {
            let mut s = self.path.as_os_str().to_os_string();
            s.push(".lock");
            PathBuf::from(s)
        };
        let _lock = acquire_lock(&lock_path).map_err(|_| TrustStoreError::Unwritable)?;
        let kept: Vec<_> = self
            .read_entries()?
            .into_iter()
            .filter(|(h, _)| h != host)
            .collect();
        let tmp_path = {
            let mut s = self.path.as_os_str().to_os_string();
            s.push(".tmp");
            PathBuf::from(s)
        };
        self.write_atomic(&tmp_path, &kept)
    }

    /// Write `entries` to `tmp_path`, sync, then atomically rename over
    /// the live store. Any failure discards the temp file and returns
    /// `Unwritable` — the live store is never replaced by a partial
    /// write (#380 hazard, checked per Codex P1 on #207).
    fn write_atomic(
        &self,
        tmp_path: &Path,
        entries: &[(String, HostKeyView)],
    ) -> Result<(), TrustStoreError> {
        let mut tmp = File::create(tmp_path).map_err(|_| TrustStoreError::Unwritable)?;
        let persisted = (|| -> std::io::Result<()> {
            for (h, k) in entries {
                writeln!(tmp, "{} {} {}", h, k.key_algo, k.fingerprint)?;
            }
            tmp.sync_all()?;
            Ok(())
        })();
        drop(tmp);
        match persisted {
            Ok(()) => fs::rename(tmp_path, &self.path).map_err(|_| TrustStoreError::Unwritable),
            Err(_) => {
                let _ = fs::remove_file(tmp_path);
                Err(TrustStoreError::Unwritable)
            }
        }
    }
}

impl TrustStore for FileTrustStore {
    fn entries(&self, host: &str) -> Result<Vec<HostKeyView>, TrustStoreError> {
        Ok(self
            .read_entries()?
            .into_iter()
            .filter(|(h, _)| h == host)
            .map(|(_, k)| k)
            .collect())
    }

    fn remember(&mut self, host: &str, key: &HostKeyView) -> Result<(), TrustStoreError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|_| TrustStoreError::Unwritable)?;
        }
        let lock_path = {
            let mut s = self.path.as_os_str().to_os_string();
            s.push(".lock");
            PathBuf::from(s)
        };
        // An unpersisted accepted key would make every later invocation
        // a silent first-use — persistence failure must be an error the
        // caller surfaces, never a quiet skip (Codex P1 on #207).
        let _lock = acquire_lock(&lock_path).map_err(|_| TrustStoreError::Unwritable)?;

        let mut entries = self.read_entries()?;
        if entries.iter().any(|(h, k)| {
            h == host && k.key_algo == key.key_algo && k.fingerprint == key.fingerprint
        }) {
            return Ok(());
        }
        entries.push((host.to_string(), key.clone()));

        let tmp_path = {
            let mut s = self.path.as_os_str().to_os_string();
            s.push(".tmp");
            PathBuf::from(s)
        };
        // write_atomic keeps the #380 guarantee: the rename is
        // unreachable unless the temp store fully persisted; a partial
        // swap over known_hosts destroys trust.
        self.write_atomic(&tmp_path, &entries)
    }

    fn forget(&mut self, host: &str) -> Result<(), TrustStoreError> {
        self.forget_impl(host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use conwrt_core::ssh::HostKeyView;

    #[test]
    fn malformed_record_fails_closed_instead_of_dropping_the_pin() {
        // Codex P1 on #207: a truncated record silently dropped by the
        // old parser would un-pin that host and let TOFU accept a
        // replacement key. It must surface as Malformed, and entries()
        // must refuse.
        let dir =
            std::env::temp_dir().join(format!("conwrt-trust-malformed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("known_hosts");
        std::fs::write(
            &path,
            "h:22 ssh-ed25519 SHA256:abc
truncated-host
",
        )
        .unwrap();
        let store = FileTrustStore::new(path.clone());
        let err = store.entries("h:22").unwrap_err();
        assert_eq!(
            err,
            conwrt_core::ssh::TrustStoreError::Malformed("truncated-host".into())
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn remember_in_unwritable_dir_is_an_error_not_a_silent_skip() {
        // Codex P1 on #207: an accepted-but-unpersisted key makes every
        // later invocation a silent first-use.
        use conwrt_core::ssh::TrustStore;
        let dir = std::env::temp_dir().join(format!("conwrt-trust-ro-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let ro = {
            let mut p = std::fs::metadata(&dir).unwrap().permissions();
            p.set_mode(0o500);
            p
        };
        std::fs::set_permissions(&dir, ro).unwrap();
        let mut store = FileTrustStore::new(dir.join("known_hosts"));
        let key = HostKeyView {
            key_algo: "ssh-ed25519".into(),
            fingerprint: "SHA256:abc".into(),
        };
        let r = store.remember("h:22", &key);
        assert!(matches!(
            r,
            Err(conwrt_core::ssh::TrustStoreError::Unwritable)
        ));
        let mut rw = std::fs::metadata(&dir).unwrap().permissions();
        rw.set_mode(0o700);
        std::fs::set_permissions(&dir, rw).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

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
        store
            .remember("h:22", &key("ssh-ed25519", "SHA256:aaa"))
            .unwrap();
        assert_eq!(
            store.entries("h:22").unwrap(),
            vec![key("ssh-ed25519", "SHA256:aaa")]
        );
        assert!(store.entries("other:22").unwrap().is_empty());
    }

    #[test]
    fn persists_across_instances_and_dedupes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let mut a = FileTrustStore::new(&path);
        a.remember("h:22", &key("ssh-ed25519", "SHA256:aaa"))
            .unwrap();
        a.remember("h:22", &key("ssh-ed25519", "SHA256:aaa"))
            .unwrap(); // dedupe
        a.remember("h:22", &key("rsa-sha2-256", "SHA256:bbb"))
            .unwrap(); // second algo

        let b = FileTrustStore::new(&path);
        assert_eq!(b.entries("h:22").unwrap().len(), 2);

        let mut c = FileTrustStore::new(&path);
        c.remember("h2:22", &key("ssh-ed25519", "SHA256:ccc"))
            .unwrap();
        let d = FileTrustStore::new(&path);
        assert_eq!(d.entries("h:22").unwrap().len(), 2);
        assert_eq!(d.entries("h2:22").unwrap().len(), 1);
    }

    #[test]
    fn file_holds_fingerprints_only_and_survives_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let mut store = FileTrustStore::new(&path);
        store
            .remember("h:22", &key("ssh-ed25519", "SHA256:aaa"))
            .unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert_eq!(contents, "h:22 ssh-ed25519 SHA256:aaa\n");

        // Comment and blank lines survive; a non-empty malformed line is
        // now a hard error instead of being silently dropped (Codex P1
        // on #207 — see malformed_record_fails_closed_... below).
        fs::write(&path, "# comment line\nh:22 ssh-ed25519 SHA256:aaa\n\n").unwrap();
        let store = FileTrustStore::new(&path);
        assert_eq!(store.entries("h:22").unwrap().len(), 1);
    }

    #[test]
    fn absent_file_is_empty_not_error() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileTrustStore::new(dir.path().join("nope"));
        assert!(store.entries("h:22").unwrap().is_empty());
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
                    )
                    .unwrap();
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
                    store.entries(&format!("host{i}-{j}:22")).unwrap().len(),
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
        store
            .remember("h1:22", &key("ssh-ed25519", "SHA256:aaa"))
            .unwrap();
        store
            .remember("h2:22", &key("ssh-ed25519", "SHA256:bbb"))
            .unwrap();
        store.forget("h1:22").unwrap();
        assert!(store.entries("h1:22").unwrap().is_empty());
        assert_eq!(store.entries("h2:22").unwrap().len(), 1);
        // Absent host: no-op, other entries intact, no error.
        store.forget("never-seen:22").unwrap();
        assert_eq!(store.entries("h2:22").unwrap().len(), 1);
        // Persists across instances.
        let reopened = FileTrustStore::new(&path);
        assert!(reopened.entries("h1:22").unwrap().is_empty());
        assert_eq!(reopened.entries("h2:22").unwrap().len(), 1);
    }

    #[test]
    fn forget_on_absent_file_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = FileTrustStore::new(dir.path().join("nope"));
        store.forget("h:22").unwrap(); // must not panic or create the file
        assert!(store.entries("h:22").unwrap().is_empty());
    }

    #[test]
    fn leftover_lock_file_from_a_dead_process_does_not_block() {
        // Under the old O_EXCL scheme a crashed holder left the lock file
        // behind and every later writer had to wait out a 3s timeout
        // before taking it over. With flock the sidecar is pure lock
        // identity: a leftover file from a dead process is unlocked by
        // definition (its fd is closed), so remember() proceeds at once.
        // Crash cleanup is the kernel's job now — there is deliberately
        // no timeout logic left here to test.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        let lock_path = {
            let mut s = path.as_os_str().to_os_string();
            s.push(".lock");
            PathBuf::from(s)
        };
        fs::write(&lock_path, "left behind by a dead process").unwrap();
        let mut store = FileTrustStore::new(&path);
        store
            .remember("h:22", &key("ssh-ed25519", "SHA256:aaa"))
            .unwrap();
        assert_eq!(store.entries("h:22").unwrap().len(), 1);
    }
}
