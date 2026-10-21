//! Cache cleaning — parity for `conwrt cache clean`
//! (`_cache_clean` in `scripts/conwrt/cmd_info.py`).

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cache::sorted_subdirs;

/// Options for [`clean_cache`].
#[derive(Debug, Clone, Default)]
pub struct CleanOptions {
    /// Keep only the newest build per profile (by cache-directory mtime,
    /// like `_cache_clean --keep-latest`).
    pub keep_latest: bool,
    /// Restrict cleaning to one profile. Matches both `dlink_covr…` and
    /// `dlink-covr…` spellings, like `_cache_clean --model-id` does.
    pub profile: Option<String>,
}

/// What [`clean_cache`] removed.
#[derive(Debug, Clone, Default)]
pub struct CleanReport {
    /// Removed cache directories.
    pub removed: Vec<PathBuf>,
    /// Sum of file sizes that lived directly inside the removed
    /// directories (non-recursive, matching the Python byte count).
    pub freed_bytes: u64,
}

/// Removes cached builds from `images_root`.
///
/// With `keep_latest`, every profile keeps its newest cache directory
/// (highest mtime); without it, all cache directories go. The caller owns
/// confirmation/dry-run presentation — this function only computes and
/// removes, so it stays testable without a TTY.
pub fn clean_cache(images_root: &Path, options: &CleanOptions) -> std::io::Result<CleanReport> {
    let mut report = CleanReport::default();
    for profile_dir in sorted_subdirs(images_root)? {
        let profile = profile_dir
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if let Some(wanted) = &options.profile {
            let underscore = wanted.replace('-', "_");
            if profile != *wanted && profile != underscore {
                continue;
            }
        }

        let mut hash_dirs = sorted_subdirs(&profile_dir)?;
        // Oldest first — `_cache_clean` sorts by st_mtime and drops every
        // directory except the last.
        hash_dirs.sort_by_key(|dir| mtime(dir));

        if options.keep_latest {
            if hash_dirs.len() > 1 {
                let keep = hash_dirs.len() - 1;
                report.removed.extend(hash_dirs.drain(..keep));
            }
        } else {
            report.removed.extend(hash_dirs);
        }
    }

    for dir in &report.removed {
        report.freed_bytes += flat_size(dir);
        fs::remove_dir_all(dir)?;
    }
    Ok(report)
}

fn mtime(dir: &Path) -> SystemTime {
    fs::metadata(dir)
        .and_then(|meta| meta.modified())
        .unwrap_or(UNIX_EPOCH)
}

fn flat_size(dir: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    entries
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let meta = entry.metadata().ok()?;
            meta.is_file().then_some(meta.len())
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_build(root: &Path, profile: &str, key: &str, file_bytes: usize) -> PathBuf {
        let dir = root.join(profile).join(key);
        fs::create_dir_all(&dir).expect("mkdir");
        fs::write(dir.join("fw.bin"), vec![0u8; file_bytes]).expect("write");
        dir
    }

    #[test]
    fn clean_all_removes_every_profile_dir() {
        let root = tempfile::tempdir().expect("tempdir");
        make_build(root.path(), "a_prof", "key1", 100);
        make_build(root.path(), "b_prof", "key2", 50);

        let report = clean_cache(root.path(), &CleanOptions::default()).expect("clean");
        assert_eq!(report.removed.len(), 2);
        assert_eq!(report.freed_bytes, 150);
        assert!(!root.path().join("a_prof").join("key1").exists());
    }

    #[test]
    fn keep_latest_preserves_newest_mtime() {
        let root = tempfile::tempdir().expect("tempdir");
        // Directory mtimes follow entry creation, so `old` is created
        // first and `new` last.
        let old = make_build(root.path(), "a_prof", "old0000", 10);
        std::thread::sleep(std::time::Duration::from_millis(20));
        let new = make_build(root.path(), "a_prof", "new1111", 20);

        let report = clean_cache(
            root.path(),
            &CleanOptions {
                keep_latest: true,
                profile: None,
            },
        )
        .expect("clean");
        assert_eq!(report.removed, vec![old]);
        assert!(new.is_dir());
    }

    #[test]
    fn keep_latest_with_single_build_removes_nothing() {
        let root = tempfile::tempdir().expect("tempdir");
        make_build(root.path(), "a_prof", "key1", 10);
        let report = clean_cache(
            root.path(),
            &CleanOptions {
                keep_latest: true,
                profile: None,
            },
        )
        .expect("clean");
        assert!(report.removed.is_empty());
    }

    #[test]
    fn profile_filter_matches_dash_and_underscore_spellings() {
        let root = tempfile::tempdir().expect("tempdir");
        make_build(root.path(), "dlink_covr", "key1", 10);
        make_build(root.path(), "other_prof", "key2", 10);

        let report = clean_cache(
            root.path(),
            &CleanOptions {
                profile: Some("dlink-covr".into()),
                ..CleanOptions::default()
            },
        )
        .expect("clean");
        assert_eq!(report.removed.len(), 1);
        assert!(report.removed[0].ends_with("dlink_covr/key1"));
    }

    #[test]
    fn clean_missing_root_is_noop() {
        let root = tempfile::tempdir().expect("tempdir");
        let report = clean_cache(root.path().join("nope").as_path(), &CleanOptions::default())
            .expect("clean");
        assert!(report.removed.is_empty());
        assert_eq!(report.freed_bytes, 0);
    }
}
