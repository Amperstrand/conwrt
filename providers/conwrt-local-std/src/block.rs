//! Host [`BlockWriter`] for the MAAS lab disk pipeline (issue #169):
//! the real dd-equivalent file I/O behind `conwrt_maas::flash`.
//!
//! CI-provable parts run against a temp file (`tempfile`): write, read-back,
//! and error surfacing. Two operations need lab-side system utilities and
//! fail with actionable errors when absent — this is deliberate honesty,
//! not a stub: a `growpart`/`mkfs.vfat` dance can only be proven on the
//! bench (owner-gated), never in CI.
//!
//! - `grow_partition` shells out to `growpart <path> <partition>` (the
//!   util-linux/cloud-guestutils tool the lab recipe's Phase-3 resize uses).
//! - `write_seed` stages the cloud-init trio into `<path>.seed/` as
//!   `user-data`, `meta-data`, `network-config`; assembling the FAT
//!   CIDATA volume from the staging dir is the lab-side step.
//!
//! **Safety**: the writer opens exactly the path it is given. Pointing it
//! at a whole-disk device node (`/dev/sdX`) rewrites that device — the
//! caller owns that decision (AGENTS.md specimen/serial gates apply).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use conwrt_maas::flash::{BlockWriter, CloudInitSeed, Sha256};
use sha2::Digest as _;
use thiserror::Error;

/// Failures of the host block writer.
#[derive(Debug, Error)]
pub enum BlockWriterError {
    /// Filesystem-level failure on the target path.
    #[error("block I/O failed on {path}: {source}")]
    Io {
        /// The target path.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// A lab-side utility (`growpart`) is not installed.
    #[error("grow_partition needs the `growpart` utility (cloud-guestutils) installed")]
    GrowpartMissing,
    /// `growpart` ran and failed.
    #[error("growpart failed for {path} partition {partition}: {stderr}")]
    GrowpartFailed {
        /// The target path.
        path: PathBuf,
        /// 1-based partition number.
        partition: u8,
        /// Truncated stderr from the utility.
        stderr: String,
    },
    /// The opened device node is not the device that was verified —
    /// a rename/reassign race between specimen gate and open.
    #[error("device reassign race: opened {} but expected {expected}", opened.display())]
    DeviceReassigned {
        /// What the open handle actually resolves to.
        opened: PathBuf,
        /// What the specimen gate verified.
        expected: PathBuf,
    },
}

/// File-backed [`BlockWriter`]: the image target is a regular file (or a
/// loop-device path in the lab); the seed stages next to it.
#[derive(Debug)]
pub struct FileBlockWriter {
    path: PathBuf,
    partition: Option<u8>,
    growpart: Option<PathBuf>,
    /// Retained handle: a pre-opened device (see [`FileBlockWriter::open_device`])
    /// or the just-written file. All writes and verification reads on a
    /// device go through THIS inode — the pathname is never re-resolved
    /// after the specimen gate.
    handle: Option<std::fs::File>,
}

/// Read-back verification chunk: bounded memory regardless of image size.
const VERIFY_CHUNK: usize = 1 << 20;

impl FileBlockWriter {
    /// Writer for the image target at `path` (no partition growing).
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            partition: None,
            growpart: None,
            handle: None,
        }
    }

    /// Open the block device at `path` read+write NOW and pin it: every
    /// later write and verification read goes through this handle, so an
    /// unplug/reassign of `/dev/sdX` between the specimen gate and the
    /// write cannot redirect the destructive path onto a different,
    /// never-verified device (the held inode just starts erroring).
    /// On Linux the opened node's name is cross-checked against `path`
    /// to close the verify-open race itself.
    pub fn open_device(path: impl Into<PathBuf>) -> Result<Self, BlockWriterError> {
        let path = path.into();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(io_err(&path))?;
        verify_opened_device_name(&file, &path)?;
        Ok(Self {
            path,
            partition: None,
            growpart: None,
            handle: Some(file),
        })
    }

    /// Builder: grow this 1-based partition after write verification
    /// (requires `growpart` at the given or default PATH location).
    #[must_use]
    pub fn with_growpart(mut self, partition: u8, growpart: impl Into<PathBuf>) -> Self {
        self.partition = Some(partition);
        self.growpart = Some(growpart.into());
        self
    }

    /// Where the cloud-init seed stages (`<target>.seed/`).
    fn seed_dir(&self) -> PathBuf {
        let mut s = self.path.clone().into_os_string();
        s.push(".seed");
        PathBuf::from(s)
    }

    /// Durability gate before any verification read: flush the retained
    /// write handle so read-backs are checked against what the kernel
    /// committed, not a stale page cache.
    fn sync_written(&self) -> Result<(), BlockWriterError> {
        if let Some(f) = &self.handle {
            f.sync_all().map_err(io_err(&self.path))?;
        }
        Ok(())
    }

    /// A handle for verification reads: a dup of the retained handle
    /// (same inode — pathname reassignment cannot redirect it) or, for
    /// the plain-file flow, a fresh open with the cache evicted.
    fn verify_file(&self) -> Result<std::fs::File, BlockWriterError> {
        match &self.handle {
            Some(f) => {
                let dup = f.try_clone().map_err(io_err(&self.path))?;
                evict_page_cache(&dup);
                Ok(dup)
            }
            None => open_verify_reader(&self.path),
        }
    }
}

#[cfg(target_os = "linux")]
fn verify_opened_device_name(
    file: &std::fs::File,
    expected: &Path,
) -> Result<(), BlockWriterError> {
    use std::os::unix::io::AsRawFd;
    let opened = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(io_err(expected))?;
    if opened.file_name() != expected.file_name() {
        return Err(BlockWriterError::DeviceReassigned {
            opened,
            expected: expected.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_opened_device_name(
    _file: &std::fs::File,
    _expected: &Path,
) -> Result<(), BlockWriterError> {
    Ok(())
}

/// Verification reads go through a fresh handle with the page cache
/// evicted first (`POSIX_FADV_DONTNEED`), so bytes come from the media.
fn open_verify_reader(path: &Path) -> Result<std::fs::File, BlockWriterError> {
    let f = std::fs::File::open(path).map_err(io_err(path))?;
    evict_page_cache(&f);
    Ok(f)
}

#[cfg(target_os = "linux")]
fn evict_page_cache(f: &std::fs::File) {
    use std::os::unix::io::AsRawFd;
    // Pages are clean after sync_all, so DONTNEED evicts them and the
    // verification read comes from the media, not the cache.
    let _ = nix::fcntl::posix_fadvise(
        f.as_raw_fd(),
        0,
        0,
        nix::fcntl::PosixFadviseAdvice::POSIX_FADV_DONTNEED,
    );
}

#[cfg(not(target_os = "linux"))]
fn evict_page_cache(_f: &std::fs::File) {}

fn io_err(path: &Path) -> impl Fn(std::io::Error) -> BlockWriterError + '_ {
    move |source| BlockWriterError::Io {
        path: path.to_path_buf(),
        source,
    }
}

impl BlockWriter for FileBlockWriter {
    type Error = BlockWriterError;

    async fn write_image(&mut self, image: &[u8]) -> Result<(), Self::Error> {
        // std::fs inside async: the lab flow calls this from a host
        // runner, not a shared reactor; keep the I/O synchronous and
        // simple (the mock-era pipeline has no concurrency requirement).
        use std::io::Seek;
        let mut f = match self.handle.take() {
            // Pre-opened device: write through the pinned inode.
            Some(mut f) => {
                f.seek(std::io::SeekFrom::Start(0))
                    .map_err(io_err(&self.path))?;
                f
            }
            // Regular-file flow: create (truncate) and retain; read+write
            // so verification can dup the same handle.
            None => std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&self.path)
                .map_err(io_err(&self.path))?,
        };
        f.write_all(image).map_err(io_err(&self.path))?;
        f.sync_all().map_err(io_err(&self.path))?;
        self.handle = Some(f);
        Ok(())
    }

    async fn read_back(&mut self, len: usize) -> Result<Vec<u8>, Self::Error> {
        use std::io::{Read, Seek};
        self.sync_written()?;
        let mut f = self.verify_file()?;
        f.seek(std::io::SeekFrom::Start(0))
            .map_err(io_err(&self.path))?;
        let mut buf = vec![0u8; len];
        f.read_exact(&mut buf).map_err(io_err(&self.path))?;
        Ok(buf)
    }

    async fn read_back_digest(&mut self, len: usize) -> Result<Sha256, Self::Error> {
        use std::io::{Read, Seek};
        self.sync_written()?;
        let mut f = self.verify_file()?;
        f.seek(std::io::SeekFrom::Start(0))
            .map_err(io_err(&self.path))?;
        let mut h = sha2::Sha256::new();
        let mut chunk = vec![0u8; VERIFY_CHUNK];
        let mut remaining = len;
        while remaining > 0 {
            let want = remaining.min(chunk.len());
            f.read_exact(&mut chunk[..want])
                .map_err(io_err(&self.path))?;
            h.update(&chunk[..want]);
            remaining -= want;
        }
        Ok(Sha256::from_digest(h.finalize().into()))
    }

    async fn grow_partition(&mut self) -> Result<(), Self::Error> {
        let partition = self.partition.ok_or(BlockWriterError::GrowpartMissing)?;
        let growpart = self.growpart.clone().unwrap_or_else(|| "growpart".into());
        let out = Command::new(&growpart)
            .arg(&self.path)
            .arg(partition.to_string())
            .output()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    BlockWriterError::GrowpartMissing
                } else {
                    BlockWriterError::Io {
                        path: self.path.clone(),
                        source: e,
                    }
                }
            })?;
        if !out.status.success() {
            return Err(BlockWriterError::GrowpartFailed {
                path: self.path.clone(),
                partition,
                stderr: String::from_utf8_lossy(&out.stderr)
                    .chars()
                    .take(200)
                    .collect(),
            });
        }
        Ok(())
    }

    async fn write_seed(&mut self, seed: &CloudInitSeed) -> Result<(), Self::Error> {
        let dir = self.seed_dir();
        std::fs::create_dir_all(&dir).map_err(io_err(&dir))?;
        let user_data_path = dir.join("user-data");
        std::fs::write(&user_data_path, &seed.user_data).map_err(io_err(&user_data_path))?;
        let meta_path = dir.join("meta-data");
        std::fs::write(&meta_path, &seed.meta_data).map_err(io_err(&meta_path))?;
        if let Some(nc) = &seed.network_config {
            let nc_path = dir.join("network-config");
            std::fs::write(&nc_path, nc).map_err(io_err(&nc_path))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use conwrt_maas::flash::{CloudInitSeed, DiskFlashPlan, Sha256, execute_flash};

    const IMAGE: &[u8] = b"lab disk image stand-in bytes";

    fn seed() -> CloudInitSeed {
        CloudInitSeed {
            user_data: "#cloud-config\n".into(),
            meta_data: "instance-id: pi-lab".into(),
            network_config: Some("network: {}".into()),
        }
    }

    #[tokio::test]
    async fn file_writer_roundtrips_write_and_read_back() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut w = FileBlockWriter::new(tmp.path());

        w.write_image(IMAGE).await.unwrap();
        assert_eq!(w.read_back(IMAGE.len()).await.unwrap(), IMAGE);
    }

    #[tokio::test]
    async fn read_back_digest_matches_whole_image_hash_across_chunks() {
        // 2.5 MiB of non-uniform bytes → three VERIFY_CHUNK iterations.
        let image: Vec<u8> = (0..2_621_440).map(|i| (i % 251) as u8).collect();
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut w = FileBlockWriter::new(tmp.path());

        w.write_image(&image).await.unwrap();
        let digest = w.read_back_digest(image.len()).await.unwrap();
        assert_eq!(digest, Sha256::hash(&image));
        assert_eq!(w.read_back(image.len()).await.unwrap(), image);
    }

    #[tokio::test]
    async fn full_pipeline_against_a_real_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut w = FileBlockWriter::new(tmp.path());
        let plan = DiskFlashPlan::new(Sha256::hash(IMAGE)).with_seed(seed());

        let report = execute_flash(&plan, IMAGE, &mut w).await.unwrap();

        assert_eq!(report.bytes_written, IMAGE.len());
        assert!(report.seed_injected);
        let seed_dir = {
            let mut s = tmp.path().as_os_str().to_os_string();
            s.push(".seed");
            PathBuf::from(s)
        };
        assert_eq!(
            std::fs::read_to_string(seed_dir.join("user-data")).unwrap(),
            "#cloud-config\n"
        );
        assert_eq!(
            std::fs::read_to_string(seed_dir.join("meta-data")).unwrap(),
            "instance-id: pi-lab"
        );
        assert_eq!(
            std::fs::read_to_string(seed_dir.join("network-config")).unwrap(),
            "network: {}"
        );
    }

    /// Seam-level tampering: flip file contents between write and
    /// read-back — only the writer sits between those two pipeline steps.
    struct TamperingWriter {
        path: PathBuf,
        inner: FileBlockWriter,
    }

    impl conwrt_maas::flash::BlockWriter for TamperingWriter {
        type Error = BlockWriterError;

        async fn write_image(&mut self, image: &[u8]) -> Result<(), Self::Error> {
            self.inner.write_image(image).await?;
            let mut tampered = image.to_vec();
            tampered[0] ^= 0xff; // same length, different content
            std::fs::write(&self.path, tampered).map_err(io_err(&self.path))?;
            Ok(())
        }

        async fn read_back(&mut self, len: usize) -> Result<Vec<u8>, Self::Error> {
            self.inner.read_back(len).await
        }

        async fn grow_partition(&mut self) -> Result<(), Self::Error> {
            self.inner.grow_partition().await
        }

        async fn write_seed(&mut self, seed: &CloudInitSeed) -> Result<(), Self::Error> {
            self.inner.write_seed(seed).await
        }
    }

    #[tokio::test]
    async fn corrupt_target_file_fails_read_back_verification() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut w = TamperingWriter {
            path: tmp.path().to_path_buf(),
            inner: FileBlockWriter::new(tmp.path()),
        };
        let plan = DiskFlashPlan::new(Sha256::hash(IMAGE)).with_seed(seed());

        let err = execute_flash(&plan, IMAGE, &mut w).await.unwrap_err();
        assert!(matches!(
            err,
            conwrt_maas::flash::FlashError::WrittenChecksum { .. }
        ));
        let seed_dir = {
            let mut s = tmp.path().as_os_str().to_os_string();
            s.push(".seed");
            PathBuf::from(s)
        };
        assert!(!seed_dir.exists(), "no seed after failed verification");
    }

    #[tokio::test]
    async fn unwritable_path_surfaces_io_error() {
        let mut w = FileBlockWriter::new("/nonexistent-dir-does-not-exist/disk.img");
        let err = w.write_image(IMAGE).await.unwrap_err();
        assert!(matches!(err, BlockWriterError::Io { .. }));
    }

    #[tokio::test]
    async fn grow_partition_without_configuration_is_actionable() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut w = FileBlockWriter::new(tmp.path());
        let err = w.grow_partition().await.unwrap_err();
        assert!(matches!(err, BlockWriterError::GrowpartMissing));
    }

    #[tokio::test]
    async fn grow_partition_missing_binary_is_actionable() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut w =
            FileBlockWriter::new(tmp.path()).with_growpart(1, "/nonexistent-growpart-binary");
        let err = w.grow_partition().await.unwrap_err();
        assert!(matches!(err, BlockWriterError::GrowpartMissing));
    }
}
