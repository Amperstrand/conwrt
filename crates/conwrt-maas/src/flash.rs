//! Lab disk-flash pipeline (issue #169): verify → write → verify → inject.
//!
//! Port of the MAAS portable-lab Phase-3 semantics (`recipes/raspberry-pi/
//! maas-portable-lab.md`: verify image checksum → dd to the USB disk →
//! resize partition → inject cloud-init seed) as a typed, inspectable
//! pipeline. The two invariants that make a lab disk safe to boot are
//! enforced HERE, in provider-independent code:
//!
//! 1. **An image whose SHA-256 does not match the plan is never written**
//!    (the checksum gate runs before the first [`BlockWriter`] call).
//! 2. **A cloud-init seed is never injected onto a disk whose read-back
//!    does not match the image** (injection runs only after verification).
//!
//! [`BlockWriter`] is the single I/O seam (ADR-0003): a host provider
//! implements it with real file/dd I/O when live validation happens
//! (owner-gated); [`crate::mock::MockBlockWriter`] records calls for tests.
//! This is distinct from [`conwrt_types::FlashMethod`] (the model-JSON
//! flash-method definitions for routers): the lab disk is a new flash
//! *target*, not a new router flash method — when the pipeline generalizes
//! past the MAAS lab it can move to `conwrt-image` and reuse this shape.

use alloc::format;
use alloc::string::{String, ToString};
use core::fmt;
use core::str::FromStr;

use sha2::{Digest, Sha256 as Sha256Digest};

/// A validated SHA-256 checksum (type-safe: cannot be confused with a
/// raw string, cannot hold malformed hex).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256([u8; 32]);

impl Sha256 {
    /// Hash `bytes` (image contents or read-back contents).
    #[must_use]
    pub fn hash(bytes: &[u8]) -> Self {
        let mut h = Sha256Digest::new();
        h.update(bytes);
        Self(h.finalize().into())
    }

    /// Lowercase hex form (64 chars), as used in checksums.txt artifacts.
    #[must_use]
    pub fn as_hex(&self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}

impl fmt::Display for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_hex())
    }
}

/// Malformed checksum text (wrong length or non-hex characters).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sha256ParseError;

impl fmt::Display for Sha256ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected 64 hex characters")
    }
}

impl core::error::Error for Sha256ParseError {}

impl FromStr for Sha256 {
    type Err = Sha256ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Sha256ParseError);
        }
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = (chunk[0] as char).to_digit(16).ok_or(Sha256ParseError)?;
            let lo = (chunk[1] as char).to_digit(16).ok_or(Sha256ParseError)?;
            out[i] = ((hi << 4) | lo) as u8;
        }
        Ok(Self(out))
    }
}

/// The cloud-init seed injected onto the lab disk (CIDATA volume):
/// `user-data` and `meta-data` are required, `network-config` optional —
/// the exact trio the recipe's Phase-3 injection step writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudInitSeed {
    /// cloud-init user-data (starts with `#cloud-config` for the MAAS lab).
    pub user_data: String,
    /// Instance-id / local-hostname metadata.
    pub meta_data: String,
    /// Optional network-config (netplan/legacy form).
    pub network_config: Option<String>,
}

/// A disk-flash plan: WHAT must be true, never HOW to do it.
///
/// Built from the lab recipe's parameters (image + its published SHA-256,
/// partition grow, seed contents) and executed by [`execute_flash`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskFlashPlan {
    /// Published checksum the image MUST match before any write happens.
    pub image_sha256: Sha256,
    /// Grow the written partition after verification (recipe Phase 3: the
    /// 50GB resize for fast fsck).
    pub grow_partition: bool,
    /// Cloud-init seed to inject after read-back verification.
    pub seed: Option<CloudInitSeed>,
}

impl DiskFlashPlan {
    /// Plan for `image` with its published checksum and no seed/grow.
    #[must_use]
    pub fn new(image_sha256: Sha256) -> Self {
        Self {
            image_sha256,
            grow_partition: false,
            seed: None,
        }
    }

    /// Builder: grow the partition after write verification.
    #[must_use]
    pub fn with_grow(mut self) -> Self {
        self.grow_partition = true;
        self
    }

    /// Builder: inject this cloud-init seed after verification.
    #[must_use]
    pub fn with_seed(mut self, seed: CloudInitSeed) -> Self {
        self.seed = Some(seed);
        self
    }
}

/// Failures of the disk-flash pipeline. `ImageChecksum` and
/// `WrittenChecksum` mean the disk was NOT modified past the failed gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlashError {
    /// The image hash did not match the plan — nothing was written.
    ImageChecksum {
        /// Checksum the plan published.
        expected: Sha256,
        /// Checksum the image actually has.
        actual: Sha256,
    },
    /// The read-back hash did not match — no grow/seed was performed.
    WrittenChecksum {
        /// Checksum the image has.
        expected: Sha256,
        /// Checksum the disk read-back has.
        actual: Sha256,
    },
    /// The writer (disk I/O) failed; its `Display` text is preserved.
    Writer(String),
}

impl fmt::Display for FlashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ImageChecksum { expected, actual } => write!(
                f,
                "image checksum mismatch: expected {expected}, refusing to write (got {actual})"
            ),
            Self::WrittenChecksum { expected, actual } => write!(
                f,
                "disk read-back mismatch: expected {expected}, refusing grow/seed (got {actual})"
            ),
            Self::Writer(e) => write!(f, "disk writer failed: {e}"),
        }
    }
}

impl core::error::Error for FlashError {}

/// The disk I/O seam: write the image, read bytes back, grow the
/// partition, write the cloud-init seed. A host provider implements this
/// with real block-device I/O; tests use [`crate::mock::MockBlockWriter`].
///
/// Providers must treat `write_image` as all-or-nothing for the image
/// region; verification of the result is THIS pipeline's job, not theirs.
pub trait BlockWriter {
    /// Provider-specific error detail (surfaced via [`FlashError::Writer`]).
    type Error: fmt::Display;

    /// Write `image` to the target disk starting at the image region.
    async fn write_image(&mut self, image: &[u8]) -> Result<(), Self::Error>;

    /// Read back the first `len` bytes of the written region.
    async fn read_back(&mut self, len: usize) -> Result<alloc::vec::Vec<u8>, Self::Error>;

    /// Grow the last partition to fill the disk (idempotent).
    async fn grow_partition(&mut self) -> Result<(), Self::Error>;

    /// Write the cloud-init seed volume.
    async fn write_seed(&mut self, seed: &CloudInitSeed) -> Result<(), Self::Error>;
}

/// What a completed flash did, for the inventory/evidence trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlashReport {
    /// Bytes of image written.
    pub bytes_written: usize,
    /// Whether the partition was grown.
    pub partition_grown: bool,
    /// Whether a cloud-init seed was injected.
    pub seed_injected: bool,
}

/// Execute `plan` against `writer` with `image` in memory.
///
/// Gate order (each step only runs if the previous passed):
/// hash-check `image` → write → read-back hash-check → grow → seed.
/// A failing gate aborts with [`FlashError`] and guarantees the disk was
/// not modified past that gate.
pub async fn execute_flash<W: BlockWriter>(
    plan: &DiskFlashPlan,
    image: &[u8],
    writer: &mut W,
) -> Result<FlashReport, FlashError> {
    let actual = Sha256::hash(image);
    if actual != plan.image_sha256 {
        return Err(FlashError::ImageChecksum {
            expected: plan.image_sha256,
            actual,
        });
    }

    writer
        .write_image(image)
        .await
        .map_err(|e| FlashError::Writer(e.to_string()))?;

    let read_back = writer
        .read_back(image.len())
        .await
        .map_err(|e| FlashError::Writer(e.to_string()))?;
    let written = Sha256::hash(&read_back);
    if written != plan.image_sha256 {
        return Err(FlashError::WrittenChecksum {
            expected: plan.image_sha256,
            actual: written,
        });
    }

    if plan.grow_partition {
        writer
            .grow_partition()
            .await
            .map_err(|e| FlashError::Writer(e.to_string()))?;
    }

    let seed_injected = if let Some(seed) = &plan.seed {
        writer
            .write_seed(seed)
            .await
            .map_err(|e| FlashError::Writer(e.to_string()))?;
        true
    } else {
        false
    };

    Ok(FlashReport {
        bytes_written: image.len(),
        partition_grown: plan.grow_partition,
        seed_injected,
    })
}
