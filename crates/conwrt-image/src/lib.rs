//! # conwrt-image
//!
//! ASU (Attended SysUpgrade) firmware-image client for conwrt — Rust
//! parity for `scripts/firmware-manager.py`, following the strangler-fig
//! migration (ADR-0001): library first, no CLI yet.
//!
//! The crate is std-only (no `no_std` requirement) and performs no I/O at
//! import time; every network interaction goes through the [`AsuClient`]
//! seam, so tests run entirely against mocks — never the real ASU
//! service.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub mod error;
pub mod types;

pub use error::ImageError;
pub use types::{
    BuildManifest, BuildRequest, BuildStatus, ImageType, ManifestImage, StatusValue,
    SubmitResponse,
};
