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

pub mod cache;
pub mod clean;
pub mod client;
pub mod error;
pub mod http;
pub mod metadata;
pub mod timestamp;
pub mod types;
pub mod workflow;

pub use cache::request_cache_key;
pub use clean::{CleanOptions, CleanReport, clean_cache};
pub use client::{AsuClient, AsuEndpoints, DEFAULT_ASU_BASE, PollConfig, USER_AGENT};
pub use error::ImageError;
pub use http::ReqwestAsuClient;
pub use metadata::{
    CachedImage, CachedMetadata, ListEntry, METADATA_FILENAME, find_cached, find_cached_build,
    list_entries, read_metadata, show_metadata,
};
pub use types::{
    BuildManifest, BuildRequest, BuildStatus, ImageType, ManifestImage, StatusValue, SubmitResponse,
};
pub use workflow::{RequestExtras, RequestOutcome, request_and_cache};
