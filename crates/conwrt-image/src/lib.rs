//! # conwrt-image
//!
//! ASU (Attended SysUpgrade) firmware-image client for conwrt — Rust
//! parity for `scripts/firmware-manager.py` plus vanilla OpenWrt image
//! sourcing from `downloads.openwrt.org` (`scripts/conwrt/image_source.py`),
//! following the strangler-fig migration (ADR-0001): library first, no CLI
//! yet.
//!
//! The crate is std-only (no `no_std` requirement) and performs no I/O at
//! import time; every network interaction goes through the [`AsuClient`]
//! and [`DownloadsClient`](downloads::DownloadsClient) seams, so tests run
//! entirely against mocks — never the real ASU service or download host.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub mod cache;
pub mod clean;
pub mod client;
pub mod downloads;
pub mod error;
pub mod http;
pub mod metadata;
pub mod timestamp;
pub mod types;
pub mod vanilla;
pub mod workflow;

pub use cache::request_cache_key;
pub use clean::{CleanOptions, CleanReport, clean_cache};
pub use client::{AsuClient, AsuEndpoints, DEFAULT_ASU_BASE, PollConfig, USER_AGENT};
pub use downloads::{
    DOWNLOADS_USER_AGENT, DownloadsClient, FetchOptions, FetchedImage, ReqwestDownloadsClient,
    fetch_image,
};
pub use error::ImageError;
pub use http::ReqwestAsuClient;
pub use metadata::{
    CachedImage, CachedMetadata, ListEntry, METADATA_FILENAME, find_cached, find_cached_build,
    list_entries, read_metadata, show_metadata,
};
pub use types::{
    BuildManifest, BuildRequest, BuildStatus, ImageType, ManifestImage, StatusValue, SubmitResponse,
};
pub use vanilla::{
    DEFAULT_DOWNLOADS_BASE, DEFAULT_IMAGE_SUFFIX, DEFAULT_RELEASE, ReleaseOverrides,
    SuffixOverrides, VanillaModel, image_filename, image_url, is_full_release, parse_sha256sums,
    resolve_image_suffix, resolve_release, target_dir_url,
};
pub use workflow::{RequestExtras, RequestOutcome, request_and_cache};
