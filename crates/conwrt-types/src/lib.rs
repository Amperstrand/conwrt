//! # conwrt-types
//!
//! Shared domain types for conwrt 2.0: species-level device model data
//! (parsed from the existing `models/*.json` corpus), MAC/OUI identification
//! primitives, and schema-parity validation.
//!
//! This crate is Tier-A per ADR-0002: `no_std` + `alloc` by default. JSON
//! parsing and the filesystem registry loader are gated behind the `json`
//! feature (which implies `std`).
#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

pub mod mac;
pub mod model;
pub mod validate;

#[cfg(feature = "json")]
pub mod registry;

pub use mac::{MacAddress, OuiPrefix};
pub use model::{DeviceModel, FlashMethod, OpenwrtInfo};
