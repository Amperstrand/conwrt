//! Filesystem model registry (std + JSON feature).
//!
//! Loads and validates the shared `models/*.json` corpus. Rust and the 1.x
//! Python validator must both stay green on the same tree (ADR-0001).

use crate::model::DeviceModel;
use crate::validate::validate_model;
use alloc::vec::Vec;
use std::path::{Path, PathBuf};

/// A loaded, validated set of device models.
#[derive(Debug, Clone, Default)]
pub struct ModelRegistry {
    models: Vec<DeviceModel>,
}

/// One file-level outcome: the path and, on failure, why it failed.
#[derive(Debug)]
pub struct InvalidModel {
    /// The file that failed.
    pub path: PathBuf,
    /// Schema/validation problems (empty when the file failed to parse).
    pub problems: Vec<String>,
}

impl InvalidModel {
    /// Parse failure wrapper.
    pub fn parse_error(path: PathBuf, error: serde_json::Error) -> Self {
        Self {
            path,
            problems: vec![alloc::format!("JSON parse error: {error}")],
        }
    }

    /// I/O failure wrapper.
    pub fn io_error(path: PathBuf, error: std::io::Error) -> Self {
        Self {
            path,
            problems: vec![alloc::format!("read error: {error}")],
        }
    }
}

/// Failure to load the registry directory at all.
#[derive(Debug)]
pub enum RegistryError {
    /// The directory could not be read.
    BadDir(std::io::Error),
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::BadDir(e) => write!(f, "cannot read models directory: {e}"),
        }
    }
}

impl std::error::Error for RegistryError {}

impl ModelRegistry {
    /// Load and validate every `*.json` in `dir`.
    ///
    /// Valid models are collected; invalid ones are returned alongside so
    /// callers can report everything in one pass (validator UX parity with
    /// `make validate-models`).
    pub fn load_dir(dir: &Path) -> Result<(Self, Vec<InvalidModel>), RegistryError> {
        let entries = std::fs::read_dir(dir).map_err(RegistryError::BadDir)?;
        let mut models = Vec::new();
        let mut invalid = Vec::new();
        let mut paths: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect();
        paths.sort();

        for path in paths {
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .map(ToString::to_string);
            let contents = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(e) => {
                    invalid.push(InvalidModel::io_error(path, e));
                    continue;
                }
            };
            let model: DeviceModel = match serde_json::from_str(&contents) {
                Ok(m) => m,
                Err(e) => {
                    invalid.push(InvalidModel::parse_error(path, e));
                    continue;
                }
            };
            let problems = validate_model(&model, stem.as_deref());
            if problems.is_empty() {
                models.push(model);
            } else {
                invalid.push(InvalidModel { path, problems });
            }
        }
        Ok((Self { models }, invalid))
    }

    /// The validated models, sorted by file name.
    #[must_use]
    pub fn models(&self) -> &[DeviceModel] {
        &self.models
    }
}
