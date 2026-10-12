//! Parity test: the entire real `models/*.json` corpus (shared with conwrt
//! 1.x and `make validate-models`) parses and validates through Rust.
//! If this fails while `make validate-models` passes, that is a parity bug
//! (ADR-0001) — not a model problem.

#[cfg(feature = "json")]
mod corpus {
    use conwrt_types::registry::ModelRegistry;
    use std::path::Path;

    fn repo_models_dir() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models")
    }

    #[test]
    fn all_real_models_validate() {
        let dir = repo_models_dir();
        let (registry, invalid) = ModelRegistry::load_dir(&dir)
            .unwrap_or_else(|e| panic!("cannot load {}: {e}", dir.display()));

        assert!(
            invalid.is_empty(),
            "invalid models (Rust validator must match `make validate-models`):\n{}",
            invalid
                .iter()
                .map(|m| { format!("  {}: {}", m.path.display(), m.problems.join("; ")) })
                .collect::<Vec<_>>()
                .join("\n")
        );
        // 24 models as of 2026-10; the point is "all of them", so assert a
        // healthy floor rather than an exact count.
        assert!(
            registry.models().len() >= 20,
            "expected the full corpus, got {}",
            registry.models().len()
        );
    }
}
