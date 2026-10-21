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

#[cfg(feature = "json")]
mod lossless_and_negatives {
    use conwrt_types::DeviceModel;
    use conwrt_types::registry::ModelRegistry;
    use std::path::Path;

    fn repo(p: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(p)
    }

    #[test]
    fn corpus_roundtrips_losslessly_through_the_typed_projection() {
        // #118: every untyped field survives the parse via `extras`, in
        // document order — reserializing the model reproduces the original
        // document structurally. This is the proof that no vendor or
        // bootloader metadata can be dropped by Rust tooling.
        for path in std::fs::read_dir(repo("../../models")).expect("models dir") {
            let path = path.expect("entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let original: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&path).expect("read"))
                    .expect("parse original");
            let model: DeviceModel =
                serde_json::from_str(&std::fs::read_to_string(&path).expect("read"))
                    .expect("parse model");
            let roundtripped = serde_json::to_value(&model).expect("reserialize model");
            assert_eq!(
                roundtripped,
                original,
                "{}: typed projection lost or reordered data",
                path.display()
            );
        }
    }

    #[test]
    fn negative_fixtures_are_rejected_like_the_schema_rejects_them() {
        // The Rust half of the #118 parity contract: every fixture under
        // tests/fixtures/schema-negative/ (each rejected by the Python
        // jsonschema run — see tests/test_model_schema_parity.py) must
        // ALSO fail here, by parse error or validation problems.
        let root = repo("../../tests/fixtures/schema-negative");
        let mut cases = 0;
        for entry in std::fs::read_dir(&root).expect("negatives dir") {
            let case_dir = entry.expect("entry").path();
            if !case_dir.is_dir() {
                continue;
            }
            cases += 1;
            let (registry, invalid) = ModelRegistry::load_dir(&case_dir)
                .unwrap_or_else(|e| panic!("load {}: {e}", case_dir.display()));
            assert!(
                !invalid.is_empty() || registry.models().is_empty(),
                "{}: Rust ACCEPTED a fixture the schema rejects — parity drift (#118)",
                case_dir.display()
            );
        }
        assert!(cases >= 5, "expected the parity fixture set, found {cases}");
    }
}
