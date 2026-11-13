# Lane: zycast spec-conformance (5h block 2026-11-11, ratified by overwatch)
Normative: docs/zycast/SPEC.md (conwrt #691). Deliverables:
1. Test vectors from SPEC: frame layout (30B header, BE fields), checksum16
   (folded byte-sum, SPEC §3), gate-chain classes (§6), state machine (§5).
   New: crates/conwrt-protocols/tests/zycast_spec_vectors.rs — cite SPEC
   section on every assertion.
2. DRY refactor of crates/conwrt-protocols/src/zycast.rs against SPEC
   (constants, header encode/decode single-sourced, ImageType bits = §4).
3. Sender behaviors cite SPEC sections in doc comments.
Rules: worktree-isolated (this dir); parity-corpus lane on
rust/parity-corpus-on-ports-m concurrently — fetch + check branches before
push; tmux for builds; green gates (fmt 1.99, clippy, tests) before PR to
Amperstrand/conwrt; no rack. Closeout ~11:45 UTC to handoff.
