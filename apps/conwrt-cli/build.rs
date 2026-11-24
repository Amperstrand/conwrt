//! Stamp the parity render helper with the workspace git HEAD it was
//! built from (#432 consequence 2): the pytest parity harness compares
//! the binary's stamp against the CURRENT HEAD and rebuilds on
//! mismatch, so a stale binary shared via a global target-dir cache can
//! never produce false "no Rust profile for <preset>" reds (observed
//! 2026-11-24 on a docs-only diff).
//!
//! Hermetic builds: if git is unavailable or the tree is not a repo,
//! the stamp is "unknown" and the harness skips the staleness check
//! (builds still correct, just unguarded).

fn main() {
    let stamp = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into()))
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=CONWRT_RENDER_STAMP={stamp}");
    // The harness drives rebuilds (it detects staleness AFTER build);
    // rerun only when this script itself changes.
    println!("cargo:rerun-if-changed=build.rs");
}
