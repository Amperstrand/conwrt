//! `conwrt-plan-render` — parity-harness helper binary.
//!
//! Renders one use-case parity fixture (`tests/fixtures/parity/*.json`)
//! through the Rust plan pipeline (fixture → Profile → plan_profile →
//! render_shell) and prints the shell script to stdout. The pytest parity
//! harness invokes this to diff the Rust render against the Python
//! `render_shell` for the same fixture. Not part of the operator-facing
//! CLI surface.
//!
//! Usage: `conwrt-plan-render <fixture.json>`

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: conwrt-plan-render <fixture.json>");
        return ExitCode::FAILURE;
    }
    match conwrt_core::parity::render_fixture_file(std::path::Path::new(&args[1])) {
        Ok(script) => {
            print!("{script}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("parity render failed: {err}");
            ExitCode::FAILURE
        }
    }
}
