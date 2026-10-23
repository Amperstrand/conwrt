//! Binary integration tests for `conwrt probe --scenario …` — the
//! scripted-mock surface of the diagnostic workflow (§7 item-2 audit,
//! 2026-10-23). The live twin `conwrt diagnose` binds a LocalProber and
//! cannot run in CI; this file pins the deterministic half: for every
//! NamedScenario the CLI must report the verdict the workflow contract
//! promises (state, evidence flags, notes) plus the mock-provider
//! footer that keeps the demo surface distinct from the real one.
//!
//! The multi-target SWEEP (`conwrt.py probe`) has no Rust twin — see
//! parity-matrix §7 for the deprecation-gate audit this pin supports.
//! Candidate lines are corpus-derived (MAC OUI match) and asserted by
//! prefix only, so corpus growth does not churn these tests.

use std::path::Path;
use std::process::Command;

fn conwrt() -> Command {
    Command::new(env!("CARGO_BIN_EXE_conwrt"))
}

fn models_dir() -> String {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models");
    dir.to_str().expect("models dir is utf-8").to_string()
}

fn run_scenario(scenario: &str) -> (bool, String) {
    let out = conwrt()
        .arg("probe")
        .arg("--scenario")
        .arg(scenario)
        .arg("--dir")
        .arg(models_dir())
        .output()
        .expect("run conwrt probe");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

const FOOTER: &str = "(provider: scripted mock — `conwrt diagnose` uses the local provider)";

#[test]
fn scenario_off_reports_link_down() {
    let (ok, out) = run_scenario("off");
    assert!(ok, "stderr/stdout: {out}");
    assert!(
        out.contains("state:      off\n"),
        "state line missing in:\n{out}"
    );
    assert!(
        out.contains("note:       link is down: powered off or unplugged\n"),
        "note missing in:\n{out}"
    );
    assert!(
        !out.contains("evidence:"),
        "off must not show evidence flags:\n{out}"
    );
    assert!(
        !out.contains("candidate:"),
        "off must not guess candidates:\n{out}"
    );
    assert!(out.contains(FOOTER), "mock footer missing in:\n{out}");
}

#[test]
fn scenario_unreachable_reports_no_responses() {
    let (ok, out) = run_scenario("unreachable");
    assert!(ok, "{out}");
    assert!(out.contains("state:      unreachable\n"), "in:\n{out}");
    assert!(
        out.contains("note:       no responses on any channel\n"),
        "in:\n{out}"
    );
    assert!(
        !out.contains("evidence:"),
        "unreachable must not show evidence flags:\n{out}"
    );
    assert!(
        !out.contains("candidate:"),
        "unreachable must not guess candidates:\n{out}"
    );
    assert!(out.contains(FOOTER), "in:\n{out}");
}

#[test]
fn scenario_uboot_reports_recovery_server() {
    let (ok, out) = run_scenario("uboot");
    assert!(ok, "{out}");
    assert!(out.contains("state:      uboot-recovery\n"), "in:\n{out}");
    assert!(
        out.contains("evidence:   ping=true http=true ssh=false\n"),
        "in:\n{out}"
    );
    assert!(
        out.contains("note:       no SSH while a recovery server answers: bootloader mode\n"),
        "in:\n{out}"
    );
    assert!(
        out.contains("candidate:  "),
        "candidates expected for a MAC-matched responder:\n{out}"
    );
    assert!(out.contains(FOOTER), "in:\n{out}");
}

#[test]
fn scenario_openwrt_reports_banner_plus_http() {
    let (ok, out) = run_scenario("openwrt");
    assert!(ok, "{out}");
    assert!(out.contains("state:      openwrt\n"), "in:\n{out}");
    assert!(
        out.contains("evidence:   ping=true http=true ssh=true\n"),
        "in:\n{out}"
    );
    assert!(
        out.contains("note:       SSH banner 'dropbear_2024.86' plus OpenWrt HTTP fingerprints\n"),
        "in:\n{out}"
    );
    assert!(out.contains("candidate:  "), "in:\n{out}");
    assert!(out.contains(FOOTER), "in:\n{out}");
}

#[test]
fn scenario_ssh_only_reports_unconfirmed_os() {
    // The deliberate §2 divergence: a bare dropbear banner is NOT
    // speculative-openwrt — the Rust classifier says ssh-only and names
    // the refinement path. The Python sweep classifier answers
    // "openwrt" for any SSH responder (parity-matrix §7 audit).
    let (ok, out) = run_scenario("ssh-only");
    assert!(ok, "{out}");
    assert!(out.contains("state:      ssh-only\n"), "in:\n{out}");
    assert!(
        out.contains("evidence:   ping=true http=false ssh=true\n"),
        "in:\n{out}"
    );
    assert!(
        out.contains("note:       SSH banner 'SSH-2.0-dropbear_2024.86' answered with no identifying HTTP evidence\n"),
        "in:\n{out}"
    );
    assert!(
        out.contains("note:       OS unconfirmed: stock firmwares also run dropbear; board evidence refines this\n"),
        "in:\n{out}"
    );
    assert!(out.contains("candidate:  "), "in:\n{out}");
    assert!(out.contains(FOOTER), "in:\n{out}");
}

#[test]
fn scenario_stock_reports_vendor_ui() {
    let (ok, out) = run_scenario("stock");
    assert!(ok, "{out}");
    assert!(out.contains("state:      stock-vendor\n"), "in:\n{out}");
    assert!(
        out.contains("evidence:   ping=true http=true ssh=false\n"),
        "in:\n{out}"
    );
    assert!(
        out.contains("note:       vendor UI without SSH: treating as stock firmware\n"),
        "in:\n{out}"
    );
    assert!(out.contains("candidate:  "), "in:\n{out}");
    assert!(out.contains(FOOTER), "in:\n{out}");
}
