//! Ring-1 tests for plan execution: apply (single-script exec) + read-only
//! verification loop, against the in-process SSH fixture.

#[path = "common/mod.rs"]
mod common;

use common::{FIXTURE_PASSWORD, Fixture};
use conwrt_core::plan::{Profile, SqmProfile, VerificationCheck, plan_profile, render_shell};
use conwrt_core::ssh::{MemoryTrustStore, TrustMode};
use conwrt_core::state::DeviceState;
use conwrt_local_std::execute::apply_plan;
use conwrt_local_std::ssh::{SshAuth, SshOptions, SshTarget, connect};

fn model() -> conwrt_types::DeviceModel {
    serde_json::from_str(
        "{\"id\":\"glinet-gl-ar150\",\"vendor\":\"GL.iNet\",\"description\":\"AR150\",\
          \"openwrt\":{\"target\":\"ath79/generic\",\"device\":\"glinet,gl-ar150\",\
          \"profile\":\"glinet_gl-ar150\",\"version\":\"24\"},\
          \"mac_oui\":[\"94:83:C4\"],\"capabilities\":[\"ethernet\",\"wifi\",\"usb\"]}",
    )
    .expect("fixture model parses")
}

fn sqm() -> SqmProfile {
    SqmProfile {
        download_kbps: 340_000,
        upload_kbps: 19_000,
        interface: "wan".into(),
        qdisc: "cake".into(),
        script: "piece_of_cake.qos".into(),
        link_layer: "none".into(),
        overhead: 0,
    }
}

fn plan() -> conwrt_core::plan::Plan {
    plan_profile(&DeviceState::OpenWrt, &model(), &Profile::Sqm(sqm())).expect("plans")
}

fn check<'a>(plan: &'a conwrt_core::plan::Plan, needle: &str) -> &'a VerificationCheck {
    plan.verification
        .iter()
        .find(|c| c.description.contains(needle))
        .expect("check present in plan")
}

async fn connected(fixture: &Fixture) -> conwrt_local_std::ssh::SshSession {
    let target = SshTarget {
        addr: fixture.addr.clone(),
        user: "root".to_string(),
        auth: SshAuth::Password(FIXTURE_PASSWORD.to_string()),
    };
    let mut store = MemoryTrustStore::new();
    connect(
        &target,
        &mut store,
        &SshOptions {
            mode: TrustMode::TrustOnFirstUse,
            ..Default::default()
        },
    )
    .await
    .expect("connect")
}

#[tokio::test]
async fn apply_runs_whole_script_then_verifies() {
    let fixture = Fixture::start().await;
    let plan = plan();
    let script = render_shell(&plan);
    fixture.set_exec_response(&script, 0, "conwrt-plan-applied\n");
    fixture.set_exec_response(&check(&plan, "rate").command, 0, "ok\n");
    fixture.set_exec_response(
        &check(&plan, "qdisc").command,
        0,
        "qdisc cake 80e9: dev eth0 root\n",
    );
    fixture.set_exec_response("/etc/init.d/sqm enabled && echo yes", 0, "yes\n");

    let session = connected(&fixture).await;
    let outcome = apply_plan(&session, &plan).await.expect("apply");

    assert!(outcome.applied);
    assert!(
        outcome.fully_verified(),
        "verification: {:?}",
        outcome.verification
    );
    assert_eq!(outcome.verification.len(), 3);
    assert_eq!(outcome.verification[0].stdout, "ok");
    drop(session);
}

#[tokio::test]
async fn failed_script_is_data_not_error_and_skips_verification() {
    let fixture = Fixture::start().await;
    let plan = plan();
    let script = render_shell(&plan);
    fixture.set_exec_response(&script, 1, "");
    fixture.set_exec_response(&check(&plan, "rate").command, 0, "ok\n");

    let session = connected(&fixture).await;
    let outcome = apply_plan(&session, &plan)
        .await
        .expect("apply call itself succeeds");

    assert!(!outcome.applied);
    assert!(!outcome.fully_verified());
    assert!(
        outcome.verification.is_empty(),
        "no verification after a failed apply"
    );
    drop(session);
}

#[tokio::test]
async fn verification_failure_is_reported_per_check() {
    let fixture = Fixture::start().await;
    let plan = plan();
    let script = render_shell(&plan);
    fixture.set_exec_response(&script, 0, "applied\n");
    fixture.set_exec_response(&check(&plan, "rate").command, 0, "ok\n");
    fixture.set_exec_response(
        &check(&plan, "qdisc").command,
        0,
        "qdisc fq_codel 9: dev eth0 root\n",
    );
    fixture.set_exec_response("/etc/init.d/sqm enabled && echo yes", 0, "yes\n");

    let session = connected(&fixture).await;
    let outcome = apply_plan(&session, &plan).await.expect("apply");

    assert!(outcome.applied, "the script itself succeeded");
    assert!(!outcome.fully_verified(), "the cake check must fail");
    let failed = outcome
        .verification
        .iter()
        .find(|v| !v.passed)
        .expect("one failed check");
    assert_eq!(failed.description, "qdisc active on the shaped device");
    drop(session);
}

#[tokio::test]
async fn verification_nonzero_exit_fails_the_check() {
    let fixture = Fixture::start().await;
    let plan = plan();
    let script = render_shell(&plan);
    fixture.set_exec_response(&script, 0, "applied\n");
    fixture.set_exec_response(&check(&plan, "rate").command, 1, "");
    fixture.set_exec_response(
        &check(&plan, "qdisc").command,
        0,
        "qdisc cake 1: dev eth0 root\n",
    );
    fixture.set_exec_response("/etc/init.d/sqm enabled && echo yes", 0, "yes\n");

    let session = connected(&fixture).await;
    let outcome = apply_plan(&session, &plan).await.expect("apply");

    assert!(outcome.applied);
    assert!(!outcome.fully_verified());
    assert!(
        !outcome.verification[0].passed,
        "exit 1 must fail the check"
    );
    drop(session);
}
