//! Ring-1 tests for plan execution: apply (single-script exec) + read-only
//! verification loop, against the in-process SSH fixture.

#[path = "common/mod.rs"]
mod common;

use common::{FIXTURE_PASSWORD, Fixture};
use conwrt_core::plan::{Profile, SqmProfile, VerificationCheck, plan_profile};
use conwrt_core::ssh::{MemoryTrustStore, TrustMode};
use conwrt_core::state::DeviceState;
use conwrt_local_std::execute::{apply_plan, render_apply_script};
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
    let script = render_apply_script(&plan);
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
    let script = render_apply_script(&plan);
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
    let script = render_apply_script(&plan);
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
    let script = render_apply_script(&plan);
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

/// #427: the executor reverts every committed config's staged baseline
/// before the first mutation, independent of plan-level RevertUci ops.
#[test]
fn apply_script_reverts_every_committed_config_before_mutations() {
    use conwrt_core::plan::{WireguardClientProfile, render_shell};
    let model = conwrt_types::DeviceModel {
        id: "t".into(),
        vendor: "T".into(),
        description: "d".into(),
        openwrt: conwrt_types::OpenwrtInfo {
            target: "x/y".into(),
            device: "t,d".into(),
            profile: "t_d".into(),
            version: "24".into(),
            board_name: None,
            board_names: None,
            default_ip: None,
            extras: Default::default(),
        },
        capabilities: None,
        flash_methods: None,
        mac_oui: Vec::new(),
        serial_console: None,
        warnings: None,
        extras: Default::default(),
    };
    let plan = plan_profile(
        &conwrt_core::state::DeviceState::OpenWrt,
        &model,
        &Profile::WireguardClient(WireguardClientProfile {
            peer_public_key: "K".into(),
            endpoint_host: "vpn.example.com".into(),
            ..WireguardClientProfile::default()
        }),
    )
    .expect("plan");
    let script = render_apply_script(&plan);
    let rev_net = script
        .find("uci -q revert network")
        .expect("revert network");
    let rev_fw = script
        .find("uci -q revert firewall")
        .expect("revert firewall");
    let first_mutation = render_shell(&plan)
        .find("uci set network.wg0=interface")
        .expect("mutation");
    assert!(rev_net < first_mutation && rev_fw < first_mutation);
    // distinct configs, first-occurrence order, no duplicates
    assert!(rev_net < rev_fw);
    assert_eq!(script.matches("uci -q revert network").count(), 1);
}

/// #427 + Codex #446 P1-1: tether-style plans embed `uci commit` inside
/// verbatim Shell payloads — the revert preamble must see those too.
#[test]
fn apply_script_reverts_configs_committed_inside_shell_ops() {
    use conwrt_core::plan::Plan;
    let plan = Plan {
        profile_id: "shell-commits".into(),
        model_id: "t".into(),
        ops: vec![
            conwrt_core::plan::PlanOp::Shell {
                command: "uci set network.usbwan=interface; \
                          uci commit network; \
                          uci add_list firewall.z.network='usbwan'; \
                          uci commit firewall"
                    .into(),
            },
            conwrt_core::plan::PlanOp::CommitUci {
                config: "wireless".into(),
            },
        ],
        verification: vec![],
    };
    let script = render_apply_script(&plan);
    let rev_net = script
        .find("uci -q revert network")
        .expect("revert network");
    let rev_fw = script
        .find("uci -q revert firewall")
        .expect("revert firewall");
    let rev_wl = script
        .find("uci -q revert wireless")
        .expect("revert wireless");
    let mutation = script
        .find("uci set network.usbwan=interface")
        .expect("mutation");
    assert!(rev_net < mutation && rev_fw < mutation && rev_wl < mutation);
}

// --- #555 deadman/recovery-window tests ---------------------------------

use conwrt_core::plan::{Plan, PlanOp, ServiceAction};
use conwrt_local_std::execute::{apply_plan_with_recovery, deadman_cancel_cmd};

fn network_restart_plan() -> conwrt_core::plan::Plan {
    Plan {
        profile_id: "deadman-probe".into(),
        model_id: "test".into(),
        ops: vec![
            PlanOp::Shell {
                command: "uci set network.deadman_probe=interface; uci commit network".into(),
            },
            PlanOp::Service {
                name: "network".into(),
                action: ServiceAction::Restart,
            },
        ],
        verification: vec![VerificationCheck {
            description: "probe marker".into(),
            command: "cat /tmp/deadman-probe".into(),
            expect_contains: "applied".into(),
        }],
    }
}

/// A plan that never restarts networking must NOT pay the deadman tax.
#[test]
fn deadman_not_armed_for_non_network_plan() {
    let script = render_apply_script(&plan());
    assert!(
        !script.contains("conwrt-deadman"),
        "sqm plan arms no deadman:\n{script}"
    );
}

/// The typed `Service { network, Restart }` op arms: snapshots exactly the
/// committed configs, after the #427 revert preamble, before the first
/// mutation, with a detached cancel-poll revert script.
#[test]
fn deadman_armed_for_service_network_restart() {
    let plan = network_restart_plan();
    let script = render_apply_script(&plan);
    let arm = script.find("# --- deadman").expect("arm block present");
    let revert = script.find("uci -q revert network").expect("#427 preamble");
    let mutation = script
        .find("uci set network.deadman_probe=interface")
        .expect("mutation");
    assert!(revert < arm, "arm comes after the revert preamble");
    assert!(arm < mutation, "arm comes before the first mutation");
    assert!(script.contains("uci -q export network > \"$DM_DIR/snapshots/network.uci\""));
    assert!(
        !script.contains("snapshots/firewall.uci\" 2>/dev/null\nuci -q export firewall"),
        "only committed configs are snapshotted"
    );
    assert!(script.contains("setsid \"$DM_DIR/revert.sh\""));
    assert!(script.contains("CONWRT_DM_EOF"));
    // the device-side poll honors the cancel flag for the whole window
    assert!(script.contains("[ -e \"$DM_DIR/cancel\" ] && exit 0"));
}

/// The verbatim escape hatch (`/etc/init.d/network restart` inside a
/// Shell payload) arms too — same dual-scan shape as #427.
#[test]
fn deadman_armed_for_shell_embedded_network_restart() {
    let plan = Plan {
        profile_id: "shell-restart".into(),
        model_id: "test".into(),
        ops: vec![PlanOp::Shell {
            command: "uci commit network; /etc/init.d/network restart".into(),
        }],
        verification: vec![],
    };
    let script = render_apply_script(&plan);
    assert!(
        script.contains("# --- deadman"),
        "shell-embedded restart arms"
    );
}

/// The explicit-window render arms the DEVICE with the caller's window —
/// recovery loop and deadman must share one window, else the executor
/// reports "expired, reverting" while the device still waits (observed
/// ring-2: 8s recovery vs 300s device arm, revert never observed).
#[test]
fn windowed_render_arms_device_with_the_same_window() {
    let plan = network_restart_plan();
    let script = conwrt_local_std::execute::render_apply_script_windowed(&plan, 8);
    assert!(script.contains("within 8s"), "arm names the 8s window");
    assert!(
        !script.contains("within 300s"),
        "no env-default window leaks into the windowed render"
    );
}

/// A verified-good apply cancels the armed deadman on the device.
#[tokio::test]
async fn deadman_cancelled_after_verified_apply() {
    let fixture = Fixture::start().await;
    let plan = network_restart_plan();
    let script = render_apply_script(&plan);
    fixture.set_exec_response(&script, 0, "");
    fixture.set_exec_response("cat /tmp/deadman-probe", 0, "applied\n");
    fixture.set_exec_response(&deadman_cancel_cmd(), 0, "deadman-cancelled\n");

    let session = connected(&fixture).await;
    let outcome = apply_plan(&session, &plan).await.expect("apply");
    assert!(outcome.fully_verified());
    assert!(outcome.deadman_armed);
    assert!(outcome.deadman_cancelled, "cancel was sent and confirmed");
    assert!(!outcome.channel_lost);
    drop(session);
}

/// Channel closed before an exit status, no reconnect path: the outcome is
/// fate-unknown (never a clean failure), the deadman stays armed.
#[tokio::test]
async fn channel_drop_without_exit_status_is_fate_unknown() {
    let fixture = Fixture::start().await;
    let plan = network_restart_plan();
    let script = render_apply_script(&plan);
    fixture.set_exec_drop(&script);

    let session = connected(&fixture).await;
    let outcome = apply_plan(&session, &plan)
        .await
        .expect("still data, not error");
    assert!(!outcome.applied);
    assert!(outcome.channel_lost);
    assert!(outcome.deadman_armed);
    assert!(!outcome.deadman_cancelled);
    assert!(
        outcome.stderr.contains("deadman armed"),
        "{}",
        outcome.stderr
    );
    drop(session);
}

/// The #555 recovery path: channel dies mid-script → immediate reconnect →
/// verification passes on the reconnected session → deadman cancelled,
/// outcome reports the recovery with the evidence.
#[tokio::test]
async fn recovery_verifies_and_cancels_after_channel_loss() {
    let fixture = Fixture::start().await;
    let plan = network_restart_plan();
    let script = render_apply_script(&plan);
    fixture.set_exec_drop(&script);
    fixture.set_exec_response("cat /tmp/deadman-probe", 0, "applied\n");
    fixture.set_exec_response(&deadman_cancel_cmd(), 0, "deadman-cancelled\n");

    let session = connected(&fixture).await;
    let addr = fixture.addr.clone();
    let reconnect = move || {
        let addr = addr.clone();
        async move {
            let target = SshTarget {
                addr,
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
        }
    };
    let outcome = apply_plan_with_recovery(&session, &plan, reconnect)
        .await
        .expect("recovery succeeds");
    assert!(outcome.applied, "verified good on the live device");
    assert!(outcome.fully_verified());
    assert!(outcome.channel_lost);
    assert!(outcome.deadman_cancelled);
    assert!(outcome.stderr.contains("reconnected within the window"));
    drop(session);
}

/// Window exhausted with the device never coming back: the error names the
/// revert the device will perform — the defined recovery entry.
#[tokio::test]
async fn recovery_window_expiry_names_the_revert() {
    let fixture = Fixture::start().await;
    let plan = network_restart_plan();
    // the drop fixture matches the script VERBATIM — stage the same
    // window the windowed apply renders, or the channel never drops
    let script = conwrt_local_std::execute::render_apply_script_windowed(&plan, 2);
    fixture.set_exec_drop(&script);

    let session = connected(&fixture).await;
    let err = conwrt_local_std::execute::apply_plan_with_recovery_windowed(
        &session,
        &plan,
        || async {
            Err(conwrt_local_std::ssh::SshError::Transport(
                "device dark".into(),
            ))
        },
        2,
        1,
    )
    .await
    .expect_err("window must expire");
    let msg = err.to_string();
    assert!(msg.contains("deadman armed"), "{msg}");
    assert!(msg.contains("2s window expires"), "{msg}");
    drop(session);
}
