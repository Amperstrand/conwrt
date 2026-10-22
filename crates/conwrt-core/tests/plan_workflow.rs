//! Desired-state planning workflow tests (#113 minimal slice): the planner
//! composes with `diagnose`, is provably I/O-free, and refuses to plan for
//! devices without a confirmed OpenWrt identity.

use conwrt_core::mock::{MockProber, NamedScenario};
use conwrt_core::plan::{
    DohProfile, PlanOp, Profile, ServiceAction, SqmProfile, UciValue, Unsupported, render_shell,
};
use conwrt_core::{DeviceState, diagnose, plan_profile};
use core::net::IpAddr;

fn model() -> conwrt_types::DeviceModel {
    serde_json::from_str(
        "{\"id\":\"glinet-gl-ar150\",\"vendor\":\"GL.iNet\",\"description\":\"AR150\",\
          \"openwrt\":{\"target\":\"ath79/generic\",\"device\":\"glinet,gl-ar150\",\
          \"profile\":\"glinet_gl-ar150\",\"version\":\"24\",\"default_ip\":\"192.168.8.1\"},\
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

fn target() -> IpAddr {
    IpAddr::from([192, 168, 8, 1])
}

#[test]
fn sqm_plan_ops_are_typed_and_ordered() {
    let model = model();
    let plan = plan_profile(&DeviceState::OpenWrt, &model, &Profile::Sqm(sqm()))
        .expect("confirmed OpenWrt plans fine");

    assert_eq!(plan.profile_id, "sqm");
    assert_eq!(plan.model_id, "glinet-gl-ar150");

    let kinds: Vec<&str> = plan
        .ops
        .iter()
        .map(|op| match op {
            PlanOp::EnsurePackage { .. } => "package",
            PlanOp::RevertUci { .. } => "revert",
            PlanOp::ClearUciSections { .. } => "clear",
            PlanOp::ResolveNetworkDevice { .. } => "resolve",
            PlanOp::SetUciSection { .. } => "section",
            PlanOp::SetUciOptions { .. } => "options",
            PlanOp::UciDeleteOption { .. } => "delete-option",
            PlanOp::UciAddList { .. } => "add-list",
            PlanOp::ResetUciConfig { .. } => "reset-config",
            PlanOp::CleanupUciSections { .. } => "cleanup",
            PlanOp::CommitUci { .. } => "commit",
            PlanOp::Service { .. } => "service",
            PlanOp::Shell { .. } => "shell",
        })
        .collect();
    assert_eq!(
        kinds,
        [
            "package", "package", "shell", "shell", "shell", "shell", "options", "commit",
            "service", "service", "shell"
        ]
    );

    let names: Vec<&str> = plan
        .ops
        .iter()
        .filter_map(|op| match op {
            PlanOp::EnsurePackage { name } => Some(name.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(names, ["sqm-scripts", "luci-app-sqm"]);

    // The shell ops mirror the 1.x builder's raw ShellCommands op-for-op:
    // clear loop, `_sqm_dev` resolution, section creation, then the
    // interface line pointing at the resolved device (1.x `wan` lesson).
    let shells: Vec<&str> = plan
        .ops
        .iter()
        .filter_map(|op| match op {
            PlanOp::Shell { command } => Some(command.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        shells[0],
        "for _s in $(uci -q show sqm 2>/dev/null | grep '=queue' | cut -d. -f2 | cut -d= -f1); do uci -q delete sqm.$_s; done; true"
    );
    assert!(shells[1].starts_with("_sqm_dev=$(uci get network.wan.device 2>/dev/null);"));
    assert_eq!(shells[2], "uci set sqm.wan=queue");
    assert_eq!(shells[3], "uci set sqm.wan.interface=\"$_sqm_dev\"");
    assert_eq!(
        shells[4],
        "echo \"SQM configured: 340000/19000 kbit/s (cake) on $_sqm_dev\""
    );

    let section = plan.ops.iter().find_map(|op| match op {
        PlanOp::SetUciOptions { options, .. } => Some(options),
        _ => None,
    });
    let options = section.expect("plan sets the sqm queue options");
    let get = |key: &str| {
        options
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("option {key} missing"))
    };
    assert_eq!(get("download"), UciValue::Literal("340000".into()));
    assert_eq!(get("upload"), UciValue::Literal("19000".into()));
    // 1.x option order: enabled first — interface is the separate shell
    // line emitted directly after section creation, before these values.
    assert_eq!(options.first().map(|(k, _)| k.as_str()), Some("enabled"));

    let services: Vec<(String, ServiceAction)> = plan
        .ops
        .iter()
        .filter_map(|op| match op {
            PlanOp::Service { name, action } => Some((name.clone(), *action)),
            _ => None,
        })
        .collect();
    assert_eq!(
        services,
        [
            ("sqm".into(), ServiceAction::Enable),
            ("sqm".into(), ServiceAction::Restart)
        ]
    );
    assert_eq!(plan.verification.len(), 3);
}

#[test]
fn planning_is_pure_over_a_recorded_provider() {
    let target = target();
    let mut prober = MockProber::responding(target, NamedScenario::OpenWrt);
    let models = vec![model()];
    let diagnosis = pollster::block_on(diagnose(&mut prober, target, &models)).unwrap();

    let calls_after_diagnose = prober.calls().len();
    assert!(calls_after_diagnose > 0, "diagnose exercised capabilities");

    let plan = plan_profile(&diagnosis.state, &models[0], &Profile::Sqm(sqm()))
        .expect("plans for OpenWrt");
    assert!(!plan.ops.is_empty());
    assert_eq!(
        prober.calls().len(),
        calls_after_diagnose,
        "planning must not touch the provider (dry-run purity)"
    );
}

#[test]
fn unconfirmed_states_never_get_plans() {
    let model = model();
    for state in [
        DeviceState::SshOnly,
        DeviceState::StockVendor,
        DeviceState::UbootRecovery,
        DeviceState::Off,
        DeviceState::Unreachable,
        DeviceState::Unknown,
    ] {
        let refusal = plan_profile(&state, &model, &Profile::Sqm(sqm())).expect_err("must refuse");
        assert_eq!(
            refusal,
            Unsupported::UnconfirmedDeviceState(state),
            "state {state:?}"
        );
    }
}

#[test]
fn ssh_only_scenario_end_to_end_is_refused() {
    let target = target();
    let mut prober = MockProber::responding(target, NamedScenario::SshOnly);
    let models = vec![model()];
    let diagnosis = pollster::block_on(diagnose(&mut prober, target, &models)).unwrap();
    assert_eq!(diagnosis.state, DeviceState::SshOnly);
    match plan_profile(&diagnosis.state, &models[0], &Profile::Sqm(sqm())) {
        Err(Unsupported::UnconfirmedDeviceState(DeviceState::SshOnly)) => {}
        other => panic!("expected SshOnly refusal, got {other:?}"),
    }
}

#[test]
fn invalid_params_are_rejected_before_any_ops() {
    let model = model();
    let bad = SqmProfile {
        download_kbps: 0,
        ..sqm()
    };
    assert_eq!(
        plan_profile(&DeviceState::OpenWrt, &model, &Profile::Sqm(bad)),
        Err(Unsupported::InvalidParams(
            "download_kbps must be ≥ 1".into()
        ))
    );
}

fn doh() -> DohProfile {
    DohProfile {
        provider: "quad9".into(),
        listen_port: 5053,
    }
}

#[test]
fn doh_plan_ports_1x_semantics() {
    let model = model();
    let plan = plan_profile(&DeviceState::OpenWrt, &model, &Profile::Doh(doh())).expect("plans");
    assert_eq!(plan.profile_id, "doh");

    let script = render_shell(&plan);
    assert!(script.contains("opkg install 'https-dns-proxy'"));
    assert!(script.contains("uci -q delete https-dns-proxy >/dev/null 2>&1 || true"));
    assert!(script.contains("uci set https-dns-proxy.main=https_dns_proxy"));
    assert!(
        script.contains(
            "uci set https-dns-proxy.main.resolver_url='https://dns.quad9.net/dns-query'"
        )
    );
    assert!(script.contains("uci set https-dns-proxy.main.listen_port='5053'"));
    assert!(script.contains("uci set dhcp.@dnsmasq[0].noresolv='1'"));
    assert!(script.contains("uci -q delete dhcp.@dnsmasq[0].server || true"));
    assert!(script.contains("uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#5053'"));
    assert!(script.contains("uci commit dhcp"));
    assert!(script.contains("/etc/init.d/dnsmasq restart"));
    assert_eq!(plan.verification.len(), 3);
}

#[test]
fn doh_custom_url_must_be_https() {
    let model = model();
    let bad = DohProfile {
        provider: "http://insecure.example/dns-query".into(),
        listen_port: 5053,
    };
    assert!(matches!(
        plan_profile(&DeviceState::OpenWrt, &model, &Profile::Doh(bad)),
        Err(Unsupported::InvalidParams(_))
    ));
}

#[test]
fn doh_unconfirmed_state_refused_like_sqm() {
    let model = model();
    assert_eq!(
        plan_profile(&DeviceState::SshOnly, &model, &Profile::Doh(doh())),
        Err(Unsupported::UnconfirmedDeviceState(DeviceState::SshOnly))
    );
}
