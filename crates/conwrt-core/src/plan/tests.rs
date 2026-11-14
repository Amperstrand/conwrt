use super::*;

fn model_with_capabilities(caps: Option<Vec<String>>) -> DeviceModel {
    let caps_json = caps.map(|c| {
        let list: Vec<String> = c.iter().map(|c| format!("\"{c}\"")).collect();
        format!(", \"capabilities\": [{}]", list.join(", "))
    });
    let json = format!(
        "{{\"id\":\"test-model\",\"vendor\":\"Test\",\"description\":\"d\",\
              \"openwrt\":{{\"target\":\"x/y\",\"device\":\"t,d\",\"profile\":\"t_d\",\"version\":\"25.12.6\"}},\
              \"mac_oui\":[]{}}}",
        caps_json.unwrap_or_default()
    );
    serde_json::from_str(&json).expect("fixture model parses")
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

#[test]
fn openwrt_24x_models_get_deprecation_warning_not_refusal() {
    let v24 = model_with_version("24.10.2");
    let plan = plan_profile(
        &DeviceState::OpenWrt,
        &v24,
        &Profile::Sqm(test_sqm_defaults()),
    )
    .expect("24.x plans — policy is warn, not refuse");
    assert_eq!(plan.warnings.len(), 1);
    assert!(plan.warnings[0].contains("24.x"));
    assert!(plan.warnings[0].contains("CVE-2026-98432"));
    // and the warning renders as a comment, never a command
    let script = render_shell(&plan);
    assert!(script.contains("# WARNING: OpenWrt 24.x"));
    let command = script
        .lines()
        .find(|l| l.trim_start().starts_with("WARNING") && !l.starts_with('#'));
    assert!(
        command.is_none(),
        "warning must render as a comment line only"
    );
    // 25.12 models: no warning
    let v25 = model_with_version("25.12.6");
    let clean = plan_profile(
        &DeviceState::OpenWrt,
        &v25,
        &Profile::Sqm(test_sqm_defaults()),
    )
    .expect("plans");
    assert!(clean.warnings.is_empty());
}

#[test]
fn live_release_overrides_stale_model_version() {
    let mp = || {
        Profile::MptcpBonding(MptcpBondingProfile {
            server_ipv4: "203.0.113.7".into(),
            server_port: 16384,
            uuid: "u".into(),
        })
    };
    let v24_model = model_with_version("24.10.2");
    // device sysupgraded under a stale `24.10.2` model: the
    // authenticated 25.12.6 release wins — plans, no warning
    let plan = plan_profile_for_device(&DeviceState::OpenWrt, &v24_model, &mp(), Some("25.12.6"))
        .expect("live release wins over the stale model claim");
    assert!(plan.warnings.is_empty());
    // and the reverse: a model claiming 25.12 on a device actually
    // running 24.10 is judged by reality — refused + (via the
    // model path) would warn
    assert!(matches!(
        plan_profile_for_device(
            &DeviceState::OpenWrt,
            &model_with_version("25.12.6"),
            &mp(),
            Some("24.10.2")
        ),
        Err(Unsupported::OpenWrtTooOld { .. })
    ));
    // unparseable live release falls back to the model claim
    assert!(
        plan_profile_for_device(
            &DeviceState::OpenWrt,
            &model_with_version("25.12.6"),
            &mp(),
            Some("local-build-2026")
        )
        .is_ok()
    );
    // None = offline planning, model claim governs
    assert!(matches!(
        plan_profile_for_device(&DeviceState::OpenWrt, &v24_model, &mp(), None),
        Err(Unsupported::OpenWrtTooOld { .. })
    ));
}

#[test]
fn mptcp_bonding_requires_25_12_floor() {
    // 24.10 model: hard refusal with both versions in the error
    let v2410 = model_with_version("24.10.2");
    let refused = plan_profile(
        &DeviceState::OpenWrt,
        &v2410,
        &Profile::MptcpBonding(MptcpBondingProfile {
            server_ipv4: "203.0.113.7".into(),
            server_port: 16384,
            uuid: "0f0e0d0c-0b0a-4909-8807-060504030201".into(),
        }),
    );
    match refused {
        Err(Unsupported::OpenWrtTooOld { have, need }) => {
            assert_eq!((have.as_str(), need.as_str()), ("24.10.2", "25.12"));
        }
        other => panic!("expected OpenWrtTooOld, got {other:?}"),
    }
    // 25.0-era minor below floor also refuses; 25.12+ and bare `25`
    // (minor unknown → cannot judge) pass
    assert!(matches!(
        plan_profile(
            &DeviceState::OpenWrt,
            &model_with_version("25.6.1"),
            &Profile::MptcpBonding(MptcpBondingProfile {
                server_ipv4: "203.0.113.7".into(),
                server_port: 16384,
                uuid: "u".into(),
            })
        ),
        Err(Unsupported::OpenWrtTooOld { .. })
    ));
    for ok_version in ["25.12.6", "25", "snapshot"] {
        assert!(
            plan_profile(
                &DeviceState::OpenWrt,
                &model_with_version(ok_version),
                &Profile::MptcpBonding(MptcpBondingProfile {
                    server_ipv4: "203.0.113.7".into(),
                    server_port: 16384,
                    uuid: "u".into(),
                })
            )
            .is_ok(),
            "{ok_version} must plan"
        );
    }
}

#[test]
fn mptcp_verification_includes_cve_2026_98432_kernel_floor() {
    let plan = plan_profile(
        &DeviceState::OpenWrt,
        &model_with_capabilities(None),
        &Profile::MptcpBonding(MptcpBondingProfile {
            server_ipv4: "203.0.113.7".into(),
            server_port: 16384,
            uuid: "u".into(),
        }),
    )
    .expect("plans");
    let cve = plan
        .verification
        .iter()
        .find(|c| c.description.contains("CVE-2026-98432"))
        .expect("CVE kernel-floor check");
    assert!(cve.description.contains("6.12.113"));
    assert!(cve.command.contains("uname -r"));
    // the encoded floor: awk major>6 || (6, >12 || 12 && >=113)
    assert!(cve.command.contains("a[2]==12 && a[3]>=113"));
    assert_eq!(cve.expect_contains, "patched");
}

fn model_with_version(version: &str) -> DeviceModel {
    let json = format!(
        "{{\"id\":\"test-model\",\"vendor\":\"Test\",\"description\":\"d\",\
              \"openwrt\":{{\"target\":\"x/y\",\"device\":\"t,d\",\"profile\":\"t_d\",\"version\":\"{version}\"}},\
              \"mac_oui\":[]}}"
    );
    serde_json::from_str(&json).expect("fixture model parses")
}

#[test]
fn capabilities_gate_rejects_missing_tag() {
    let model = model_with_capabilities(Some(vec!["ethernet".into()]));
    assert!(capabilities_satisfied(&model, &["usb"]).is_err());
    let full = model_with_capabilities(Some(vec!["ethernet".into(), "usb".into()]));
    assert!(capabilities_satisfied(&full, &["usb"]).is_ok());
    let none = model_with_capabilities(None);
    assert!(capabilities_satisfied(&none, &[]).is_ok());
}

#[test]
fn param_bounds_match_1x() {
    assert!(sqm().validate().is_ok());
    // Codex P2 on #127: a hyphenated alias is fine as a device name but
    // not as the `sqm.$INTERFACE` UCI section id — rpcd rejects it.
    {
        let mut s = sqm();
        s.interface = "wan-backup".into();
        assert!(s.validate().is_err());
    }
    // Codex P2 on #127: unsupported/empty qdisc must fail at plan time,
    // not device-side after apply.
    {
        let mut s = sqm();
        s.qdisc = "hfsc".into();
        assert!(s.validate().is_err());
        let mut s2 = sqm();
        s2.qdisc = String::new();
        assert!(s2.validate().is_err());
    }
    assert!(matches!(
        SqmProfile {
            download_kbps: 0,
            ..sqm()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    assert!(matches!(
        SqmProfile {
            upload_kbps: 0,
            ..sqm()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    assert!(matches!(
        SqmProfile {
            overhead: 513,
            ..sqm()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    assert!(matches!(
        SqmProfile {
            interface: "eth0; rm -rf /".into(),
            ..sqm()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
}

#[test]
fn render_shell_matches_1x_conventions() {
    let model = model_with_capabilities(None);
    let plan = plan_profile(
        &DeviceState::OpenWrt,
        &model,
        &Profile::Sqm(SqmProfile {
            download_kbps: 340_000,
            upload_kbps: 19_000,
            ..test_sqm_defaults()
        }),
    )
    .expect("plans");
    let script = render_shell(&plan);
    assert!(script.starts_with("#!/bin/sh\n"));
    assert!(script.contains("set -e"));
    // package install covers both package managers; the opkg branch
    // must skip the (offline-failing) update for installed packages
    assert!(
        script.contains(
            "if command -v apk >/dev/null 2>&1; then apk add 'sqm-scripts' || { apk update"
        )
    );
    assert!(script.contains("opkg list-installed 'sqm-scripts' 2>/dev/null"));
    assert!(script.contains("|| { opkg update && opkg install 'sqm-scripts'; }; fi"));
    // clear-sections idiom, 1.x shape: one line, `done; true` joined
    assert!(script.contains(
            "for _s in $(uci -q show sqm 2>/dev/null | grep '=queue' | cut -d. -f2 | cut -d= -f1); do uci -q delete sqm.$_s; done; true"
        ));
    // device resolution is the 1.x one-line `_sqm_dev` idiom (not the
    // typed multi-line `_conwrt_dev_*` block), with the 2.x-only
    // `|| true` set -e guard
    assert!(script.contains(
        "_sqm_dev=$(uci get network.wan.device 2>/dev/null || true); if [ -z \"$_sqm_dev\" ]"
    ));
    assert!(script.contains("uci set sqm.wan.interface=\"$_sqm_dev\""));
    // 1.x option order: interface directly after section creation,
    // before enabled
    let interface_at = script
        .find("uci set sqm.wan.interface=")
        .expect("interface line");
    let enabled_at = script
        .find("uci set sqm.wan.enabled=")
        .expect("enabled line");
    let create_at = script.find("uci set sqm.wan=queue").expect("creation line");
    assert!(create_at < interface_at && interface_at < enabled_at);
    // single-quoted literals, 1.x convention
    assert!(script.contains("uci set sqm.wan.download='340000'"));
    assert!(script.contains("uci set sqm.wan.upload='19000'"));
    assert!(script.contains("uci commit sqm"));
    assert!(script.contains("/etc/init.d/sqm enable"));
    assert!(script.contains("/etc/init.d/sqm restart"));
    // 1.x closes with the echo summary on the resolved device
    assert!(script.contains("echo \"SQM configured: 340000/19000 kbit/s (cake) on $_sqm_dev\""));
}

#[test]
fn render_shell_quotes_hostile_literals() {
    let model = model_with_capabilities(None);
    let mut sqm = test_sqm_defaults();
    sqm.script = "evil'; rm -rf /; '".into();
    let plan = plan_profile(&DeviceState::OpenWrt, &model, &Profile::Sqm(sqm)).expect("plans");
    let script = render_shell(&plan);
    assert!(
        script.contains("uci set sqm.wan.script='evil'\''; rm -rf /; '\'''"),
        "single quotes must be escaped, not interpolated: {script}"
    );
}

#[test]
fn doh_validation_rejects_port_zero() {
    let model = model_with_capabilities(None);
    let refused = plan_profile(
        &DeviceState::OpenWrt,
        &model,
        &Profile::Doh(DohProfile {
            provider: "cloudflare".into(),
            listen_port: 0,
        }),
    );
    assert!(
        matches!(refused, Err(Unsupported::InvalidParams(_))),
        "port 0 must never plan 127.0.0.1#0"
    );
    let ok = plan_profile(
        &DeviceState::OpenWrt,
        &model,
        &Profile::Doh(DohProfile {
            provider: "cloudflare".into(),
            listen_port: 5053,
        }),
    );
    assert!(ok.is_ok());
}

#[test]
fn sqm_verification_targets_the_shaped_device_exactly() {
    let model = model_with_capabilities(None);
    let plan = plan_profile(
        &DeviceState::OpenWrt,
        &model,
        &Profile::Sqm(test_sqm_defaults()),
    )
    .expect("plans");
    let qdisc = plan
        .verification
        .iter()
        .find(|c| c.description.contains("qdisc"))
        .expect("qdisc check");
    // scoped to one resolved device, never a global `tc qdisc show`
    assert!(qdisc.command.contains("tc qdisc show dev \"$_d\""));
    assert_ne!(qdisc.command, "tc qdisc show");
    let rate = plan
        .verification
        .iter()
        .find(|c| c.description.contains("rate"))
        .expect("rate check");
    // exact equality, not a substring that 110000 would also satisfy
    assert!(
        rate.command
            .starts_with("test \"$(uci -q get sqm.wan.download)\" = '10000'")
    );
}

#[test]
fn doh_verification_uses_exact_predicates() {
    let model = model_with_capabilities(None);
    let plan = plan_profile(
        &DeviceState::OpenWrt,
        &model,
        &Profile::Doh(DohProfile {
            provider: "cloudflare".into(),
            listen_port: 5053,
        }),
    )
    .expect("plans");
    let resolver = plan
        .verification
        .iter()
        .find(|c| c.description.contains("resolver"))
        .expect("resolver check");
    assert!(
        resolver
            .command
            .starts_with("test \"$(uci -q get https-dns-proxy.main.resolver_url)\" = ")
    );
    let forward = plan
        .verification
        .iter()
        .find(|c| c.description.contains("dnsmasq"))
        .expect("forward check");
    assert!(forward.command.contains("grep -qx '127.0.0.1#5053'"));
}

#[test]
fn sqm_plan_mirrors_1x_builder_op_stream() {
    let model = model_with_capabilities(None);
    let plan = plan_profile(
        &DeviceState::OpenWrt,
        &model,
        &Profile::Sqm(test_sqm_defaults()),
    )
    .expect("plans");
    let script = render_shell(&plan);
    // 1.x has no revert step: its clear-sections loop already deletes
    // every staged AND committed queue section (uci show displays the
    // merged view) before fresh values are staged, so /tmp/.uci debris
    // cannot survive the commit.
    assert!(
        !script.contains("uci revert"),
        "1.x parity: no revert step, the clear loop is the baseline reset:\n{script}"
    );
    // clear loop precedes the first sqm mutation
    let clear_pos = script
        .find("uci -q show sqm")
        .expect("script clears sqm sections");
    let first_mutation = script.find("uci set sqm").expect("script mutates sqm");
    assert!(
        clear_pos < first_mutation,
        "clear must precede the first sqm mutation:\n{script}"
    );
    // the echo summary is the final command line of the script body
    let lines: Vec<&str> = script
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('#') && t != "set -e"
        })
        .collect();
    assert_eq!(
        lines.last(),
        Some(&"echo \"SQM configured: 10000/5000 kbit/s (cake) on $_sqm_dev\""),
        "1.x closes with the SQM summary echo"
    );
}

fn test_sqm_defaults() -> SqmProfile {
    SqmProfile {
        download_kbps: 10_000,
        upload_kbps: 5_000,
        interface: "wan".into(),
        qdisc: "cake".into(),
        script: "piece_of_cake.qos".into(),
        link_layer: "none".into(),
        overhead: 0,
    }
}

// ---- tether / wireguard-client / guest-wifi ports (parity §4) ----

fn wireguard() -> WireguardClientProfile {
    WireguardClientProfile {
        peer_public_key: "SERVERKEY".into(),
        endpoint_host: "vpn.example.com".into(),
        ..WireguardClientProfile::default()
    }
}

fn plan_for(profile: Profile) -> Plan {
    let caps = profile.requires().first().map(|cap| vec![(**cap).into()]);
    plan_profile(
        &DeviceState::OpenWrt,
        &model_with_capabilities(caps),
        &profile,
    )
    .expect("plans")
}

#[test]
fn wireguard_param_bounds_match_1x_validators() {
    assert!(wireguard().validate().is_ok());
    // validate_host: empty, junk, embedded shell metacharacters
    assert!(matches!(
        WireguardClientProfile {
            endpoint_host: String::new(),
            ..wireguard()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    assert!(matches!(
        WireguardClientProfile {
            endpoint_host: "vpn; rm -rf /".into(),
            ..wireguard()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    assert!(matches!(
        WireguardClientProfile {
            endpoint_host: "-leadingdash.example.com".into(),
            ..wireguard()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    // validate_port bounds (1-65535)
    assert!(matches!(
        WireguardClientProfile {
            endpoint_port: 0,
            ..wireguard()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    // registry required-param gate: peer_public_key
    assert!(matches!(
        WireguardClientProfile {
            peer_public_key: String::new(),
            ..wireguard()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    // IPv4 endpoints are first-class hosts (1.x _IPV4_RE branch)
    assert!(
        WireguardClientProfile {
            endpoint_host: "10.0.0.1".into(),
            ..wireguard()
        }
        .validate()
        .is_ok()
    );
}

#[test]
fn wireguard_kill_switch_branches_match_1x() {
    let on = render_shell(&plan_for(Profile::WireguardClient(wireguard())));
    assert!(on.contains("wg_client_killswitch.name='KillSwitch-Reject-NonVPN'"));
    assert!(on.contains("wg show wg0"));
    assert!(on.contains("uci delete firewall.wg_client_killswitch"));
    assert!(on.contains("fw4 restart"));

    let off = render_shell(&plan_for(Profile::WireguardClient(
        WireguardClientProfile {
            kill_switch: false,
            ..wireguard()
        },
    )));
    assert!(!off.contains("wg_client_killswitch"));
    assert!(!off.contains("wg show wg0"));
}

#[test]
fn wireguard_dns_and_psk_branches_match_1x() {
    let dns = render_shell(&plan_for(Profile::WireguardClient(
        WireguardClientProfile {
            dns: "9.9.9.9".into(),
            ..wireguard()
        },
    )));
    assert!(dns.contains("uci add_list network.wg0.dns='9.9.9.9'"));

    let no_dns = render_shell(&plan_for(Profile::WireguardClient(
        WireguardClientProfile {
            dns: String::new(),
            ..wireguard()
        },
    )));
    assert!(!no_dns.contains("uci add_list"));

    let psk = render_shell(&plan_for(Profile::WireguardClient(
        WireguardClientProfile {
            peer_psk: "my-secret-psk".into(),
            ..wireguard()
        },
    )));
    assert!(psk.contains("uci set network.wg0_peer.preshared_key='my-secret-psk'"));
}

#[test]
fn wireguard_firewall_cleanup_uses_1x_while_loop_shape() {
    let script = render_shell(&plan_for(Profile::WireguardClient(wireguard())));
    assert!(script.contains(
        "while uci show firewall 2>/dev/null | grep -q \"name='vpn'\"; do \
             _s=$(uci show firewall 2>/dev/null | grep \"name='vpn'\" \
             | head -1 | cut -d. -f2 | cut -d= -f1); \
             uci delete \"firewall.$_s\" 2>/dev/null; done; true"
    ));
    assert!(script.contains("uci set firewall.wg_client_vpn.name='vpn'"));
    assert!(script.contains("uci set firewall.wg_client_fwd.dest='vpn'"));
    assert!(script.contains("echo 'WireGuard client configured: vpn.example.com:51820'"));
}

// ---- cashu-vpn-client port (1.x `cashu_vpn_client.py`, experimental) ----

fn cashu_vpn() -> CashuVpnClientProfile {
    CashuVpnClientProfile {
        peer_public_key: "EXITKEY".into(),
        peer_ip: "10.66.42.2/32".into(),
        server_host: "vpn.example.com".into(),
        ..CashuVpnClientProfile::default()
    }
}

#[test]
fn cashu_vpn_param_bounds_match_1x_required_gates() {
    assert!(cashu_vpn().validate().is_ok());
    assert!(matches!(
        CashuVpnClientProfile {
            peer_public_key: String::new(),
            ..cashu_vpn()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    assert!(matches!(
        CashuVpnClientProfile {
            peer_ip: "10.66.42.2".into(),
            ..cashu_vpn()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    assert!(matches!(
        CashuVpnClientProfile {
            peer_ip: String::new(),
            ..cashu_vpn()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    assert!(matches!(
        CashuVpnClientProfile {
            server_host: String::new(),
            ..cashu_vpn()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    assert!(matches!(
        CashuVpnClientProfile {
            server_host: "vpn; rm -rf /".into(),
            ..cashu_vpn()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    assert!(matches!(
        CashuVpnClientProfile {
            server_port: 0,
            ..cashu_vpn()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
}

#[test]
fn cashu_vpn_requires_ethernet_capability() {
    let missing = model_with_capabilities(Some(vec!["wifi".into()]));
    let refusal = plan_profile(
        &DeviceState::OpenWrt,
        &missing,
        &Profile::CashuVpnClient(cashu_vpn()),
    );
    assert!(matches!(
        refusal,
        Err(Unsupported::MissingCapability { .. })
    ));
    let plan = plan_for(Profile::CashuVpnClient(cashu_vpn()));
    assert_eq!(plan.profile_id, "cashu-vpn-client");
}

#[test]
fn cashu_vpn_render_matches_1x_shape() {
    let script = render_shell(&plan_for(Profile::CashuVpnClient(cashu_vpn())));
    assert!(script.contains("kmod-wireguard"));
    assert!(script.contains("wireguard-tools"));
    assert!(script.contains("uci set network.wg0.addresses='10.66.42.2/32'"));
    assert!(script.contains("uci add_list network.wg0.dns='1.1.1.1'"));
    assert!(script.contains("uci set network.wg0_peer.public_key='EXITKEY'"));
    assert!(script.contains("uci set network.wg0_peer.endpoint_host='vpn.example.com'"));
    assert!(script.contains("uci set firewall.cashu_vpn_zone.name='vpn'"));
    assert!(script.contains("uci set firewall.cashu_vpn_fwd.dest='vpn'"));
    assert!(script.contains("cashu_vpn_killswitch.name='KillSwitch-Reject-NonVPN'"));
    assert!(script.contains("uci delete firewall.cashu_vpn_killswitch"));
    assert!(script.contains(
        "echo 'Cashu VPN client configured: vpn.example.com:51820 (peer_ip=10.66.42.2/32)'"
    ));
}

#[test]
fn cashu_vpn_kill_switch_and_dns_branches() {
    let off = render_shell(&plan_for(Profile::CashuVpnClient(CashuVpnClientProfile {
        kill_switch: false,
        ..cashu_vpn()
    })));
    assert!(!off.contains("cashu_vpn_killswitch"));
    assert!(!off.contains("wg show wg0"));

    let multi_dns = render_shell(&plan_for(Profile::CashuVpnClient(CashuVpnClientProfile {
        dns: "1.1.1.1, 9.9.9.9".into(),
        ..cashu_vpn()
    })));
    assert!(multi_dns.contains("uci add_list network.wg0.dns='1.1.1.1'"));
    assert!(multi_dns.contains("uci add_list network.wg0.dns='9.9.9.9'"));

    let no_dns = render_shell(&plan_for(Profile::CashuVpnClient(CashuVpnClientProfile {
        dns: String::new(),
        ..cashu_vpn()
    })));
    assert!(!no_dns.contains("uci add_list"));
}

#[test]
fn cashu_vpn_unconfirmed_state_refused() {
    let model = model_with_capabilities(Some(vec!["ethernet".into()]));
    assert_eq!(
        plan_profile(
            &DeviceState::SshOnly,
            &model,
            &Profile::CashuVpnClient(cashu_vpn())
        ),
        Err(Unsupported::UnconfirmedDeviceState(DeviceState::SshOnly))
    );
}

#[test]
fn wireguard_server_default_render_matches_1x_shape() {
    let script = render_shell(&plan_for(Profile::WireguardServer(
        WireguardServerProfile {
            private_key: "test_key_12345".into(),
            ..WireguardServerProfile::default()
        },
    )));
    assert!(script.contains("uci set network.wg0=interface"));
    assert!(script.contains("uci set network.wg0.proto='wireguard'"));
    assert!(script.contains("uci set network.wg0.private_key='test_key_12345'"));
    assert!(script.contains("uci set network.wg0.listen_port='51820'"));
    assert!(script.contains("uci add_list network.wg0.addresses='10.1.99.1/24'"));
    assert!(script.contains(
        "mkdir -p /etc/wireguard && \
                             wg show wg0 public-key > /etc/wireguard/server_public_key \
                             2>/dev/null || true"
    ));
    assert!(script.contains("uci commit network"));
    assert!(script.contains("uci commit firewall"));
    assert!(
        !script.contains("wg0_peer1"),
        "no peer by default (1.x branch)"
    );
}

#[test]
fn wireguard_server_custom_params_match_1x_shape() {
    let script = render_shell(&plan_for(Profile::WireguardServer(
        WireguardServerProfile {
            private_key: "abc123".into(),
            listen_port: 12_345,
            subnet: "172.16.0.1/16".into(),
            ..WireguardServerProfile::default()
        },
    )));
    assert!(script.contains("uci set network.wg0.listen_port='12345'"));
    assert!(script.contains("uci add_list network.wg0.addresses='172.16.0.1/16'"));
    assert!(script.contains("uci set firewall.wg_server_allow.dest_port='12345'"));
    assert!(
        script.contains("echo \"WireGuard server configured: port 12345, subnet 172.16.0.1/16\"")
    );
}

#[test]
fn wireguard_server_peer_and_psk_branches_match_1x() {
    let with_peer = render_shell(&plan_for(Profile::WireguardServer(
        WireguardServerProfile {
            private_key: "server_key".into(),
            peer1_public_key: "peer_pub_key".into(),
            peer1_allowed_ips: "10.1.99.2/32".into(),
            ..WireguardServerProfile::default()
        },
    )));
    assert!(with_peer.contains("uci set network.wg0_peer1=wireguard_wg0"));
    assert!(with_peer.contains("uci set network.wg0_peer1.public_key='peer_pub_key'"));
    assert!(with_peer.contains("uci set network.wg0_peer1.allowed_ips='10.1.99.2/32'"));
    assert!(with_peer.contains("uci set network.wg0_peer1.route_allowed_ips='1'"));
    assert!(!with_peer.contains("preshared_key"));

    let with_psk = render_shell(&plan_for(Profile::WireguardServer(
        WireguardServerProfile {
            private_key: "server_key".into(),
            peer1_public_key: "peer_pub_key".into(),
            peer1_psk: "shared_secret_key".into(),
            ..WireguardServerProfile::default()
        },
    )));
    assert!(with_psk.contains("uci set network.wg0_peer1.preshared_key='shared_secret_key'"));
    assert!(
        with_psk
            .find("route_allowed_ips")
            .zip(with_psk.find("preshared_key"))
            .is_some_and(|(route, psk)| route < psk),
        "psk renders last (1.x dict insertion order)"
    );
}

#[test]
fn wireguard_server_firewall_sections_match_1x_shape() {
    let script = render_shell(&plan_for(Profile::WireguardServer(
        WireguardServerProfile::default(),
    )));
    assert!(script.contains(
        "while uci show firewall 2>/dev/null | grep -q \"name='Allow-WireGuard'\"; do \
             _s=$(uci show firewall 2>/dev/null | grep \"name='Allow-WireGuard'\" \
             | head -1 | cut -d. -f2 | cut -d= -f1); \
             uci delete \"firewall.$_s\" 2>/dev/null; done; true"
    ));
    assert!(script.contains("uci set firewall.wg_server_vpn.name='vpn'"));
    assert!(script.contains("uci set firewall.wg_server_vpn.input='ACCEPT'"));
    assert!(script.contains("uci set firewall.wg_server_fwd_lan.dest='lan'"));
    assert!(script.contains("uci set firewall.wg_server_fwd_wan.dest='wan'"));
    assert!(script.contains("uci set firewall.wg_server_allow.src='wan'"));
    assert!(script.contains("uci set firewall.wg_server_allow.proto='udp'"));
    assert!(script.contains("/etc/init.d/network restart"));
}

#[test]
fn ssh_hardening_default_and_flipped_branches_match_1x() {
    let default_script = render_shell(&plan_for(Profile::SshHardening(
        SshHardeningProfile::default(),
    )));
    assert!(default_script.contains("uci set dropbear.@dropbear[0].PasswordAuth='off'"));
    assert!(default_script.contains("uci set dropbear.@dropbear[0].RootPasswordAuth='off'"));
    assert!(default_script.contains("uci set dropbear.@dropbear[0].Port='22'"));
    assert!(default_script.contains("uci set dropbear.@dropbear[0].IdleTimeout='300'"));
    assert!(default_script.contains("uci set dropbear.@dropbear[0].MaxAuthTries='3'"));
    assert!(default_script.contains("uci set dropbear.@dropbear[0].GatewayPorts='no'"));
    assert!(default_script.contains("uci commit dropbear"));
    assert!(default_script.contains("/etc/init.d/dropbear restart"));
    assert!(
        default_script
            .contains("echo \"SSH hardened: password_auth=off idle=300s max_tries=3 port=22\"")
    );

    let flipped = render_shell(&plan_for(Profile::SshHardening(SshHardeningProfile {
        disable_password_auth: false,
        idle_timeout: 0,
        max_auth_tries: 1,
        port: 2222,
        restrict_gateway_ports: false,
    })));
    assert!(flipped.contains("uci set dropbear.@dropbear[0].PasswordAuth='on'"));
    assert!(flipped.contains("uci set dropbear.@dropbear[0].GatewayPorts='yes'"));
    assert!(flipped.contains("uci set dropbear.@dropbear[0].IdleTimeout='0'"));
    assert!(
        flipped.contains("echo \"SSH hardened: password_auth=on idle=0s max_tries=1 port=2222\"")
    );
}

#[test]
fn travelmate_branches_and_capability_gate_match_1x() {
    let default_script = render_shell(&plan_for(Profile::Travelmate(TravelmateProfile::default())));
    assert!(default_script.contains("uci set travelmate.global.trm_enabled='1'"));
    assert!(default_script.contains("uci set travelmate.global.trm_captive='1'"));
    assert!(default_script.contains("uci set travelmate.global.trm_timeout='60'"));
    assert!(default_script.contains("uci set travelmate.global.trm_retry='5'"));
    assert!(default_script.contains("uci set travelmate.global.trm_radio='radio0'"));
    assert!(default_script.contains("uci commit travelmate"));
    assert!(default_script.contains("/etc/init.d/travelmate enable"));
    assert!(default_script.contains("/etc/init.d/travelmate restart"));
    assert!(default_script.contains("echo \"Travelmate configured: auto-connect on radio0\""));

    let flipped = render_shell(&plan_for(Profile::Travelmate(TravelmateProfile {
        radio: "radio1".into(),
        timeout: 30,
        retry: 2,
        captive: false,
        ..TravelmateProfile::default()
    })));
    assert!(flipped.contains("uci set travelmate.global.trm_captive='0'"));
    assert!(flipped.contains("uci set travelmate.global.trm_timeout='30'"));
    assert!(flipped.contains("uci set travelmate.global.trm_retry='2'"));
    assert!(flipped.contains("uci set travelmate.global.trm_radio='radio1'"));
    assert!(flipped.contains("echo \"Travelmate configured: auto-connect on radio1\""));

    // wifi capability gate (1.x requires_capabilities=["wifi"])
    let no_wifi = conwrt_types::DeviceModel {
        id: "no-wifi".into(),
        vendor: "Test".into(),
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
        capabilities: Some(vec!["ethernet".into()]),
        flash_methods: None,
        mac_oui: Vec::new(),
        serial_console: None,
        warnings: None,
        extras: Default::default(),
    };
    assert!(matches!(
        plan_profile(&DeviceState::OpenWrt, &no_wifi, &Profile::Travelmate(TravelmateProfile::default())),
        Err(Unsupported::MissingCapability { capability, .. }) if capability == "wifi"
    ));
}

#[test]
fn travelmate_uplink_seeding_renders_sta_profiles() {
    let plan = plan_for(Profile::Travelmate(TravelmateProfile {
        uplinks: vec![
            WifiUplink {
                ssid: "home-net".into(),
                psk: "hunter2 son".into(),
                encryption: "psk2".into(),
                radio: "radio1".into(),
                iface: "trm_uplink1".into(),
            },
            WifiUplink {
                ssid: "cafe open".into(),
                psk: String::new(),
                encryption: "none".into(),
                radio: "radio0".into(),
                iface: "trm_uplink2".into(),
            },
        ],
        ..TravelmateProfile::default()
    }));
    let script = render_shell(&plan);
    assert!(script.contains("uci set travelmate.global.trm_iface='trm_wwan'"));
    assert!(script.contains("uci set travelmate.global.trm_uplink='trm_wwan'"));
    assert!(script.contains("uci set network.trm_wwan=interface"));
    assert!(script.contains("uci set network.trm_wwan.proto='dhcp'"));
    assert!(script.contains("uci set network.trm_wwan.metric='100'"));
    assert!(script.contains("uci set network.trm_wwan6=interface"));
    assert!(script.contains("uci set network.trm_wwan6.device='@trm_wwan'"));
    assert!(script.contains("uci set network.trm_wwan6.proto='dhcpv6'"));
    // the 1.x wan-zone helper (del_list-then-add_list on the NAME-matched zone), both ifaces
    assert!(script.contains("uci add_list firewall.\"$_z\".network='trm_wwan'"));
    assert!(script.contains("uci add_list firewall.\"$_z\".network='trm_wwan6'"));
    assert!(script.contains("uci set wireless.trm_uplink1=wifi-iface"));
    assert!(script.contains("uci set wireless.trm_uplink1.device='radio1'"));
    assert!(script.contains("uci set wireless.trm_uplink1.mode='sta'"));
    assert!(script.contains("uci set wireless.trm_uplink1.network='trm_wwan'"));
    assert!(script.contains("uci set wireless.trm_uplink1.ssid='home-net'"));
    assert!(script.contains("uci set wireless.trm_uplink1.encryption='psk2'"));
    assert!(script.contains("uci set wireless.trm_uplink1.key='hunter2 son'"));
    // travelmate recognition pairs: uplink sections in its own config
    assert!(script.contains("uci set travelmate.trm_uplink1=uplink"));
    assert!(script.contains("uci set travelmate.trm_uplink1.device='radio1'"));
    assert!(script.contains("uci set travelmate.trm_uplink1.enabled='1'"));
    assert!(script.contains("uci set travelmate.trm_uplink2=uplink"));
    assert!(script.contains("uci set travelmate.trm_uplink2.enabled='1'"));
    // open network: no key option at all
    assert!(script.contains("uci set wireless.trm_uplink2.ssid='cafe open'"));
    assert!(script.contains("uci set wireless.trm_uplink2.encryption='none'"));
    assert!(!script.contains("trm_uplink2.key"));
    assert!(script.contains("uci commit wireless"));
    assert!(script.contains("wifi reload; ubus call network.interface.trm_wwan up"));
    // secrets stay single-quote-escaped, never interpolated raw
    let hostile = plan_for(Profile::Travelmate(TravelmateProfile {
        uplinks: vec![WifiUplink {
            ssid: "ev'; rm -rf /; '".into(),
            psk: "p'w".into(),
            encryption: "psk2".into(),
            radio: "radio0".into(),
            iface: "trm_uplink3".into(),
        }],
        ..TravelmateProfile::default()
    }));
    let hostile_script = render_shell(&hostile);
    assert!(hostile_script.contains("uci set wireless.trm_uplink3.ssid='ev'\''; rm -rf /; '\''"));
    assert!(hostile_script.contains("uci set wireless.trm_uplink3.key='p'\''w'"));
}

#[test]
fn travelmate_without_uplinks_stays_1x_shape() {
    let script = render_shell(&plan_for(Profile::Travelmate(TravelmateProfile::default())));
    assert!(!script.contains("trm_iface"));
    assert!(!script.contains("wifi-iface"));
    assert!(!script.contains("trm_wwan"));
}

#[test]
fn sqm_resolve_survives_set_e_when_wan_device_is_absent() {
    // the 2.x preamble is `set -e` (1.x runs bare); an unguarded
    // `var=$(uci get ...)` kills the whole script under `sh -c`
    // exec when the option is missing — found live via
    // `conwrt apply --execute` on a fixture VM without wan.device.
    let script = render_shell(&plan_for(Profile::Sqm(test_sqm_defaults())));
    assert!(
        script.contains("_sqm_dev=$(uci get network.wan.device 2>/dev/null || true)"),
        "resolve substitution must be set -e safe"
    );
}

#[test]
fn adguard_default_and_custom_render_match_1x_shape() {
    let script = render_shell(&plan_for(Profile::Adguard(AdguardProfile::default())));
    assert!(script.contains("uci set adguardhome.adguardhome=adguardhome"));
    assert!(script.contains("uci set adguardhome.adguardhome.enabled='1'"));
    assert!(script.contains("uci set adguardhome.adguardhome.http_address='0.0.0.0:3000'"));
    assert!(script.contains("uci set adguardhome.adguardhome.dns_port='5353'"));
    assert!(script.contains("uci commit adguardhome"));
    assert!(script.contains("/etc/init.d/adguardhome enable"));
    assert!(script.contains("/etc/init.d/adguardhome start"));
    assert!(script.contains("uci set dhcp.@dnsmasq[0].noresolv='1'"));
    assert!(script.contains("uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#5353'"));
    assert!(script.contains("uci commit dhcp"));
    assert!(script.contains("/etc/init.d/dnsmasq restart"));
    assert!(
        script
            .contains("echo \"AdGuard Home configured: DNS on port 5353, web UI at 0.0.0.0:3000\"")
    );

    let custom = render_shell(&plan_for(Profile::Adguard(AdguardProfile {
        listen_ip: "192.168.1.1".into(),
        web_port: 8080,
        dns_port: 5333,
    })));
    assert!(custom.contains("uci set adguardhome.adguardhome.http_address='192.168.1.1:8080'"));
    assert!(custom.contains("uci add_list dhcp.@dnsmasq[0].server='127.0.0.1#5333'"));
    assert!(custom.contains("web UI at 192.168.1.1:8080"));
}

#[test]
fn mesh11sd_key_branch_order_and_required_gate_match_1x() {
    let no_key = render_shell(&plan_for(Profile::Mesh11sd(Mesh11sdProfile {
        mesh_id: "testmesh".into(),
        ..Mesh11sdProfile::default()
    })));
    assert!(no_key.contains("uci set mesh11sd.setup.auto_mesh_id='testmesh'"));
    assert!(no_key.contains("uci set mesh11sd.setup.mesh_gate_base_ssid='MeshNet'"));
    assert!(no_key.contains("uci set mesh11sd.setup.mesh_gate_encryption='1'"));
    assert!(no_key.contains("uci set mesh11sd.setup.auto_config='0'"));
    assert!(!no_key.contains("mesh_gate_key"));
    assert!(no_key.contains("uci commit mesh11sd"));
    assert!(no_key.contains("service mesh11sd restart 2>/dev/null || true"));
    assert!(no_key.contains("echo \"Mesh11sd configured: mesh_id=testmesh ssid=MeshNet\""));

    let with_key = render_shell(&plan_for(Profile::Mesh11sd(Mesh11sdProfile {
        mesh_id: "m2".into(),
        ssid: "Backhaul".into(),
        encryption: "3".into(),
        key: "mesh pass".into(),
        auto_config: "2".into(),
    })));
    // 1.x dict insertion order: key BETWEEN encryption and auto_config
    let enc = with_key.find("mesh_gate_encryption='3'").expect("enc");
    let key = with_key.find("mesh_gate_key='mesh pass'").expect("key");
    let auto = with_key.find("auto_config='2'").expect("auto");
    assert!(enc < key && key < auto, "1.x option order must hold");

    // required-param gate
    assert!(matches!(
        Mesh11sdProfile::default().validate(),
        Err(Unsupported::InvalidParams(_))
    ));
}

#[test]
fn rescue_watchdog_payload_is_verbatim_with_target_substituted() {
    let script = render_shell(&plan_for(Profile::RescueWatchdog(RescueWatchdogProfile {
        target: "192.168.105.10".into(),
    })));
    assert!(script.contains("cat > /etc/init.d/rescue-watchdog << 'WD_EOF'"));
    assert!(script.contains("procd_set_param respawn 3600 5 0"));
    assert!(script.contains("TARGET=\"${WATCHDOG_TARGET:-192.168.105.10}\""));
    assert!(script.contains("[ \"$FAILS\" -ge 3 ]"));
    assert!(script.contains("/etc/init.d/rescue-watchdog enable"));
    // no unsubstituted placeholder survives
    assert!(!script.contains("__TARGET__"));
}

#[test]
fn mwan3_shape_members_policy_rules_and_track_ip_fix() {
    let script = render_shell(&plan_for(Profile::Mwan3(Mwan3Profile::default())));
    assert!(script.contains("uci -q delete mwan3 >/dev/null 2>&1 || true"));
    assert!(script.contains("uci set mwan3.wan=interface"));
    assert!(script.contains("uci set mwan3.wan.enabled='1'"));
    // the 1.x `list track_ip` defect is FIXED: real add_list ops per section
    assert!(script.contains("uci add_list mwan3.wan.track_ip='1.0.0.1'"));
    assert!(script.contains("uci add_list mwan3.usbwan.track_ip='8.8.4.4'"));
    assert!(!script.contains("list track_ip"));
    assert!(script.contains("uci set mwan3.wan.family='ipv4'"));
    assert!(script.contains("uci set mwan3.usbwan=interface"));
    // failover metrics: primary m1w1, secondary m2w1
    assert!(script.contains("uci set mwan3.wan_m1_w1=member"));
    assert!(script.contains("uci set mwan3.usbwan_m2_w1=member"));
    assert!(script.contains("uci set mwan3.wan_policy=policy"));
    assert!(script.contains("uci add_list mwan3.wan_policy.use_member='wan_m1_w1'"));
    assert!(script.contains("uci add_list mwan3.wan_policy.use_member='usbwan_m2_w1'"));
    assert!(script.contains("uci set mwan3.wan_policy.last_resort='default'"));
    assert!(script.contains("uci set mwan3.default_rule_v4=rule"));
    assert!(
        script.contains(
            "uci set mwan3.https_rule.rule"
                .replace(".rule", "=rule")
                .as_str()
        )
    );
    assert!(script.contains("uci commit mwan3"));
    assert!(script.contains("/etc/init.d/mwan3 restart"));
    assert!(script.contains("echo \"mwan3 configured: wan (primary) + usbwan (failover)\""));

    // balanced flips the metrics/weights; non-default primary gets its
    // own tracked section (1.x hardcoded `wan` — Codex #448 P1)
    let balanced = render_shell(&plan_for(Profile::Mwan3(Mwan3Profile {
        primary: "wwan2".into(),
        secondary: "wwan".into(),
        policy: "balanced".into(),
        track_ips: vec!["9.9.9.9".into()],
    })));
    assert!(balanced.contains("uci set mwan3.wwan2=interface"));
    assert!(balanced.contains("uci set mwan3.wwan2_m1_w2=member"));
    assert!(balanced.contains("uci set mwan3.wwan_m1_w1=member"));
    assert!(balanced.contains("uci add_list mwan3.wwan.track_ip='9.9.9.9'"));

    // interface_name charset gate
    assert!(matches!(
        Mwan3Profile {
            primary: "wan; rm".into(),
            ..Mwan3Profile::default()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    // policy is interpolated into the echo line — hostile values refused
    assert!(matches!(
        Mwan3Profile {
            policy: "x'; rm -rf /; '".into(),
            ..Mwan3Profile::default()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
}

#[test]
fn pbr_shape_gates_and_strict_branch_match_1x() {
    let script = render_shell(&plan_for(Profile::Pbr(PbrProfile::default())));
    assert!(script.contains("uci set pbr.config=pbr"));
    assert!(script.contains("uci set pbr.config.enabled='1'"));
    assert!(script.contains("uci set pbr.config.verbosity='2'"));
    assert!(script.contains("uci set pbr.config.strict_enforcement='1'"));
    assert!(script.contains("uci set pbr.config.resolver_set='none'"));
    assert!(script.contains("uci set pbr.config.nft_file_helper='1'"));
    // 1.x renders the interface wiring UNQUOTED (byte parity); the
    // validate() charset gate is the safety story for these bytes
    assert!(script.contains("uci set pbr.config.netifd_interface_default=wan"));
    assert!(script.contains("uci add_list pbr.config.netifd_interface_local=lan"));
    assert!(script.contains("uci commit pbr"));
    assert!(script.contains("/etc/init.d/pbr enable"));
    assert!(script.contains("/etc/init.d/pbr restart"));
    assert!(
        script
            .contains("echo \"pbr configured. Verify with: nft list table inet pbr 2>/dev/null\"")
    );
    assert!(script.contains("echo \"Check status: /etc/init.d/pbr status\""));

    // strict off flips the enforcement bit; custom interfaces ride
    // the same unquoted lines
    let lenient = render_shell(&plan_for(Profile::Pbr(PbrProfile {
        wan_interface: "wwan".into(),
        lan_interface: "guest".into(),
        strict_enforcement: false,
    })));
    assert!(lenient.contains("uci set pbr.config.strict_enforcement='0'"));
    assert!(lenient.contains("uci set pbr.config.netifd_interface_default=wwan"));
    assert!(lenient.contains("uci add_list pbr.config.netifd_interface_local=guest"));

    // interface_name charset gate (both directions of the wiring)
    assert!(matches!(
        PbrProfile {
            wan_interface: "wan; rm -rf /".into(),
            ..PbrProfile::default()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    assert!(matches!(
        PbrProfile {
            lan_interface: "$(reboot)".into(),
            ..PbrProfile::default()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
}

#[test]
fn openclash_shape_gates_and_branches_match_1x() {
    let plan = plan_for(Profile::OpenClash(OpenClashProfile::default()));
    let script = render_shell(&plan);
    // dnsmasq→dnsmasq-full swap rides the plan AND LEADS the
    // package installs (Codex #486 rounds 1+4): luci-app-openclash
    // depends on dnsmasq-full, so on an opkg device with default
    // dnsmasq the swap must complete before the dependent resolves.
    // Download-first (round 6): a dead feed aborts BEFORE the
    // removal, never leaving the router without dnsmasq.
    let swap = plan
            .ops
            .iter()
            .position(|op| matches!(op, PlanOp::Shell { command } if command.starts_with("if [ -n \"$(opkg list-installed dnsmasq")))
            .expect("swap op present");
    let full = plan
        .ops
        .iter()
        .position(|op| matches!(op, PlanOp::EnsurePackage { name } if name == "dnsmasq-full"))
        .expect("dnsmasq-full install present");
    let luci = plan
        .ops
        .iter()
        .position(|op| matches!(op, PlanOp::EnsurePackage { name } if name == "luci-app-openclash"))
        .expect("luci-app-openclash install present");
    assert!(
        swap < full && full < luci,
        "swap must precede dnsmasq-full, which must precede luci-app-openclash"
    );
    assert!(script.contains("opkg download dnsmasq-full) && opkg remove dnsmasq"));
    // staged /tmp/.uci debris reverted before the first mutation
    assert!(script.contains("uci -q revert openclash 2>/dev/null || true"));
    assert!(script.contains("mkdir -p /etc/openclash/config"));
    assert!(script.contains("uci set openclash.config.enable='1'"));
    assert!(
        script.contains("uci set openclash.config.config_path='/etc/openclash/config/config.yaml'")
    );
    assert!(script.contains("uci set openclash.config.proxy_type='ss'"));
    assert!(script.contains("uci set openclash.config.core_type='Meta'"));
    assert!(script.contains("uci set openclash.config.dashboard_type='Official'"));
    assert!(script.contains("uci set openclash.config.dns_mode='redir-host'"));
    assert!(script.contains("uci set openclash.config.operation_mode='redir-host'"));
    assert!(script.contains("uci commit openclash"));
    assert!(script.contains("/etc/init.d/openclash enable"));
    assert!(script.contains("echo \"OpenClash configured: Meta core, ss proxy\""));
    assert!(
        script.contains("echo \"Post-flash: import your subscription config via the LuCI web UI\"")
    );

    // custom params ride the same lines; operation_mode mirrors dns_mode
    let custom = render_shell(&plan_for(Profile::OpenClash(OpenClashProfile {
        proxy_type: "trojan".into(),
        core_type: "Tun".into(),
        dns_mode: "fake-ip".into(),
    })));
    assert!(custom.contains("uci set openclash.config.proxy_type='trojan'"));
    assert!(custom.contains("uci set openclash.config.core_type='Tun'"));
    assert!(custom.contains("uci set openclash.config.dns_mode='fake-ip'"));
    assert!(custom.contains("uci set openclash.config.operation_mode='fake-ip'"));
    assert!(custom.contains("echo \"OpenClash configured: Tun core, trojan proxy\""));

    // token charset gate on every interpolated param (the
    // double-quoted echo is the hole this closes — mwan3/#448 class)
    for (field, hostile_value) in [
        ("proxy_type", "ss\"; reboot; echo \""),
        ("core_type", "$(poweroff)"),
        ("dns_mode", "redir-host\nreboot"),
        ("proxy_type", ""),
    ] {
        let mut hostile = OpenClashProfile::default();
        match field {
            "proxy_type" => hostile.proxy_type = hostile_value.into(),
            "core_type" => hostile.core_type = hostile_value.into(),
            _ => hostile.dns_mode = hostile_value.into(),
        }
        assert!(
            matches!(hostile.validate(), Err(Unsupported::InvalidParams(_))),
            "{field} gate must reject {hostile_value:?}"
        );
    }
}

#[test]
fn ssl_shape_branches_and_provider_gate_match_1x() {
    let plan = plan_for(Profile::Ssl(SslProfile::default()));
    let script = render_shell(&plan);
    // TLS-backend guard (Codex #486 round 5): the libustream
    // variants own the same libustream-ssl.so, so wolfssl installs
    // ONLY when no backend is present — an existing
    // mbedtls/openssl backend is preserved, never clashed
    assert!(script.contains("| grep -q '^libustream-'"));
    assert!(script.contains("opkg install libustream-wolfssl"));
    assert!(!plan.ops.iter().any(|op| matches!(
        op,
        PlanOp::EnsurePackage { name } if name == "libustream-wolfssl"
    )));
    assert!(plan.ops.iter().any(|op| matches!(
        op,
        PlanOp::EnsurePackage { name } if name == "ca-bundle"
    )));
    // cert-presence guard wraps the whole uhttpd block (Codex #486
    // P1 round 2): a cert-less router skips the wiring loudly
    // instead of pointing uhttpd at missing files
    assert!(script.contains(
        "if [ -f /etc/tollgate/ssl/server.crt ] && [ -f /etc/tollgate/ssl/server.key ]; then"
    ));
    assert!(script.contains("uci set uhttpd.main.cert='/etc/tollgate/ssl/server.crt'"));
    assert!(script.contains("uci set uhttpd.main.key='/etc/tollgate/ssl/server.key'"));
    // idempotent listen_https reset (round-1 fix): the delete is
    // guarded so an HTTP-only config still gets both listeners
    assert!(script.contains("uci -q delete uhttpd.main.listen_https || true"));
    assert!(script.contains("uci add_list uhttpd.main.listen_https='0.0.0.0:443'"));
    assert!(script.contains("uci add_list uhttpd.main.listen_https='[::]:443'"));
    assert!(!script.contains("listen_https &&"));
    assert!(script.contains("uci commit uhttpd"));
    assert!(script.contains("/etc/init.d/uhttpd restart"));
    assert!(script.contains("echo 'ssl: uhttpd HTTPS wired on :443'"));
    // staged /tmp/.uci debris reverted inside each guard before
    // the first mutation (AGENTS.md staging rule)
    assert!(script.contains("uci -q revert uhttpd 2>/dev/null || true"));
    assert!(script.contains("uci -q revert nodogsplash 2>/dev/null || true"));
    assert!(script.contains(
            "echo 'ssl: /etc/tollgate/ssl certs not present yet — skipping uhttpd HTTPS wiring (deploy certs, then re-run)' >&2"
        ));
    // explicit nodogsplash existence guard with a propagating body
    // (Codex #486 P2 round 2): failures abort instead of riding a
    // trailing `|| true` to a fake success
    assert!(script.contains("if uci -q show nodogsplash >/dev/null 2>&1; then"));
    // del_list-before-add_list keeps re-runs idempotent (Codex #486
    // round 4): uci lists are append-only
    assert!(script.contains(
        "uci -q del_list nodogsplash.@nodogsplash[0].users_to_router='allow tcp port 443' || true"
    ));
    assert!(
        script.contains(
            "uci add_list nodogsplash.@nodogsplash[0].users_to_router='allow tcp port 443'"
        )
    );
    assert!(!script.contains("nodogsplash restart || true"));
    assert!(script.contains("echo 'ssl: nodogsplash allows tcp/443 to the router'"));

    // cert-less skip must FAIL the apply, not report `applied` for
    // a no-op (Codex #486 round 3): outcome verification gates on
    // certs existing plus the uci readbacks
    let plan = plan_for(Profile::Ssl(SslProfile::default()));
    let descriptions: Vec<&str> = plan
        .verification
        .iter()
        .map(|c| c.description.as_str())
        .collect();
    assert!(descriptions.contains(&"certs deployed for uhttpd HTTPS (host-side post-flash step)"));
    assert!(descriptions.contains(&"uhttpd cert path persisted"));
    assert!(descriptions.contains(&"uhttpd listens on 443"));
    // nds-only shape keeps no post-hoc checks (runtime-conditional
    // outcome when nodogsplash is absent)
    let nds_only = plan_for(Profile::Ssl(SslProfile {
        enable_uhttpd_https: false,
        ..SslProfile::default()
    }));
    assert!(nds_only.verification.is_empty());

    // uhttpd off drops the whole HTTPS block, keeps the nds line
    let no_uhttpd = render_shell(&plan_for(Profile::Ssl(SslProfile {
        enable_uhttpd_https: false,
        ..SslProfile::default()
    })));
    assert!(!no_uhttpd.contains("uhttpd"));
    assert!(no_uhttpd.contains("nodogsplash"));

    // nds off drops only the nodogsplash line
    let no_nds = render_shell(&plan_for(Profile::Ssl(SslProfile {
        open_port_443_nds: false,
        ..SslProfile::default()
    })));
    assert!(no_nds.contains("uci commit uhttpd"));
    assert!(!no_nds.contains("nodogsplash"));

    // provider choice gate — 1.x declared the choices but never
    // enforced them in _resolve_params (newline injection into the
    // comment line was live shell)
    assert!(matches!(
        SslProfile {
            provider: "lancert\nreboot".into(),
            ..SslProfile::default()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    assert!(matches!(
        SslProfile {
            provider: "evil".into(),
            ..SslProfile::default()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    for ok in ["lancert", "qip", "manual"] {
        assert!(
            SslProfile {
                provider: ok.into(),
                ..SslProfile::default()
            }
            .validate()
            .is_ok()
        );
    }
}

#[test]
fn vpn_pia_shape_gates_and_branches_match_1x() {
    let base = VpnPiaProfile {
        username: "p1234567".into(),
        password: "testpass".into(),
        region: "czech".into(),
        upstream_gateway: "192.168.1.1".into(),
        ..VpnPiaProfile::default()
    };
    let script = render_shell(&plan_for(Profile::VpnPia(base.clone())));
    // curl IS ensured — the script's first act is `curl -u` auth
    // (hardening audit; the surfshark #604-P2 class)
    assert!(script.contains("# install package curl"));
    // one heredoc runtime-API payload: keypair on device, token
    // exchange, addKey, abort-before-cleanup gates
    assert!(script.contains("cat > /tmp/vpn_setup.sh << 'VPN_SETUP_EOF'"));
    assert!(script.contains("wg genkey > /tmp/vpn_private.key"));
    assert!(script.contains("curl -fs -m 15 -u 'p1234567:testpass'"));
    assert!(script.contains("https://czech.privacy.network:1337/addKey"));
    assert!(script.contains("aborting before wg0 cleanup"));
    // creds with a single quote survive sh-quoted (1.x parity)
    let quoted = render_shell(&plan_for(Profile::VpnPia(VpnPiaProfile {
        password: "p$a\"b'c".into(),
        ..base.clone()
    })));
    assert!(
        quoted.contains("-u 'p1234567:p$a\"b'\''c'"),
        "sh_quote parity"
    );

    // gates: creds required + no control chars, region alnum,
    // gateway IPv4, iface charset
    for hostile in [
        VpnPiaProfile {
            username: String::new(),
            ..base.clone()
        },
        VpnPiaProfile {
            password: "l1\nl2".into(),
            ..base.clone()
        },
        VpnPiaProfile {
            region: "czech; poweroff".into(),
            ..base.clone()
        },
        VpnPiaProfile {
            region: "prague-1".into(),
            ..base.clone()
        },
        VpnPiaProfile {
            upstream_gateway: "not-an-ip".into(),
            ..base.clone()
        },
        VpnPiaProfile {
            upstream_iface: "wwan; x".into(),
            ..base
        },
    ] {
        assert!(
            matches!(hostile.validate(), Err(Unsupported::InvalidParams(_))),
            "gate must reject {hostile:?}"
        );
    }
}

#[test]
fn vpn_nordvpn_openvpn_shape_gates_and_branches_match_1x() {
    let base = VpnNordvpnOpenvpnProfile {
        username: "svcuser1234".into(),
        password: "svcpass5678abcd".into(),
        station: "193.29.107.10".into(),
        hostname: "de500.nordvpn.com".into(),
        ..VpnNordvpnOpenvpnProfile::default()
    };
    let script = render_shell(&plan_for(Profile::VpnNordvpnOpenvpn(base.clone())));
    // one heredoc payload; CA + tls-auth + credentials as static files
    assert!(script.contains("cat > /tmp/nordvpn_openvpn_setup.sh << 'VPN_SETUP_EOF'"));
    assert!(script.contains("cat > /etc/openvpn/nordvpn.ta << 'NORD_TA_EOF'"));
    assert!(script.contains(
        "cat > /etc/openvpn/nordvpn.auth << 'NORD_AUTH_EOF'\nsvcuser1234\nsvcpass5678abcd"
    ));
    assert!(script.contains("chmod 600 /etc/openvpn/nordvpn.auth"));
    // template-faithful: multi-port remotes + x509 CN pin from the
    // SAME server object + tls-auth direction
    assert!(script.contains("uci add_list openvpn.nordvpn.remote='193.29.107.10 1234'"));
    assert!(script.contains("uci set openvpn.nordvpn.verify_x509_name='de500.nordvpn.com name'"));
    assert!(script.contains("uci set openvpn.nordvpn.tls_auth='/etc/openvpn/nordvpn.ta'"));
    assert!(script.contains("uci set openvpn.nordvpn.key_direction='1'"));
    assert!(script.contains("uci set openvpn.nordvpn.cipher='AES-256-CBC'"));
    assert!(script.contains("uci set openvpn.nordvpn.proto='udp'"));

    // tcp variant flips the proto only
    let tcp = render_shell(&plan_for(Profile::VpnNordvpnOpenvpn(
        VpnNordvpnOpenvpnProfile {
            proto: "tcp".into(),
            ..base.clone()
        },
    )));
    assert!(tcp.contains("uci set openvpn.nordvpn.proto='tcp'"));

    // gates: creds required + no control chars + no delimiters,
    // station IPv4, hostname charset, proto choice, cipher charset
    for hostile in [
        VpnNordvpnOpenvpnProfile {
            username: String::new(),
            ..base.clone()
        },
        VpnNordvpnOpenvpnProfile {
            password: "l1\nl2".into(),
            ..base.clone()
        },
        VpnNordvpnOpenvpnProfile {
            username: "NORD_AUTH_EOF".into(),
            ..base.clone()
        },
        VpnNordvpnOpenvpnProfile {
            station: "de500.nordvpn.com".into(),
            ..base.clone()
        },
        VpnNordvpnOpenvpnProfile {
            hostname: "host; poweroff".into(),
            ..base.clone()
        },
        VpnNordvpnOpenvpnProfile {
            proto: "icmp".into(),
            ..base.clone()
        },
        VpnNordvpnOpenvpnProfile {
            cipher: "AES-256-CBC'; reboot".into(),
            ..base
        },
    ] {
        assert!(
            matches!(hostile.validate(), Err(Unsupported::InvalidParams(_))),
            "gate must reject {hostile:?}"
        );
    }
}

#[test]
fn vpn_nordvpn_shape_gates_and_branches_match_1x() {
    let base = VpnNordvpnProfile {
        private_key: "STUBPRIVKEYbase64filledfortestonly0000=".into(),
        server_public_key: "STUBPUBKEYbase64filledfortestonly0000=".into(),
        endpoint_host: "de500.nordvpn.com".into(),
        route_target: "193.29.107.10".into(),
        upstream_gateway: "192.168.8.1".into(),
        ..VpnNordvpnProfile::default()
    };
    let script = render_shell(&plan_for(Profile::VpnNordvpn(base.clone())));
    // heredoc payload + the resolved statics riding double-quoted
    // assignments (validate()'s charsets gate them)
    assert!(script.contains("cat > /tmp/vpn_setup.sh << 'VPN_SETUP_EOF'"));
    assert!(script.contains("WG_PRIV=\"STUBPRIVKEYbase64filledfortestonly0000=\""));
    // the endpoint /32 pin uses the RESOLVED route target, not the hostname
    assert!(script.contains("nordvpn_server_route.target='193.29.107.10'"));
    // post-API-change contract: a HOSTNAME route target is valid (1.x pins
    // de500.nordvpn.com and lets the router resolve) — PR #629
    {
        let host = VpnNordvpnProfile {
            route_target: "de500.nordvpn.com".into(),
            ..base.clone()
        };
        assert!(
            host.validate().is_ok(),
            "hostname route_target must be accepted"
        );
        let hs = render_shell(&plan_for(Profile::VpnNordvpn(host)));
        assert!(hs.contains("nordvpn_server_route.target='de500.nordvpn.com'"));
    }
    // wg tunnel + 30s handshake verify tail
    assert!(script.contains("uci set network.wg0.proto='wireguard'"));
    assert!(script.contains("wg show wg0 2>/dev/null | grep -q 'latest handshake'"));
    // NordVPN DNS pair
    assert!(script.contains("uci add_list dhcp.@dnsmasq[0].server='103.86.99.100'"));

    // empty gateway swaps the static pin for the bounded discovery block
    let discover = render_shell(&plan_for(Profile::VpnNordvpn(VpnNordvpnProfile {
        upstream_gateway: String::new(),
        ..base.clone()
    })));
    assert!(discover.contains("VPN_GW=$(ip -4 route show default dev wwan"));
    assert!(!discover.contains("gateway='192.168.8.1'"));
    // the sed captures need SINGLE backslashes at render time —
    // doubled ones match nothing and the discovery always times
    // out (Codex #526 P2; the source template's \\ must not leak)
    assert!(discover.contains("sed -n 's/.*via \\([0-9.]\\+\\).*/\\1/p'"));
    assert!(!discover.contains("\\\\("));

    // gates: base64 keys, resolved-IP route target, numeric fields,
    // CIDR address, host-or-ip endpoint, iface charset
    for hostile in [
        VpnNordvpnProfile {
            private_key: "line1\nline2".into(),
            ..base.clone()
        },
        VpnNordvpnProfile {
            server_public_key: "$(reboot)".into(),
            ..base.clone()
        },
        VpnNordvpnProfile {
            route_target: String::new(),
            ..base.clone()
        },
        VpnNordvpnProfile {
            route_target: "not an ip".into(),
            ..base.clone()
        },
        VpnNordvpnProfile {
            endpoint_host: "de; poweroff".into(),
            ..base.clone()
        },
        VpnNordvpnProfile {
            endpoint_port: "51820; reboot".into(),
            ..base.clone()
        },
        VpnNordvpnProfile {
            address: "10.5.0.2".into(),
            ..base.clone()
        },
        VpnNordvpnProfile {
            upstream_iface: "wwan; x".into(),
            ..base
        },
    ] {
        assert!(
            matches!(hostile.validate(), Err(Unsupported::InvalidParams(_))),
            "gate must reject {hostile:?}"
        );
    }
}

#[test]
fn tollgate_shape_branches_and_gates_match_1x() {
    let tg = TollgateProfile {
        gateway_name: "net4sats".into(),
        gateway_domain: "net4sats.lan".into(),
        allow_lan_ssh: true,
        mint_url: "https://mint.example.com".into(),
        lightning_address: "user@domain.com".into(),
        price_per_minute: 5,
        upstream_usd_per_gb: "0.83".into(),
        markup: "2.0".into(),
        fx_sats_per_usd: 2500,
        ..TollgateProfile::default()
    };
    let script = render_shell(&plan_for(Profile::Tollgate(tg.clone())));
    assert!(script.contains("uci set nodogsplash.@nodogsplash[0].enabled='1'"));
    assert!(script.contains("uci set nodogsplash.@nodogsplash[0].gatewayname='net4sats'"));
    assert!(
        script.contains("uci set nodogsplash.@nodogsplash[0].gatewaydomainname='net4sats.lan'")
    );
    assert!(script.contains("uci set nodogsplash.@nodogsplash[0].clientid='mac'"));
    // idempotency fixes: guarded del_list pairs, named payment section
    for rule in [
        "allow tcp port 2121",
        "allow tcp port 2050",
        "allow tcp port 22",
    ] {
        assert!(script.contains(&format!(
            "uci -q del_list nodogsplash.@nodogsplash[0].users_to_router='{rule}' \
                 2>/dev/null || true"
        )));
        assert!(script.contains(&format!(
            "uci add_list nodogsplash.@nodogsplash[0].users_to_router='{rule}'"
        )));
    }
    assert!(!script.contains("uci add tollgate"));
    assert!(script.contains("uci set tollgate.payment=tollgate"));
    assert!(script.contains("uci set tollgate.payment.mint_url='https://mint.example.com'"));
    assert!(script.contains("uci set tollgate.payment.price_per_minute='5'"));
    assert!(script.contains("uci commit tollgate"));
    // hotplug hook: verbatim script body, literal \u2014 escape kept
    assert!(script.contains("[ \"$INTERFACE\" = \"wwan\" ] || exit 0"));
    assert!(script.contains("logger -t tollgate-hotplug \"wwan up \\u2014 restarting tollgate\""));
    // fx-derived price: 0.83/1024*2500*2.0 = 4.05 -> ceil 5
    assert!(script.contains("P=$(( ( 5 * SS + 1048575 ) / 1048576 ))"));
    assert!(script.contains("5 sat/MiB"));

    // minimal profile: no payment section, no ssh rule, hotplug on
    let minimal = render_shell(&plan_for(Profile::Tollgate(TollgateProfile::default())));
    assert!(minimal.contains("uci set nodogsplash.@nodogsplash[0].enabled='1'"));
    assert!(!minimal.contains("users_to_router='allow tcp port 22'"));
    assert!(!minimal.contains("tollgate.payment"));
    assert!(minimal.contains("[ \"$INTERFACE\" = \"wwan\" ]"));
    // hotplug off drops the hook entirely
    let no_hotplug = render_shell(&plan_for(Profile::Tollgate(TollgateProfile {
        install_hotplug: false,
        ..TollgateProfile::default()
    })));
    assert!(!no_hotplug.contains("hotplug.d/iface"));
    // explicit price pins the direct path
    let explicit = render_shell(&plan_for(Profile::Tollgate(TollgateProfile {
        price_sats_per_mib: 8,
        ..TollgateProfile::default()
    })));
    assert!(explicit.contains("P=$(( ( 8 * SS + 1048575 ) / 1048576 ))"));

    // gates: runtime injection via hotplug_interface; clientid
    // choice set; pricing bounds + the purity-delta fx requirement
    assert!(matches!(
        TollgateProfile {
            hotplug_interface: "wwan$(reboot)".into(),
            ..tg.clone()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    assert!(matches!(
        TollgateProfile {
            clientid: "evil".into(),
            ..tg.clone()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    assert!(matches!(
        TollgateProfile {
            markup: "0".into(),
            ..tg.clone()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    assert!(matches!(
        TollgateProfile {
            fx_sats_per_usd: 0,
            ..tg.clone()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    assert!(matches!(
        TollgateProfile {
            upstream_usd_per_gb: "not-a-number".into(),
            ..tg.clone()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    // overflow guard: absurd derived prices are rejected, never
    // wrapped to a zero (free-access) price (Codex #601 P2 round 3)
    assert!(matches!(
        TollgateProfile {
            upstream_usd_per_gb: "1000000000".into(),
            markup: "2".into(),
            fx_sats_per_usd: 2500,
            ..tg.clone()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    // NaN/inf operands are rejected, never laundered through the
    // 1.0 clamp into a 1-sat price (Codex #601 P2 round 4)
    for bad in ["NaN", "inf", "-inf"] {
        assert!(
            matches!(
                TollgateProfile {
                    markup: bad.into(),
                    ..tg.clone()
                }
                .validate(),
                Err(Unsupported::InvalidParams(_))
            ),
            "markup {bad} must be refused"
        );
    }
    assert!(matches!(
        TollgateProfile {
            upstream_usd_per_gb: "NaN".into(),
            ..tg.clone()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
}

#[test]
fn tollgate_security_shape_matches_1x() {
    let script = render_shell(&plan_for(Profile::TollgateSecurity(
        TollgateSecurityProfile,
    )));
    for (suffix, cidr) in [
        ("10", "10.0.0.0/8"),
        ("172", "172.16.0.0/12"),
        ("192", "192.168.0.0/16"),
        ("LL", "169.254.0.0/16"),
    ] {
        assert!(script.contains(&format!(
            "uci set firewall.Block-LAN-To-RFC1918-{suffix}=rule"
        )));
        assert!(script.contains(&format!(
            "uci set firewall.Block-LAN-To-RFC1918-{suffix}.dest_ip='{cidr}'"
        )));
        assert!(script.contains(&format!(
            "uci set firewall.Block-LAN-To-RFC1918-{suffix}.target='DROP'"
        )));
    }
    assert!(!script.contains("uci add firewall"));
    assert!(script.contains("uci commit firewall"));
    assert!(script.contains("uci commit wireless"));
    assert!(script.contains("/etc/init.d/firewall restart"));
    assert!(script.contains("wifi reload"));
    // isolation targets DISCOVERED wifi-iface sections — no
    // hardcoded factory radio names (single-radio devices abort
    // otherwise, Codex #601 P2 round 2)
    assert!(!script.contains("default_radio0"));
    assert!(!script.contains("default_radio1"));
    assert!(script.contains("uci set wireless.$_s.isolate='1'"));
    assert!(!script.contains("OUTPUT"));
    // the P1 fix verifies EFFECTIVE protection: the live fw4
    // ruleset must carry the block rule, not just staged UCI — and
    // the whole TABLE (fw4 puts src-zone rules in forward_lan)
    let plan = plan_for(Profile::TollgateSecurity(TollgateSecurityProfile));
    let live = plan
        .verification
        .iter()
        .find(|c| c.description.contains("LIVE"))
        .expect("live-ruleset check");
    assert!(live.command.contains("nft list table inet fw4"));
    assert!(!live.command.contains("list chain"));
    assert!(live.command.contains("Block-LAN-To-RFC1918-192"));
    // the libustream TLS backend is presence-guarded (P2), never
    // unconditionally ensured
    let tg_script = render_shell(&plan_for(Profile::Tollgate(TollgateProfile::default())));
    assert!(tg_script.contains("| grep -q '^libustream-'"));
    assert!(!tg_script.contains("# install package libustream-wolfssl"));
    // wifi capability gate (1.x requires_capabilities=["wifi"])
    assert_eq!(
        Profile::TollgateSecurity(TollgateSecurityProfile).requires(),
        &["wifi"]
    );
}

#[test]
fn vpn_node_shape_gates_and_json_match_1x() {
    let vn = VpnNodeProfile {
        nsec: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
        endpoint_host: "vpn.example.com".into(),
        ..VpnNodeProfile::default()
    };
    let script = render_shell(&plan_for(Profile::VpnNode(vn.clone())));
    assert!(script.contains("cat > /etc/vpn-listing.sh << 'SCRIPT'"));
    assert!(script.contains("-k 30402"));
    assert!(script.contains("-d \"vpn-node\""));
    assert!(script.contains("-t \"region=US\""));
    assert!(script.contains("-t \"price=50sat/hour\""));
    assert!(script.contains(
        "-c '{\"type\":\"vpn-service\",\"name\":\"VPN Node\",\
                 \"endpoint\":\"vpn.example.com:51820\""
    ));
    assert!(script.contains("wss://relay.damus.io wss://relay.cashu.email 2>&1"));
    assert!(script.contains(
            "echo '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' > /etc/vpn-node/nsec"
        ));
    assert!(script.contains("chmod 600 /etc/vpn-node/nsec"));

    // gates: the full baked-text surface
    for bad in [
        VpnNodeProfile {
            nsec: "x'; rm -rf /".into(),
            ..vn.clone()
        },
        VpnNodeProfile {
            title: "John's VPN".into(),
            ..vn.clone()
        },
        VpnNodeProfile {
            content: "say \"hi\"".into(),
            ..vn.clone()
        },
        VpnNodeProfile {
            d_tag: "a\"; rm".into(),
            ..vn.clone()
        },
        VpnNodeProfile {
            endpoint_host: "a; rm -rf /".into(),
            ..vn.clone()
        },
        VpnNodeProfile {
            country: "swe".into(),
            ..vn.clone()
        },
        VpnNodeProfile {
            price_amount: 0,
            ..vn.clone()
        },
        VpnNodeProfile {
            price_unit: "century".into(),
            ..vn.clone()
        },
        VpnNodeProfile {
            relays: "wss://a;rm".into(),
            ..vn.clone()
        },
        VpnNodeProfile {
            nak_path: "/usr/bin/nak; rm".into(),
            ..vn.clone()
        },
    ] {
        assert!(
            matches!(bad.validate(), Err(Unsupported::InvalidParams(_))),
            "must refuse: {:?}",
            bad
        );
    }
    // token-shaped payloads survive the single-pass substitution
    let tok = render_shell(&plan_for(Profile::VpnNode(VpnNodeProfile {
        d_tag: "a__NSEC__b".into(),
        ..vn.clone()
    })));
    assert!(tok.contains("-d \"a__NSEC__b\""));
}

#[test]
fn vpn_surfshark_shape_and_gates_match_1x() {
    let ss = VpnSurfsharkProfile {
        username: "svcuser".into(),
        password: "svcpass".into(),
        country: "Germany".into(),
        upstream_gateway: "192.168.8.1".into(),
        ..VpnSurfsharkProfile::default()
    };
    let script = render_shell(&plan_for(Profile::VpnSurfshark(ss.clone())));
    assert!(script.contains("cat > /tmp/vpn_setup.sh << 'VPN_SETUP_EOF'"));
    assert!(script.contains("-d '{\"username\":\"svcuser\",\"password\":\"svcpass\"}')"));
    assert!(script.contains("test(\"Germany\";\"i\")"));
    assert!(script.contains("uci set network.surfshark_server_route.gateway='192.168.8.1'"));
    assert!(script.contains("uci set network.wg0.proto='wireguard'"));
    assert!(script.contains("uci set firewall.vpn_zone.name='vpn'"));
    assert!(script.contains("uci add_list dhcp.@dnsmasq[0].server='162.252.172.57'"));
    assert!(script.contains("wg show wg0"));
    assert!(script.contains("sh /tmp/vpn_setup.sh"));
    // no country: first-server branch, no baked filter
    let no_country = render_shell(&plan_for(Profile::VpnSurfshark(VpnSurfsharkProfile {
        country: String::new(),
        ..ss.clone()
    })));
    assert!(no_country.contains("jq -r '.[0]'"));
    assert!(!no_country.contains("country/"));
    // gates: quote/backslash creds, jq-pattern country, non-IP
    // gateway, iface charset
    for bad in [
        VpnSurfsharkProfile {
            username: "x'; rm -rf /; '".into(),
            ..ss.clone()
        },
        VpnSurfsharkProfile {
            password: "a\\b".into(),
            ..ss.clone()
        },
        VpnSurfsharkProfile {
            country: "Ger\"; rm".into(),
            ..ss.clone()
        },
        VpnSurfsharkProfile {
            upstream_gateway: "$(reboot)".into(),
            ..ss.clone()
        },
        VpnSurfsharkProfile {
            upstream_iface: "wwan; rm".into(),
            ..ss.clone()
        },
    ] {
        assert!(
            matches!(bad.validate(), Err(Unsupported::InvalidParams(_))),
            "must refuse: {:?}",
            bad
        );
    }
    // token-shaped credentials survive substitution verbatim
    // (single-pass, values never re-scanned — Codex #604 P2 r5)
    let tok = render_shell(&plan_for(Profile::VpnSurfshark(VpnSurfsharkProfile {
        password: "abc__IFACE__def".into(),
        ..ss.clone()
    })));
    assert!(tok.contains("\"password\":\"abc__IFACE__def\""));
}

#[test]
fn vpn_openvpn_shape_branches_and_gates_match_1x() {
    let vo = VpnOpenvpnProfile {
        ovpn_config: "client\nremote vpn.example.com 1194\nproto udp\nauth-user-pass".into(),
        username: "svcuser".into(),
        password: "svcpass".into(),
        ..VpnOpenvpnProfile::default()
    };
    let script = render_shell(&plan_for(Profile::VpnOpenvpn(vo.clone())));
    assert!(script.contains("cat > /etc/openvpn/vpn-client.ovpn << 'OVPNEOF'"));
    assert!(script.contains("remote vpn.example.com 1194"));
    // credentials ride UCI overrides (init-script contract, P1 fix)
    assert!(!script.contains("vpn-auth.txt"));
    assert!(script.contains("uci set openvpn.vpn_client=openvpn"));
    assert!(script.contains("uci set openvpn.vpn_client.username='svcuser'"));
    assert!(script.contains("uci set openvpn.vpn_client.password='svcpass'"));
    // unmanaged interface on the real tunnel device — proto='openvpn'
    // is not a netifd protocol (Codex #603 P1 finding 3)
    assert!(script.contains("uci set network.vpn_if.proto='none'"));
    assert!(script.contains("uci set network.vpn_if.device='tun0'"));
    assert!(!script.contains("uci set network.vpn_if.proto='openvpn'"));
    assert!(script.contains("uci set firewall.vpn_zone.network='vpn_if'"));
    assert!(script.contains("uci set firewall.vpn_killswitch.name='KillSwitch-Reject-NonVPN'"));
    // the fail-open pairing the 1.x preset forgot
    assert!(script.contains("ip -4 addr show dev tun0"));
    assert!(
        script.contains("echo 'VPN: tun interface failed — removing kill switch to restore WAN'")
    );

    // no creds: no auth file; no kill switch: no killswitch section
    let bare = render_shell(&plan_for(Profile::VpnOpenvpn(VpnOpenvpnProfile {
        ovpn_config: "client".into(),
        kill_switch: false,
        ..VpnOpenvpnProfile::default()
    })));
    assert!(!bare.contains("vpn-auth.txt"));
    assert!(!bare.contains("uci set firewall.vpn_killswitch=rule"));
    assert!(!bare.contains("tun interface failed"));

    // gates: heredoc terminators, credential newlines, proto choice
    assert!(matches!(
        VpnOpenvpnProfile {
            ovpn_config: "client\nOVPNEOF\nreboot".into(),
            ..vo.clone()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    assert!(matches!(
        VpnOpenvpnProfile {
            password: "AUTHEOF".into(),
            ..vo.clone()
        }
        .validate(),
        Ok(())
    ));
    assert!(matches!(
        VpnOpenvpnProfile {
            username: "u\nrm -rf /".into(),
            ..vo.clone()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    assert!(matches!(
        VpnOpenvpnProfile {
            proto: "udp; reboot".into(),
            ..vo.clone()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
}

#[test]
fn ap_nostr_id_gates_match_1x_plus_charset() {
    let good = ApNostrIdProfile {
        npub: "npub1qqv9p7wq3zq5x2swp3jv4tdd6syr8whs".into(),
        nsec: "nsec1qqv9p7wq3zq5x2swp3jv4tdd6syr8whs".into(),
    };
    assert!(good.validate().is_ok());

    // both-or-neither (1.x gate)
    let neither = ApNostrIdProfile::default();
    assert!(matches!(
        neither.validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    let half = ApNostrIdProfile {
        npub: good.npub.clone(),
        nsec: String::new(),
    };
    assert!(matches!(
        half.validate(),
        Err(Unsupported::InvalidParams(_))
    ));

    // prefixes (1.x gate)
    let bad_prefix = ApNostrIdProfile {
        npub: "npub2qqv9p7wq3zq5x2swp3jv4tdd6syr8whs".into(),
        nsec: good.nsec.clone(),
    };
    assert!(matches!(
        bad_prefix.validate(),
        Err(Unsupported::InvalidParams(_))
    ));

    // charset: a quote-bearing npub would close the single-quoted
    // printf and run arbitrary shell — refused, never quoted.
    let hostile = ApNostrIdProfile {
        npub: "npub1qqv9'; touch /tmp/conwrt-pwned;".into(),
        nsec: good.nsec.clone(),
    };
    assert!(matches!(
        hostile.validate(),
        Err(Unsupported::InvalidParams(_))
    ));

    // non-bech32 body (an 'o' — excluded from the BIP-173 charset)
    let non_bech32 = ApNostrIdProfile {
        npub: "npub1goldenfixture0000examplepub111key".into(),
        nsec: good.nsec.clone(),
    };
    assert!(matches!(
        non_bech32.validate(),
        Err(Unsupported::InvalidParams(_))
    ));
}

#[test]
fn mptcp_bonding_shape_and_gates_match_1x() {
    let mp = MptcpBondingProfile {
        server_ipv4: "203.0.113.7".into(),
        server_port: 16384,
        uuid: "0f0e0d0c-0b0a-4909-8807-060504030201".into(),
    };
    let script = render_shell(&plan_for(Profile::MptcpBonding(mp.clone())));
    // installer line: values UNQUOTED (1.x bytes); validate() gates
    assert!(script.contains(
        "curl -fsSL owrt.bondingshouldbefree.org | sh -s -- \
             --server-ipv4 203.0.113.7 --server-port 16384 \
             --uuid 0f0e0d0c-0b0a-4909-8807-060504030201"
    ));
    assert!(script.contains("echo \"BSBF installed. Verify: bsbf-bonding --status\""));
    assert!(script.contains("echo \"Monitor: bsbf-netspeed\""));
    assert!(script.contains("echo \"Uninstall: bsbf-bonding --uninstall\""));
    // kernel prerequisite probes the upstream sysctl, never the
    // legacy /proc/net/mptcp_net dir (Codex #600 P2)
    let plan = plan_for(Profile::MptcpBonding(mp.clone()));
    let kernel_check = plan
        .verification
        .iter()
        .find(|c| c.description.contains("MPTCP"))
        .expect("kernel prerequisite check");
    assert!(kernel_check.command.contains("/proc/sys/net/mptcp/enabled"));
    assert_eq!(kernel_check.expect_contains, "1");
    assert!(!kernel_check.command.contains("mptcp_net"));
    // hostname endpoints stay first-class (validate_host parity)
    assert!(
        MptcpBondingProfile {
            server_ipv4: "vps.example.com".into(),
            ..mp.clone()
        }
        .validate()
        .is_ok()
    );

    // injection gates: hostile values never reach the pipe-to-sh line
    for bad in [
        MptcpBondingProfile {
            server_ipv4: "1.2.3.4; rm -rf /".into(),
            ..mp.clone()
        },
        MptcpBondingProfile {
            server_ipv4: "$(reboot)".into(),
            ..mp.clone()
        },
        MptcpBondingProfile {
            server_ipv4: String::new(),
            ..mp.clone()
        },
        MptcpBondingProfile {
            server_port: 0,
            ..mp.clone()
        },
        MptcpBondingProfile {
            uuid: "$(reboot)".into(),
            ..mp.clone()
        },
        MptcpBondingProfile {
            uuid: String::new(),
            ..mp.clone()
        },
    ] {
        assert!(
            matches!(bad.validate(), Err(Unsupported::InvalidParams(_))),
            "must refuse: {:?}",
            bad
        );
    }
}

#[test]
fn vpn_pia_token_shaped_credentials_survive_substitution() {
    // hardening-audit regression: chained `.replace()` rewrote
    // token-shaped payloads inside the quoted creds before the
    // single-pass substitution landed (surfshark #604-P2 class)
    let base = VpnPiaProfile {
        username: "u__IFACE__x".into(),
        password: "p__GATEWAY__y".into(),
        region: "czech".into(),
        upstream_gateway: "192.168.1.1".into(),
        ..VpnPiaProfile::default()
    };
    let script = render_shell(&plan_for(Profile::VpnPia(base)));
    // creds survive verbatim …
    assert!(script.contains("-u 'u__IFACE__x:p__GATEWAY__y'"));
    // … while the real tokens still substituted
    assert!(script.contains("https://czech.privacy.network:1337/addKey"));
    assert!(script.contains("uci set network.pia_server_route.gateway='192.168.1.1'"));
}

#[test]
fn vpn_pia_openvpn_shape_gates_and_branches_match_1x() {
    let plan = plan_for(Profile::VpnPiaOpenvpn(VpnPiaOpenvpnProfile {
        username: "p1234567".into(),
        password: "testpass".into(),
        upstream_gateway: "192.168.8.1".into(),
        ..VpnPiaOpenvpnProfile::default()
    }));
    let script = render_shell(&plan);
    // one heredoc payload, run verbatim via sh (1.x transport_sh)
    assert!(script.contains("cat > /tmp/pia_openvpn_setup.sh << 'VPN_SETUP_EOF'"));
    assert!(script.contains("sh /tmp/pia_openvpn_setup.sh"));
    // credentials ride the quoted auth heredoc; the CA rides its own
    assert!(script.contains("cat > /etc/openvpn/pia.auth << 'PIA_AUTH_EOF'\np1234567\ntestpass"));
    assert!(script.contains("chmod 600 /etc/openvpn/pia.auth"));
    // endpoint pool + remote-random + the validated no-persist-tun
    assert!(script.contains("uci add_list openvpn.pia.remote='151.241.122.99 8080'"));
    assert!(script.contains("uci set openvpn.pia.remote_random='1'"));
    assert!(!script.contains("uci set openvpn.pia.persist_tun"));
    // kill switch + management rules + tunnel DNS
    assert!(script.contains("uci set firewall.vpn_killswitch.target='REJECT'"));
    assert!(script.contains("uci set firewall.vpn_mgmt.name='Allow-VPN-Management'"));
    assert!(script.contains("uci add_list dhcp.@dnsmasq[0].server='10.0.0.243'"));
    // the failure TAIL removes the kill switch when tun0 never comes up
    assert!(script.contains("removing kill switch to restore WAN"));

    // branches: kill switch off drops the rule AND the tail; mgmt off
    // drops the rule; empty gateway drops the route pin block
    let no_kill = render_shell(&plan_for(Profile::VpnPiaOpenvpn(VpnPiaOpenvpnProfile {
        username: "p1234567".into(),
        password: "testpass".into(),
        kill_switch: false,
        allow_management: false,
        ..VpnPiaOpenvpnProfile::default()
    })));
    assert!(!no_kill.contains("vpn_killswitch"));
    assert!(!no_kill.contains("vpn_mgmt"));
    assert!(!no_kill.contains("ip route replace"));
    assert!(no_kill.contains("vpn_zone"));

    // gates: required creds, control chars (heredoc line injection),
    // IPv4 remotes/gateway, numeric port, iface charset
    assert!(matches!(
        VpnPiaOpenvpnProfile::default().validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    let base = VpnPiaOpenvpnProfile {
        username: "p1".into(),
        password: "pw".into(),
        ..VpnPiaOpenvpnProfile::default()
    };
    assert!(base.validate().is_ok());
    for hostile in [
        VpnPiaOpenvpnProfile {
            password: "line1\nline2".into(),
            ..base.clone()
        },
        VpnPiaOpenvpnProfile {
            password: "PIA_AUTH_EOF".into(),
            ..base.clone()
        },
        VpnPiaOpenvpnProfile {
            username: "VPN_SETUP_EOF".into(),
            ..base.clone()
        },
        VpnPiaOpenvpnProfile {
            username: "p1\nroot".into(),
            ..base.clone()
        },
        VpnPiaOpenvpnProfile {
            port: "8080; reboot".into(),
            ..base.clone()
        },
        VpnPiaOpenvpnProfile {
            upstream_gateway: "not-an-ip".into(),
            ..base.clone()
        },
        VpnPiaOpenvpnProfile {
            upstream_iface: "wan; poweroff".into(),
            ..base.clone()
        },
        VpnPiaOpenvpnProfile {
            remotes: vec!["$(reboot)".into()],
            ..base
        },
    ] {
        assert!(
            matches!(hostile.validate(), Err(Unsupported::InvalidParams(_))),
            "gate must reject {hostile:?}"
        );
    }
}

#[test]
fn nodns_payloads_substitution_and_validator_gates() {
    let script = render_shell(&plan_for(Profile::Nodns(NodnsProfile::default())));
    assert!(script.contains("cat > /etc/init.d/nodns-bridge << 'NODNS_INIT_EOF'"));
    assert!(script.contains("procd_set_param command /usr/bin/nodns-poll.sh"));
    assert!(script.contains("cat > /usr/bin/nodns-poll.sh << 'NODNS_POLL_EOF'"));
    // substituted values land inside the poll script, no placeholders leak
    assert!(script.contains("ZONE=\"nodns.shop\""));
    assert!(script.contains("API_URL=\"https://nodns.shop\""));
    assert!(script.contains("POLL_INTERVAL=300"));
    assert!(!script.contains("__ZONE__"));
    assert!(!script.contains("__URL__"));
    assert!(!script.contains("__POLL_INTERVAL__"));
    // the awk zone parser rides along verbatim
    assert!(script.contains("if (name == \"@\") name = z"));
    assert!(
        script.contains("uci add_list dhcp.@dnsmasq[0].addnhosts='/etc/dnsmasq.d/nodns.hosts'")
    );
    assert!(script.contains("uci commit dhcp"));
    assert!(script.contains("/etc/init.d/nodns-bridge enable"));
    assert!(script.contains("/etc/init.d/nodns-bridge start"));
    assert!(script.contains(
        "echo \"nodns bridge configured: zone=nodns.shop interval=300s url=https://nodns.shop\""
    ));

    let flipped = render_shell(&plan_for(Profile::Nodns(NodnsProfile {
        zone: "example.net".into(),
        api_url: "http://localhost:8080".into(),
        poll_interval: 60,
    })));
    assert!(flipped.contains("ZONE=\"example.net\""));
    assert!(flipped.contains("API_URL=\"http://localhost:8080\""));
    assert!(flipped.contains("POLL_INTERVAL=60"));

    // 1.x validators: interval range, URL scheme, zone whitespace
    assert!(matches!(
        NodnsProfile {
            poll_interval: 59,
            ..NodnsProfile::default()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    assert!(matches!(
        NodnsProfile {
            api_url: "ftp://x".into(),
            ..NodnsProfile::default()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    assert!(matches!(
        NodnsProfile {
            zone: "bad zone".into(),
            ..NodnsProfile::default()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    // shell metacharacters refuse (values interpolate into the
    // runtime script's double-quoted assignments)
    assert!(matches!(
        NodnsProfile {
            api_url: "https://x/$(reboot)".into(),
            ..NodnsProfile::default()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    assert!(matches!(
        NodnsProfile {
            zone: "a;reboot".into(),
            ..NodnsProfile::default()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
}

#[test]
fn auto_sqm_script_hook_branches_and_gates() {
    let script = render_shell(&plan_for(Profile::AutoSqm(AutoSqmProfile {
        download_kbps: 20_000,
        ..AutoSqmProfile::default()
    })));
    assert!(script.contains("uci set auto_sqm.config=auto_sqm"));
    assert!(script.contains("uci set auto_sqm.config.mode='static'"));
    assert!(script.contains("uci set auto_sqm.config.download_kbps='20000'"));
    assert!(script.contains("uci commit auto_sqm"));
    assert!(script.contains("cat <<'AUTO_SQM_EOF' > /usr/sbin/auto-sqm"));
    // the runtime script body rides along verbatim
    assert!(script.contains("measure_wget() {"));
    assert!(script.contains("apply_sqm \"$DL_SPEED\" \"$UL_SPEED\""));
    assert!(script.contains("cat <<'HOTPLUG_EOF' > /etc/hotplug.d/iface/10-sqm-autotune"));
    assert!(script.contains(
        "[ \"$ACTION\" = \"ifup\" ] && [ \"$INTERFACE\" = \"wan\" ] && /usr/sbin/auto-sqm &"
    ));
    // static + known speeds: run immediately
    assert!(script.contains("/usr/sbin/auto-sqm\n"));
    assert!(!script.contains("crontabs/root"));

    // dynamic: cron entry + cron enable/restart, no immediate run
    let dynamic = render_shell(&plan_for(Profile::AutoSqm(AutoSqmProfile {
        mode: "dynamic".into(),
        dynamic_interval_hours: 6,
        ..AutoSqmProfile::default()
    })));
    assert!(dynamic.contains("sed -i '/auto-sqm/d' /etc/crontabs/root"));
    assert!(dynamic.contains("echo '0 */6 * * * /usr/sbin/auto-sqm' >> /etc/crontabs/root"));
    assert!(dynamic.contains("/etc/init.d/cron enable"));
    assert!(dynamic.contains("/etc/init.d/cron restart"));
    assert!(dynamic.contains("echo 'auto-sqm: will measure and configure on WAN ifup'"));

    // interface_name charset gates (both fields)
    assert!(matches!(
        AutoSqmProfile {
            interface: "wan; rm".into(),
            ..AutoSqmProfile::default()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    assert!(matches!(
        AutoSqmProfile {
            device: "eth0 x".into(),
            ..AutoSqmProfile::default()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
}

#[test]
fn tether_param_bounds_and_capability_gate() {
    assert!(TetherProfile::default().validate().is_ok());
    assert!(matches!(
        TetherProfile {
            interface: "eth0; rm -rf /".into(),
            ..TetherProfile::default()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    assert!(matches!(
        TetherProfile {
            detect_timeout_secs: 0,
            ..TetherProfile::default()
        }
        .validate(),
        Err(Unsupported::InvalidParams(_))
    ));
    // requires usb — a model without it is refused before any op
    let refusal = plan_profile(
        &DeviceState::OpenWrt,
        &model_with_capabilities(None),
        &Profile::Tether(TetherProfile::default()),
    )
    .expect_err("must refuse");
    assert!(matches!(
        refusal,
        Unsupported::MissingCapability {
            capability: ref c,
            ..
        } if c == "usb"
    ));
}

#[test]
fn tether_variant_scripts_and_packages() {
    for (variant, golden_id) in [
        (TetherVariant::Auto, "tether"),
        (TetherVariant::Android, "tether-android"),
        (TetherVariant::AndroidAdb, "tether-android-adb"),
        (TetherVariant::Ios, "tether-ios"),
    ] {
        let plan = plan_for(Profile::Tether(TetherProfile {
            variant,
            ..TetherProfile::default()
        }));
        assert_eq!(plan.profile_id, golden_id);
        let script = render_shell(&plan);
        assert!(script.contains("for _ in $(seq 1 45); do"));
        let wants_usbmuxd = matches!(variant, TetherVariant::Auto | TetherVariant::Ios);
        assert_eq!(
            script.contains("/usr/sbin/usbmuxd -v -U -f >/dev/null 2>&1 &"),
            wants_usbmuxd
        );
        let wants_adb = matches!(variant, TetherVariant::Auto | TetherVariant::AndroidAdb);
        assert_eq!(
            script.contains("99-usb-tether-adb << 'HOTPLUG_EOF'"),
            wants_adb
        );
        assert_eq!(
            script.contains("adb"),
            wants_adb || variant == TetherVariant::Auto
        );
        // Android detection drivers vs iOS ipheth
        match variant {
            TetherVariant::Android | TetherVariant::AndroidAdb => {
                assert!(script.contains("rndis\\|cdc_ether"));
                assert!(!script.contains("ipheth"));
            }
            TetherVariant::Ios => {
                assert!(script.contains("ipheth"));
                assert!(script.contains("apple\\|iphone"));
            }
            TetherVariant::Auto => {
                assert!(script.contains("usbnet\\|ipheth"));
                assert!(script.contains("apple\\|iphone"));
            }
        }
        let pkg_count = plan
            .ops
            .iter()
            .filter(|op| matches!(op, PlanOp::EnsurePackage { .. }))
            .count();
        assert_eq!(pkg_count, variant.packages().len());
    }
}

#[test]
fn tether_heredoc_reassembles_adjacently() {
    let plan = plan_for(Profile::Tether(TetherProfile::default()));
    let script = render_shell(&plan);
    // The heredoc body must follow the cat line immediately (byte
    // adjacency — no comment or blank line in between).
    let lines: Vec<&str> = script.lines().collect();
    let cat_at = lines
        .iter()
        .position(|l| l.contains("<< 'HOTPLUG_EOF'"))
        .expect("heredoc opener");
    assert_eq!(
        lines[cat_at + 1],
        "[ \"$ACTION\" = \"bind\" ] || exit 0",
        "heredoc body must start on the next line"
    );
    let eof_at = lines
        .iter()
        .position(|l| *l == "HOTPLUG_EOF")
        .expect("heredoc terminator");
    assert!(lines[..eof_at].iter().any(|l| l.contains(") &")));
}

#[test]
fn wireguard_profiles_ensure_kernel_module_for_runtime_applies() {
    // Runtime applies on vanilla apk/opkg-era images need the kernel
    // module — the historical package set (wireguard-tools,
    // luci-proto-wireguard) only worked because ASU bakes resolved
    // kmod dependencies at image build time (x1860 25.12.6 hardware
    // finding, lane wanapk).
    let client = plan_for(Profile::WireguardClient(WireguardClientProfile {
        peer_public_key: "dGhpcyBpcyBhIHRlc3Qga2V5IGZvciB3aXJlZ3VhcmQ=".into(),
        endpoint_host: "vpn.example.com".into(),
        ..WireguardClientProfile::default()
    }));
    let server = plan_for(Profile::WireguardServer(WireguardServerProfile::default()));
    for plan in [client, server] {
        assert!(
            plan.ops
                .iter()
                .any(|op| matches!(op, PlanOp::EnsurePackage { name } if name == "kmod-wireguard")),
            "wireguard plans must ensure kmod-wireguard for runtime applies"
        );
    }
}

#[test]
fn guest_wifi_param_bounds_match_1x_validators() {
    assert!(GuestWifiProfile::default().validate().is_ok());
    // validate_ssid: empty, >32 bytes, control characters
    for bad in [
        GuestWifiProfile {
            ssid: String::new(),
            ..GuestWifiProfile::default()
        },
        GuestWifiProfile {
            ssid: "x".repeat(33),
            ..GuestWifiProfile::default()
        },
        GuestWifiProfile {
            ssid: "bad\u{1}ssid".into(),
            ..GuestWifiProfile::default()
        },
        GuestWifiProfile {
            key: "line\nbreak".into(),
            ..GuestWifiProfile::default()
        },
        GuestWifiProfile {
            encryption: "wep".into(),
            ..GuestWifiProfile::default()
        },
        GuestWifiProfile {
            band: "2.4".into(),
            ..GuestWifiProfile::default()
        },
        GuestWifiProfile {
            network_name: "guest net".into(),
            ..GuestWifiProfile::default()
        },
    ] {
        assert!(
            matches!(bad.validate(), Err(Unsupported::InvalidParams(_))),
            "{bad:?} must be rejected"
        );
    }
    // capability gate: wifi
    let refusal = plan_profile(
        &DeviceState::OpenWrt,
        &model_with_capabilities(None),
        &Profile::GuestWifi(GuestWifiProfile::default()),
    )
    .expect_err("must refuse");
    assert!(matches!(
        refusal,
        Unsupported::MissingCapability {
            capability: ref c,
            ..
        } if c == "wifi"
    ));
}

#[test]
fn guest_wifi_key_branch_and_custom_params_render_1x_shapes() {
    let with_key = render_shell(&plan_for(Profile::GuestWifi(GuestWifiProfile {
        ssid: "Cafe".into(),
        key: "cafe-pass".into(),
        encryption: "psk-mixed".into(),
        band: "5ghz".into(),
        isolation: false,
        network_name: "voyeurs".into(),
    })));
    assert!(with_key.contains("uci set wireless.guest_ap.key='cafe-pass'"));
    assert!(with_key.contains("uci set wireless.guest_ap.encryption=psk-mixed"));
    assert!(with_key.contains("\"5g\""));
    assert!(with_key.contains("uci set wireless.guest_ap.isolate=0"));
    assert!(with_key.contains("uci set network.voyeurs.ipaddr=\"$_guest_prefix.1\""));
    assert!(with_key.contains("uci set firewall.voyeurs_dns.name='Allow-DNS-voyeurs'"));

    let open = render_shell(&plan_for(Profile::GuestWifi(GuestWifiProfile::default())));
    assert!(!open.contains("guest_ap.key="));
    assert!(open.contains("uci set wireless.guest_ap.isolate=1"));
}

#[test]
fn hostile_values_are_quoted_not_interpolated() {
    // The shell-op escape hatch must never let a hostile value break
    // out of its quoting (1.x sh_quote behavior at render time).
    let script = render_shell(&plan_for(Profile::GuestWifi(GuestWifiProfile {
        ssid: "evil'; rm -rf /; '".into(),
        ..GuestWifiProfile::default()
    })));
    assert!(
        script.contains("uci set wireless.guest_ap.ssid='evil'\''; rm -rf /; '\''"),
        "ssid must be single-quote escaped: {script}"
    );
    // uci section names derived from user input stay identifier-safe
    let script = render_shell(&plan_for(Profile::WireguardClient(
        WireguardClientProfile {
            private_key: "k'; dropbear off".into(),
            ..wireguard()
        },
    )));
    assert!(script.contains("uci set network.wg0.private_key='k'\''; dropbear off'"));
}
