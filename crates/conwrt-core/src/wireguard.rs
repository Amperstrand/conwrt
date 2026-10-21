//! WireGuard client/server desired-state profiles — port of the 1.x use
//! cases `scripts/use_cases/wireguard_client.py` and
//! `scripts/use_cases/wireguard_server.py` (both `test_status=tested`;
//! client verified on D-Link COVR-X1860 A1, server via ops
//! characterization + transport parity, and both exercised end-to-end in
//! the QEMU VM by PR #409's integration suite).
//!
//! # Parity contract
//!
//! The plans produced here render to shell that is semantically identical
//! to the Python `render_shell(build_configure_ops(params))` output for the
//! same params. This is enforced by the cross-implementation parity harness
//! (`tests/test_parity_rust_plan.py` + the `parity` module), which renders
//! the same JSON fixtures through both implementations and diffs the
//! normalized command streams. Op order, option order inside sections, and
//! every literal string mirror the Python builders exactly.
//!
//! Python uses `ShellCommand` ops for the section-type declarations
//! (`uci set network.wg0=interface`) and for the non-UCI escape hatches
//! (public-key export, echo summaries, kill-switch verification loop);
//! here those map to `PlanOp::SetUciSection` with no options and
//! `PlanOp::ShellCommand` respectively.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::plan::{PlanOp, UciValue, Unsupported};

/// WireGuard VPN client — route traffic through a VPN tunnel
/// (`scripts/use_cases/wireguard_client.py`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireguardClientProfile {
    /// WireGuard private key (`generate` = auto-generate on first boot).
    pub private_key: String,
    /// VPN server public key (required).
    pub peer_public_key: String,
    /// VPN server hostname or IPv4 address (required, validated like 1.x
    /// `shell_safe.validate_host`).
    pub endpoint_host: String,
    /// VPN server UDP port (1–65535).
    pub endpoint_port: u16,
    /// Optional pre-shared key (empty = none).
    pub peer_psk: String,
    /// Tunnel IP address with CIDR.
    pub address: String,
    /// DNS server through tunnel (empty = use the peer's).
    pub dns: String,
    /// Block all traffic if the VPN drops.
    pub kill_switch: bool,
    /// IPs to route through the tunnel.
    pub allowed_ips: String,
}

impl WireguardClientProfile {
    /// 1.x defaults (`wireguard_client._resolve_params`).
    #[must_use]
    pub fn defaults() -> Self {
        Self {
            private_key: String::from("generate"),
            peer_public_key: String::new(),
            endpoint_host: String::new(),
            endpoint_port: 51820,
            peer_psk: String::new(),
            address: String::from("10.67.0.2/32"),
            dns: String::new(),
            kill_switch: true,
            allowed_ips: String::from("0.0.0.0/0, ::/0"),
        }
    }

    /// Bounds mirrored from the 1.x validators: `validate_host` /
    /// `validate_port` on the endpoint plus the `peer_public_key`
    /// `required=True` param definition.
    pub fn validate(&self) -> Result<(), Unsupported> {
        if self.peer_public_key.is_empty() {
            return Err(Unsupported::InvalidParams(
                "peer_public_key must not be empty".into(),
            ));
        }
        if !is_host_or_ipv4(&self.endpoint_host) {
            return Err(Unsupported::InvalidParams(format!(
                "endpoint_host must be a valid hostname or IPv4 address, got: '{}'",
                self.endpoint_host
            )));
        }
        if self.endpoint_port == 0 {
            return Err(Unsupported::InvalidParams(
                "endpoint_port must be 1-65535".into(),
            ));
        }
        Ok(())
    }
}

/// WireGuard VPN server — remote access to the local network
/// (`scripts/use_cases/wireguard_server.py`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireguardServerProfile {
    /// WireGuard private key (`generate` = auto-generate on first boot).
    pub private_key: String,
    /// UDP listen port.
    pub listen_port: u16,
    /// VPN client subnet (server IP + CIDR).
    pub subnet: String,
    /// First peer's public key (empty = no peer sections).
    pub peer1_public_key: String,
    /// First peer's allowed IPs.
    pub peer1_allowed_ips: String,
    /// First peer's pre-shared key (optional).
    pub peer1_psk: String,
}

impl WireguardServerProfile {
    /// 1.x defaults (`wireguard_server._resolve_params`).
    #[must_use]
    pub fn defaults() -> Self {
        Self {
            private_key: String::from("generate"),
            listen_port: 51820,
            subnet: String::from("10.1.99.1/24"),
            peer1_public_key: String::new(),
            peer1_allowed_ips: String::from("10.1.99.2/32"),
            peer1_psk: String::new(),
        }
    }

    /// 1.x only `int()`-casts `listen_port` (no range check); the u16
    /// already narrows that to 0–65535 and 0 is not a usable WireGuard
    /// port, so it is rejected here.
    pub fn validate(&self) -> Result<(), Unsupported> {
        if self.listen_port == 0 {
            return Err(Unsupported::InvalidParams(
                "listen_port must be 1-65535".into(),
            ));
        }
        Ok(())
    }
}

/// `shell_safe.validate_host`: non-empty, an IPv4 address, or a hostname
/// matching `^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$` (≤ 253 bytes).
fn is_host_or_ipv4(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    if is_ipv4(value) {
        return true;
    }
    value.len() <= 253
        && value
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && value
            .chars()
            .last()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// `shell_safe._IPV4_RE`: four dot-separated octets 0–255 (leading zeros
/// allowed by the regex, `01` parses to 1 either way).
fn is_ipv4(value: &str) -> bool {
    let mut octets = 0;
    for part in value.split('.') {
        octets += 1;
        if octets > 4 {
            return false;
        }
        if part.is_empty() || part.len() > 3 || !part.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        if part.parse::<u16>().unwrap_or(999) > 255 {
            return false;
        }
    }
    octets == 4
}

fn literal(v: &str) -> UciValue {
    UciValue::Literal(v.to_string())
}

/// Delete stale anonymous firewall sections matching `pattern` until none
/// remain (idempotent reconfigure). Byte-for-byte the 1.x helper
/// `profile.uci_helpers.uci_cleanup_sections_sh`.
#[must_use]
pub fn cleanup_uci_sections_sh(config: &str, pattern: &str) -> String {
    let mut out = String::new();
    out.push_str("while uci show ");
    out.push_str(config);
    out.push_str(" 2>/dev/null | grep -q \"");
    out.push_str(pattern);
    out.push_str("\"; do _s=$(uci show ");
    out.push_str(config);
    out.push_str(" 2>/dev/null | grep \"");
    out.push_str(pattern);
    out.push_str("\" | head -1 | cut -d. -f2 | cut -d= -f1); uci delete \"");
    out.push_str(config);
    out.push_str(".$_s\" 2>/dev/null; done; true");
    out
}

/// 1.x kill-switch verification loop (`wireguard_client.py`); the em-dash
/// is part of the parity-tested output.
fn killswitch_verify_command() -> String {
    String::from(
        "i=0; while [ $i -lt 30 ]; do if wg show wg0 2>/dev/null | grep -q 'latest handshake'; \
         then echo 'WG kill-switch: tunnel verified'; exit 0; fi; sleep 1; i=$((i+1)); done; \
         echo 'WG kill-switch: tunnel failed \u{2014} removing kill switch to restore WAN'; \
         uci delete firewall.wg_client_killswitch; uci commit firewall; fw4 restart",
    )
}

/// Build the wireguard-client plan ops (mirror of
/// `_build_wireguard_client_ops`, same order and literals).
pub(crate) fn wireguard_client_ops(p: &WireguardClientProfile) -> Vec<PlanOp> {
    let mut ops = vec![
        PlanOp::SetUciSection {
            config: "network".into(),
            section: "wg0".into(),
            section_type: "interface".into(),
            options: Vec::new(),
        },
        PlanOp::SetUciOptions {
            config: "network".into(),
            section: "wg0".into(),
            options: vec![
                ("proto".into(), literal("wireguard")),
                ("private_key".into(), literal(&p.private_key)),
                ("addresses".into(), literal(&p.address)),
            ],
        },
    ];
    if !p.dns.is_empty() {
        ops.push(PlanOp::UciAddList {
            config: "network".into(),
            section: "wg0".into(),
            option: "dns".into(),
            value: p.dns.clone(),
        });
    }
    ops.extend(vec![
        PlanOp::SetUciSection {
            config: "network".into(),
            section: "wg0_peer".into(),
            section_type: "wireguard_wg0".into(),
            options: Vec::new(),
        },
        PlanOp::SetUciOptions {
            config: "network".into(),
            section: "wg0_peer".into(),
            options: vec![
                ("public_key".into(), literal(&p.peer_public_key)),
                ("endpoint_host".into(), literal(&p.endpoint_host)),
                (
                    "endpoint_port".into(),
                    literal(&p.endpoint_port.to_string()),
                ),
                ("allowed_ips".into(), literal(&p.allowed_ips)),
                ("route_allowed_ips".into(), literal("1")),
                ("persistent_keepalive".into(), literal("25")),
            ],
        },
    ]);
    if !p.peer_psk.is_empty() {
        ops.push(PlanOp::SetUciOptions {
            config: "network".into(),
            section: "wg0_peer".into(),
            options: vec![("preshared_key".into(), literal(&p.peer_psk))],
        });
    }

    // Named firewall sections + while-loop cleanup of stale anonymous
    // sections to prevent accumulation across reconfigure runs.
    ops.extend(vec![
        PlanOp::CleanupUciSections {
            config: "firewall".into(),
            pattern: "name='vpn'".into(),
        },
        PlanOp::CleanupUciSections {
            config: "firewall".into(),
            pattern: "dest='vpn'".into(),
        },
        PlanOp::CleanupUciSections {
            config: "firewall".into(),
            pattern: "name='KillSwitch-Reject-NonVPN'".into(),
        },
        PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "wg_client_vpn".into(),
            section_type: "zone".into(),
            options: Vec::new(),
        },
        PlanOp::SetUciOptions {
            config: "firewall".into(),
            section: "wg_client_vpn".into(),
            options: vec![
                ("name".into(), literal("vpn")),
                ("input".into(), literal("REJECT")),
                ("output".into(), literal("ACCEPT")),
                ("forward".into(), literal("REJECT")),
                ("masq".into(), literal("1")),
                ("mtu_fix".into(), literal("1")),
                ("network".into(), literal("wg0")),
            ],
        },
        PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "wg_client_fwd".into(),
            section_type: "forwarding".into(),
            options: Vec::new(),
        },
        PlanOp::SetUciOptions {
            config: "firewall".into(),
            section: "wg_client_fwd".into(),
            options: vec![
                ("src".into(), literal("lan")),
                ("dest".into(), literal("vpn")),
            ],
        },
    ]);

    if p.kill_switch {
        ops.extend(vec![
            PlanOp::SetUciSection {
                config: "firewall".into(),
                section: "wg_client_killswitch".into(),
                section_type: "rule".into(),
                options: Vec::new(),
            },
            PlanOp::SetUciOptions {
                config: "firewall".into(),
                section: "wg_client_killswitch".into(),
                options: vec![
                    ("name".into(), literal("KillSwitch-Reject-NonVPN")),
                    ("src".into(), literal("lan")),
                    ("dest".into(), literal("wan")),
                    ("proto".into(), literal("all")),
                    ("target".into(), literal("REJECT")),
                ],
            },
        ]);
    }

    ops.extend(vec![
        PlanOp::CommitUci {
            config: "network".into(),
        },
        PlanOp::CommitUci {
            config: "firewall".into(),
        },
        PlanOp::Service {
            name: "network".into(),
            action: crate::plan::ServiceAction::Restart,
        },
        PlanOp::ShellCommand {
            command: format!(
                "echo 'WireGuard client configured: {}:{}'",
                p.endpoint_host, p.endpoint_port
            ),
        },
    ]);

    if p.kill_switch {
        ops.push(PlanOp::ShellCommand {
            command: killswitch_verify_command(),
        });
    }

    ops
}

/// Build the wireguard-server plan ops (mirror of
/// `_build_wireguard_server_ops`, same order and literals).
pub(crate) fn wireguard_server_ops(p: &WireguardServerProfile) -> Vec<PlanOp> {
    let listen_port = p.listen_port.to_string();
    let mut ops = vec![
        PlanOp::SetUciSection {
            config: "network".into(),
            section: "wg0".into(),
            section_type: "interface".into(),
            options: Vec::new(),
        },
        PlanOp::SetUciOptions {
            config: "network".into(),
            section: "wg0".into(),
            options: vec![
                ("proto".into(), literal("wireguard")),
                ("private_key".into(), literal(&p.private_key)),
                ("listen_port".into(), literal(&listen_port)),
            ],
        },
        PlanOp::UciAddList {
            config: "network".into(),
            section: "wg0".into(),
            option: "addresses".into(),
            value: p.subnet.clone(),
        },
        PlanOp::ShellCommand {
            command: String::from(
                "mkdir -p /etc/wireguard && \
                 wg show wg0 public-key > /etc/wireguard/server_public_key 2>/dev/null || true",
            ),
        },
    ];

    if !p.peer1_public_key.is_empty() {
        ops.push(PlanOp::SetUciSection {
            config: "network".into(),
            section: "wg0_peer1".into(),
            section_type: "wireguard_wg0".into(),
            options: Vec::new(),
        });
        let mut peer_values = vec![
            ("public_key".into(), literal(&p.peer1_public_key)),
            ("allowed_ips".into(), literal(&p.peer1_allowed_ips)),
            ("route_allowed_ips".into(), literal("1")),
        ];
        if !p.peer1_psk.is_empty() {
            peer_values.push(("preshared_key".into(), literal(&p.peer1_psk)));
        }
        ops.push(PlanOp::SetUciOptions {
            config: "network".into(),
            section: "wg0_peer1".into(),
            options: peer_values,
        });
    }

    ops.extend(vec![
        PlanOp::CleanupUciSections {
            config: "firewall".into(),
            pattern: "name='vpn'".into(),
        },
        PlanOp::CleanupUciSections {
            config: "firewall".into(),
            pattern: "name='Allow-WireGuard'".into(),
        },
        PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "wg_server_vpn".into(),
            section_type: "zone".into(),
            options: Vec::new(),
        },
        PlanOp::SetUciOptions {
            config: "firewall".into(),
            section: "wg_server_vpn".into(),
            options: vec![
                ("name".into(), literal("vpn")),
                ("input".into(), literal("ACCEPT")),
                ("output".into(), literal("ACCEPT")),
                ("forward".into(), literal("REJECT")),
                ("masq".into(), literal("1")),
                ("mtu_fix".into(), literal("1")),
                ("network".into(), literal("wg0")),
            ],
        },
        PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "wg_server_fwd_lan".into(),
            section_type: "forwarding".into(),
            options: Vec::new(),
        },
        PlanOp::SetUciOptions {
            config: "firewall".into(),
            section: "wg_server_fwd_lan".into(),
            options: vec![
                ("src".into(), literal("vpn")),
                ("dest".into(), literal("lan")),
            ],
        },
        PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "wg_server_fwd_wan".into(),
            section_type: "forwarding".into(),
            options: Vec::new(),
        },
        PlanOp::SetUciOptions {
            config: "firewall".into(),
            section: "wg_server_fwd_wan".into(),
            options: vec![
                ("src".into(), literal("vpn")),
                ("dest".into(), literal("wan")),
            ],
        },
        PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "wg_server_allow".into(),
            section_type: "rule".into(),
            options: Vec::new(),
        },
        PlanOp::SetUciOptions {
            config: "firewall".into(),
            section: "wg_server_allow".into(),
            options: vec![
                ("name".into(), literal("Allow-WireGuard")),
                ("src".into(), literal("wan")),
                ("dest_port".into(), literal(&listen_port)),
                ("proto".into(), literal("udp")),
                ("target".into(), literal("ACCEPT")),
            ],
        },
        PlanOp::CommitUci {
            config: "network".into(),
        },
        PlanOp::CommitUci {
            config: "firewall".into(),
        },
        PlanOp::Service {
            name: "network".into(),
            action: crate::plan::ServiceAction::Restart,
        },
        PlanOp::ShellCommand {
            command: format!(
                "echo \"WireGuard server configured: port {listen_port}, subnet {}\"",
                p.subnet
            ),
        },
    ]);

    ops
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{Profile, plan_profile, render_shell};
    use crate::state::DeviceState;
    use conwrt_types::DeviceModel;

    fn model() -> DeviceModel {
        let json = r#"{"id":"test-model","vendor":"Test","description":"d",
              "openwrt":{"target":"x/y","device":"t,d","profile":"t_d","version":"24"},
              "mac_oui":[]}"#;
        serde_json::from_str(json).expect("fixture model parses")
    }

    fn client() -> WireguardClientProfile {
        WireguardClientProfile {
            peer_public_key: "server-pub".into(),
            endpoint_host: "vpn.example.com".into(),
            ..WireguardClientProfile::defaults()
        }
    }

    #[test]
    fn client_defaults_match_1x() {
        let d = WireguardClientProfile::defaults();
        assert_eq!(d.private_key, "generate");
        assert_eq!(d.endpoint_port, 51820);
        assert_eq!(d.address, "10.67.0.2/32");
        assert_eq!(d.allowed_ips, "0.0.0.0/0, ::/0");
        assert!(d.kill_switch);
        assert_eq!(d.peer_psk, "");
        assert_eq!(d.dns, "");
    }

    #[test]
    fn server_defaults_match_1x() {
        let d = WireguardServerProfile::defaults();
        assert_eq!(d.listen_port, 51820);
        assert_eq!(d.subnet, "10.1.99.1/24");
        assert_eq!(d.peer1_allowed_ips, "10.1.99.2/32");
        assert_eq!(d.peer1_psk, "");
    }

    #[test]
    fn client_validation_mirrors_shell_safe() {
        assert!(client().validate().is_ok());
        // host validation: 1.x validate_host rejects empty/bad hosts,
        // accepts IPv4 and plain hostnames. Note 256.1.1.1 fails the IPv4
        // regex but PASSES the 1.x hostname regex (digits+dots) — accepted.
        for bad in [
            "",
            "bad host",
            "vpn.example.com-",
            "-vpn.example",
            "ex%ample",
        ] {
            let mut p = client();
            p.endpoint_host = bad.into();
            assert!(
                matches!(p.validate(), Err(Unsupported::InvalidParams(_))),
                "host {bad:?} must be rejected"
            );
        }
        for good in [
            "192.168.1.1",
            "255.255.255.255",
            "vpn.example.com",
            "a",
            "256.1.1.1",
        ] {
            let mut p = client();
            p.endpoint_host = good.into();
            assert!(p.validate().is_ok(), "host {good:?} must be accepted");
        }
        // 1.x validate_port: 1-65535
        let mut p = client();
        p.endpoint_port = 0;
        assert!(matches!(p.validate(), Err(Unsupported::InvalidParams(_))));
        // required peer public key
        let mut p = client();
        p.peer_public_key = String::new();
        assert!(matches!(p.validate(), Err(Unsupported::InvalidParams(_))));
    }

    #[test]
    fn server_port_zero_rejected() {
        let mut p = WireguardServerProfile::defaults();
        p.listen_port = 0;
        assert!(matches!(p.validate(), Err(Unsupported::InvalidParams(_))));
    }

    #[test]
    fn cleanup_helper_renders_exactly_like_1x() {
        // Byte-for-byte the Python `uci_cleanup_sections_sh` output.
        assert_eq!(
            cleanup_uci_sections_sh("firewall", "name='vpn'"),
            "while uci show firewall 2>/dev/null | grep -q \"name='vpn'\"; do \
             _s=$(uci show firewall 2>/dev/null | grep \"name='vpn'\" | head -1 \
             | cut -d. -f2 | cut -d= -f1); uci delete \"firewall.$_s\" 2>/dev/null; done; true"
        );
        assert_eq!(
            cleanup_uci_sections_sh("firewall", "name='Allow-WireGuard'"),
            "while uci show firewall 2>/dev/null | grep -q \"name='Allow-WireGuard'\"; do \
             _s=$(uci show firewall 2>/dev/null | grep \"name='Allow-WireGuard'\" | head -1 \
             | cut -d. -f2 | cut -d= -f1); uci delete \"firewall.$_s\" 2>/dev/null; done; true"
        );
    }

    #[test]
    fn client_plan_renders_1x_lines() {
        let plan = plan_profile(
            &DeviceState::OpenWrt,
            &model(),
            &Profile::WireguardClient(client()),
        )
        .expect("plans");
        assert_eq!(plan.profile_id, "wireguard-client");
        let script = render_shell(&plan);
        assert!(script.contains("uci set network.wg0=interface"));
        assert!(script.contains("uci set network.wg0.proto='wireguard'"));
        assert!(script.contains("uci set network.wg0.private_key='generate'"));
        assert!(script.contains("uci set network.wg0.addresses='10.67.0.2/32'"));
        assert!(script.contains("uci set network.wg0_peer=wireguard_wg0"));
        assert!(script.contains("uci set network.wg0_peer.public_key='server-pub'"));
        assert!(script.contains("uci set network.wg0_peer.endpoint_host='vpn.example.com'"));
        assert!(script.contains("uci set network.wg0_peer.endpoint_port='51820'"));
        assert!(script.contains("uci set network.wg0_peer.allowed_ips='0.0.0.0/0, ::/0'"));
        assert!(script.contains("uci set network.wg0_peer.route_allowed_ips='1'"));
        assert!(script.contains("uci set network.wg0_peer.persistent_keepalive='25'"));
        // no dns/psk by default
        assert!(!script.contains("uci add_list network.wg0.dns"));
        assert!(!script.contains("preshared_key"));
        // firewall zone, forwarding, kill switch
        assert!(script.contains("uci set firewall.wg_client_vpn=zone"));
        assert!(script.contains("uci set firewall.wg_client_vpn.name='vpn'"));
        assert!(script.contains("uci set firewall.wg_client_vpn.input='REJECT'"));
        assert!(script.contains("uci set firewall.wg_client_vpn.masq='1'"));
        assert!(script.contains("uci set firewall.wg_client_fwd=forwarding"));
        assert!(script.contains("uci set firewall.wg_client_fwd.dest='vpn'"));
        assert!(script.contains("uci set firewall.wg_client_killswitch=rule"));
        assert!(
            script
                .contains("uci set firewall.wg_client_killswitch.name='KillSwitch-Reject-NonVPN'")
        );
        assert!(script.contains("uci commit network"));
        assert!(script.contains("uci commit firewall"));
        assert!(script.contains("/etc/init.d/network restart"));
        assert!(script.contains("echo 'WireGuard client configured: vpn.example.com:51820'"));
        assert!(script.contains("wg show wg0 2>/dev/null | grep -q 'latest handshake'"));
        assert!(script.contains("fw4 restart"));
    }

    #[test]
    fn client_plan_without_kill_switch_drops_rule_and_loop() {
        let mut p = client();
        p.kill_switch = false;
        let plan = plan_profile(
            &DeviceState::OpenWrt,
            &model(),
            &Profile::WireguardClient(p),
        )
        .expect("plans");
        let script = render_shell(&plan);
        assert!(!script.contains("wg_client_killswitch"));
        assert!(!script.contains("latest handshake"));
        assert!(script.contains("uci commit firewall"));
    }

    #[test]
    fn client_plan_with_dns_and_psk() {
        let mut p = client();
        p.dns = "10.64.0.1".into();
        p.peer_psk = "shared-secret".into();
        let plan = plan_profile(
            &DeviceState::OpenWrt,
            &model(),
            &Profile::WireguardClient(p),
        )
        .expect("plans");
        let script = render_shell(&plan);
        assert!(script.contains("uci add_list network.wg0.dns='10.64.0.1'"));
        assert!(script.contains("uci set network.wg0_peer.preshared_key='shared-secret'"));
    }

    #[test]
    fn server_plan_renders_1x_lines() {
        let plan = plan_profile(
            &DeviceState::OpenWrt,
            &model(),
            &Profile::WireguardServer(WireguardServerProfile::defaults()),
        )
        .expect("plans");
        assert_eq!(plan.profile_id, "wireguard-server");
        let script = render_shell(&plan);
        assert!(script.contains("uci set network.wg0=interface"));
        assert!(script.contains("uci set network.wg0.listen_port='51820'"));
        // server addresses go through add_list (1.x asymmetry vs client)
        assert!(script.contains("uci add_list network.wg0.addresses='10.1.99.1/24'"));
        assert!(script.contains(
            "mkdir -p /etc/wireguard && wg show wg0 public-key > \
             /etc/wireguard/server_public_key 2>/dev/null || true"
        ));
        // no peer by default
        assert!(!script.contains("wg0_peer1"));
        assert!(script.contains("uci set firewall.wg_server_vpn=zone"));
        assert!(script.contains("uci set firewall.wg_server_vpn.input='ACCEPT'"));
        assert!(script.contains("uci set firewall.wg_server_fwd_lan=forwarding"));
        assert!(script.contains("uci set firewall.wg_server_fwd_wan=forwarding"));
        assert!(script.contains("uci set firewall.wg_server_allow=rule"));
        assert!(script.contains("uci set firewall.wg_server_allow.dest_port='51820'"));
        assert!(script.contains("uci set firewall.wg_server_allow.proto='udp'"));
        assert!(
            script
                .contains("echo \"WireGuard server configured: port 51820, subnet 10.1.99.1/24\"")
        );
    }

    #[test]
    fn server_plan_with_peer_and_psk() {
        let mut p = WireguardServerProfile::defaults();
        p.peer1_public_key = "peer1-pub".into();
        p.peer1_psk = "peer1-psk".into();
        let plan = plan_profile(
            &DeviceState::OpenWrt,
            &model(),
            &Profile::WireguardServer(p),
        )
        .expect("plans");
        let script = render_shell(&plan);
        assert!(script.contains("uci set network.wg0_peer1=wireguard_wg0"));
        assert!(script.contains("uci set network.wg0_peer1.public_key='peer1-pub'"));
        assert!(script.contains("uci set network.wg0_peer1.allowed_ips='10.1.99.2/32'"));
        assert!(script.contains("uci set network.wg0_peer1.preshared_key='peer1-psk'"));
        // psk comes last in the 1.x peer dict ordering
        let pk = script.find("wg0_peer1.public_key").expect("pubkey set");
        let psk = script.find("wg0_peer1.preshared_key").expect("psk set");
        assert!(pk < psk);
    }

    #[test]
    fn unconfirmed_state_refused() {
        let err = plan_profile(
            &DeviceState::SshOnly,
            &model(),
            &Profile::WireguardClient(client()),
        );
        assert!(matches!(err, Err(Unsupported::UnconfirmedDeviceState(_))));
    }
}
