//! Cross-implementation parity harness (Rust side).
//!
//! The conwrt plan pipeline exists twice: the complete 1.x Python
//! implementation (`scripts/use_cases/*` → `profile.ops.render_shell`) and
//! the Rust workspace port (`plan.rs` + this crate's profiles). This
//! module is the Rust half of the parity proof: it renders the SAME JSON
//! fixtures (`tests/fixtures/parity/*.json`) through the Rust planner and
//! renderer, so the Python half (`tests/test_parity_rust_plan.py`) can
//! diff the two outputs for the same use case + params.
//!
//! The fixtures and the Python-side goldens are authoritative; the gap
//! list (`tests/fixtures/parity/manifest.json`) records which presets
//! have NOT reached parity yet and why. The list must shrink — never
//! silently change.
//!
//! Enabled for tests and via the `parity-fixture` feature (used by the
//! `conwrt-plan-render` binary in `apps/conwrt-cli`). Requires std.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::plan::{
    AdguardProfile, ApNostrIdProfile, AutoSqmProfile, CashuVpnClientProfile,
    ConfigurationWizzardProfile, DohProfile, FipsBluetoothRfcommProfile, FipsPeer,
    FleetIdentityProfile, GuestWifiProfile, Mesh11sdProfile, MptcpBondingProfile, Mwan3Profile,
    NodnsProfile, OpenClashProfile, OpenPerfClientProfile, OpenPerfServerProfile, PbrProfile,
    Profile, RescueWatchdogProfile, SqmProfile, SshHardeningProfile, SslProfile, TetherProfile,
    TetherVariant, TollgateCellularProfile, TollgateProfile, TollgateSecurityProfile,
    TravelmateProfile, VpnIvpnProfile, VpnMullvadProfile, VpnNodeProfile, VpnNordvpnIke2Profile,
    VpnNordvpnOpenvpnProfile, VpnNordvpnProfile, VpnOpenvpnProfile, VpnPiaOpenvpnProfile,
    VpnPiaProfile, VpnSurfsharkProfile, WifiUplink, WireguardClientProfile, WireguardServerProfile,
    render_shell,
};
use crate::state::DeviceState;
use conwrt_types::DeviceModel;

/// Model id used for parity plans (the model only labels the plan header).
pub const PARITY_MODEL_ID: &str = "parity-fixture";

fn parity_model() -> DeviceModel {
    parity_model_for("24", &[])
}

/// The fixture model, with optional per-fixture OpenWrt version
/// (`model_version` — mptcp-bonding's 25.12 floor) and extra capabilities
/// (`model_capabilities` — fips-bluetooth-rfcomm needs `bluetooth`).
fn parity_model_for(version: &str, extra_caps: &[&str]) -> DeviceModel {
    let mut caps = vec!["ethernet", "wifi", "usb"];
    caps.extend_from_slice(extra_caps);
    let caps_json = caps
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(",");
    let json = format!(
        r#"{{"id":"parity-fixture","vendor":"Parity","description":"fixture",
        "openwrt":{{"target":"x/y","device":"t,d","profile":"t_d","version":"{version}"}},
        "mac_oui":[],
        "capabilities":[{caps_json}]}}"#
    );
    serde_json::from_str(&json).expect("parity fixture model parses")
}

fn get_str(params: &serde_json::Value, key: &str) -> Option<String> {
    params.get(key).and_then(|v| {
        if v.is_string() {
            v.as_str().map(String::from)
        } else if v.is_number() {
            Some(v.to_string())
        } else {
            None
        }
    })
}

fn get_u16(params: &serde_json::Value, key: &str, default: u16) -> u16 {
    params
        .get(key)
        .and_then(|v| v.as_u64())
        .map_or(default, |v| u16::try_from(v).unwrap_or(default))
}

fn get_bool(params: &serde_json::Value, key: &str, default: bool) -> bool {
    params.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
}

/// Map a parity fixture `{"use_case": ..., "params": {...}}` to a Profile.
///
/// Defaults mirror the Python `_resolve_params` helpers exactly so a
/// fixture may omit any param the Python side defaults too.
pub fn profile_from_fixture(fixture: &serde_json::Value) -> Result<Profile, String> {
    let use_case = fixture
        .get("use_case")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "fixture missing 'use_case'".to_string())?;
    let params = fixture
        .get("params")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    match use_case {
        "wireguard-client" => {
            let mut p = WireguardClientProfile::default();
            if let Some(v) = get_str(&params, "private_key") {
                p.private_key = v;
            }
            if let Some(v) = get_str(&params, "peer_public_key") {
                p.peer_public_key = v;
            }
            if let Some(v) = get_str(&params, "endpoint_host") {
                p.endpoint_host = v;
            }
            p.endpoint_port = get_u16(&params, "endpoint_port", p.endpoint_port);
            if let Some(v) = get_str(&params, "peer_psk") {
                p.peer_psk = v;
            }
            if let Some(v) = get_str(&params, "address") {
                p.address = v;
            }
            if let Some(v) = get_str(&params, "dns") {
                p.dns = v;
            }
            p.kill_switch = get_bool(&params, "kill_switch", p.kill_switch);
            if let Some(v) = get_str(&params, "allowed_ips") {
                p.allowed_ips = v;
            }
            Ok(Profile::WireguardClient(p))
        }
        "wireguard-server" => {
            let mut p = WireguardServerProfile::default();
            if let Some(v) = get_str(&params, "private_key") {
                p.private_key = v;
            }
            p.listen_port = get_u16(&params, "listen_port", p.listen_port);
            if let Some(v) = get_str(&params, "subnet") {
                p.subnet = v;
            }
            if let Some(v) = get_str(&params, "peer1_public_key") {
                p.peer1_public_key = v;
            }
            if let Some(v) = get_str(&params, "peer1_allowed_ips") {
                p.peer1_allowed_ips = v;
            }
            if let Some(v) = get_str(&params, "peer1_psk") {
                p.peer1_psk = v;
            }
            Ok(Profile::WireguardServer(p))
        }
        "sqm" => {
            let mut p = SqmProfile {
                download_kbps: 10_000,
                upload_kbps: 5_000,
                interface: "wan".into(),
                qdisc: "cake".into(),
                script: "piece_of_cake.qos".into(),
                link_layer: "none".into(),
                overhead: 0,
            };
            if let Some(v) = params.get("download_kbps").and_then(|v| v.as_u64()) {
                p.download_kbps = u32::try_from(v).map_err(|_| "download_kbps out of range")?;
            }
            if let Some(v) = params.get("upload_kbps").and_then(|v| v.as_u64()) {
                p.upload_kbps = u32::try_from(v).map_err(|_| "upload_kbps out of range")?;
            }
            if let Some(v) = get_str(&params, "interface") {
                p.interface = v;
            }
            if let Some(v) = get_str(&params, "qdisc") {
                p.qdisc = v;
            }
            if let Some(v) = get_str(&params, "script") {
                p.script = v;
            }
            if let Some(v) = get_str(&params, "link_layer") {
                p.link_layer = v;
            }
            if let Some(v) = params.get("overhead").and_then(|v| v.as_u64()) {
                p.overhead = u16::try_from(v).map_err(|_| "overhead out of range")?;
            }
            Ok(Profile::Sqm(p))
        }
        "doh" => {
            let p = DohProfile {
                provider: get_str(&params, "provider").unwrap_or_else(|| "cloudflare".into()),
                listen_port: get_u16(&params, "listen_port", 5053),
            };
            Ok(Profile::Doh(p))
        }
        "adguard" => {
            let p = AdguardProfile {
                listen_ip: get_str(&params, "listen_ip").unwrap_or_else(|| "0.0.0.0".into()),
                web_port: get_u16(&params, "web_port", 3000),
                dns_port: get_u16(&params, "dns_port", 5353),
            };
            Ok(Profile::Adguard(p))
        }
        "ssh-hardening" => {
            let p = SshHardeningProfile {
                disable_password_auth: get_bool(&params, "disable_password_auth", true),
                idle_timeout: params
                    .get("idle_timeout")
                    .and_then(|v| v.as_u64())
                    .map(|v| u32::try_from(v).map_err(|_| "idle_timeout out of range"))
                    .transpose()?
                    .unwrap_or(300),
                max_auth_tries: params
                    .get("max_auth_tries")
                    .and_then(|v| v.as_u64())
                    .map(|v| u32::try_from(v).map_err(|_| "max_auth_tries out of range"))
                    .transpose()?
                    .unwrap_or(3),
                port: get_u16(&params, "port", 22),
                restrict_gateway_ports: get_bool(&params, "restrict_gateway_ports", true),
            };
            Ok(Profile::SshHardening(p))
        }
        "mwan3" => {
            let mut p = Mwan3Profile::default();
            if let Some(v) = get_str(&params, "primary") {
                p.primary = v;
            }
            if let Some(v) = get_str(&params, "secondary") {
                p.secondary = v;
            }
            if let Some(v) = get_str(&params, "policy") {
                p.policy = v;
            }
            if let Some(list) = params.get("track_ips").and_then(|v| v.as_array()) {
                p.track_ips = list
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect();
            }
            Ok(Profile::Mwan3(p))
        }
        "mesh11sd" => {
            let p = Mesh11sdProfile {
                mesh_id: get_str(&params, "mesh_id").ok_or("mesh_id is required")?,
                ssid: get_str(&params, "ssid").unwrap_or_else(|| "MeshNet".into()),
                encryption: get_str(&params, "encryption").unwrap_or_else(|| "1".into()),
                key: get_str(&params, "key").unwrap_or_default(),
                auto_config: get_str(&params, "auto_config").unwrap_or_else(|| "0".into()),
            };
            Ok(Profile::Mesh11sd(p))
        }
        "travelmate" => {
            let mut p = TravelmateProfile::default();
            if let Some(v) = get_str(&params, "radio") {
                p.radio = v;
            }
            if let Some(v) = params.get("timeout").and_then(|v| v.as_u64()) {
                p.timeout = u32::try_from(v).map_err(|_| "timeout out of range")?;
            }
            if let Some(v) = params.get("retry").and_then(|v| v.as_u64()) {
                p.retry = u32::try_from(v).map_err(|_| "retry out of range")?;
            }
            p.captive = get_bool(&params, "captive", true);
            if let Some(list) = params.get("uplinks").and_then(|v| v.as_array()) {
                for (idx, up) in list.iter().enumerate() {
                    let get = |k: &str| {
                        up.get(k)
                            .and_then(|v| v.as_str())
                            .map(str::to_string)
                            .unwrap_or_default()
                    };
                    p.uplinks.push(WifiUplink {
                        ssid: get("ssid"),
                        psk: get("psk"),
                        encryption: get("encryption"),
                        radio: get("radio"),
                        // 1.x seeded-uplink section naming: trm_uplink<idx+1>
                        iface: format!("trm_uplink{}", idx + 1),
                    });
                }
            }
            Ok(Profile::Travelmate(p))
        }
        "ssl" => {
            let p = SslProfile {
                provider: get_str(&params, "provider").unwrap_or_else(|| "lancert".into()),
                enable_uhttpd_https: get_bool(&params, "enable_uhttpd_https", true),
                open_port_443_nds: get_bool(&params, "open_port_443_nds", true),
            };
            Ok(Profile::Ssl(p))
        }
        "nodns" => {
            let mut p = NodnsProfile::default();
            if let Some(v) = get_str(&params, "zone") {
                p.zone = v;
            }
            if let Some(v) = get_str(&params, "api_url") {
                p.api_url = v;
            }
            if let Some(v) = params.get("poll_interval").and_then(|v| v.as_u64()) {
                p.poll_interval = u32::try_from(v).map_err(|_| "poll_interval out of range")?;
            }
            Ok(Profile::Nodns(p))
        }
        "pbr" => {
            let mut p = PbrProfile::default();
            if let Some(v) = get_str(&params, "wan_interface") {
                p.wan_interface = v;
            }
            if let Some(v) = get_str(&params, "lan_interface") {
                p.lan_interface = v;
            }
            p.strict_enforcement = get_bool(&params, "strict_enforcement", true);
            Ok(Profile::Pbr(p))
        }
        "openclash" => {
            let p = OpenClashProfile {
                proxy_type: get_str(&params, "proxy_type").unwrap_or_else(|| "ss".into()),
                core_type: get_str(&params, "core_type").unwrap_or_else(|| "Meta".into()),
                dns_mode: get_str(&params, "dns_mode").unwrap_or_else(|| "redir-host".into()),
            };
            Ok(Profile::OpenClash(p))
        }
        "guest-wifi" => {
            let p = GuestWifiProfile {
                ssid: get_str(&params, "ssid").unwrap_or_else(|| "Guest".into()),
                key: get_str(&params, "key").unwrap_or_default(),
                encryption: get_str(&params, "encryption").unwrap_or_else(|| "psk2".into()),
                band: get_str(&params, "band").unwrap_or_else(|| "2.4ghz".into()),
                isolation: get_bool(&params, "isolation", true),
                network_name: get_str(&params, "network_name").unwrap_or_else(|| "guest".into()),
            };
            Ok(Profile::GuestWifi(p))
        }
        "tollgate" => {
            let mut p = TollgateProfile::default();
            if let Some(v) = get_str(&params, "gateway_name") {
                p.gateway_name = v;
            }
            if let Some(v) = get_str(&params, "gateway_domain") {
                p.gateway_domain = v;
            }
            if let Some(v) = get_str(&params, "clientid") {
                p.clientid = v;
            }
            if let Some(v) = get_str(&params, "mint_url") {
                p.mint_url = v;
            }
            if let Some(v) = get_str(&params, "lightning_address") {
                p.lightning_address = v;
            }
            if let Some(v) = get_str(&params, "hotplug_interface") {
                p.hotplug_interface = v;
            }
            if let Some(v) = params.get("price_per_minute").and_then(|v| v.as_u64()) {
                p.price_per_minute =
                    u32::try_from(v).map_err(|_| "price_per_minute out of range")?;
            }
            if let Some(v) = params.get("price_sats_per_mib").and_then(|v| v.as_u64()) {
                p.price_sats_per_mib =
                    u32::try_from(v).map_err(|_| "price_sats_per_mib out of range")?;
            }
            p.allow_lan_ssh = get_bool(&params, "allow_lan_ssh", false);
            p.install_hotplug = get_bool(&params, "install_hotplug", true);
            Ok(Profile::Tollgate(p))
        }
        "tollgate-security" => Ok(Profile::TollgateSecurity(TollgateSecurityProfile)),
        "auto-sqm" => {
            let mut p = AutoSqmProfile::default();
            if let Some(v) = get_str(&params, "mode") {
                p.mode = v;
            }
            if let Some(v) = get_str(&params, "interface") {
                p.interface = v;
            }
            if let Some(v) = get_str(&params, "device") {
                p.device = v;
            }
            if let Some(v) = get_str(&params, "qdisc") {
                p.qdisc = v;
            }
            if let Some(v) = get_str(&params, "script") {
                p.script = v;
            }
            if let Some(v) = get_str(&params, "measurement_mode") {
                p.measurement_mode = v;
            }
            if let Some(v) = get_str(&params, "iperf3_host") {
                p.iperf3_host = v;
            }
            if let Some(v) = get_str(&params, "test_url") {
                p.test_url = v;
            }
            for (key, slot) in [
                ("target_percent", &mut p.target_percent),
                ("download_kbps", &mut p.download_kbps),
                ("upload_kbps", &mut p.upload_kbps),
                ("upload_fallback_kbps", &mut p.upload_fallback_kbps),
                ("hysteresis_percent", &mut p.hysteresis_percent),
                ("dynamic_interval_hours", &mut p.dynamic_interval_hours),
            ] {
                if let Some(v) = params.get(key).and_then(|v| v.as_u64()) {
                    *slot = u32::try_from(v).map_err(|_| "auto-sqm numeric param out of range")?;
                }
            }
            if let Some(v) = params.get("iperf3_port").and_then(|v| v.as_u64()) {
                p.iperf3_port = u16::try_from(v).map_err(|_| "iperf3_port out of range")?;
            }
            Ok(Profile::AutoSqm(p))
        }
        "cashu-vpn-client" => {
            let mut p = CashuVpnClientProfile::default();
            if let Some(v) = get_str(&params, "private_key") {
                p.private_key = v;
            }
            p.peer_public_key =
                get_str(&params, "peer_public_key").ok_or("peer_public_key is required")?;
            p.peer_ip = get_str(&params, "peer_ip").ok_or("peer_ip is required")?;
            if let Some(v) = get_str(&params, "server_host") {
                p.server_host = v;
            }
            if let Some(v) = params.get("server_port").and_then(|v| v.as_u64()) {
                p.server_port = u16::try_from(v).map_err(|_| "server_port out of range")?;
            }
            if let Some(v) = get_str(&params, "allowed_ips") {
                p.allowed_ips = v;
            }
            if let Some(v) = get_str(&params, "dns") {
                p.dns = v;
            }
            p.kill_switch = get_bool(&params, "kill_switch", true);
            Ok(Profile::CashuVpnClient(p))
        }
        "rescue-watchdog" => {
            let p = RescueWatchdogProfile {
                target: get_str(&params, "target").unwrap_or_else(|| "192.168.1.254".into()),
            };
            Ok(Profile::RescueWatchdog(p))
        }
        "tether" | "tether-android" | "tether-android-adb" | "tether-ios" => {
            let variant = match use_case {
                "tether" => TetherVariant::Auto,
                "tether-android" => TetherVariant::Android,
                "tether-android-adb" => TetherVariant::AndroidAdb,
                _ => TetherVariant::Ios,
            };
            let mut p = TetherProfile {
                variant,
                ..TetherProfile::default()
            };
            if let Some(v) = get_str(&params, "interface") {
                p.interface = v;
            }
            Ok(Profile::Tether(p))
        }
        "ap-nostr-id" => {
            let p = ApNostrIdProfile {
                npub: get_str(&params, "npub").unwrap_or_default(),
                nsec: get_str(&params, "nsec").unwrap_or_default(),
            };
            Ok(Profile::ApNostrId(p))
        }
        "vpn-node" => {
            let mut p = VpnNodeProfile::default();
            if let Some(v) = get_str(&params, "nsec") {
                p.nsec = v;
            }
            if let Some(v) = get_str(&params, "d_tag") {
                p.d_tag = v;
            }
            if let Some(v) = get_str(&params, "title") {
                p.title = v;
            }
            if let Some(v) = get_str(&params, "endpoint_host") {
                p.endpoint_host = v;
            }
            if let Some(v) = params.get("endpoint_port").and_then(|v| v.as_u64()) {
                p.endpoint_port = u16::try_from(v).map_err(|_| "endpoint_port out of range")?;
            }
            if let Some(v) = get_str(&params, "country") {
                p.country = v;
            }
            if let Some(v) = params.get("price_amount").and_then(|v| v.as_u64()) {
                p.price_amount = u32::try_from(v).map_err(|_| "price_amount out of range")?;
            }
            if let Some(v) = get_str(&params, "price_unit") {
                p.price_unit = v;
            }
            if let Some(v) = get_str(&params, "content") {
                p.content = v;
            }
            if let Some(v) = get_str(&params, "relays") {
                p.relays = v;
            }
            if let Some(v) = get_str(&params, "nak_path") {
                p.nak_path = v;
            }
            Ok(Profile::VpnNode(p))
        }
        "openperf_client" => {
            let p = OpenPerfClientProfile {
                mgmt_ssid: get_str(&params, "mgmt_ssid").unwrap_or_else(|| "openperf".into()),
            };
            Ok(Profile::OpenPerfClient(p))
        }
        "openperf_server" => {
            let p = OpenPerfServerProfile {
                mgmt_ssid: get_str(&params, "mgmt_ssid").unwrap_or_else(|| "openperf".into()),
                port: get_u16(&params, "port", 7777),
            };
            Ok(Profile::OpenPerfServer(p))
        }
        "configurationwizzard" => Ok(Profile::ConfigurationWizzard(ConfigurationWizzardProfile)),
        "fleet_identity" => {
            let mut p = FleetIdentityProfile {
                salt: get_str(&params, "salt").ok_or("salt is required")?,
                ..Default::default()
            };
            if let Some(v) = get_str(&params, "hostname_prefix") {
                p.hostname_prefix = v;
            }
            if let Some(v) = get_str(&params, "ssid_prefix") {
                p.ssid_prefix = v;
            }
            if let Some(v) = get_str(&params, "wifi_network") {
                p.wifi_network = v;
            }
            if let Some(v) = params.get("password_length").and_then(|v| v.as_u64()) {
                p.password_length = u32::try_from(v).map_err(|_| "password_length out of range")?;
            }
            p.disarm_dhcp = get_bool(&params, "disarm_dhcp", true);
            p.configure_ap = get_bool(&params, "configure_ap", true);
            Ok(Profile::FleetIdentity(p))
        }
        "tollgate-cellular" => {
            let mut p = TollgateCellularProfile::default();
            for (key, slot) in [
                ("apn", &mut p.apn),
                ("sim_slot", &mut p.sim_slot),
                ("wan_iface", &mut p.wan_iface),
                ("usb_iface", &mut p.usb_iface),
                ("iccid", &mut p.iccid),
                ("provider", &mut p.provider),
                ("eid", &mut p.eid),
                ("balance_api", &mut p.balance_api),
                ("management_ip", &mut p.management_ip),
            ] {
                if let Some(v) = get_str(&params, key) {
                    *slot = v;
                }
            }
            Ok(Profile::TollgateCellular(p))
        }
        "vpn-ivpn" => {
            let p = VpnIvpnProfile {
                account_id: get_str(&params, "account_id").ok_or("account_id is required")?,
                upstream_gateway: get_str(&params, "upstream_gateway")
                    .unwrap_or_else(|| "192.168.8.1".into()),
                upstream_iface: get_str(&params, "upstream_iface").unwrap_or_else(|| "wwan".into()),
                kill_switch: get_bool(&params, "kill_switch", true),
            };
            Ok(Profile::VpnIvpn(p))
        }
        "vpn-mullvad" => {
            let p = VpnMullvadProfile {
                account_token: get_str(&params, "account_token")
                    .ok_or("account_token is required")?,
                country: get_str(&params, "country").unwrap_or_default(),
                upstream_gateway: get_str(&params, "upstream_gateway")
                    .ok_or("upstream_gateway is required")?,
                upstream_iface: get_str(&params, "upstream_iface").unwrap_or_else(|| "wwan".into()),
                kill_switch: get_bool(&params, "kill_switch", true),
            };
            Ok(Profile::VpnMullvad(p))
        }
        "vpn-surfshark" => {
            let p = VpnSurfsharkProfile {
                username: get_str(&params, "username").ok_or("username is required")?,
                password: get_str(&params, "password").ok_or("password is required")?,
                country: get_str(&params, "country").unwrap_or_default(),
                upstream_gateway: get_str(&params, "upstream_gateway")
                    .ok_or("upstream_gateway is required")?,
                upstream_iface: get_str(&params, "upstream_iface").unwrap_or_else(|| "wwan".into()),
                kill_switch: get_bool(&params, "kill_switch", true),
            };
            Ok(Profile::VpnSurfshark(p))
        }
        "vpn-pia" => {
            let p = VpnPiaProfile {
                username: get_str(&params, "username").ok_or("username is required")?,
                password: get_str(&params, "password").ok_or("password is required")?,
                region: get_str(&params, "region").unwrap_or_else(|| "netherlands".into()),
                upstream_gateway: get_str(&params, "upstream_gateway")
                    .ok_or("upstream_gateway is required")?,
                upstream_iface: get_str(&params, "upstream_iface").unwrap_or_else(|| "wwan".into()),
                kill_switch: get_bool(&params, "kill_switch", true),
                ..Default::default()
            };
            Ok(Profile::VpnPia(p))
        }
        "vpn-openvpn" => {
            let p = VpnOpenvpnProfile {
                ovpn_config: get_str(&params, "ovpn_config").ok_or("ovpn_config is required")?,
                username: get_str(&params, "username").unwrap_or_default(),
                password: get_str(&params, "password").unwrap_or_default(),
                proto: get_str(&params, "proto").unwrap_or_else(|| "udp".into()),
                kill_switch: get_bool(&params, "kill_switch", true),
            };
            Ok(Profile::VpnOpenvpn(p))
        }
        "vpn-pia-openvpn" => {
            let p = VpnPiaOpenvpnProfile {
                username: get_str(&params, "username").unwrap_or_default(),
                password: get_str(&params, "password").unwrap_or_default(),
                port: get_str(&params, "port").unwrap_or_else(|| "1198".into()),
                upstream_gateway: get_str(&params, "upstream_gateway").unwrap_or_default(),
                upstream_iface: get_str(&params, "upstream_iface").unwrap_or_else(|| "wan".into()),
                kill_switch: get_bool(&params, "kill_switch", true),
                allow_management: get_bool(&params, "allow_management", true),
                ..Default::default()
            };
            Ok(Profile::VpnPiaOpenvpn(p))
        }
        "vpn-nordvpn-openvpn" => {
            let p = VpnNordvpnOpenvpnProfile {
                username: get_str(&params, "username").unwrap_or_else(|| "svcuser1234".into()),
                password: get_str(&params, "password").unwrap_or_else(|| "svcpass5678abcd".into()),
                station: get_str(&params, "station").unwrap_or_else(|| "193.29.107.10".into()),
                hostname: get_str(&params, "server").unwrap_or_else(|| "de500.nordvpn.com".into()),
                ..Default::default()
            };
            Ok(Profile::VpnNordvpnOpenvpn(p))
        }
        "mptcp-bonding" => {
            let p = MptcpBondingProfile {
                server_ipv4: get_str(&params, "server_ipv4").unwrap_or_default(),
                server_port: get_u16(&params, "server_port", 0),
                uuid: get_str(&params, "uuid").unwrap_or_default(),
            };
            Ok(Profile::MptcpBonding(p))
        }
        "vpn-nordvpn-ikev2" => {
            let p = VpnNordvpnIke2Profile {
                username: get_str(&params, "username").ok_or("username is required")?,
                password: get_str(&params, "password").ok_or("password is required")?,
                station: get_str(&params, "station").ok_or("station is required")?,
                hostname: get_str(&params, "hostname")
                    .or_else(|| get_str(&params, "server"))
                    .ok_or("hostname is required")?,
                hw_accel: get_bool(&params, "hw_accel", true),
                kill_switch: get_bool(&params, "kill_switch", true),
                allow_management: get_bool(&params, "allow_management", true),
                ..Default::default()
            };
            Ok(Profile::VpnNordvpnIke2(p))
        }
        "fips-bluetooth-rfcomm" => {
            let mut p = FipsBluetoothRfcommProfile {
                role: get_str(&params, "role").unwrap_or_else(|| "client".into()),
                channel: u8::try_from(params.get("channel").and_then(|v| v.as_u64()).unwrap_or(1))
                    .map_err(|_| "channel out of range")?,
                tun_enabled: get_bool(&params, "tun_enabled", true),
                tun_dns: get_bool(&params, "tun_dns", true),
                tun_gateway: get_bool(&params, "tun_gateway", true),
                bt_pin: get_str(&params, "bt_pin").unwrap_or_else(|| "0000".into()),
                peers: Vec::new(),
            };
            if let Some(list) = params.get("peers").and_then(|v| v.as_array()) {
                for entry in list {
                    let get = |k: &str| {
                        entry
                            .get(k)
                            .and_then(|v| v.as_str())
                            .map(String::from)
                            .unwrap_or_default()
                    };
                    p.peers.push(FipsPeer {
                        npub: get("npub"),
                        bt_mac: get("bt_mac"),
                        alias: get("alias"),
                    });
                }
            }
            Ok(Profile::FipsBluetoothRfcomm(p))
        }
        "vpn-nordvpn" => {
            let p = VpnNordvpnProfile {
                private_key: get_str(&params, "private_key")
                    .unwrap_or_else(|| "STUBPRIVKEYbase64filledfortestonly0000=".into()),
                server_public_key: get_str(&params, "server_public_key")
                    .unwrap_or_else(|| "STUBPUBKEYbase64filledfortestonly0000=".into()),
                endpoint_host: get_str(&params, "server")
                    .unwrap_or_else(|| "de500.nordvpn.com".into()),
                // 1.x post-API-change pins the SERVER HOSTNAME as the /32
                // route target (no more station-IP lookup) — default to the
                // server param, same as the Python stub pipeline.
                route_target: get_str(&params, "route_target")
                    .or_else(|| get_str(&params, "server"))
                    .unwrap_or_else(|| "de500.nordvpn.com".into()),
                endpoint_port: get_str(&params, "endpoint_port").unwrap_or_else(|| "51820".into()),
                address: get_str(&params, "address").unwrap_or_else(|| "10.5.0.2/32".into()),
                mtu: get_str(&params, "mtu").unwrap_or_else(|| "1420".into()),
                keepalive: get_str(&params, "keepalive").unwrap_or_else(|| "25".into()),
                upstream_gateway: get_str(&params, "upstream_gateway")
                    .unwrap_or_else(|| "192.168.8.1".into()),
                upstream_iface: get_str(&params, "upstream_iface").unwrap_or_else(|| "wwan".into()),
                ..VpnNordvpnProfile::default()
            };
            Ok(Profile::VpnNordvpn(p))
        }
        other => Err(format!("no Rust profile for use case '{other}' yet")),
    }
}

/// Render a parity fixture through the full Rust pipeline:
/// fixture → Profile → `plan_profile` → `render_shell`.
pub fn render_fixture(fixture: &serde_json::Value) -> Result<String, String> {
    let profile = profile_from_fixture(fixture)?;
    let extra_caps: Vec<&str> = fixture
        .get("model_capabilities")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect::<Vec<&str>>())
        .unwrap_or_default();
    let model = parity_model_for(
        fixture
            .get("model_version")
            .and_then(|v| v.as_str())
            .unwrap_or("24"),
        &extra_caps,
    );
    let plan = crate::plan::plan_profile(&DeviceState::OpenWrt, &model, &profile)
        .map_err(|e| e.to_string())?;
    Ok(render_shell(&plan))
}

/// Read a fixture file and render it (std convenience for the
/// `conwrt-plan-render` binary).
pub fn render_fixture_file(path: &std::path::Path) -> Result<String, String> {
    let raw =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let fixture: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("parsing {}: {e}", path.display()))?;
    render_fixture(&fixture)
}

/// Strip presentation-only lines shared by both renderers: shebang,
/// `set -e`, comment lines, blank lines, and the 2.x-only package-install
/// preamble (`EnsurePackage` apk/opkg blocks — a deliberate Rust-side
/// extension; 1.x Python bakes packages into the image, so its configure
/// render has no install lines; same exclusion as
/// `tests/use_case_goldens.rs`). The 2.x preamble is `set -e` where 1.x
/// runs bare, so 2.x guards best-effort command substitutions with
/// `|| true` (the #365 set-e-kills-assignments lesson) — those guards
/// are stripped here for the same reason the preamble is: they are the
/// 2.x shell-options shim, not semantic drift. What remains is the
/// pure command stream — the level at which parity is asserted on the
/// Rust side (EQUAL fixtures must match the Python golden byte-for-byte
/// after this filter).
pub fn command_lines(script: &str) -> Vec<String> {
    script
        .lines()
        .map(|l| l.trim())
        .map(|l| l.replace(" || true)", ")").replace(" || true ;", " ;"))
        // Executor-side decorations with no semantic effect — the SAME
        // set the pytest harness strips (its _DROP_WORDS / -q-after-uci /
        // trailing-||-true rules): structured-op renders carry them
        // (`uci -q delete … || true`) while 1.x renders bare, and the
        // golden pin compares the semantic command stream.
        .map(|l| {
            if let Some(stripped) = l.strip_suffix(" || true") {
                stripped.to_string()
            } else {
                l
            }
        })
        .map(|l| l.replace("uci -q ", "uci "))
        .filter(|l| {
            !l.is_empty()
                && !l.starts_with('#')
                && *l != "set -e"
                && !l.starts_with("#!")
                && !l.starts_with("opkg install ")
                && !l.starts_with("if command -v apk ")
                && !l.starts_with("&& apk add ")
                && !l.starts_with("if ! (opkg list-installed ")
                && !l.starts_with("if [ -n \"$(opkg list-installed ")
            // 1.x mptcp-bonding one-liner package install — same semantic
            // as the structured-op preamble above (pytest side mirrors).
            && !l.starts_with("apk add curl 2>/dev/null")
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/parity")
            .canonicalize()
            .expect("tests/fixtures/parity exists (run from repo checkout)")
    }

    fn manifest() -> serde_json::Value {
        let raw = std::fs::read_to_string(fixtures_dir().join("manifest.json"))
            .expect("parity manifest.json readable");
        serde_json::from_str(&raw).expect("parity manifest.json parses")
    }

    /// Every fixture whose manifest entry says EQUAL must render, through
    /// the Rust pipeline, the exact command lines of the Python-generated
    /// golden file (comments/blank lines stripped on both sides).
    #[test]
    fn equal_fixtures_match_python_goldens() {
        let manifest = manifest();
        let fixtures = manifest
            .get("fixtures")
            .and_then(|v| v.as_object())
            .expect("manifest has fixtures");
        let mut checked = 0;
        for (stem, entry) in fixtures {
            if entry.get("expect").and_then(|v| v.as_str()) != Some("EQUAL") {
                continue;
            }
            let fixture_path = fixtures_dir().join(format!("{stem}.json"));
            let rendered = render_fixture_file(&fixture_path)
                .unwrap_or_else(|e| panic!("{stem}: render failed: {e}"));
            let golden = std::fs::read_to_string(fixtures_dir().join(format!("golden/{stem}.sh")))
                .unwrap_or_else(|e| panic!("{stem}: golden missing: {e}"));
            let got = command_lines(&rendered);
            let want = command_lines(&golden);
            assert_eq!(
                want,
                got,
                "{stem}: Rust render diverged from Python golden{}",
                first_diff(&want, &got)
            );
            checked += 1;
        }
        assert!(checked > 0, "no EQUAL fixtures recorded in manifest");
    }

    /// GAP fixtures must still render (the gap is in output parity, not in
    /// plannability) and must carry at least one documented reason.
    #[test]
    fn gap_fixtures_render_and_are_documented() {
        let manifest = manifest();
        let fixtures = manifest
            .get("fixtures")
            .and_then(|v| v.as_object())
            .expect("manifest has fixtures");
        for (stem, entry) in fixtures {
            if entry.get("expect").and_then(|v| v.as_str()) != Some("GAP") {
                continue;
            }
            let reasons = entry
                .get("gap_reasons")
                .and_then(|v| v.as_array())
                .unwrap_or_else(|| panic!("{stem}: GAP entry needs gap_reasons"));
            assert!(!reasons.is_empty(), "{stem}: gap_reasons must not be empty");
            let fixture_path = fixtures_dir().join(format!("{stem}.json"));
            assert!(
                render_fixture_file(&fixture_path).is_ok(),
                "{stem}: GAP fixture must still render through Rust"
            );
        }
    }

    fn first_diff(want: &[String], got: &[String]) -> String {
        for (i, (w, g)) in want.iter().zip(got.iter()).enumerate() {
            if w != g {
                return format!(
                    "\nfirst diff at line {}:\n  python: {w}\n  rust:   {g}",
                    i + 1
                );
            }
        }
        if want.len() != got.len() {
            return format!(
                "\nline count differs: python {} vs rust {}",
                want.len(),
                got.len()
            );
        }
        String::new()
    }

    #[test]
    fn command_lines_strips_presentation() {
        let script = "#!/bin/sh\n# comment\nset -e\n\nuci commit firewall\n";
        assert_eq!(
            command_lines(script),
            vec!["uci commit firewall".to_string()]
        );
    }
}
