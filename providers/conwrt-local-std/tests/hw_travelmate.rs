//! Ring-3 e2e (real hardware): travelmate with the deploying host's
//! saved WiFi credentials — the "flash and it just works" promise.
//!
//! Gated by env (all required, else skip):
//! - `CONWRT_HW_TARGET`     — `ip:port` of the router
//! - `CONWRT_HW_KEY`        — SSH key path
//! - `CONWRT_HW_EXPECT_MAC` — specimen gate: br-lan MAC that must match
//!
//! Reads the HOST's NetworkManager saved wifi profiles via `sudo -n
//! nmcli -s` (passwordless sudo), seeds each personal network onto the
//! router as a travelmate STA uplink, applies the plan with the 2.x
//! executor, and watches a REAL association (ubus trm_wwan up + IPv4).
//!
//! PRIVACY: SSIDs and PSKs NEVER appear in any test output — failure
//! messages and progress lines carry only counts and SipHash labels
//! (ssid‥hash8). Raw `logread` output is never printed; only grep
//! counts. Nothing is committed to the repo.
//!
//! Status (2026-10-22, specimen x1860-1 @ 25.12.6): **GREEN end-to-end
//! from a clean slate** — the plan applies + verifies, travelmate 2.4.9
//! recognizes the seeded uplinks (paired `uplink` sections carrying
//! `enabled=1` are REQUIRED — its `f_getcfg` matches device+ssid and
//! `f_setif` force-disables unpaired ifaces), auto-joins a host-seeded
//! network, `trm_wwan` DHCPs, and travelmate's own captive probe
//! reports `net ok`. Teardown restores the specimen (verified by
//! readback).
//!
//! No-LLM regression use — run against any specimen with the env pins:
//! ```text
//! CONWRT_HW_TARGET=<ip:22> CONWRT_HW_KEY=<key> \
//! CONWRT_HW_EXPECT_MAC=<br-lan mac> \
//! cargo test -p conwrt-local-std --test hw_travelmate -- --nocapture
//! ```
//! Prerequisites: OpenWrt 25.x with `travelmate luci-app-travelmate
//! ca-bundle ca-certificates` installable (online) or preinstalled, a
//! `wifi` capability, and this host's saved networks readable via
//! passwordless sudo.

use conwrt_core::confirm;
use conwrt_core::plan::{PlanOp, Profile, TravelmateProfile, WifiUplink, plan_profile};
use conwrt_core::ssh::{MemoryTrustStore, TrustMode};
use conwrt_core::state::DeviceState;
use conwrt_local_std::execute::apply_plan;
use conwrt_local_std::fingerprint::fingerprint;
use conwrt_local_std::ssh::{SshAuth, SshOptions, SshTarget, connect};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fn ssid_label(ssid: &str) -> String {
    let mut h = DefaultHasher::new();
    ssid.hash(&mut h);
    format!("ssid‥{:08x}", h.finish() as u32)
}

struct SavedWifi {
    ssid: String,
    psk: String,
    encryption: String,
    five_ghz: bool,
}

/// Extract the host's saved personal WiFis from NetworkManager's
/// on-disk profiles (`/etc/NetworkManager/system-connections/*.nmconnection`,
/// read via one passwordless-sudo pass; NM's list-mode `connection show`
/// cannot emit per-setting secret fields). Enterprise (wpa-eap) and
/// credential-less entries are skipped.
fn host_saved_wifis() -> Vec<SavedWifi> {
    let out = std::process::Command::new("sudo")
        .args([
            "-n",
            "sh",
            "-c",
            "for f in /etc/NetworkManager/system-connections/* \
             /run/NetworkManager/system-connections/*; do \
             echo ==F==; cat \"$f\"; done",
        ])
        .output()
        .expect("run sudo cat");
    if !out.status.success() {
        panic!(
            "sudo nmconnection read failed: exit {:?}",
            out.status.code()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut wifis = Vec::new();
    for stanza in text.split("==F==") {
        if !stanza.contains("[wifi]") {
            continue;
        }
        let get = |prefix: &str| -> Option<String> {
            stanza.lines().find_map(|l| {
                l.strip_prefix(prefix)
                    .map(|v| v.trim().trim_matches('"').to_string())
            })
        };
        let Some(ssid) = get("ssid=") else { continue };
        if ssid.is_empty() {
            continue;
        }
        let psk = get("psk=").unwrap_or_default();
        let key_mgmt = get("key-mgmt=").unwrap_or_default();
        let band = get("band=").unwrap_or_default();
        let (encryption, ok) = match key_mgmt.as_str() {
            "sae" => ("sae", true),
            "wpa-psk" => ("psk2", true),
            "" if psk.is_empty() => ("none", true),
            _ => ("", false), // wpa-eap / unknown: not seedable tonight
        };
        if !ok || (encryption != "none" && psk.is_empty()) {
            eprintln!("skip {}: unsupported auth", ssid_label(&ssid));
            continue;
        }
        wifis.push(SavedWifi {
            ssid,
            psk,
            encryption: encryption.into(),
            five_ghz: band == "a",
        });
    }
    wifis
}

fn hw_enabled() -> Option<(String, String, String)> {
    let target = std::env::var("CONWRT_HW_TARGET").ok()?;
    let key = std::env::var("CONWRT_HW_KEY").ok()?;
    let mac = std::env::var("CONWRT_HW_EXPECT_MAC").ok()?;
    Some((target, key, mac))
}

#[tokio::test]
async fn travelmate_seeds_host_networks_and_joins_on_real_hardware() {
    let Some((target, key, expect_mac)) = hw_enabled() else {
        eprintln!("skipping: CONWRT_HW_TARGET/KEY/EXPECT_MAC not set");
        return;
    };

    let saved = host_saved_wifis();
    assert!(
        !saved.is_empty(),
        "host must have at least one seedable saved wifi"
    );
    eprintln!(
        "seeding {} saved wifi(s) from the deploying host",
        saved.len()
    );

    let mut store = MemoryTrustStore::new();
    let session = connect(
        &SshTarget {
            addr: target.clone(),
            user: "root".into(),
            auth: SshAuth::KeyFile {
                path: key.clone().into(),
                passphrase: None,
            },
        },
        &mut store,
        &SshOptions {
            mode: TrustMode::TrustOnFirstUse,
            ..Default::default()
        },
    )
    .await
    .expect("connect to router");

    // specimen + identity gate: board, release, and the pinned MAC
    let report = fingerprint(&session).await.expect("fingerprint");
    assert_eq!(
        confirm(DeviceState::SshOnly, report.release.as_ref()),
        DeviceState::OpenWrt
    );
    let mac = session
        .exec("ip link show br-lan | grep ether | awk '{print $2}' | tr 'A-F' 'a-f'")
        .await
        .expect("mac readback");
    let mac = String::from_utf8_lossy(&mac.stdout).trim().to_string();
    assert_eq!(
        mac,
        expect_mac.to_lowercase(),
        "SPECIMEN GATE: br-lan MAC mismatch"
    );

    // live radio map: band '5g' radio for 5GHz uplinks, else the 2g radio
    let bands = radio_bands(&session).await;
    let mut uplinks = Vec::new();
    for (i, w) in saved.iter().enumerate() {
        uplinks.push(WifiUplink {
            ssid: w.ssid.clone(),
            psk: w.psk.clone(),
            encryption: w.encryption.clone(),
            radio: if w.five_ghz {
                bands.five_g.clone()
            } else {
                bands.two_g.clone()
            },
            iface: format!("trm_uplink{}", i + 1),
        });
    }

    let model = conwrt_types::DeviceModel {
        id: format!("hw-{}", report.board_name.clone().unwrap_or_default()),
        vendor: "D-Link".into(),
        description: "e2e specimen".into(),
        openwrt: conwrt_types::OpenwrtInfo {
            target: "ramips/mt7621".into(),
            device: report.board_name.clone().unwrap_or_default(),
            profile: "dlink_covr-x1860-a1".into(),
            version: report
                .release
                .as_ref()
                .and_then(|r| r.release.clone())
                .unwrap_or_default(),
            board_name: report.board_name.clone(),
            board_names: None,
            default_ip: None,
            extras: Default::default(),
        },
        capabilities: Some(vec!["ethernet".into(), "wifi".into()]),
        flash_methods: None,
        mac_oui: Vec::new(),
        serial_console: None,
        warnings: None,
        extras: Default::default(),
    };

    let profile = Profile::Travelmate(TravelmateProfile {
        uplinks,
        ..TravelmateProfile::default()
    });
    let plan =
        plan_profile(&DeviceState::OpenWrt, &model, &profile).expect("plan for confirmed hardware");
    assert!(plan.ops.iter().any(|op| matches!(op, PlanOp::SetUciSection { section, .. } if section.starts_with("trm_uplink"))));

    let outcome = apply_plan(&session, &plan).await.expect("apply over SSH");
    assert!(
        outcome.applied,
        "script must exit 0 on hardware:\n{}",
        redact(&outcome.script, &saved)
    );
    assert!(
        outcome.fully_verified(),
        "verification failed: {:?}",
        outcome.verification
    );
    eprintln!("plan applied + verified on hardware; watching association");

    // watch for a REAL association: trm_wwan up with an IPv4 lease.
    // Evidence is collected FIRST and teardown ALWAYS runs before any
    // assert fires — a failed watch must not leave seeded credentials
    // and STA sections on the specimen (lesson from the first live run).
    let mut associated = false;
    for _ in 0..60 {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        let st = session
            .exec("ubus call network.interface.trm_wwan status 2>/dev/null | grep -c '\"up\": true'; ubus call network.interface.trm_wwan status 2>/dev/null | grep -c 'ipv4-address'")
            .await
            .expect("wwan status");
        let counts: Vec<u32> = String::from_utf8_lossy(&st.stdout)
            .lines()
            .filter_map(|l| l.trim().parse().ok())
            .collect();
        if counts.len() == 2 && counts[0] >= 1 && counts[1] >= 1 {
            associated = true;
            break;
        }
    }
    let joined = session
        .exec("for i in $(iw dev | awk '/Interface/{print $2}'); do iwinfo $i iwgetid 2>/dev/null; done | head -1")
        .await
        .expect("joined ssid");
    let joined_ssid = String::from_utf8_lossy(&joined.stdout)
        .lines()
        .find_map(|l| l.split("ESSID:").nth(1))
        .map(|s| s.trim().trim_matches('"').to_string())
        .unwrap_or_default();
    let logcount = session
        .exec("logread 2>/dev/null | grep -c travelmate || true")
        .await
        .expect("logread count");
    let logcount_s = String::from_utf8_lossy(&logcount.stdout).trim().to_string();

    teardown(&session, saved.len()).await;
    let check = session
        .exec("uci -q get wireless.trm_uplink1.ssid >/dev/null 2>&1 && echo left || echo clean")
        .await
        .expect("teardown verify sta");
    assert!(
        String::from_utf8_lossy(&check.stdout)
            .trim()
            .contains("clean"),
        "seeded STA section survived teardown"
    );
    let check = session
        .exec("uci -q get network.trm_wwan.proto >/dev/null 2>&1 && echo left || echo clean")
        .await
        .expect("teardown verify wwan");
    assert!(
        String::from_utf8_lossy(&check.stdout)
            .trim()
            .contains("clean"),
        "trm_wwan survived teardown"
    );
    let check = session
        .exec("uci -q get travelmate.global.trm_iface >/dev/null 2>&1 && echo left || echo clean")
        .await
        .expect("teardown verify iface opt");
    assert!(
        String::from_utf8_lossy(&check.stdout)
            .trim()
            .contains("clean"),
        "trm_iface option survived teardown"
    );
    let check = session
        .exec("uci -q get travelmate.global.trm_enabled")
        .await
        .expect("teardown verify enabled");
    assert_eq!(
        String::from_utf8_lossy(&check.stdout).trim(),
        "0",
        "travelmate must be disabled after teardown"
    );

    if associated {
        let label = if joined_ssid.is_empty() {
            "(readback n/a)".to_string()
        } else {
            ssid_label(&joined_ssid)
        };
        eprintln!(
            "ASSOCIATED via {label} — travelmate log lines: {}",
            logcount_s
        );
    }
    assert!(
        associated,
        "trm_wwan never came up with an IPv4 lease within 300s ({} seeded networks, hashes only: {})",
        saved.len(),
        saved
            .iter()
            .map(|w| ssid_label(&w.ssid))
            .collect::<Vec<_>>()
            .join(", ")
    );
}

/// Restore the specimen to its pre-test state: seeded STA sections,
/// the trm_wwan/trm_wwan6 uplink pair, wan-zone membership, and the
/// travelmate global options this plan touched (back to package
/// defaults, service disabled). Idempotent — safe to re-run.
async fn teardown(session: &conwrt_local_std::ssh::SshSession, seeded: usize) {
    let seeded_ifaces: String = (1..=seeded)
        .map(|i| format!("uci -q delete wireless.trm_uplink{i}; "))
        .collect();
    let _ = session
        .exec(&format!(
            "{seeded_ifaces}\
             for i in 1 2 3 4 5 6 7 8; do uci -q delete travelmate.trm_uplink$i; done; \
             uci -q delete network.trm_wwan; uci -q delete network.trm_wwan6; \
             for _z in $(uci show firewall 2>/dev/null | grep '=zone' | cut -d. -f2 | cut -d= -f1); do \
               uci -q del_list firewall.\"$_z\".network='trm_wwan' 2>/dev/null; \
               uci -q del_list firewall.\"$_z\".network='trm_wwan6' 2>/dev/null; done; \
             uci -q set travelmate.global.trm_enabled='0'; \
             uci -q delete travelmate.global.trm_automatic; \
             uci -q delete travelmate.global.trm_captive; \
             uci -q delete travelmate.global.trm_timeout; \
             uci -q delete travelmate.global.trm_retry; \
             uci -q delete travelmate.global.trm_radio; \
             uci -q delete travelmate.global.trm_iface; \
             uci -q delete travelmate.global.trm_uplink; \
             uci -q delete travelmate.global.trm_debug; \
             uci commit wireless; uci commit network; uci commit firewall; uci commit travelmate; \
             /etc/init.d/travelmate disable; /etc/init.d/travelmate stop; \
             wifi reload; \
             ip route del default 2>/dev/null; true"
        ))
        .await
        .expect("teardown");
}

struct Bands {
    two_g: String,
    five_g: String,
}

async fn radio_bands(session: &conwrt_local_std::ssh::SshSession) -> Bands {
    let out = session
        .exec("for r in radio0 radio1 radio2 radio3; do b=$(uci -q get wireless.$r.band); [ -n \"$b\" ] && echo $r=$b; done")
        .await
        .expect("radio bands");
    let mut two_g = "radio0".to_string();
    let mut five_g = "radio1".to_string();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let (radio, band) = line.split_once('=').unwrap_or(("", ""));
        match band {
            "5g" | "6g" => five_g = radio.to_string(),
            _ => two_g = radio.to_string(),
        }
    }
    Bands { two_g, five_g }
}

/// Replace every seeded SSID/PSK occurrence before anything is printed.
fn redact(text: &str, saved: &[SavedWifi]) -> String {
    let mut t = text.to_string();
    for w in saved {
        t = t.replace(&w.ssid, &ssid_label(&w.ssid));
        if !w.psk.is_empty() {
            t = t.replace(&w.psk, "psk‥redacted");
        }
    }
    t
}
