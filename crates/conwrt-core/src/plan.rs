//! Minimal desired-state planning slice (#113): observed state + model facts
//! + one desired-state profile → a typed, inspectable, I/O-free plan.
//!
//! Planning is a **pure function** — no provider, no probes, no mutation.
//! The apply/verify executor (M7 proper) later renders the same `PlanOp`s to
//! shell or ubus, mirroring conwrt 1.x's typed ops pipeline
//! (`scripts/profile/ops.py`). The dry-run purity of this slice is proven by
//! the call-recording `MockProber`: planning after a diagnosis leaves the
//! capability journal untouched.
//!
//! Safety invariant: the planner only emits configuration plans for devices
//! whose OpenWrt identity is **confirmed** (`DeviceState::OpenWrt` requires
//! positive HTTP fingerprints, not just an SSH banner — see `state.rs`).
//! `SshOnly`/`StockVendor`/`Unknown` are rejected: firmware identity is a
//! hard precondition for configuring a device (AGENTS.md identity gates).
use crate::state::DeviceState;
use alloc::format;
use alloc::string::ToString;
use conwrt_types::DeviceModel;

mod plan_cellular_bodies;
mod planners;
mod profiles;
mod render;
mod types;

// Re-exports: every historical `crate::plan::X` path keeps working.
use planners::*;
pub use profiles::*;
pub use render::render_shell;
use types::*;
pub use types::{Plan, PlanOp, Profile, ServiceAction, UciValue, Unsupported, VerificationCheck};

#[cfg(test)]
mod tests;

/// Plan against the device's AUTHENTICATED release when the apply path
/// has it (`/etc/openwrt_release` DISTRIB_RELEASE via fingerprint) —
/// the species-level model version is a qualification claim that goes
/// stale the moment a device is sysupgraded (Codex #606 P2: a device
/// upgraded to 25.12 under a `version: "24"` model was refused despite
/// running a supported kernel). Unparseable live values (local builds)
/// fall back to the model claim; `None` is offline planning.
pub fn plan_profile_for_device(
    state: &DeviceState,
    model: &DeviceModel,
    profile: &Profile,
    live_release: Option<&str>,
) -> Result<Plan, Unsupported> {
    if let Some(live) = live_release {
        if parse_openwrt_version(live).is_some() {
            let mut live_model = model.clone();
            live_model.openwrt.version = live.to_string();
            return plan_profile(state, &live_model, profile);
        }
    }
    plan_profile(state, model, profile)
}

/// Plan the operations to reach a profile's desired state, judged
/// against the species-level model claim (offline planning — prefer
/// [`plan_profile_for_device`] when the live release is known).
///
/// Pure: consumes the already-classified state, model facts, and the profile;
/// performs no I/O and touches no provider.
pub fn plan_profile(
    state: &DeviceState,
    model: &DeviceModel,
    profile: &Profile,
) -> Result<Plan, Unsupported> {
    if *state != DeviceState::OpenWrt {
        return Err(Unsupported::UnconfirmedDeviceState(*state));
    }
    capabilities_satisfied(model, profile.requires())?;
    if let Some((need_major, need_minor)) = profile.min_openwrt() {
        if let Some((major, minor)) = parse_openwrt_version(&model.openwrt.version) {
            let below = major < need_major
                || (major == need_major && minor.is_some_and(|m| m < need_minor));
            if below {
                return Err(Unsupported::OpenWrtTooOld {
                    have: model.openwrt.version.clone(),
                    need: format!("{need_major}.{need_minor}"),
                });
            }
        }
        // unparseable (e.g. `snapshot`): cannot judge — the runtime
        // kernel check in the plan's verification covers reality
    }
    let mut plan = match profile {
        Profile::Sqm(sqm) => plan_sqm(model, sqm),
        Profile::Doh(doh) => plan_doh(model, doh),
        Profile::Tether(tether) => plan_tether(model, tether),
        Profile::WireguardClient(wg) => plan_wireguard_client(model, wg),
        Profile::WireguardServer(wg) => plan_wireguard_server(model, wg),
        Profile::CashuVpnClient(wg) => plan_cashu_vpn_client(model, wg),
        Profile::SshHardening(sh) => plan_ssh_hardening(model, sh),
        Profile::Travelmate(tm) => plan_travelmate(model, tm),
        Profile::Adguard(ag) => plan_adguard(model, ag),
        Profile::Mesh11sd(mesh) => plan_mesh11sd(model, mesh),
        Profile::RescueWatchdog(wd) => plan_rescue_watchdog(model, wd),
        Profile::Mwan3(mw) => plan_mwan3(model, mw),
        Profile::Pbr(pbr) => plan_pbr(model, pbr),
        Profile::Nodns(nd) => plan_nodns(model, nd),
        Profile::AutoSqm(asq) => plan_auto_sqm(model, asq),
        Profile::GuestWifi(gw) => plan_guest_wifi(model, gw),
        Profile::OpenClash(oc) => plan_openclash(model, oc),
        Profile::Ssl(ssl) => plan_ssl(model, ssl),
        Profile::VpnPiaOpenvpn(pia) => plan_vpn_pia_openvpn(model, pia),
        Profile::VpnNordvpn(nv) => plan_vpn_nordvpn(model, nv),
        Profile::VpnNordvpnOpenvpn(nv) => plan_vpn_nordvpn_openvpn(model, nv),
        Profile::VpnPia(pia) => plan_vpn_pia(model, pia),
        Profile::MptcpBonding(mp) => plan_mptcp_bonding(model, mp),
        Profile::ApNostrId(a) => plan_ap_nostr_id(model, a),
        Profile::VpnOpenvpn(vo) => plan_vpn_openvpn(model, vo),
        Profile::VpnSurfshark(ss) => plan_vpn_surfshark(model, ss),
        Profile::VpnIvpn(iv) => plan_vpn_ivpn(model, iv),
        Profile::VpnMullvad(mu) => plan_vpn_mullvad(model, mu),
        Profile::VpnNode(vn) => plan_vpn_node(model, vn),
        Profile::VpnNordvpnIke2(i2) => plan_vpn_nordvpn_ike2(model, i2),
        Profile::OpenPerfClient(oc) => plan_openperf_client(model, oc),
        Profile::OpenPerfServer(os) => plan_openperf_server(model, os),
        Profile::ConfigurationWizzard(cw) => plan_configuration_wizzard(model, cw),
        Profile::FipsBluetoothRfcomm(fp) => plan_fips_bluetooth_rfcomm(model, fp),
        Profile::Tollgate(tg) => plan_tollgate(model, tg),
        Profile::TollgateSecurity(ts) => plan_tollgate_security(model, ts),
        Profile::FleetIdentity(fi) => plan_fleet_identity(model, fi),
        Profile::TollgateCellular(tc) => plan_tollgate_cellular(model, tc),
    }?;
    // 24.x deprecation advisory (warning, not refusal — policy: warn
    // and plan the upgrade; see the deprecation tracking issue):
    // 24.10 kernels (6.6) sit past end-of-support with unpatched CVEs
    // (e.g. CVE-2026-98432, fixed at 6.6.159) and most presets are
    // 25.x-qualified.
    if let Some((24, _)) = parse_openwrt_version(&model.openwrt.version) {
        plan.warnings.push(
            "OpenWrt 24.x is past end-of-support: known kernel CVEs unpatched \
             (CVE-2026-98432 fixed only at 6.6.159+) and 25.x is the \
             qualified release family — plan an upgrade"
                .into(),
        );
    }
    Ok(plan)
}
