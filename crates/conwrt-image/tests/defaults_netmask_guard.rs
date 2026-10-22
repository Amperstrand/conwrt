//! The netmask guard: defaults scripts that set a static LAN `ipaddr`
//! without a paired `netmask` are rejected.
//!
//! Root cause this encodes (2026-10-14 postmortem, x1860): an ASU image
//! baked `network.lan.ipaddr` with no netmask; OpenWrt 25.12 netifd
//! defaults the missing netmask to /32 (24.10 defaulted /24), leaving the
//! device v4-reachable only at L2 — ARP answers, no IP services. The
//! Python builder emits the pair everywhere (`scripts/profile/builder.py`
//! "netmask to /24" comment); this guard keeps the Rust request path from
//! regressing the same class.

use conwrt_image::types::validate_defaults_script;

#[test]
fn ipaddr_without_netmask_is_rejected() {
    let script = "uci set network.lan.ipaddr='192.168.105.52'\nuci commit network\n";
    let err = validate_defaults_script(script).expect_err("must reject ipaddr without netmask");
    let msg = err.to_string();
    assert!(
        msg.contains("network.lan.ipaddr"),
        "names the section: {msg}"
    );
    assert!(msg.contains("netmask"), "names the missing pair: {msg}");
}

#[test]
fn ipaddr_with_paired_netmask_passes() {
    let script = "uci set network.lan.ipaddr='192.168.105.52'\nuci set network.lan.netmask='255.255.255.0'\nuci commit network\n";
    validate_defaults_script(script).expect("paired static address is fine");
}

#[test]
fn dhcp_default_needs_no_netmask() {
    // No static ipaddr anywhere — nothing to guard.
    let script = "uci set dhcp.lan.ignore='1'\nuci commit dhcp\n";
    validate_defaults_script(script).expect("no ipaddr, no requirement");
}

#[test]
fn the_pair_must_match_the_section() {
    // netmask on a DIFFERENT section does not satisfy the lan pair.
    let script = "uci set network.lan.ipaddr='192.168.105.52'\nuci set network.wan.netmask='255.255.255.0'\n";
    validate_defaults_script(script).expect_err("cross-section pairing is not a pairing");
}

#[test]
fn only_uci_set_lines_count() {
    // Mentions in comments, echoes, or unrelated keys are not setters.
    let script = "# note: ipaddr is set by the operator\n\
                  echo 'network.lan.ipaddr comes from elsewhere'\n\
                  uci set network.lan.proto='static'\n";
    validate_defaults_script(script).expect("no setter, no requirement");
}

#[test]
fn double_quoted_setters_are_parsed_too() {
    let script = "uci set network.lan.ipaddr=\"192.168.105.52\"\nuci set network.lan.netmask=\"255.255.255.0\"\n";
    validate_defaults_script(script).expect("quoted variants still pair");
}

#[test]
fn empty_and_absent_defaults_pass() {
    validate_defaults_script("").expect("empty script is fine");
    validate_defaults_script("# just a comment\n").expect("comment-only is fine");
}
