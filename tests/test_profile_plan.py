from __future__ import annotations

import base64

from config import ConwrtConfig, UseCaseConfig, WifiSTAConfig
from profile import build_plan, print_plan
from profile.plan import StepKind
from profile.render import opkg_install_script


def test_build_plan_collects_use_case_packages() -> None:
    cfg = ConwrtConfig(
        use_cases=[
            UseCaseConfig(name="sqm", params={"download_kbps": 1000, "upload_kbps": 500}),
        ],
    )
    plan = build_plan(cfg, mode="post_install")
    assert "sqm-scripts" in plan.all_packages()


def test_asu_build_includes_packages() -> None:
    cfg = ConwrtConfig(
        use_cases=[
            UseCaseConfig(name="sqm", params={"download_kbps": 1000, "upload_kbps": 500}),
        ],
    )
    plan = build_plan(cfg, mode="asu_build")
    assert "sqm-scripts" in plan.all_packages()
    assert "download" in plan.asu_defaults_script().lower() or "sqm" in plan.asu_defaults_script().lower()


def test_opkg_install_script() -> None:
    script = opkg_install_script(["sqm-scripts", "luci-app-sqm"], ["wpad-basic"])
    assert "opkg update" in script
    assert "sqm-scripts" in script
    assert "wpad-basic" in script


def test_build_plan_wan_ssh_explicit_false_ignores_cfg() -> None:
    cfg = ConwrtConfig(wan_ssh=True)
    plan = build_plan(cfg, mode="post_install", wan_ssh=False)
    assert not any(s.kind == StepKind.WAN_SSH for s in plan.steps)


def test_build_plan_password_override_not_cfg() -> None:
    cfg = ConwrtConfig(password_mode="from-config")
    plan = build_plan(cfg, mode="post_install", password="from-cli")
    pw_steps = [s for s in plan.steps if s.kind == StepKind.PASSWORD]
    assert len(pw_steps) == 1
    cli_b64 = base64.b64encode(b"from-cli").decode()
    cfg_b64 = base64.b64encode(b"from-config").decode()
    assert cli_b64 in pw_steps[0].configure_script
    assert cfg_b64 not in pw_steps[0].configure_script


def test_print_plan_does_not_raise(capsys) -> None:
    cfg = ConwrtConfig(use_cases=[])
    plan = build_plan(cfg, mode="preview")
    print_plan(plan)
    out = capsys.readouterr().out
    assert "Profile plan" in out


def test_usb_use_case_skipped_on_non_usb_device() -> None:
    """USB tethering use cases must be filtered out for devices without USB."""
    cfg = ConwrtConfig(
        use_cases=[UseCaseConfig(name="tether-android-adb")],
    )
    plan = build_plan(cfg, mode="asu_build", model_capabilities=["ethernet", "wifi"])
    usb_pkgs = {"kmod-usb2", "kmod-usb-net", "kmod-usb-net-rndis", "kmod-usb-net-cdc-ether", "usbutils", "adb"}
    assert usb_pkgs.isdisjoint(set(plan.all_packages())), (
        f"USB packages should not be included for non-USB device, found: {usb_pkgs & set(plan.all_packages())}"
    )
    script = plan.asu_defaults_script()
    assert "usb-tether" not in script, "USB tether uci-defaults should not appear for non-USB device"


def test_usb_use_case_included_on_usb_device() -> None:
    """USB tethering use cases must be included for devices with USB."""
    cfg = ConwrtConfig(
        use_cases=[UseCaseConfig(name="tether-android-adb")],
    )
    plan = build_plan(cfg, mode="asu_build", model_capabilities=["ethernet", "wifi", "usb"])
    all_pkgs = set(plan.all_packages())
    assert "kmod-usb2" in all_pkgs, "USB packages should be included for USB-capable device"
    script = plan.asu_defaults_script()
    assert "usb-tether" in script, "USB tether uci-defaults should appear for USB-capable device"


def test_no_capabilities_disables_filtering() -> None:
    """When model_capabilities is None or empty, all use cases pass through."""
    cfg = ConwrtConfig(
        use_cases=[UseCaseConfig(name="tether-android-adb")],
    )
    plan_no_caps = build_plan(cfg, mode="asu_build", model_capabilities=None)
    plan_empty_caps = build_plan(cfg, mode="asu_build", model_capabilities=[])
    # No capabilities = no filtering, USB use cases pass through
    assert "kmod-usb2" in plan_no_caps.all_packages()
    assert "kmod-usb2" in plan_empty_caps.all_packages()


def test_mac_hash_ip_step_generated() -> None:
    cfg = ConwrtConfig(lan_ip_mode="mac-hash")
    plan = build_plan(
        cfg, mode="post_install", model_id="asus-lyra-map-ac2200",
    )
    mac_steps = [s for s in plan.steps if s.kind == StepKind.LAN_IP_MAC_HASH]
    assert len(mac_steps) == 1
    step = mac_steps[0]
    assert "10.$_o2.$_o3.1" in step.configure_script
    assert "sha256sum" in step.configure_script
    assert step.include_in_post_install is True


def test_mac_hash_ip_firstboot_script() -> None:
    cfg = ConwrtConfig(lan_ip_mode="mac-hash")
    plan = build_plan(
        cfg, mode="post_install", model_id="asus-lyra-map-ac2200",
    )
    mac_steps = [s for s in plan.steps if s.kind == StepKind.LAN_IP_MAC_HASH]
    assert len(mac_steps) == 1
    fb = mac_steps[0].firstboot_script
    assert "eth0/address" in fb
    assert "uci set network.lan.ipaddr" in fb
    assert "uci commit network" in fb


def test_mac_hash_ip_works_without_model() -> None:
    cfg = ConwrtConfig(lan_ip_mode="mac-hash")
    plan = build_plan(cfg, mode="post_install", model_id="")
    mac_steps = [s for s in plan.steps if s.kind == StepKind.LAN_IP_MAC_HASH]
    assert len(mac_steps) == 1


def test_mac_hash_ip_skipped_with_static_mode() -> None:
    cfg = ConwrtConfig(lan_ip_mode="static")
    plan = build_plan(
        cfg, mode="post_install", model_id="asus-lyra-map-ac2200",
    )
    mac_steps = [s for s in plan.steps if s.kind == StepKind.LAN_IP_MAC_HASH]
    assert len(mac_steps) == 0


def test_hostname_model_mac_pattern() -> None:
    cfg = ConwrtConfig(hostname_pattern="model_mac")
    plan = build_plan(
        cfg, mode="post_install", model_id="asus-lyra-map-ac2200",
    )
    host_steps = [s for s in plan.steps if s.kind == StepKind.HOSTNAME]
    assert len(host_steps) == 1
    assert "lyra_" in host_steps[0].configure_script


def test_wwan_setup_step_before_wifi_sta() -> None:
    cfg = ConwrtConfig(
        wifi_sta=WifiSTAConfig(band="5ghz", ssid="Upstream", encryption="psk2", key="pass"),
    )
    plan = build_plan(cfg, mode="post_install")
    wwan_steps = [s for s in plan.steps if s.kind == StepKind.WWAN_SETUP]
    sta_steps = [s for s in plan.steps if s.kind == StepKind.WIFI_STA]
    assert len(wwan_steps) == 1
    assert len(sta_steps) == 1
    assert "network.wwan=interface" in wwan_steps[0].configure_script
    assert "proto='dhcp'" in wwan_steps[0].configure_script
    assert "'wan'" in wwan_steps[0].configure_script
    assert sta_steps[0].wifi_params["network"] == "wwan"
    wwan_idx = plan.steps.index(wwan_steps[0])
    sta_idx = plan.steps.index(sta_steps[0])
    assert wwan_idx < sta_idx


def test_no_wwan_step_without_wifi_sta() -> None:
    cfg = ConwrtConfig()
    plan = build_plan(cfg, mode="post_install")
    wwan_steps = [s for s in plan.steps if s.kind == StepKind.WWAN_SETUP]
    assert len(wwan_steps) == 0


def test_hostname_uses_static_when_no_pattern() -> None:
    cfg = ConwrtConfig(hostname="my-router")
    plan = build_plan(
        cfg, mode="post_install", model_id="asus-lyra-map-ac2200",
    )
    host_steps = [s for s in plan.steps if s.kind == StepKind.HOSTNAME]
    assert len(host_steps) == 1
    assert "my-router" in host_steps[0].configure_script


def test_cli_lan_ip_mode_overrides_config() -> None:
    cfg = ConwrtConfig(lan_ip_mode="static")
    plan = build_plan(
        cfg, mode="post_install", model_id="asus-lyra-map-ac2200",
        lan_ip_mode="mac-hash",
    )
    mac_steps = [s for s in plan.steps if s.kind == StepKind.LAN_IP_MAC_HASH]
    assert len(mac_steps) == 1


def test_cli_hostname_pattern_overrides_config() -> None:
    cfg = ConwrtConfig(hostname_pattern="static")
    plan = build_plan(
        cfg, mode="post_install", model_id="asus-lyra-map-ac2200",
        hostname_pattern="model_mac",
    )
    host_steps = [s for s in plan.steps if s.kind == StepKind.HOSTNAME]
    assert len(host_steps) == 1
    assert "lyra_" in host_steps[0].configure_script
