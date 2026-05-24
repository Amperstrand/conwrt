from __future__ import annotations

import base64

from config import ConwrtConfig, UseCaseConfig
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
