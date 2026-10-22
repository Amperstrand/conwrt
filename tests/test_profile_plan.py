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


def test_opkg_install_script_apk_selfheal_and_offline_guard() -> None:
    """The install line must carry the 2.x EnsurePackage semantics
    (#421 lineage / a11bfd6): the apk branch self-heals a missing index
    (a fresh 25.x boot may lack the adb index until `apk update`), and
    the opkg branch short-circuits when everything is already installed
    so an offline device stays usable (AGENTS.md package rules)."""
    script = opkg_install_script(["wireguard-tools"])
    assert "apk add wireguard-tools || { apk update && apk add wireguard-tools; }" in script
    assert '[ -n "$(opkg list-installed wireguard-tools 2>/dev/null)" ]' in script


def test_opkg_install_script_offline_guard_covers_every_package() -> None:
    script = opkg_install_script(["a-pkg", "b-pkg"])
    assert '[ -n "$(opkg list-installed a-pkg 2>/dev/null)" ] && [ -n "$(opkg list-installed b-pkg 2>/dev/null)" ]' in script


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
    assert "uci set network.lan.netmask" in step.configure_script
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
    assert "uci set network.lan.netmask" in fb
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


LAN_STEP_KINDS = {StepKind.LAN_IP, StepKind.LAN_IP_MAC_HASH}


def _lan_steps(plan):
    return [s for s in plan.steps if s.kind in LAN_STEP_KINDS]


def test_lan_ip_mode_keep_adds_no_lan_step() -> None:
    cfg = ConwrtConfig(lan_ip_mode="keep", lan_ip="192.168.1.99")
    plan = build_plan(cfg, mode="post_install")
    assert _lan_steps(plan) == [], "keep mode must not move the LAN even when lan_ip is set"


def test_lan_ip_mode_keep_wins_over_builder_arg_default() -> None:
    cfg = ConwrtConfig(lan_ip_mode="keep")
    plan = build_plan(cfg, mode="post_install", lan_ip_mode="keep")
    assert _lan_steps(plan) == []


def test_lan_ip_mode_static_with_lan_ip_adds_static_step() -> None:
    cfg = ConwrtConfig(lan_ip_mode="static", lan_ip="192.168.1.50")
    plan = build_plan(cfg, mode="post_install")
    kinds = [s.kind for s in _lan_steps(plan)]
    assert StepKind.LAN_IP in kinds
    step = next(s for s in _lan_steps(plan) if s.kind == StepKind.LAN_IP)
    # Regression (#151): a static ipaddr emitted without an explicit netmask
    # leaves 25.12 netifd defaulting to /32 — the device goes receive-only.
    assert "uci set network.lan.netmask" in step.firstboot_script
    assert "uci set network.lan.netmask" in step.configure_script


def test_lan_ip_mode_static_without_lan_ip_adds_no_step() -> None:
    """Preserved historical behavior: static mode without lan_ip skips the LAN
    step entirely (nothing to set)."""
    cfg = ConwrtConfig(lan_ip_mode="static", lan_ip="")
    plan = build_plan(cfg, mode="post_install")
    assert _lan_steps(plan) == []


def test_default_mode_is_mac_hash() -> None:
    cfg = ConwrtConfig()
    plan = build_plan(cfg, mode="post_install")
    kinds = [s.kind for s in _lan_steps(plan)]
    assert StepKind.LAN_IP_MAC_HASH in kinds


def test_asu_defaults_step_exit_isolation(tmp_path) -> None:
    """A step's early `exit 0` must not skip later steps in the ASU defaults
    file. Steps must run with a stubbed uci on PATH: with real `|| exit 1`
    failure propagation (#229), a missing binary would abort the file for
    the wrong reason."""
    cfg = ConwrtConfig(
        wifi_sta=WifiSTAConfig(band="5ghz", ssid="up", encryption="psk2", key="k"),
        use_cases=[UseCaseConfig(name="nodns")],
    )
    plan = build_plan(cfg, mode="asu_build")
    script = plan.asu_defaults_script()

    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    (stub_dir / "uci").write_text("#!/bin/sh\nexit 0\n")
    (stub_dir / "uci").chmod(0o755)
    marker_file = tmp_path / "done"
    # Execute the real joined script with the marker appended; the wifi_sta
    # block ends in `exit 0` on band match — later blocks must still run.
    sentinel = f'echo done > {marker_file}'
    import subprocess
    result = subprocess.run(
        ["sh", "-c", f"{script}\n\n{sentinel}"],
        capture_output=True, text=True, timeout=30,
        env={"PATH": f"{stub_dir}:/usr/bin:/bin", "src": "", "i": "0"},
    )
    assert marker_file.exists(), f"later steps skipped: {result.stderr[-400:]}"


def test_asu_defaults_failure_aborts_file(tmp_path) -> None:
    """#229: a failing step must make the whole defaults file exit non-zero.
    uci_apply_defaults deletes only scripts that exit 0, so failing fast
    keeps the file for retry next boot instead of consuming a half-applied
    first boot (the recovery-flash SSH lockout)."""
    import subprocess
    cfg = ConwrtConfig()
    plan = build_plan(cfg, mode="asu_build")
    from profile.plan import ProfileStep
    plan.steps.insert(
        0, ProfileStep(kind=StepKind.USE_CASE, label="boom", firstboot_script="false")
    )
    script = plan.asu_defaults_script()
    assert "(\nfalse\n) || exit 1" in script
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    (stub_dir / "uci").write_text("#!/bin/sh\nexit 0\n")
    (stub_dir / "uci").chmod(0o755)
    result = subprocess.run(
        ["sh", "-c", script],
        capture_output=True, text=True, timeout=30,
        env={"PATH": f"{stub_dir}:/usr/bin:/bin", "src": "", "i": "0"},
    )
    assert result.returncode != 0


def test_wifi_sta_firstboot_expands_radio_variable() -> None:
    """The radio loop variable must reach uci as device="$_r", not literal '$_r'.

    Regression: single-quoted by render_shell, the 25.12.5 NordVPN build baked
    wireless.default_radio1.device='$_r' and the WiFi STA never came up.
    """
    from profile.wifi import wifi_sta_firstboot_script

    script = wifi_sta_firstboot_script("5ghz", "upstream", "psk2", key="k", network="wwan")
    assert "'$_r'" not in script, "radio variable baked as literal — STA will not bind"
    assert 'device="$_r"' in script
    assert "exit 0" not in script, "early exit would skip later ASU default steps"
    assert "break" in script


# --- TOFB opt-in image flag (#228 / ADR-0013, follow-up to PR #236) -------

def test_build_plan_tofb_step_present() -> None:
    plan = build_plan(ConwrtConfig(), mode="asu_build", tofb=True)
    steps = [s for s in plan.steps if s.kind == StepKind.TOFB]
    assert len(steps) == 1
    step = steps[0]
    assert step.include_in_asu is True
    # Image-only feature: no SSH/post-install side (scripts/tofb.py is the
    # operator side against a running unit).
    assert step.include_in_post_install is False
    assert step.configure_script == ""


def test_build_plan_tofb_default_absent() -> None:
    # Opt-in only: default builds must not change the ASU payload at all.
    plan = build_plan(ConwrtConfig(), mode="asu_build")
    assert not any(s.kind == StepKind.TOFB for s in plan.steps)
    assert "tofb" not in plan.asu_defaults_script().lower()


def test_build_plan_tofb_step_is_last_for_retention() -> None:
    # uci_apply_defaults deletes the defaults file based on the LAST
    # command's status, so the TOFB step must close the file: a failed
    # install then retains every step for next-boot retry (#229/#235).
    cfg = ConwrtConfig(lan_ip_mode="mac-hash")
    plan = build_plan(cfg, mode="asu_build", tofb=True, model_id="asus-lyra-map-ac2200")
    assert plan.steps[-1].kind == StepKind.TOFB


def test_build_plan_tofb_fragment_in_defaults_script() -> None:
    plan = build_plan(ConwrtConfig(), mode="asu_build", tofb=True)
    defaults = plan.asu_defaults_script()
    assert "sha256sum /etc/conwrt/tofb-device.sh" in defaults
    assert "/etc/init.d/tofb enable || exit 1" in defaults
    # Standard subshell isolation like every other step, and last block.
    # (#229: every block carries a `) || exit 1` failure-propagation tail,
    # so assert on the last BLOCK's content, not the literal suffix.)
    last_block = defaults.rstrip().rsplit("\n(", 1)[-1]
    assert "/etc/init.d/tofb enabled" in last_block
