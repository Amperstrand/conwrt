"""Apply a ProfilePlan to a running router via SSH."""
from __future__ import annotations

import subprocess
import time
from typing import Callable, Optional

from profile.plan import ProfilePlan, ProfileStep, StepKind
from profile.ops import render_shell, render_ubus
from profile.render import opkg_install_script
from profile.wifi import band_to_uci, wifi_ap_uci_lines, wifi_detect_radio_shell, wifi_sta_uci_lines
from ssh_utils import ssh_cmd


LogFn = Callable[[str], None]


def _run_ssh(
    ip: str,
    command: str,
    ssh_key: str,
    log: LogFn,
    timeout: int = 60,
) -> bool:
    r = subprocess.run(
        ssh_cmd(ip, command, key=ssh_key or None, connect_timeout=10),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if r.returncode != 0:
        if r.stderr:
            log(f"    stderr: {r.stderr.strip()[:200]}")
        return False
    return True


def _apply_wifi_step(
    ip: str,
    step: ProfileStep,
    ssh_key: str,
    log: LogFn,
    reload_wifi: bool,
) -> bool:
    detect = wifi_detect_radio_shell(step.wifi_detect_band)
    r = subprocess.run(
        ssh_cmd(ip, detect, key=ssh_key or None, connect_timeout=10),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    radio = r.stdout.strip()
    if not radio:
        log(f"  ⚠ {step.label}: no radio for band '{step.wifi_detect_band}'")
        return False

    p = step.wifi_params
    if step.wifi_role == "sta":
        cmds = wifi_sta_uci_lines(
            radio, p["ssid"], p["encryption"], p.get("key", ""), p.get("network", "wan"),
            country_code=p.get("country_code", "DE"),
        )
    else:
        cmds = wifi_ap_uci_lines(
            radio, p["ssid"], p["encryption"], p.get("key", ""),
            p.get("channel", "auto"), p.get("network", "lan"),
            country_code=p.get("country_code", "DE"),
        )
    if reload_wifi:
        cmds += ["uci commit wireless", "wifi reload"]
    else:
        cmds += ["uci commit wireless"]
    chain = " && ".join(cmds)
    ok = _run_ssh(ip, chain, ssh_key, log)
    if ok:
        log(f"  ✓ {step.label}: configured on {radio}")
    else:
        log(f"  ⚠ {step.label}: failed")
    return ok


def apply_plan(
    plan: ProfilePlan,
    ip: str,
    ssh_key: str = "",
    dry_run: bool = False,
    log: Optional[LogFn] = None,
) -> str:
    """Apply plan steps over SSH. Returns final IP (may change after LAN step)."""
    from profile.render import print_plan, ssh_steps_preview

    _log = log or (lambda _m: None)

    if dry_run:
        _log("DRY RUN — no changes will be made to the router")
        print_plan(plan)
        print()
        print("SSH commands that would run:")
        for line in ssh_steps_preview(plan):
            print(f"  {line}")
        return ip

    opkg_pkgs: list[str] = []
    opkg_remove: list[str] = []
    for step in plan.steps:
        if step.kind == StepKind.USE_CASE and step.opkg_packages:
            for p in step.opkg_packages:
                if p not in opkg_pkgs:
                    opkg_pkgs.append(p)
            for r in step.opkg_remove:
                if r not in opkg_remove:
                    opkg_remove.append(r)

    if opkg_pkgs or opkg_remove:
        _log(f"  opkg: installing {len(opkg_pkgs)} package(s)...")
        script = opkg_install_script(opkg_pkgs, opkg_remove)
        if not _run_ssh(ip, script, ssh_key, _log, timeout=300):
            _log("  ⚠ opkg install failed")

    wifi_steps = [s for s in plan.steps if s.kind in (StepKind.WIFI_STA, StepKind.WIFI_AP)]
    last_wifi_idx = len(wifi_steps) - 1
    wifi_i = 0

    for step in plan.steps:
        if step.skipped_reason:
            continue
        if not step.include_in_post_install:
            continue
        if step.kind in (StepKind.OPKG_BATCH,):
            continue
        if step.kind == StepKind.LAN_IP:
            continue  # caller handles LAN IP last
        if step.kind == StepKind.LAN_IP_MAC_HASH:
            continue  # caller handles MAC-hash IP last (drops SSH)

        if step.kind == StepKind.SSH_KEY:
            continue  # caller installs keys idempotently before apply_plan (configure)

        if step.kind in (StepKind.WIFI_STA, StepKind.WIFI_AP):
            reload = wifi_i >= last_wifi_idx
            wifi_i += 1
            _apply_wifi_step(ip, step, ssh_key, _log, reload_wifi=reload)
            continue

        script = render_shell(step.ops) if step.ops else step.configure_script

        if step.kind == StepKind.USE_CASE and script:
            _log(f"  use case '{step.use_case_name}': applying...")
            chain = "; ".join(
                ln for ln in script.strip().splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            )
            if chain and _run_ssh(ip, chain, ssh_key, _log):
                _log(f"  ✓ use case '{step.use_case_name}': applied")
            elif chain:
                _log(f"  ⚠ use case '{step.use_case_name}': failed")

        elif script and step.kind not in (StepKind.USE_CASE,):
            chain = " && ".join(
                ln for ln in script.strip().splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            )
            if chain:
                _log(f"  {step.label}...")
                if _run_ssh(ip, chain, ssh_key, _log):
                    _log(f"  ✓ {step.label}")

    return ip


def _apply_wifi_ubus(
    client: object,
    step: ProfileStep,
    log: LogFn,
) -> bool:
    """Configure WiFi via ubus: discover radio, then apply STA/AP settings.

    Two-phase flow:
    1. ``ubus call network.wireless status`` → find radio matching band
    2. ``uci.set`` / ``uci.delete`` / ``uci.commit`` via ubus RPC
    """
    from ubus_utils import UbusClient

    assert isinstance(client, UbusClient)
    uci_band = band_to_uci(step.wifi_detect_band)
    radio = client.find_radio_for_band(uci_band)
    if not radio:
        log(f"  ⚠ {step.label}: no radio for band '{step.wifi_detect_band}'")
        return False

    section = f"default_{radio}"
    p = step.wifi_params

    try:
        client.uci_set("wireless", radio, {"disabled": "0"})

        if step.wifi_role == "ap":
            channel = p.get("channel", "auto")
            if channel and channel != "auto":
                client.uci_set("wireless", radio, {"channel": channel})

        try:
            client.uci_delete("wireless", section, "disabled")
        except Exception:
            pass

        values: dict[str, str] = {
            "device": radio,
            "mode": step.wifi_role,
            "ssid": p["ssid"],
            "encryption": p["encryption"],
        }
        if p.get("key"):
            values["key"] = p["key"]
        values["network"] = p.get("network", "lan" if step.wifi_role == "ap" else "wan")

        client.uci_set("wireless", section, values)
        client.uci_commit("wireless")

        log(f"  ✓ {step.label}: configured on {radio}")
        return True
    except Exception as e:
        log(f"  ⚠ {step.label}: {e}")
        return False


def apply_ubus(
    plan: ProfilePlan,
    ip: str,
    username: str = "root",
    password: str = "",
    dry_run: bool = False,
    log: Optional[LogFn] = None,
    skip_fallback: bool = True,
) -> str:
    """Apply plan steps via ubus HTTP instead of SSH.

    Sends typed ops as ubus RPC calls. ShellCommand ops (fallback=True)
    are skipped unless ``skip_fallback=False`` — the router must have
    the rpcd exec plugin for shell fallback to work.

    WiFi steps use two-phase ubus: discover radio via
    ``network.wireless status``, then apply UCI settings.
    """
    from ubus_utils import UbusClient

    _log = log or (lambda _m: None)

    if dry_run:
        _log("DRY RUN (ubus) — no changes will be made to the router")
        for step in plan.steps:
            if not step.ops or step.skipped_reason:
                continue
            calls = render_ubus(step.ops)
            if skip_fallback:
                calls = [c for c in calls if not c.params.get("fallback")]
            if calls:
                _log(f"  {step.label}: {len(calls)} ubus call(s)")
        return ip

    client = UbusClient(ip)
    client.login(username, password)
    _log("  ubus: authenticated")

    for step in plan.steps:
        if step.skipped_reason:
            continue
        if not step.include_in_post_install:
            continue
        if not step.ops:
            continue

        if step.kind in (StepKind.WIFI_STA, StepKind.WIFI_AP):
            _apply_wifi_ubus(client, step, _log)
            continue

        if step.kind == StepKind.SSH_KEY:
            continue

        if step.opkg_packages:
            _log(f"  ⚠ {step.label}: package install skipped (requires SSH)")
            continue

        calls = render_ubus(step.ops)
        if skip_fallback:
            fallback_count = sum(1 for c in calls if c.params.get("fallback"))
            calls = [c for c in calls if not c.params.get("fallback")]
            if fallback_count:
                _log(f"  {step.label}: {fallback_count} shell command(s) skipped")

        if not calls:
            continue

        try:
            _log(f"  {step.label}: sending {len(calls)} ubus call(s)...")
            for call in calls:
                client.call(call.object_name, call.method, call.params)
            _log(f"  ✓ {step.label}")
        except Exception as e:
            _log(f"  ⚠ {step.label}: {e}")

    return ip


def verify_persistence(
    ip: str,
    ssh_key: str = "",
    expected_hostname: str = "",
    timeout: int = 180,
    log: Optional[LogFn] = None,
) -> bool:
    """Flush UBIFS cache, reboot, wait for SSH, and verify key settings survived.

    UBIFS overlay persistence: file writes sit in write-back cache and are lost
    on unclean power loss. ``uci commit`` persists because it does explicit
    fsync.  Regular file writes (authorized_keys, /etc/shadow) need ``sync;
    sync; reboot`` to flush.  NEVER use ``network restart`` to apply changes.

    Returns True if all checks pass, False otherwise.
    """
    _log = log or (lambda _m: None)
    _log("  Persistence: flushing UBIFS cache and rebooting...")

    _run_ssh(ip, "sync; sync; reboot", ssh_key, _log, timeout=15)

    _log("  Persistence: waiting for device to reboot...")
    start = time.time()
    back = False
    while time.time() - start < timeout:
        if time.time() - start < 15:
            time.sleep(5)
            continue
        try:
            r = subprocess.run(
                ssh_cmd(ip, "echo SSH_OK", key=ssh_key or None, connect_timeout=5),
                capture_output=True, text=True, timeout=10, check=False,
            )
            if "SSH_OK" in r.stdout:
                back = True
                break
        except Exception:
            pass
        time.sleep(5)

    if not back:
        _log(f"  ⚠ Persistence: device did not come back within {timeout}s")
        return False

    _log("  Persistence: device is back, verifying...")

    checks_cmd = (
        "echo hostname=$(uci get system.@system[0].hostname 2>/dev/null || echo ''); "
        "echo sshkey_lines=$(wc -l < /etc/dropbear/authorized_keys 2>/dev/null || echo 0)"
    )
    r = subprocess.run(
        ssh_cmd(ip, checks_cmd, key=ssh_key or None, connect_timeout=10),
        capture_output=True, text=True, timeout=15, check=False,
    )

    if r.returncode != 0:
        _log(f"  ⚠ Persistence: verification SSH failed (rc={r.returncode})")
        return False

    result: dict[str, str] = {}
    for line in r.stdout.strip().split("\n"):
        if "=" in line:
            k, v = line.split("=", 1)
            result[k] = v

    ok = True

    if expected_hostname:
        actual_hostname = result.get("hostname", "")
        if actual_hostname == expected_hostname:
            _log(f"  ✓ Persistence: hostname={actual_hostname}")
        else:
            _log(f"  ⚠ Persistence: hostname mismatch: expected={expected_hostname}, got={actual_hostname}")
            ok = False

    sshkey_lines = int(result.get("sshkey_lines", "0"))
    if sshkey_lines > 0:
        _log(f"  ✓ Persistence: SSH keys present ({sshkey_lines} line(s))")
    else:
        _log("  ⚠ Persistence: SSH keys missing after reboot")
        ok = False

    if ok:
        _log("  ✓ Persistence: all checks passed")
    return ok
