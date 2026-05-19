"""Apply a ProfilePlan to a running router via SSH."""
from __future__ import annotations

import subprocess
from typing import Callable, Optional

from profile.plan import ProfilePlan, ProfileStep, StepKind
from profile.render import opkg_install_script
from profile.wifi import wifi_ap_uci_lines, wifi_detect_radio_shell, wifi_sta_uci_lines
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

        if step.kind == StepKind.SSH_KEY:
            continue  # caller installs keys idempotently before apply_plan (configure)

        if step.kind in (StepKind.WIFI_STA, StepKind.WIFI_AP):
            reload = wifi_i >= last_wifi_idx
            wifi_i += 1
            _apply_wifi_step(ip, step, ssh_key, _log, reload_wifi=reload)
            continue

        if step.kind == StepKind.USE_CASE and step.configure_script:
            _log(f"  use case '{step.use_case_name}': applying...")
            chain = "; ".join(
                ln for ln in step.configure_script.strip().splitlines()
                if ln.strip() and not ln.strip().startswith("#")
            )
            if chain and _run_ssh(ip, chain, ssh_key, _log):
                _log(f"  ✓ use case '{step.use_case_name}': applied")
            elif chain:
                _log(f"  ⚠ use case '{step.use_case_name}': failed")

        elif step.configure_script and step.kind not in (StepKind.USE_CASE,):
            chain = step.configure_script.replace("\n", " && ")
            if chain:
                _log(f"  {step.label}...")
                if _run_ssh(ip, chain, ssh_key, _log):
                    _log(f"  ✓ {step.label}")

    return ip
