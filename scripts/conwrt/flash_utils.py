# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false

import json
import os
import subprocess
import time
from typing import Optional

from flash.context import log, ts
from model_loader import find_model_by_board_name
from ssh_utils import ssh_cmd, scp_cmd
from platform_utils import detect_platform
from config import load_config as _load_config
from conwrt.monitors import check_ssh


def _scp_upload(device_ip: str, firmware_path: str, ssh_key: Optional[str] = None) -> tuple[bool, str]:
    """Upload a file to a device via SCP. Returns (success, remote_path).

    Shared by _flash_via_sysupgrade, _flash_via_mtd_write, and others.
    """
    firmware_name = os.path.basename(firmware_path)
    remote_path = f"/tmp/{firmware_name}"
    size_mb = os.path.getsize(firmware_path) / 1024 / 1024

    scp_command = scp_cmd(device_ip, firmware_path, f"root@{device_ip}:{remote_path}",
                          key=ssh_key, connect_timeout=10)

    log(f"Uploading {firmware_name} ({size_mb:.1f} MB) via SCP to {device_ip}...")
    try:
        r = subprocess.run(scp_command, capture_output=True, text=True, timeout=120, check=False)
        if r.returncode != 0:
            stderr_hint = r.stderr[:300] if r.stderr else "(no stderr)"
            if "permission denied" in stderr_hint.lower():
                log(f"SCP failed (exit {r.returncode}): {stderr_hint}")
                log("Hint: check SSH key authentication — ensure the key is authorized on the device")
            else:
                log(f"SCP failed (exit {r.returncode}): {stderr_hint}")
            return False, remote_path
    except subprocess.TimeoutExpired:
        log("SCP upload timed out.")
        return False, remote_path
    except OSError as e:
        log(f"SCP error: {e}")
        return False, remote_path
    return True, remote_path


def _flash_via_sysupgrade(device_ip: str, firmware_path: str, ssh_key: Optional[str] = None,
                          keep_config: bool = False) -> bool:
    """Upload firmware via SCP and run sysupgrade; resets config (-n) unless keep_config."""
    ok, remote_path = _scp_upload(device_ip, firmware_path, ssh_key)
    if not ok:
        return False

    overlay_path = None
    on_openwrt = (not keep_config) and detect_platform() == "openwrt"
    if keep_config:
        log(f"Firmware uploaded. Running sysupgrade (keeping settings) {remote_path}...")
        cmd = f"sysupgrade {remote_path}"
    elif on_openwrt:
        from profile.overlay import build_overlay_tarball
        overlay_path = build_overlay_tarball(disable_dhcp=True)
        try:
            overlay_name = os.path.basename(overlay_path)
            overlay_remote = f"/tmp/{overlay_name}"
            scp_result = subprocess.run(
                scp_cmd(device_ip, overlay_path, f"root@{device_ip}:{overlay_remote}",
                        key=ssh_key, connect_timeout=10),
                capture_output=True, text=True, timeout=30, check=False,
            )
            if scp_result.returncode == 0:
                log(f"Firmware uploaded. Running sysupgrade -n -f {overlay_remote} {remote_path}...")
                cmd = f"sysupgrade -n -f {overlay_remote} {remote_path}"
            else:
                log("Overlay upload failed, falling back to sysupgrade -n without overlay.")
                cmd = f"sysupgrade -n {remote_path}"
        except OSError:
            log("Overlay generation failed, falling back to sysupgrade -n without overlay.")
            cmd = f"sysupgrade -n {remote_path}"
        finally:
            if overlay_path:
                try:
                    os.unlink(overlay_path)
                except OSError:
                    pass
    else:
        log(f"Firmware uploaded. Running sysupgrade -n {remote_path}...")
        cmd = f"sysupgrade -n {remote_path}"
    ssh_command = ssh_cmd(device_ip, cmd, key=ssh_key, connect_timeout=10)

    try:
        r = subprocess.run(ssh_command, capture_output=True, text=True, timeout=30, check=False)
        combined = (r.stdout or "") + (r.stderr or "")
        if (r.returncode == 0
                or "Commencing upgrade" in combined
                or "Upgrading" in combined
                or "Rebooting" in combined):
            log("sysupgrade initiated successfully.")
            return True
        if r.returncode != 0 and not r.stdout and not r.stderr:
            log("sysupgrade initiated (connection closed by remote — expected).")
            return True
        if "Connection refused" in r.stderr or "Connection timed out" in r.stderr:
            log(f"SSH connection failed during sysupgrade: {r.stderr[:200]}")
            log("Hint: device may have rejected the firmware or SSH is not available")
            return False
        log(f"sysupgrade returned {r.returncode}: {r.stdout[:200]} {r.stderr[:200]}")
        return False
    except subprocess.TimeoutExpired:
        log("sysupgrade command timed out (may have started reboot).")
        return True
    except OSError as e:
        log(f"sysupgrade error: {e}")
        return False


def _flash_via_mtd_write(device_ip: str, firmware_path: str, ssh_key: Optional[str] = None,
                         mtd_command: str = "mtd -r write /tmp/firmware.bin firmware") -> bool:
    """Upload firmware via SCP and run mtd write (for devices where sysupgrade rejects images)."""
    ok, _ = _scp_upload(device_ip, firmware_path, ssh_key)
    if not ok:
        return False

    log(f"Firmware uploaded. Running {mtd_command}...")
    ssh_command = ssh_cmd(device_ip, mtd_command, key=ssh_key, connect_timeout=10)

    try:
        r = subprocess.run(ssh_command, capture_output=True, text=True, timeout=60, check=False)
        combined = (r.stdout or "") + (r.stderr or "")
        # mtd -r reboots after write; connection drop is expected success
        if (r.returncode == 0
                or "Rebooting" in combined
                or "Writing" in combined):
            log("mtd write initiated successfully.")
            return True
        if r.returncode != 0 and not r.stdout and not r.stderr:
            log("mtd write initiated (connection closed by remote — expected).")
            return True
        if "Connection refused" in r.stderr or "Connection timed out" in r.stderr:
            log(f"SSH connection failed during mtd write: {r.stderr[:200]}")
            return False
        log(f"mtd write returned {r.returncode}: {r.stdout[:200]} {r.stderr[:200]}")
        return False
    except subprocess.TimeoutExpired:
        log("mtd write command timed out (may have started reboot).")
        return True
    except OSError as e:
        log(f"mtd write error: {e}")
        return False


def _wait_for_sysupgrade_reboot(device_ip: str, timeout: int = 180) -> bool:
    """Wait for device to come back after sysupgrade reboot."""
    log(f"Waiting for device to reboot and SSH to come back at {device_ip}...")
    start = ts()
    while ts() - start < timeout:
        if check_ssh(device_ip):
            return True
        time.sleep(10)
    log(f"Device did not come back at {device_ip} within {timeout}s")
    log("Hint: the firmware may be incompatible with this device, or the device booted on a different subnet")
    return False


def _find_model_id_by_board(board_name: str) -> Optional[str]:
    model = find_model_by_board_name(board_name)
    return model["id"] if model else None


def _verify_device_identity(device_ip: str, model_id: str,
                            ssh_key: Optional[str] = None) -> tuple[bool, str]:
    """Verify the live device at *device_ip* is an instance of *model_id*.

    AGENTS.md "Always Identify Before Flashing": read BOTH /etc/board.json
    (model.id) and /tmp/sysinfo/board_name from the device and refuse to
    flash on any mismatch. Returns (ok, detail).
    """
    command = (
        "echo '===BOARD_JSON==='; cat /etc/board.json 2>/dev/null; "
        "echo '===BOARD_NAME==='; cat /tmp/sysinfo/board_name 2>/dev/null"
    )
    try:
        r = subprocess.run(ssh_cmd(device_ip, command, key=ssh_key, connect_timeout=10),
                           capture_output=True, text=True, timeout=20, check=False)
    except (subprocess.SubprocessError, OSError) as e:
        return False, f"SSH identity probe failed: {e}"
    if r.returncode != 0:
        stderr_hint = (r.stderr or "").strip()[:200]
        return False, f"SSH identity probe rc={r.returncode}: {stderr_hint or '(no stderr)'}"

    board_json_id = ""
    board_name = ""
    if "===BOARD_JSON===" in r.stdout:
        board_section = r.stdout.split("===BOARD_JSON===", 1)[1]
        board_section = board_section.split("===BOARD_NAME===", 1)[0].strip()
        try:
            board_json_id = json.loads(board_section).get("model", {}).get("id", "")
        except (json.JSONDecodeError, AttributeError):
            board_json_id = ""
    if "===BOARD_NAME===" in r.stdout:
        name_section = r.stdout.split("===BOARD_NAME===", 1)[1].strip()
        if name_section:
            board_name = name_section.splitlines()[0].strip()

    reported = [v for v in (board_json_id, board_name) if v]
    if not reported:
        return False, ("could not read device identity — both /etc/board.json model.id "
                       "and /tmp/sysinfo/board_name are empty/unreadable")
    if board_json_id and board_name and board_json_id != board_name:
        return False, (f"device identity sources disagree: board.json='{board_json_id}' "
                       f"vs /tmp/sysinfo/board_name='{board_name}'")

    for value in reported:
        found = find_model_by_board_name(value)
        if found and found.get("id") == model_id:
            return True, f"device identity '{value}' matches model {model_id}"
    return False, (f"device at {device_ip} reports board '{reported[0]}' which does not "
                   f"match selected model '{model_id}' — refusing to flash")


def _detect_ssh_key_path() -> str:
    cfg = _load_config()
    return cfg.ssh_private_key_path
