"""Boot state detection."""
from __future__ import annotations
import subprocess
from types import SimpleNamespace
from typing import Optional
from flash.context import DEFAULT_IP, log
from flash.upload import detect_uboot_http
from ssh_utils import ssh_cmd

def check_ssh(ip: str = DEFAULT_IP) -> bool:
    try:
        r = subprocess.run(
            ssh_cmd(ip, "echo ok", connect_timeout=5),
            capture_output=True, text=True, timeout=10, check=False,
        )
        return r.returncode == 0 and "ok" in r.stdout
    except Exception:
        return False




def detect_boot_state(interface: str, profile: Optional[SimpleNamespace] = None, timeout: int = 10) -> str:
    """Probe the device to determine its current state.

    Returns: "openwrt", "uboot", "stock-hnap", "stock-edgeos", "stock-extreme", "stock-zyxel", or "unknown"
    """
    openwrt_ip = profile.openwrt_ip if profile else "192.168.1.1"
    recovery_ip = profile.recovery_ip if profile else "192.168.0.1"

    try:
        if check_ssh(openwrt_ip):
            log(f"SSH reachable at {openwrt_ip} — device is running OpenWrt")
            return "openwrt"
    except Exception as e:
        log(f"SSH probe failed for {openwrt_ip}: {e}")

    # When flash_method is dlink-hnap, check HNAP FIRST — the stock firmware
    # also responds with HTML at the recovery IP, so detect_uboot_http would
    # falsely classify it as "uboot" (line 492: startsWith("<!DOCTYPE")).
    if profile and getattr(profile, 'flash_method', '') == 'dlink-hnap':
        try:
            hnap_url = f"http://{recovery_ip}/HNAP1/"
            r = subprocess.run(
                ["curl", "-s", "--max-time", "3", hnap_url],
                capture_output=True, text=True, timeout=5, check=False,
            )
            if "HNAP" in r.stdout or "soap" in r.stdout.lower():
                log(f"HNAP API detected at {recovery_ip} — device is running stock firmware")
                return "stock-hnap"
        except Exception:
            pass

    # EdgeOS detection — check before uboot to prevent false "uboot" detection
    # (EdgeOS web UI returns HTML, which detect_uboot_http matches)
    if profile and getattr(profile, 'flash_method', '') == 'edgeos-kernel-swap':
        import shutil
        edgeos_ip = getattr(profile, 'edgeos_ip', '192.168.1.1')
        edgeos_user = getattr(profile, 'edgeos_user', 'ubnt')
        edgeos_password = getattr(profile, 'edgeos_password', 'ubnt')
        sshpass = shutil.which("sshpass")
        if sshpass:
            try:
                r = subprocess.run(
                    [sshpass, "-p", edgeos_password,
                     "ssh", "-o", "StrictHostKeyChecking=no",
                     "-o", "UserKnownHostsFile=/dev/null",
                     "-o", "ConnectTimeout=5",
                     f"{edgeos_user}@{edgeos_ip}",
                     "cat /etc/version"],
                    capture_output=True, text=True, timeout=10, check=False,
                )
                if r.returncode == 0:
                    log(f"EdgeOS detected at {edgeos_ip} — device is running stock firmware")
                    return "stock-edgeos"
            except Exception as e:
                log(f"EdgeOS SSH probe failed for {edgeos_ip}: {e}")

    if profile and getattr(profile, 'flash_method', '') == 'extreme-rdwr-tftp-initramfs':
        import shutil
        extreme_ip = getattr(profile, 'stock_default_ip', '192.168.1.1')
        extreme_user = getattr(profile, 'stock_default_user', 'admin')
        extreme_password = getattr(profile, 'stock_default_password', '')
        sshpass = shutil.which("sshpass")
        if sshpass and extreme_password:
            try:
                r = subprocess.run(
                    [sshpass, "-p", extreme_password,
                     "ssh", "-o", "StrictHostKeyChecking=no",
                     "-o", "UserKnownHostsFile=/dev/null",
                     "-o", "ConnectTimeout=5",
                     f"{extreme_user}@{extreme_ip}",
                     "which rdwr_boot_cfg"],
                    capture_output=True, text=True, timeout=10, check=False,
                )
                if r.returncode == 0:
                    log(f"Extreme stock firmware detected at {extreme_ip} — rdwr_boot_cfg available")
                    return "stock-extreme"
            except Exception as e:
                log(f"Extreme SSH probe failed for {extreme_ip}: {e}")

    if profile and getattr(profile, 'flash_method', '').startswith('oem-'):
        stock_ip = getattr(profile, 'stock_default_ip', '192.168.1.1')
        try:
            r = subprocess.run(
                ["curl", "-s", "--max-time", "3",
                 f"http://{stock_ip}/cgi-bin/dispatcher.cgi?cmd=0"],
                capture_output=True, text=True, timeout=5, check=False,
            )
            if "dispatcher" in r.stdout.lower() or "password" in r.stdout.lower():
                log(f"ZyXEL OEM web UI detected at {stock_ip} — stock firmware (dispatcher.cgi)")
                return "stock-zyxel"

            r2 = subprocess.run(
                ["curl", "-s", "--max-time", "3",
                 f"http://{stock_ip}/"],
                capture_output=True, text=True, timeout=5, check=False,
            )
            if "login" in r2.stdout.lower() or "password" in r2.stdout.lower() or r2.returncode == 0:
                log(f"OEM web UI detected at {stock_ip} — stock firmware (form login)")
                return "stock-zyxel"
        except Exception as e:
            log(f"OEM probe failed for {stock_ip}: {e}")

    try:
        found, detail = detect_uboot_http(recovery_ip)
        if found:
            log(f"Recovery HTTP at {recovery_ip} — device is in U-Boot mode ({detail})")
            return "uboot"
    except Exception as e:
        log(f"U-Boot HTTP probe failed for {recovery_ip}: {e}")

    if profile and profile.openwrt_ip and profile.recovery_ip:
        if profile.openwrt_ip != "192.168.1.1" or profile.recovery_ip != "192.168.0.1":
            log("No SSH or recovery HTTP detected on profile IPs — device may be on a different subnet")
        else:
            log("No SSH or recovery HTTP detected — device state unknown")
    else:
        log("No SSH or recovery HTTP detected — device state unknown")
    return "unknown"
