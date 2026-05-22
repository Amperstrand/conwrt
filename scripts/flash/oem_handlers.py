"""OEM firmware flash handlers for stock firmware web UI / FTP upload."""
from __future__ import annotations

import os
import random
import re
import shutil
import subprocess
import tempfile
import time
from typing import Optional

from flash.context import log, sha256_file, ts
from flash.context import State
from flash.detect import check_ssh
from ssh_utils import scp_cmd, ssh_cmd


# ─── Shared ZyXEL helpers ──────────────────────────────────────


def zyxel_encode_password(password: str) -> str:
    """Encode password using ZyXEL V2.80+ obfuscation (encode() from OEM JavaScript).

    NOT RSA — custom encoding: password chars at every 5th position (backwards),
    length digits at positions 123 and 289, rest random alphanumeric.
    Total output length: 322 - len(password) characters.
    """
    text = ""
    possible = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    length = len(password)
    remaining = length
    for i in range(1, 322 - length + 1):
        if i % 5 == 0 and remaining > 0:
            remaining -= 1
            text += password[remaining]
        elif i == 123:
            text += "0" if length < 10 else str(length // 10)
        elif i == 289:
            text += str(length % 10)
        else:
            text += random.choice(possible)
    return text


def _read_xssid_cookie(cookie_file: str) -> str:
    """Read HTTP_XSSID value from a curl cookie jar file."""
    try:
        with open(cookie_file) as f:
            for line in f:
                if "HTTP_XSSID" in line:
                    parts = line.split()
                    if len(parts) >= 7:
                        return f"HTTP_XSSID={parts[-1]}"
    except Exception:
        pass
    return ""


def extract_xssid_cookie(stock_ip: str) -> str:
    """Extract XSSID cookie from ZyXEL device via session_chk endpoint."""
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", "5", "-c", "-",
             f"http://{stock_ip}/cgi-bin/dispatcher.cgi?session_chk=1"],
            capture_output=True, text=True, timeout=8, check=False,
        )
        for line in r.stdout.splitlines():
            if "XSSID" in line or "HTTP_XSSID" in line:
                parts = line.split()
                if len(parts) >= 3:
                    return f"XSSID={parts[-1]}"
    except Exception:
        pass
    return ""


# ─── Shared OEM post-upload: poll SSH, SCP, install, verify ────


def oem_reboot_wait_and_install(ctx, openwrt_ip: str, install_fn) -> Optional[State]:
    """Shared reboot→poll SSH→SCP sysupgrade image→install→transition.

    Called by OEM_REBOOTING handler for both oem-http and oem-ftp methods.

    Args:
        ctx: RecoveryContext with profile, image_path, timeline, etc.
        openwrt_ip: IP to poll for SSH after reboot
        install_fn: callable(ctx, openwrt_ip) that does the SCP + install.
                    Returns True on success, False on failure.

    Returns:
        State.OPENWRT_BOOTING on success, State.FAILED on failure,
        None if still waiting (caller should stay in current state).
    """
    profile = ctx.profile
    flash_time = profile.flash_time_seconds

    deadline = ts() + flash_time
    while ts() < deadline:
        time.sleep(5)
        if check_ssh(openwrt_ip):
            log("OpenWrt initramfs booted — SSH available")
            ctx.timeline.ssh_available = ts()
            ctx.timeline.first_openwrt_packet = ts()
            ctx.sha256_after = sha256_file(ctx.image_path) if ctx.image_path and os.path.isfile(ctx.image_path) else ""

            if not ctx.image_path or not os.path.isfile(ctx.image_path):
                log("No sysupgrade image found — initramfs only, skipping permanent install")
                return State.COMPLETE

            success = install_fn(ctx, openwrt_ip)
            if success:
                return State.OPENWRT_BOOTING
            return State.FAILED

        elapsed = int(ts() - (ctx.timeline.flash_triggered or ts()))
        log(f"Waiting for initramfs boot... ({elapsed}s elapsed)")

    log(f"ERROR: Device did not boot within {flash_time}s")
    return State.FAILED


# ─── OEM HTTP handlers (ZyXEL GS1900-8HP style) ───────────────


def oem_http_login(stock_ip: str, username: str, password: str) -> tuple[bool, str]:
    """Login to ZyXEL OEM web UI via curl. Returns (success, cookie_header_value).

    Tries V2.80+ encode()-based POST login first, falls back to V2.00 plaintext GET.
    """
    dispatcher = f"http://{stock_ip}/cgi-bin/dispatcher.cgi"
    cookie_file = tempfile.mktemp(suffix=".cookies")
    try:
        encoded_pw = zyxel_encode_password(password)
        import urllib.parse as _up
        login_body = f"username={username}&password={_up.quote_plus(encoded_pw)}&login=true;"
        log(f"Trying V2.80+ encode()-based login for {username}...")
        r1 = subprocess.run(
            ["curl", "-s", "--max-time", "10",
             "-X", "POST", "-d", login_body, dispatcher],
            capture_output=True, text=True, timeout=15, check=False,
        )
        if "AUTHING" in r1.stdout:
            log("V2.00 firmware detected (AUTHING response), falling back to plaintext GET login")
            return oem_http_login_v200(stock_ip, username, password)

        auth_id = r1.stdout.strip().split("\n")[0].strip()
        if auth_id and len(auth_id) >= 16 and all(c in "0123456789ABCDEFabcdef" for c in auth_id):
            log(f"Got authId: {auth_id[:8]}..., waiting 500ms before login_chk...")
            # Firmware JS uses setTimeout("login_chk();", 500) — delay required
            time.sleep(0.5)
            # login_chk sets HTTP_XSSID cookie — capture to temp file
            r2 = subprocess.run(
                ["curl", "-s", "--max-time", "10", "-c", cookie_file,
                 "-X", "POST", "-d", f"authId={auth_id}&login_chk=true", dispatcher],
                capture_output=True, text=True, timeout=15, check=False,
            )
            chk_result = r2.stdout.strip().split("\n")[0].strip()
            if chk_result == "OK":
                cookie_value = _read_xssid_cookie(cookie_file)
                if cookie_value:
                    log("V2.80+ login successful")
                    return True, cookie_value
                log("V2.80+ login OK but no XSSID cookie — trying session_chk")
                cookie_value = extract_xssid_cookie(stock_ip)
                if cookie_value:
                    return True, cookie_value
                return True, ""
            if chk_result == "FAIL":
                log("V2.80+ login_chk: FAIL (wrong password?)")
            else:
                log(f"V2.80+ login_chk unexpected: {chk_result[:100]}")

        log("V2.80+ login did not get authId, trying V2.00 plaintext fallback...")
        return oem_http_login_v200(stock_ip, username, password)

    except Exception as e:
        log(f"V2.80+ login error: {e}, trying V2.00 fallback...")
        return oem_http_login_v200(stock_ip, username, password)
    finally:
        if os.path.exists(cookie_file):
            os.unlink(cookie_file)


def oem_http_login_v200(stock_ip: str, username: str, password: str) -> tuple[bool, str]:
    """Login to ZyXEL OEM V2.00 web UI via plaintext GET. Returns (success, cookie)."""
    login_url = f"http://{stock_ip}/cgi-bin/dispatcher.cgi?login=1&username={username}&password={password}"
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", "10", "-c", "-", login_url],
            capture_output=True, text=True, timeout=15, check=False,
        )
        cookie_value = ""
        for line in r.stdout.splitlines():
            if "XSSID" in line:
                parts = line.split()
                if len(parts) >= 3:
                    cookie_value = f"XSSID={parts[-1]}"
                    break
        if cookie_value:
            return True, cookie_value
        if "AUTHING" in r.stdout or r.returncode == 0:
            session_chk = subprocess.run(
                ["curl", "-s", "--max-time", "5",
                 f"http://{stock_ip}/cgi-bin/dispatcher.cgi?session_chk=1"],
                capture_output=True, text=True, timeout=8, check=False,
            )
            if "NOTIMEOUT" in session_chk.stdout:
                for line in session_chk.stdout.splitlines():
                    if "XSSID" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            cookie_value = f"XSSID={parts[-1]}"
                            break
                if cookie_value:
                    return True, cookie_value
                return True, ""
        return False, r.stdout[:200]
    except Exception as e:
        return False, str(e)[:200]


def oem_http_change_password(stock_ip: str, username: str, old_password: str,
                              new_password: str, cookie: str) -> tuple[bool, str]:
    """Change password on ZyXEL OEM V2.80+ web UI (mandatory after firmware upgrade).

    Returns (success, message).
    """
    dispatcher = f"http://{stock_ip}/cgi-bin/dispatcher.cgi"
    import urllib.parse as _up

    try:
        # Step 1: Get cmd=30 page to extract XSSID token from the form
        log("Fetching password change page (cmd=30)...")
        r_page = subprocess.run(
            ["curl", "-s", "--max-time", "10",
             "-b", cookie,
             f"{dispatcher}?cmd=30"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        xssid_token = ""
        # Look for XSSID hidden input in the form
        xssid_match = re.search(r'name=["\']XSSID["\'][^>]*value=["\']([^"\']+)["\']', r_page.stdout)
        if not xssid_match:
            xssid_match = re.search(r'value=["\']([^"\']+)["\'][^>]*name=["\']XSSID["\']', r_page.stdout)
        if xssid_match:
            xssid_token = xssid_match.group(1)
            log(f"Found XSSID token: {xssid_token[:8]}...")

        # Step 2: Encode passwords
        encoded_old = zyxel_encode_password(old_password)
        encoded_new = zyxel_encode_password(new_password)

        # Step 3: POST password change (cmd=31)
        form_fields = [
            f"XSSID={_up.quote_plus(xssid_token)}" if xssid_token else "",
            f"usrName={_up.quote_plus(username)}",
            f"usrOldPass={_up.quote_plus(encoded_old)}",
            f"usrPass={_up.quote_plus(encoded_new)}",
            f"usrPass2={_up.quote_plus(encoded_new)}",
            f"usrPassEncode={_up.quote_plus(encoded_new)}",
            "cmd=31",
            "sysSubmit=Apply",
        ]
        post_body = "&".join(f for f in form_fields if f)

        log("Submitting password change...")
        r_change = subprocess.run(
            ["curl", "-s", "--max-time", "15", "-L",
             "-b", cookie, "-c", "-",
             "-X", "POST", "-d", post_body, dispatcher],
            capture_output=True, text=True, timeout=20, check=False,
        )

        # Success: redirect to cmd=4 (main dashboard)
        if "cmd=4" in r_change.stdout or "cmd=4" in getattr(r_change, "redirect_url", ""):
            log(f"Password changed successfully to '{new_password}'")
            return True, f"Password changed to '{new_password}'"

        # Check for error alerts
        alert_match = re.search(r'alert\(["\']([^"\']+)["\']\)', r_change.stdout)
        if alert_match:
            return False, f"Password change rejected: {alert_match.group(1)}"

        # If we got redirected at all, likely success
        if r_change.stdout and len(r_change.stdout) > 100:
            log(f"Password change response ({len(r_change.stdout)} bytes), assuming success")
            return True, f"Password changed to '{new_password}'"

        return False, f"Unexpected response: {r_change.stdout[:200]}"

    except Exception as e:
        return False, f"Password change error: {e}"


def oem_http_upload(stock_ip: str, cookie: str, firmware_path: str,
                    upload_endpoint: str, timeout: int = 300) -> tuple[bool, str]:
    """Upload firmware to ZyXEL switch via OEM HTTP upload endpoint."""
    endpoint = f"http://{stock_ip}{upload_endpoint}"
    size_mb = os.path.getsize(firmware_path) / 1024 / 1024
    log(f"Uploading {os.path.basename(firmware_path)} ({size_mb:.1f} MB) to {upload_endpoint}...")
    try:
        cmd = [
            "curl", "-sk", "--show-error",
            "-H", "Expect:",
            "--max-time", str(timeout),
            "-F", "upmethod=1",
            "-F", "partition=0",
            "-F", "cmd=5904",
            "-F", f"http_file=@{firmware_path};type=application/octet-stream",
        ]
        if cookie:
            cmd.extend(["-b", cookie])
        cmd.append(endpoint)
        r = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=timeout + 30, check=False,
        )
        if r.returncode == 0:
            response_text = r.stdout.strip()
            if "Writing image to FLASH" in response_text or "Prepare for firmware upgrade" in response_text:
                log("Upload accepted — flash write in progress")
                return True, response_text[:300]
            if "Do you really want to reboot" in response_text:
                log("Upload accepted — reboot dialog received")
                return True, response_text[:300]
            if response_text:
                log(f"Upload response: {response_text[:200]}")
                return True, response_text[:300]
            return True, "empty response"
        log(f"Upload failed (exit {r.returncode}): {r.stderr[:300]}")
        return False, r.stderr[:300]
    except subprocess.TimeoutExpired:
        log("OEM HTTP upload timed out.")
        return False, "timeout"
    except Exception as e:
        log(f"OEM HTTP upload error: {e}")
        return False, str(e)


def oem_http_accept_reboot(stock_ip: str, cookie: str) -> bool:
    """Accept the reboot dialog after firmware upload on ZyXEL OEM web UI."""
    reboot_url = f"http://{stock_ip}/cgi-bin/dispatcher.cgi?cmd=5904&reboot=1"
    try:
        cmd = ["curl", "-s", "--max-time", "30", reboot_url]
        if cookie:
            cmd.extend(["-b", cookie])
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=35, check=False)
        if "Rebooting now" in r.stdout or r.returncode == 0:
            log("Reboot accepted — device is restarting")
            return True
        log(f"Reboot response: {r.stdout[:200]}")
        return True
    except Exception as e:
        log(f"Reboot accept error: {e}")
        return True


# ─── OEM FTP handlers (ZyXEL GS1920-24 style) ─────────────────


def oem_ftp_login(stock_ip: str, username: str, password: str) -> tuple[bool, str]:
    """Login to ZyXEL GS1920-24 OEM web UI (standalone form login).

    Uses /Forms/login_standalone_1 with plaintext credentials.
    Returns (success, cookie_file_path).
    """
    login_url = f"http://{stock_ip}/Forms/login_standalone_1"
    cookie_file = tempfile.mktemp(suffix=".cookies")
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", "10",
             "-c", cookie_file, "-b", cookie_file,
             "-X", "POST",
             "-d", f"Username={username}",
             "-d", f"Password={password}",
             "-d", "Login=Login",
             "-L", "-o", "/dev/null", "-w", "%{http_code}",
             login_url],
            capture_output=True, text=True, timeout=15, check=False,
        )
        if r.returncode == 0:
            log(f"GS1920-24 login HTTP {r.stdout.strip()}")
            return True, cookie_file
        return False, f"HTTP {r.stdout.strip()}"
    except Exception as e:
        return False, str(e)


def oem_ftp_enable_service(stock_ip: str, cookie_file: str) -> tuple[bool, str]:
    """Enable FTP service on ZyXEL switch via Access Service page.

    POSTs to /Forms/rpaccessservice_1 with FTP checkbox enabled.
    """
    enable_url = f"http://{stock_ip}/Forms/rpaccessservice_1"
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", "10",
             "-b", cookie_file,
             "-X", "POST",
             "-d", "RpAccessSv_ChkFTP=on",
             "-d", "RpGeneral_IptTextFTPPort=21",
             "-d", "RpAccessSv_ChkTelnet=on",
             "-d", "RpGeneral_IptTextTelnetPort=23",
             "-d", "RpAccessSv_ChkWeb=on",
             "-d", "RpAccessSv_ChkSNMP=on",
             "-d", "RpAccessSv_BtnApply=Apply",
             "-o", "/dev/null", "-w", "%{http_code}",
             enable_url],
            capture_output=True, text=True, timeout=15, check=False,
        )
        code = r.stdout.strip()
        if code in ("200", "303"):
            log(f"FTP service enabled (HTTP {code})")
            # Wait for FTP service to start
            time.sleep(2)
            return True, f"HTTP {code}"
        return False, f"Unexpected HTTP {code}"
    except Exception as e:
        return False, str(e)


def oem_ftp_upload(stock_ip: str, username: str, password: str,
                   firmware_path: str, target: str = "ras-0",
                   client_ip: str = "") -> tuple[bool, str]:
    """Upload firmware to ZyXEL switch via FTP (active mode).

    Uses curl FTP PUT in active mode (--ftp-port). The ZyNOS FTP server
    rejects PASV/EPSV with '500 Unknown command'.

    Args:
        target: FTP file target — 'ras-0' for slot 1, 'ras-1' for slot 2
        client_ip: Local IP for active FTP data connection

    Returns:
        (success, message)
    """
    size_mb = os.path.getsize(firmware_path) / 1024 / 1024
    log(f"Uploading {os.path.basename(firmware_path)} ({size_mb:.1f} MB) via FTP to {target}...")

    cmd = [
        "curl", "-v",
        "-T", firmware_path,
        f"ftp://{username}:{password}@{stock_ip}:21/{target}",
        "--connect-timeout", "10",
        "--max-time", "300",
    ]
    if client_ip:
        cmd.extend(["--ftp-port", client_ip])

    try:
        r = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=330, check=False,
        )
        output = r.stdout + r.stderr
        if r.returncode == 0 and ("226" in output or "transfer complete" in output.lower()):
            log("FTP upload successful — 226 File received OK")
            return True, "FTP upload successful"
        if r.returncode == 0:
            log(f"FTP upload completed (curl OK): {output[-200:]}")
            return True, output[-300:]
        return False, f"FTP failed (exit {r.returncode}): {output[-300:]}"
    except subprocess.TimeoutExpired:
        return False, "FTP upload timed out"
    except Exception as e:
        return False, str(e)


# ─── Install functions ─────────────────────────────────────────


def install_sysupgrade(ctx, openwrt_ip: str) -> bool:
    """SCP sysupgrade image to device and run sysupgrade -n. (GS1900-8HP style)"""
    sysupgrade_path = ctx.image_path
    if not sysupgrade_path or not os.path.isfile(sysupgrade_path):
        log("No sysupgrade image — skipping permanent install")
        return True

    remote_name = os.path.basename(sysupgrade_path)
    size_mb = os.path.getsize(sysupgrade_path) / 1024 / 1024
    log(f"Uploading sysupgrade image ({size_mb:.1f} MB) via SCP...")

    scp_result = subprocess.run(
        scp_cmd(openwrt_ip, sysupgrade_path, f"/tmp/{remote_name}", key=ctx.ssh_key_path),
        capture_output=True, text=True, timeout=120, check=False,
    )
    if scp_result.returncode != 0:
        log(f"SCP failed: {scp_result.stderr[:300]}")
        return False

    log("Sysupgrade image uploaded. Running sysupgrade -n...")
    subprocess.run(
        ssh_cmd(openwrt_ip, f"sysupgrade -n /tmp/{remote_name}", key=ctx.ssh_key_path),
        capture_output=True, text=True, timeout=30, check=False,
    )
    return True


def install_mtd_write(ctx, openwrt_ip: str) -> bool:
    """SCP loader.bin + sysupgrade.bin, then mtd write both. (GS1920-24 style)

    Follows upstream install flow from target/linux/realtek/image/common.mk
    (Device/uimage-rt-loader-bootbase): mtd write loader.bin loader, then
    mtd write sysupgrade.bin firmware, then reboot.
    """
    sysupgrade_path = ctx.image_path
    if not sysupgrade_path or not os.path.isfile(sysupgrade_path):
        log("No sysupgrade image — skipping permanent install")
        return True

    # Find loader.bin — expected next to the sysupgrade image
    image_dir = os.path.dirname(sysupgrade_path)
    loader_path = os.path.join(image_dir, "loader.bin")

    if os.path.isfile(loader_path):
        log(f"Uploading loader.bin ({os.path.getsize(loader_path) / 1024 / 1024:.1f} MB) via SCP...")
        scp_loader = subprocess.run(
            scp_cmd(openwrt_ip, loader_path, "/tmp/loader.bin", key=ctx.ssh_key_path),
            capture_output=True, text=True, timeout=120, check=False,
        )
        if scp_loader.returncode != 0:
            log(f"SCP loader.bin failed: {scp_loader.stderr[:300]}")
            return False

    remote_name = os.path.basename(sysupgrade_path)
    log(f"Uploading sysupgrade image ({os.path.getsize(sysupgrade_path) / 1024 / 1024:.1f} MB) via SCP...")
    scp_result = subprocess.run(
        scp_cmd(openwrt_ip, sysupgrade_path, f"/tmp/{remote_name}", key=ctx.ssh_key_path),
        capture_output=True, text=True, timeout=120, check=False,
    )
    if scp_result.returncode != 0:
        log(f"SCP sysupgrade failed: {scp_result.stderr[:300]}")
        return False

    # Build install commands
    commands = []
    if os.path.isfile(loader_path):
        commands.append("mtd write /tmp/loader.bin loader")
    commands.append(f"mtd -r write /tmp/{remote_name} firmware")

    install_cmd = " && ".join(commands)
    log(f"Running: {install_cmd}")
    subprocess.run(
        ssh_cmd(openwrt_ip, install_cmd, key=ctx.ssh_key_path),
        capture_output=True, text=True, timeout=120, check=False,
    )
    return True


# ─── OEM method dispatch ───────────────────────────────────────

# Maps flash method name → (install_function, has_prepare_step)
OEM_METHOD_CONFIG = {
    "oem-http": {
        "install_fn": install_sysupgrade,
        "has_prepare": False,  # no FTP-enable step
    },
    "oem-ftp": {
        "install_fn": install_mtd_write,
        "has_prepare": True,   # must enable FTP service first
    },
}


def get_oem_install_fn(method_name: str):
    """Get the install function for an OEM flash method."""
    config = OEM_METHOD_CONFIG.get(method_name, {})
    return config.get("install_fn", install_sysupgrade)


def oem_has_prepare_step(method_name: str) -> bool:
    """Whether this OEM method needs a PREPARE step (e.g., enable FTP)."""
    config = OEM_METHOD_CONFIG.get(method_name, {})
    return config.get("has_prepare", False)
