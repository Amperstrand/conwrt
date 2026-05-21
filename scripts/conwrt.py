#!/usr/bin/env python3
# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false
"""conwrt — OpenWrt flasher with auto-detection, pcap monitoring, and ASU integration.

Reads device profiles from conwrt model JSON files via model_loader.
Auto-detects device state (OpenWrt running, U-Boot recovery, or offline) and
picks the appropriate flash method (SSH sysupgrade or U-Boot HTTP upload).

Usage:
    # Flash (auto-detects method):
    conwrt --request-image --wan-ssh
    conwrt flash --model-id dlink-covr-x1860-a1 --request-image --force-uboot

    # List supported models:
    conwrt list

    # Manage cached firmware:
    conwrt cache list
    conwrt cache clean --keep-latest
    conwrt cache clean --model-id dlink-covr-x1860-a1
"""

import argparse
import hashlib
import hmac
import io
import json
import os
import queue
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from contextlib import redirect_stdout
from enum import Enum, auto
from pathlib import Path
from types import SimpleNamespace
from typing import Optional

# model_loader is in the same directory
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ssh_utils import ssh_cmd, scp_cmd
from config import load_config as _load_config
from model_loader import load_model, list_models, openwrt_asu_profile, find_model_by_board_name
from flash.device_profile import build_profile_from_model as _build_profile_from_model
from flash.device_profile import find_recovery_flash_method as _find_recovery_flash_method
from flash.context import (
    DEFAULT_IP,
    Event,
    PcapMonitorConfig,
    REBOOT_TIMEOUT,
    SILENCE_TIMEOUT_DEFAULT,
    State,
    Timeline,
    get_link_state,
    log,
    say,
    sha256_file,
    ts,
    ts_str,
)
from flash.upload import detect_uboot_http, upload_firmware, trigger_flash
from flash.detect import check_ssh, detect_boot_state as _detect_boot_state
from sticker_creds import dump_and_extract_config2, apply_credentials_to_openwrt
from zycast import run_zycast_auto
import importlib
_firmware_manager = importlib.import_module("firmware-manager")
firmware_request = _firmware_manager.cmd_request
firmware_find = _firmware_manager.cmd_find
IMAGES_DIR = _firmware_manager.IMAGES_DIR
_router_fingerprint = importlib.import_module("router-fingerprint")
fingerprint_router = _router_fingerprint.fingerprint_router
save_fingerprint = _router_fingerprint.save_fingerprint

from platform_utils import detect_platform, is_root, has_scapy, has_tcpdump, check_external_deps, get_link_state as platform_get_link_state, configure_interface_ip, remove_interface_ip
from profile import apply_plan, build_plan, print_plan
from profile.wifi import build_mgmt_wifi_script


def _setup_interface_ips(interface: str, profile: SimpleNamespace) -> None:
    if profile.client_ip:
        configure_interface_ip(interface, profile.client_ip, "24")
    openwrt_client = profile.openwrt_client_ip
    if openwrt_client and openwrt_client != profile.client_ip:
        configure_interface_ip(interface, openwrt_client, "24")


def _flash_via_sysupgrade(device_ip: str, firmware_path: str, ssh_key: Optional[str] = None) -> bool:
    """Upload firmware via SCP and run sysupgrade -n."""
    firmware_name = os.path.basename(firmware_path)
    remote_path = f"/tmp/{firmware_name}"

    scp_command = scp_cmd(device_ip, firmware_path, f"root@{device_ip}:{remote_path}",
                          key=ssh_key, connect_timeout=10)

    size_mb = os.path.getsize(firmware_path) / 1024 / 1024
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
            return False
    except subprocess.TimeoutExpired:
        log("SCP upload timed out.")
        return False
    except Exception as e:
        log(f"SCP error: {e}")
        return False

    log(f"Firmware uploaded. Running sysupgrade -n {remote_path}...")
    ssh_command = ssh_cmd(device_ip, f"sysupgrade -n {remote_path}",
                          key=ssh_key, connect_timeout=10)

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
    except Exception as e:
        log(f"sysupgrade error: {e}")
        return False


def _flash_via_mtd_write(device_ip: str, firmware_path: str, ssh_key: Optional[str] = None,
                         mtd_command: str = "mtd -r write /tmp/firmware.bin firmware") -> bool:
    """Upload firmware via SCP and run mtd write (for devices where sysupgrade rejects images)."""
    firmware_name = os.path.basename(firmware_path)
    remote_path = f"/tmp/{firmware_name}"

    scp_command = scp_cmd(device_ip, firmware_path, f"root@{device_ip}:{remote_path}",
                          key=ssh_key, connect_timeout=10)

    size_mb = os.path.getsize(firmware_path) / 1024 / 1024
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
            return False
    except subprocess.TimeoutExpired:
        log("SCP upload timed out.")
        return False
    except Exception as e:
        log(f"SCP error: {e}")
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
    except Exception as e:
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


def _detect_ssh_key_path() -> str:
    cfg = _load_config()
    return cfg.ssh_private_key_path


def cmd_setup_mgmt_wifi(args: argparse.Namespace) -> int:
    ssh_key = _detect_ssh_key_path()
    if not ssh_key:
        print("ERROR: No SSH private key found. Set [ssh].key in config.toml or install ~/.ssh/id_ed25519 or ~/.ssh/id_rsa.", file=sys.stderr)
        return 1

    verify_cmd = " && ".join([
        "uci -q get network.mgmt.ipaddr | grep -qx '172.16.0.1'",
        "uci -q get dhcp.mgmt.interface | grep -qx 'mgmt'",
        "uci -q show firewall | grep -q \"\\.name='mgmt'\"",
        "uci -q show wireless | grep -q \"\\.network='mgmt'\"",
    ])
    verify_result = subprocess.run(
        ssh_cmd(args.ip, verify_cmd, key=ssh_key, connect_timeout=10),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if verify_result.returncode == 0:
        print(f"Management WiFi already configured on {args.ip}")
        return 0

    cfg = _load_config()
    script = build_mgmt_wifi_script(txpower=cfg.mgmt_wifi_txpower)
    ssh_command = ssh_cmd(args.ip, "sh -s", key=ssh_key, connect_timeout=10)

    try:
        result = subprocess.run(
            ssh_command,
            input=script,
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print(f"ERROR: Timed out configuring management WiFi on {args.ip}.", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"ERROR: Failed to run setup script over SSH: {exc}", file=sys.stderr)
        return 1

    if result.returncode != 0:
        if result.stderr:
            print(result.stderr.strip(), file=sys.stderr)
        return result.returncode or 1

    verify_result2 = subprocess.run(
        ssh_cmd(args.ip, verify_cmd, key=ssh_key, connect_timeout=10),
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    if verify_result2.returncode != 0:
        if result.stdout.strip():
            print(result.stdout.strip())
        if verify_result2.stderr.strip():
            print(verify_result2.stderr.strip(), file=sys.stderr)
        print("ERROR: Management WiFi verification failed.", file=sys.stderr)
        return 1

    if result.stdout.strip():
        print(result.stdout.strip())
    print(f"Management WiFi configured on {args.ip}")
    return 0


def _arp_target_for_profile(profile: SimpleNamespace) -> str:
    parts = profile.recovery_ip.rsplit(".", 1)
    return f"{parts[0]}.2"


# ---------------------------------------------------------------------------
# D-Link HNAP custom AES-128 (simplified — no MixColumns)
# ---------------------------------------------------------------------------

_AES_Sbox = [
    99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,118,
    202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,
    183,253,147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,
    199,35,195,24,150,5,154,7,18,128,226,235,39,178,117,9,131,44,
    26,27,110,90,160,82,59,214,179,41,227,47,132,83,209,0,237,32,
    252,177,91,106,203,190,57,74,76,88,207,208,239,170,251,67,77,
    51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,
    245,188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,
    196,167,126,61,100,93,25,115,96,129,79,220,34,42,144,136,70,
    238,184,20,222,94,11,219,224,50,58,10,73,6,36,92,194,211,172,
    98,145,149,228,121,231,200,55,109,141,213,78,169,108,86,244,
    234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,116,31,
    75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,
    193,29,158,225,248,152,17,105,217,142,148,155,30,135,233,206,
    85,40,223,140,161,137,13,191,230,66,104,65,153,45,15,176,84,
    187,22
]

_AES_ShiftRowTab = [0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11]


def _aes_encrypt(state, key_schedule):
    for i in range(16):
        state[i] ^= key_schedule[i]
    s = 16
    while s < len(key_schedule) - 16:
        for i in range(16):
            state[i] = _AES_Sbox[state[i]]
        tmp = list(state)
        for i in range(16):
            state[i] = tmp[_AES_ShiftRowTab[i]]
        for i in range(16):
            state[i] ^= key_schedule[s + i]
        s += 16
    for i in range(16):
        state[i] = _AES_Sbox[state[i]]
    tmp = list(state)
    for i in range(16):
        state[i] = tmp[_AES_ShiftRowTab[i]]
    for i in range(16):
        state[i] ^= key_schedule[s + i]
    return state


def _str2hex(s):
    return ''.join(f'{ord(c):02x}' for c in s)


def _hexstr2arr(hexstr, length):
    result = [0] * length
    for i in range(min(len(hexstr) // 2, length)):
        result[i] = int(hexstr[2*i:2*i+2], 16)
    return result


def _arr2hex(arr):
    return ''.join(f'{b:02x}' for b in arr)


def _aes_encrypt128(plaintext, private_key):
    if not all(c in '0123456789abcdefABCDEF' for c in private_key):
        private_key = _str2hex(private_key)
    if len(private_key) > 32:
        private_key = private_key[:32]
    key_arr = _hexstr2arr(private_key, 32)
    pt_hex = _str2hex(plaintext)
    pt_arr = _hexstr2arr(pt_hex, 64)
    output = [0] * 64
    for block in range(4):
        state = [pt_arr[16*block + i] for i in range(16)]
        state = _aes_encrypt(state, key_arr)
        for i in range(16):
            output[16*block + i] = state[i]
    return _arr2hex(output)


# ---------------------------------------------------------------------------
# D-Link HNAP flash method
# ---------------------------------------------------------------------------

_HNAP_NS = "http://purenetworks.com/HNAP1/"


def _hmac_md5_hex(key: str, msg: str) -> str:
    """Return hex HMAC-MD5 of *msg* using string *key*."""
    return hmac.new(key.encode(), msg.encode(), hashlib.md5).hexdigest()


def _chang_text(s: str) -> str:
    """Swap case of each character (D-Link HNAP_AUTH helper)."""
    return s.swapcase()


def _build_soap_body(inner_xml: str) -> bytes:
    """Wrap *inner_xml* in a standard HNAP SOAP envelope."""
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        'xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
        'xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">'
        f"<soap:Body>{inner_xml}</soap:Body>"
        "</soap:Envelope>"
    )
    return xml.encode("utf-8")


def _hnap_auth_header(private_key: str, soap_action: str, timestamp: str) -> str:
    auth_hash = _hmac_md5_hex(private_key, timestamp + soap_action)
    return f"{_chang_text(auth_hash)} {timestamp}"


def _hnap_content_header(body: bytes, private_key: str) -> str:
    body_md5 = hashlib.md5(body).hexdigest().upper()
    return _aes_encrypt128(body_md5, private_key).upper()


def _parse_hnap_response(body_bytes: bytes) -> dict[str, str]:
    """Extract text values from an HNAP SOAP XML response.

    Returns a dict mapping local tag names to their text content.
    """
    result: dict[str, str] = {}
    try:
        root = ET.fromstring(body_bytes)
        for elem in root.iter():
            tag = elem.tag
            # Strip namespace prefix like {http://purenetworks.com/HNAP1/}
            if "}" in tag:
                tag = tag.split("}", 1)[1]
            if elem.text and elem.text.strip():
                result[tag] = elem.text.strip()
    except ET.ParseError:
        pass
    return result


def _hnap_post(
    url: str,
    body: bytes,
    soap_action: str,
    private_key: str = "",
    cookie: str = "",
    content_type: str = "text/xml",
    timeout: int = 60,
    send_hnap_content: bool = False,
) -> tuple[int, bytes, dict[str, str]]:
    headers: dict[str, str] = {
        "Content-Type": content_type,
        "SOAPACTION": f'"{soap_action}"',
    }
    if private_key:
        ts = str(int(time.time() * 1000))
        headers["HNAP_AUTH"] = _hnap_auth_header(private_key, soap_action, ts)
        if send_hnap_content:
            headers["HNAP_CONTENT"] = _hnap_content_header(body, private_key)
    if cookie:
        headers["Cookie"] = cookie

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_headers = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, resp.read(), resp_headers
    except urllib.error.HTTPError as exc:
        resp_body = exc.read() if exc.fp else b""
        resp_headers = {k.lower(): v for k, v in exc.headers.items()}
        return exc.code, resp_body, resp_headers
    except urllib.error.URLError as exc:
        log(f"HNAP request failed (URLError): {exc.reason}")
        return 0, b"", {}


def _hnap_login(base_url: str, soap_login: str, password: str) -> Optional[tuple[str, str]]:
    """Perform the 3-step HNAP challenge-response login.

    Returns (private_key, cookie_uid) on success, None on failure.
    Raises URLError/OSError on network errors (for retry handling).
    """
    log("HNAP: Sending login challenge-request...")
    login_request_body = _build_soap_body(
        f'<Login xmlns="{_HNAP_NS}">'
        "<Action>request</Action>"
        "<Username>Admin</Username>"
        "<LoginPassword></LoginPassword>"
        "<Captcha></Captcha>"
        "</Login>"
    )
    # D-Link HNAP requires HNAP_AUTH header even on the initial challenge-request,
    # using the literal string "withoutloginkey" as the HMAC key (per Login.js).
    status, resp_body, resp_headers = _hnap_post(
        base_url, login_request_body, soap_login,
        private_key="withoutloginkey",
    )
    if status != 200:
        log(f"HNAP: login request failed (HTTP {status})")
        return None

    parsed = _parse_hnap_response(resp_body)
    challenge = parsed.get("Challenge", "")
    public_key = parsed.get("PublicKey", "")

    # Extract session cookie: D-Link returns it in the XML <Cookie> element,
    # not as an HTTP Set-Cookie header.  Build "uid=<value>" for subsequent
    # requests.
    cookie_uid = ""
    xml_cookie = parsed.get("Cookie", "")
    if xml_cookie:
        cookie_uid = f"uid={xml_cookie}"
    if not cookie_uid:
        cookie_value = resp_headers.get("set-cookie", "")
        if cookie_value:
            for part in cookie_value.split(";"):
                part = part.strip()
                if part.lower().startswith("uid="):
                    cookie_uid = part
                    break
    if not cookie_uid:
        for header_val in resp_headers.values():
            if "uid=" in header_val:
                for part in header_val.split(";"):
                    part = part.strip()
                    if part.lower().startswith("uid="):
                        cookie_uid = part
                        break

    if not challenge or not public_key:
        log(f"HNAP: login challenge missing Challenge/PublicKey: {parsed}")
        return None

    log(f"HNAP: Got challenge (len={len(challenge)}), public_key (len={len(public_key)})")

    private_key = _hmac_md5_hex(public_key + password, challenge).upper()
    login_password = _hmac_md5_hex(private_key, challenge).upper()

    log("HNAP: Sending login (final)...")
    login_final_body = _build_soap_body(
        f'<Login xmlns="{_HNAP_NS}">'
        "<Action>login</Action>"
        "<Username>Admin</Username>"
        f"<LoginPassword>{login_password}</LoginPassword>"
        "</Login>"
    )
    status, resp_body, _ = _hnap_post(
        base_url, login_final_body, soap_login,
        private_key=private_key, cookie=cookie_uid,
    )
    if status != 200:
        log(f"HNAP: login final failed (HTTP {status})")
        return None

    parsed = _parse_hnap_response(resp_body)
    login_result = parsed.get("LoginResult", "").lower()
    if login_result != "success":
        log(f"HNAP: login rejected: {parsed}")
        return None

    log("HNAP: Login successful")
    return private_key, cookie_uid


def _flash_via_dlink_hnap(
    image_path: str,
    profile: SimpleNamespace,
    timeout: int = 300,
) -> tuple[bool, str]:
    """Upload firmware to a D-Link router via the HNAP SOAP API.

    Implements the full HNAP auth flow:
      1. Login challenge-request → get Challenge, PublicKey, Cookie
      2. Derive PrivateKey and LoginPassword via HMAC-MD5
      3. Login final with LoginPassword
      4. FirmwareUpload via multipart POST
      5. GetFirmwareValidation to trigger the flash

    The password comes from profile.default_password (set in model JSON
    flash_methods.dlink-hnap.default_password).
    """
    router_ip = profile.recovery_ip
    base_url = f"http://{router_ip}/HNAP1/"
    password = getattr(profile, "default_password", "")

    if not password:
        return False, "No default_password configured for dlink-hnap flash method"

    soap_login = f"{_HNAP_NS}Login"

    max_retries = 2
    last_error = ""
    for attempt in range(1, max_retries + 1):
        try:
            result = _hnap_login(base_url, soap_login, password)
            if result is not None:
                private_key, cookie_uid = result
                break
            last_error = "HNAP login failed (auth rejected)"
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            last_error = f"HNAP login network error: {exc}"
            if attempt < max_retries:
                log(f"HNAP: login attempt {attempt} failed ({exc}), retrying in 5s...")
                time.sleep(5)
        else:
            if attempt == max_retries:
                return False, last_error
    else:
        return False, last_error

    log("HNAP: Login successful")

    soap_upload = f"{_HNAP_NS}FirmwareUpload"
    size_mb = os.path.getsize(image_path) / 1024 / 1024
    log(f"HNAP: Uploading firmware ({size_mb:.1f} MB)...")

    if size_mb > 50:
        log(f"WARNING: Firmware is {size_mb:.1f} MB — loading into memory for multipart upload")

    boundary = f"----ConwrtBoundary{secrets.token_hex(8)}"
    filename = os.path.basename(image_path)
    with open(image_path, "rb") as f:
        file_data = f.read()

    parts = []
    parts.append(f"--{boundary}\r\n".encode())
    parts.append(
        f'Content-Disposition: form-data; name="FWFile"; filename="{filename}"\r\n'.encode()
    )
    parts.append(b"Content-Type: application/octet-stream\r\n\r\n")
    parts.append(file_data)
    parts.append(f"\r\n--{boundary}--\r\n".encode())
    multipart_body = b"".join(parts)

    upload_headers: dict[str, str] = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "SOAPACTION": f'"{soap_upload}"',
    }
    ts = str(int(time.time() * 1000))
    upload_headers["HNAP_AUTH"] = _hnap_auth_header(private_key, soap_upload, ts)
    upload_headers["HNAP_CONTENT"] = _hnap_content_header(b"", private_key)
    upload_headers["Cookie"] = cookie_uid

    req = urllib.request.Request(
        base_url, data=multipart_body, headers=upload_headers, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_body = resp.read()
    except urllib.error.HTTPError as exc:
        resp_body = exc.read() if exc.fp else b""
        if exc.code >= 400:
            return False, f"HNAP firmware upload failed (HTTP {exc.code}): {resp_body[:300]}"
    except urllib.error.URLError as exc:
        return False, f"HNAP firmware upload connection failed: {exc.reason}"

    parsed = _parse_hnap_response(resp_body)
    upload_result = parsed.get("FirmwareUploadResult", "").lower()
    if upload_result not in ("ok", "success"):
        # Some firmwares return non-standard results; log but continue
        log(f"HNAP: FirmwareUpload result: {parsed} (proceeding anyway)")

    log("HNAP: Firmware uploaded successfully")

    # --- Step 5: GetFirmwareValidation to trigger flash ---
    soap_validate = f"{_HNAP_NS}GetFirmwareValidation"
    log("HNAP: Triggering firmware validation/flash...")

    validate_body = _build_soap_body(
        f'<GetFirmwareValidation xmlns="{_HNAP_NS}" />'
    )
    status, resp_body, _ = _hnap_post(
        base_url, validate_body, soap_validate,
        private_key=private_key, cookie=cookie_uid,
        timeout=30, send_hnap_content=True,
    )
    if status not in (200, 0):
        log(f"HNAP: GetFirmwareValidation returned HTTP {status} (non-fatal)")
    else:
        parsed = _parse_hnap_response(resp_body)
        is_valid = parsed.get("IsValid", "").lower()
        result = parsed.get("GetFirmwareValidationResult", "")
        countdown = parsed.get("CountDown", "")
        if is_valid == "false":
            log("WARNING: Firmware validation FAILED — device rejected the firmware image. "
                "The stock firmware's bootloader validation blocks non-OEM firmware. "
                "Use recovery-http (U-Boot) method instead.")
        elif is_valid == "true" and countdown:
            log(f"HNAP: Flash in progress — CountDown={countdown}s")
        else:
            log(f"HNAP: Validation response — IsValid={is_valid}, Result={result}, CountDown={countdown}")

    return True, "HNAP firmware upload and validation triggered"


def check_ssh(ip: str = DEFAULT_IP) -> bool:
    try:
        r = subprocess.run(
            ssh_cmd(ip, "echo SSH_OK", connect_timeout=3),
            capture_output=True, text=True, timeout=10, check=False,
        )
        return "SSH_OK" in r.stdout
    except Exception:
        return False


def _apply_profile_post_flash(
    ip: str,
    ssh_key: str = "",
    cfg: object = None,
    model_id: str = "",
    interface: str = "",
    old_client_ip: str = "",
    *,
    password: Optional[str] = None,
    wan_ssh: Optional[bool] = None,
    ssh_key_path: Optional[str] = None,
    dry_run: bool = False,
) -> str:
    """Apply config.toml profile via unified plan (WiFi, use cases, LAN IP)."""
    from config import ConwrtConfig
    if not isinstance(cfg, ConwrtConfig):
        return ip

    model_caps: list[str] = []
    if model_id:
        try:
            model = load_model(model_id)
            model_caps = model.get("capabilities", [])
        except FileNotFoundError:
            pass

    effective_wan_ssh = cfg.wan_ssh if wan_ssh is None else wan_ssh
    plan = build_plan(
        cfg,
        mode="preview" if dry_run else "post_install",
        model_capabilities=model_caps,
        ssh_key_path=ssh_key_path,
        password=password,
        wan_ssh=effective_wan_ssh,
    )
    if not dry_run:
        log("Applying profile via SSH...")
    ip = apply_plan(plan, ip, ssh_key=ssh_key, dry_run=dry_run, log=log)

    if not dry_run and cfg.lan_ip and interface:
        new_ip = _apply_lan_ip_post_flash(
            ip, ssh_key=ssh_key, cfg=cfg,
            interface=interface, old_client_ip=old_client_ip,
        )
        if new_ip:
            ip = new_ip
    return ip


def _apply_sticker_credentials_post_flash(
    ip: str, ssh_key: str = "", model_id: str = "", cfg: object = None,
) -> None:
    """Restore factory sticker WiFi credentials after flashing.

    Only activates when the model has a ``sticker_credentials`` section in
    its model JSON AND the user hasn't configured an explicit WiFi AP in
    config.toml (sticker creds are the fallback/default).
    """
    from config import ConwrtConfig
    if not isinstance(cfg, ConwrtConfig):
        return

    if cfg.wifi_ap:
        return

    if not model_id:
        return
    try:
        model = load_model(model_id)
    except FileNotFoundError:
        return
    if "sticker_credentials" not in model:
        return

    log("Restoring factory sticker WiFi credentials...")
    key = ssh_key or None
    try:
        data = dump_and_extract_config2(ip, key=key)
    except RuntimeError as exc:
        log(f"  ⚠ sticker creds: dump failed — {exc}")
        return

    wifi = data.get("wifi", {})
    macs = data.get("macs", {})
    ssid_24g = wifi.get("ssid_24g", "")
    ssid_5g = wifi.get("ssid_5g", "")
    log(f"  Extracted: 2.4G SSID={ssid_24g or '(none)'}, "
        f"5G SSID={ssid_5g or '(none)'}")
    if macs.get("factory_mac"):
        log(f"  Factory MAC: {macs['factory_mac']}")

    try:
        apply_credentials_to_openwrt(ip, wifi, key=key, model_id=model_id)
    except RuntimeError as exc:
        log(f"  ⚠ sticker creds: apply failed — {exc}")
        return

    log("  ✓ sticker credentials applied")


def _register_wireguard_post_flash(
    ip: str, ssh_key: str = "", cfg: object = None,
) -> str:
    """Read the auto-generated WireGuard public key from the router and
    register it with the VPN server.

    Returns the public key string, or empty string on failure.
    """
    from config import ConwrtConfig
    if not isinstance(cfg, ConwrtConfig):
        return ""
    if not cfg.wireguard or not cfg.wireguard.registration_server:
        return ""

    server = cfg.wireguard.registration_server
    wg_if = cfg.wireguard.wg_interface
    key = ssh_key or None

    # Try to read the public key directly (interface may already be up)
    r = subprocess.run(
        ssh_cmd(ip, "wg show wg0 public-key 2>/dev/null", key=key, connect_timeout=10),
        capture_output=True, text=True, timeout=15, check=False,
    )
    pub_key = r.stdout.strip()

    # If interface isn't up yet, derive from private key without leaking it
    # to the process table (pipe via stdin, not command-line args)
    if not pub_key or len(pub_key) < 40:
        r1 = subprocess.run(
            ssh_cmd(ip, "uci -q get network.wg0.private_key", key=key, connect_timeout=10),
            capture_output=True, text=True, timeout=15, check=False,
        )
        priv_key = r1.stdout.strip()
        if not priv_key or priv_key == "generate":
            log("  WG: no private key found on router (WireGuard not configured)")
            return ""

        # Pipe private key through stdin to avoid exposing it in ps/process args
        r2 = subprocess.run(
            ssh_cmd(ip, "wg pubkey", key=key, connect_timeout=10),
            input=priv_key, capture_output=True, text=True, timeout=15, check=False,
        )
        pub_key = r2.stdout.strip()
        if not pub_key or len(pub_key) < 40:
            log(f"  ⚠ WG: could not derive public key (got {len(pub_key)} chars)")
            return ""

    log(f"  WG: public key = {pub_key}")

    # Read the tunnel address from the router
    r3 = subprocess.run(
        ssh_cmd(ip, "uci -q get network.wg0.addresses", key=key, connect_timeout=10),
        capture_output=True, text=True, timeout=15, check=False,
    )
    address = r3.stdout.strip()
    if not address:
        address = "0.0.0.0/0"

    # Register the peer with the VPN server
    log(f"  WG: registering peer {address} with {server}...")
    reg_cmd = f"wg set {wg_if} peer {pub_key} allowed-ips {address}"
    r4 = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null",
         "-o", "BatchMode=yes",
         "-o", "ConnectTimeout=10",
         server, reg_cmd],
        capture_output=True, text=True, timeout=15, check=False,
    )
    if r4.returncode == 0:
        log(f"  ✓ WG: peer registered with {server}")
    else:
        log(f"  ⚠ WG: registration failed — {r4.stderr.strip()[:200]}")

    addr_host = address.split("/")[0]
    persist_cmd = (
        f"grep -q '{pub_key}' /etc/wireguard/{wg_if}.conf 2>/dev/null || "
        f"printf '\\n[Peer]\\nPublicKey = {pub_key}\\nAllowedIPs = {addr_host}/32\\n' "
        f">> /etc/wireguard/{wg_if}.conf"
    )
    subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null",
         "-o", "BatchMode=yes",
         "-o", "ConnectTimeout=10",
         server, persist_cmd],
        capture_output=True, text=True, timeout=15, check=False,
    )

    return pub_key


def _client_ip_for_subnet(router_ip: str) -> str:
    """Derive a client IP on the same /24 subnet as router_ip.

    Takes the first three octets from router_ip and uses .254 as the client.
    """
    octets = router_ip.split(".")
    if len(octets) != 4:
        return ""
    return f"{octets[0]}.{octets[1]}.{octets[2]}.254"


def _apply_lan_ip_post_flash(
    ip: str, ssh_key: str = "", cfg: object = None,
    interface: str = "", old_client_ip: str = "",
) -> str:
    """Change the router's LAN IP and reconnect on the new subnet.

    This MUST be the last post-flash step — the network restart will drop SSH.
    After changing the router's LAN IP:
      1. Remove old client IP alias from the interface
      2. Add new client IP alias on the new subnet
      3. Wait for the router to come back on the new IP
      4. Verify SSH on the new IP

    Returns the new router IP, or empty string on failure.
    """
    from config import ConwrtConfig
    if not isinstance(cfg, ConwrtConfig):
        return ""
    if not cfg.lan_ip:
        return ""
    if not interface:
        log("  ⚠ LAN IP: no interface — skipping IP change")
        return ""

    new_ip = cfg.lan_ip
    if new_ip == ip:
        return new_ip

    new_client_ip = _client_ip_for_subnet(new_ip)
    if not new_client_ip:
        log(f"  ⚠ LAN IP: invalid target IP '{new_ip}'")
        return ""

    log(f"  Changing LAN IP from {ip} to {new_ip}...")
    key = ssh_key or None

    uci_commands = " && ".join([
        f"uci set network.lan.ipaddr='{new_ip}'",
        "uci commit network",
        "(/etc/init.d/network reload >/dev/null 2>&1) &",
        "exit 0",
    ])
    try:
        r = subprocess.run(
            ssh_cmd(ip, uci_commands, key=key, connect_timeout=10),
            capture_output=True, text=True, timeout=15, check=False,
        )
        log(f"  LAN IP change command sent (rc={r.returncode})")
    except subprocess.TimeoutExpired:
        log("  LAN IP change: SSH session ended (expected — network restarting)")

    time.sleep(5)

    if old_client_ip:
        remove_interface_ip(interface, old_client_ip, "24")

    plat = detect_platform()
    if plat == "darwin":
        subprocess.run(["sudo", "arp", "-d", ip], capture_output=True, check=False)
        subprocess.run(["sudo", "arp", "-d", new_ip], capture_output=True, check=False)
    else:
        subprocess.run(["ip", "neigh", "flush", "to", ip], capture_output=True, check=False)
        subprocess.run(["ip", "neigh", "flush", "to", new_ip], capture_output=True, check=False)

    configure_interface_ip(interface, new_client_ip, "24")

    log(f"  Waiting for router at {new_ip} (client IP {new_client_ip})...")
    if _wait_for_sysupgrade_reboot(new_ip, timeout=120):
        log(f"  ✓ LAN IP changed to {new_ip}")
        return new_ip
    else:
        log(f"  ⚠ LAN IP: router did not come back at {new_ip}")
        return ""


def verify_router(ip: str = DEFAULT_IP, wan_ssh_expected: bool = False,
                  mgmt_wifi_expected: bool = False) -> list[tuple[str, str]]:
    log("Verifying router state...")
    checks: list[tuple[str, str]] = []
    try:
        r = subprocess.run(
            ssh_cmd(ip,
                    "echo hostname=$(cat /proc/sys/kernel/hostname); "
                    "echo board=$(cat /etc/board.json | jsonfilter -e '@.model.id' 2>/dev/null || echo unknown); "
                    "echo kernel=$(uname -r); "
                    "echo sshkey_count=$(wc -l < /etc/dropbear/authorized_keys 2>/dev/null || echo 0); "
                    "echo sshkey_size=$(wc -c < /etc/dropbear/authorized_keys 2>/dev/null || echo 0); "
                    "echo wan_ssh=$(uci show firewall 2>/dev/null | grep Allow-SSH-WAN | wc -l); "
                    "echo uci_defaults=$(ls /etc/uci-defaults/ 2>/dev/null | wc -l); "
                    "echo mac_brlan=$(cat /sys/class/net/br-lan/address 2>/dev/null || echo ''); "
                    "echo 'mac_all='$(for f in /sys/class/net/*/address; do printf '%s=%s ' $(basename $(dirname $f)) $(cat $f 2>/dev/null); done); "
                    "echo mgmt_wifi=$(uci -q get network.mgmt.ipaddr || echo ''); "
                    "echo mgmt_ssid=$(uci -q get wireless.@wifi-iface[0].ssid || echo ''); "
                    "echo mgmt_radio=$(uci -q get wireless.radio0.disabled || echo ''); "
                    "echo nmap_ok=$(which nmap >/dev/null 2>&1 && echo yes || echo no); "
                    "echo ping_ok=$(ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 && echo yes || echo no)",
                    connect_timeout=5),
            capture_output=True, text=True, timeout=20, check=False,
        )
        for line in r.stdout.strip().split('\n'):
            if '=' in line:
                key, val = line.split('=', 1)
                checks.append((key, val))
                log(f"  verify: {key}: {val}")

        d = dict(checks)

        uci_defaults = d.get("uci_defaults", "?")
        if uci_defaults == "0":
            log("  ✓ uci-defaults: all consumed (first boot complete)")
        else:
            log(f"  ⚠ uci-defaults: {uci_defaults} remaining")

        sshkey_count = d.get("sshkey_count", "0")
        if int(sshkey_count or 0) > 0:
            log(f"  ✓ SSH keys: {sshkey_count} authorized")
        else:
            log("  ⚠ SSH keys: none found")

        if wan_ssh_expected:
            wan_ssh = d.get("wan_ssh", "0")
            if int(wan_ssh or 0) > 0:
                log("  ✓ WAN SSH: firewall rule present")
            else:
                log("  ⚠ WAN SSH: no firewall rule found")

        if mgmt_wifi_expected:
            mgmt_ip = d.get("mgmt_wifi", "")
            mgmt_ssid = d.get("mgmt_ssid", "")
            if mgmt_ip:
                log(f"  ✓ mgmt WiFi: network configured ({mgmt_ip})")
            else:
                log("  ⚠ mgmt WiFi: network not configured")
            if mgmt_ssid.startswith("MGMT-"):
                log(f"  ✓ mgmt WiFi: SSID={mgmt_ssid}")
            else:
                log(f"  ⚠ mgmt WiFi: unexpected SSID '{mgmt_ssid}'")

        ping_ok = d.get("ping_ok", "no")
        if ping_ok == "yes":
            log("  ✓ network: connectivity confirmed (ping 8.8.8.8)")
        else:
            log("  ⚠ network: no connectivity")

        nmap_ok = d.get("nmap_ok", "no")
        if nmap_ok == "yes":
            log("  ✓ extra package: nmap installed")

    except Exception as e:
        log(f"Verification failed: {e}")
    return checks


def probe_router_info(ip: str = DEFAULT_IP) -> Optional[dict]:
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from router_probe import probe_router as _probe_router
        result = _probe_router(ip=ip)
        return {
            "model": result.model,
            "vendor": result.vendor,
            "firmware_version": result.firmware_version,
            "mac": result.mac,
            "ssh_key_count": result.ssh_key_count,
            "state": result.state,
        }
    except Exception as e:
        log(f"Router probe failed: {e}")
        return None


class PcapMonitor:
    """Background thread that captures packets and emits events to a queue."""

    def __init__(self, config: PcapMonitorConfig, event_queue: queue.Queue):
        self.config = config
        self.event_queue = event_queue
        self._stop = threading.Event()
        self._last_packet_time: float = ts()
        self._silence_timeout = config.silence_timeout
        self._writer_proc: Optional[subprocess.Popen] = None
        self._reader_proc: Optional[subprocess.Popen] = None
        self._known_uboot_macs: set[str] = set()
        self._pcap_writer = None
        self._scapy = None

    def stop(self) -> None:
        self._stop.set()

    def _start_writer(self) -> Optional[subprocess.Popen]:
        try:
            tcpdump_cmd = ["tcpdump", "-i", self.config.interface,
                           "-w", self.config.pcap_path, "-n", "-U", "--immediate-mode",
                           "--buffer-size=16384"]
            if not is_root():
                tcpdump_cmd = ["sudo", "-n"] + tcpdump_cmd
            proc = subprocess.Popen(
                tcpdump_cmd,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            time.sleep(0.5)
            if proc.poll() is not None:
                err = proc.stderr.read().decode(errors="replace")
                log(f"tcpdump writer failed: {err.strip()}")
                return None
            return proc
        except FileNotFoundError:
            log("tcpdump not found")
            return None

    def _start_reader(self) -> Optional[subprocess.Popen]:
        if not os.path.isfile(self.config.pcap_path):
            return None
        try:
            proc = subprocess.Popen(
                ["tcpdump", "-r", self.config.pcap_path, "-nn", "-l"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            return proc
        except FileNotFoundError:
            return None

    def _restart_writer(self) -> None:
        if self._writer_proc and self._writer_proc.poll() is None:
            self._writer_proc.terminate()
            try:
                self._writer_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._writer_proc.kill()
        time.sleep(2)
        new_proc = self._start_writer()
        if new_proc:
            self._writer_proc = new_proc
            log("tcpdump writer restarted")

    def _emit(self, event: Event, detail: str = "") -> None:
        self._last_packet_time = ts()
        self.event_queue.put((event, ts(), detail))

    def _open_pcap_writer(self, append: bool) -> None:
        if self._scapy is None:
            raise RuntimeError("scapy not initialized")
        pcap_dir = os.path.dirname(self.config.pcap_path)
        if pcap_dir:
            os.makedirs(pcap_dir, exist_ok=True)
        self._pcap_writer = self._scapy.PcapWriter(
            self.config.pcap_path,
            append=append,
            sync=True,
        )

    def _close_pcap_writer(self) -> None:
        if self._pcap_writer is None:
            return
        try:
            self._pcap_writer.close()
        except Exception:
            pass
        self._pcap_writer = None

    def _write_packet(self, packet: object) -> None:
        if self._pcap_writer is None:
            self._open_pcap_writer(append=os.path.exists(self.config.pcap_path))
        try:
            self._pcap_writer.write(packet)
        except Exception as e:
            log(f"pcap writer error, reopening append writer: {e}")
            self._close_pcap_writer()
            self._open_pcap_writer(append=os.path.exists(self.config.pcap_path))
            self._pcap_writer.write(packet)

    def _packet_detail(self, packet: object) -> str:
        try:
            return str(packet.summary())[:120]
        except Exception:
            return packet.__class__.__name__[:120]

    def _payload_looks_like_http(self, packet: object) -> bool:
        if self._scapy is None or not packet.haslayer(self._scapy.Raw):
            return False
        try:
            raw_layer = packet.getlayer(self._scapy.Raw)
            if raw_layer is None:
                return False
            payload = bytes(getattr(raw_layer, "load", b""))
        except Exception:
            return False
        return payload.startswith((
            b"GET ",
            b"POST ",
            b"HEAD ",
            b"PUT ",
            b"DELETE ",
            b"OPTIONS ",
            b"PATCH ",
            b"HTTP/1.",
        ))

    def _handle_packet(self, packet: object) -> None:
        if self._scapy is None:
            return

        self._last_packet_time = ts()
        self._write_packet(packet)

        arp_target = self.config.recovery_ip.rsplit(".", 1)[0] + ".2"
        detail = self._packet_detail(packet)

        if packet.haslayer(self._scapy.ARP):
            try:
                arp = packet.getlayer(self._scapy.ARP)
                if arp is None:
                    raise ValueError("missing ARP layer")
                src_mac = getattr(arp, "hwsrc", "").lower()
                if int(getattr(arp, "op", 0)) == 1 and getattr(arp, "pdst", "") == arp_target:
                    if self.config.router_mac_openwrt and src_mac != self.config.router_mac_openwrt.lower():
                        self._emit(Event.UBOOT_ARP_192_168_1_2, f"src_mac={src_mac}")
                        return
                    self._emit(Event.UBOOT_ARP_192_168_1_2, detail)
                    return
            except Exception:
                pass

        if packet.haslayer(self._scapy.IP):
            try:
                ip = packet.getlayer(self._scapy.IP)
                if ip is None:
                    raise ValueError("missing IP layer")
                if (
                    getattr(ip, "src", "") == self.config.recovery_ip
                    and packet.haslayer(self._scapy.TCP)
                    and self._payload_looks_like_http(packet)
                ):
                    self._emit(Event.UBOOT_HTTP, detail)
            except Exception:
                pass

        if self.config.router_mac_openwrt and packet.haslayer(self._scapy.IPv6):
            try:
                ether = packet.getlayer(self._scapy.Ether) if packet.haslayer(self._scapy.Ether) else None
                ipv6 = packet.getlayer(self._scapy.IPv6)
                if ipv6 is None:
                    raise ValueError("missing IPv6 layer")
                if (
                    ether is not None
                    and getattr(ether, "src", "").lower() == self.config.router_mac_openwrt.lower()
                    and int(getattr(ipv6, "nh", -1)) == 58
                ):
                    self._emit(Event.ICMPV6_FROM_ROUTER, detail)
            except Exception:
                pass

        if packet.haslayer(self._scapy.UDP):
            try:
                udp = packet.getlayer(self._scapy.UDP)
                if udp is None:
                    raise ValueError("missing UDP layer")
                if int(getattr(udp, "sport", 0)) == 4919 or int(getattr(udp, "dport", 0)) == 4919:
                    self._emit(Event.FAILSAFE_BROADCAST, detail)
                if (
                    self.config.zycast_multicast_group
                    and packet.haslayer(self._scapy.IP)
                ):
                    ip_layer = packet.getlayer(self._scapy.IP)
                    if ip_layer is not None:
                        dst_ip = getattr(ip_layer, "dst", "")
                        dst_port = int(getattr(udp, "dport", 0))
                        if (
                            dst_ip == self.config.zycast_multicast_group
                            and dst_port == self.config.zycast_multicast_port
                        ):
                            self._emit(Event.ZYCAST_MULTICAST_DETECTED, detail)
            except Exception:
                pass

    def _check_silence(self, last_silence_check: float, interval: int = 5) -> float:
        now = ts()
        if now - last_silence_check < interval:
            return last_silence_check
        if now - self._last_packet_time >= self._silence_timeout:
            self.event_queue.put((
                Event.NO_PACKETS_FOR_N_SECONDS, now,
                f"no packets for {int(now - self._last_packet_time)}s",
            ))
            self._last_packet_time = now
        return now

    def _parse_line(self, line: str) -> None:
        line = line.strip()
        if not line:
            return

        lower = line.lower()
        recovery_ip = self.config.recovery_ip
        arp_target = recovery_ip.rsplit(".", 1)[0] + ".2"

        if "http" in lower and recovery_ip in lower:
            if "length" in lower:
                self._emit(Event.UBOOT_HTTP, line[:120])

        if "arp" in lower and f"who-has {arp_target}" in lower:
            mac_match = re.search(
                r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:'
                r'[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', line,
            )
            if mac_match:
                src_mac = mac_match.group(1).lower()
                if self.config.router_mac_openwrt and src_mac != self.config.router_mac_openwrt.lower():
                    self._emit(Event.UBOOT_ARP_192_168_1_2, f"src_mac={src_mac}")
                    return
            self._emit(Event.UBOOT_ARP_192_168_1_2, line[:120])

        # ICMPv6 from router's real MAC (OpenWrt booting — uses different MAC than U-Boot)
        if "icmp6" in lower and self.config.router_mac_openwrt:
            router_mac = self.config.router_mac_openwrt.lower()
            if router_mac in lower:
                self._emit(Event.ICMPV6_FROM_ROUTER, line[:120])

        # Failsafe broadcast (UDP 4919)
        if "udp" in lower and "4919" in lower:
            self._emit(Event.FAILSAFE_BROADCAST, line[:120])

        if (
            self.config.zycast_multicast_group
            and "udp" in lower
            and self.config.zycast_multicast_group in line
            and str(self.config.zycast_multicast_port) in line
        ):
            self._emit(Event.ZYCAST_MULTICAST_DETECTED, line[:120])

    def _run_tcpdump_fallback(self) -> Optional[bool]:
        self._writer_proc = self._start_writer()

        if not self._writer_proc:
            return None

        # Wait for pcap file header to be written
        time.sleep(1)

        self._reader_proc = self._start_reader()

        last_silence_check = ts()

        while not self._stop.is_set():
            if self._writer_proc and self._writer_proc.poll() is not None:
                log("tcpdump writer died (interface gone?), will restart when link returns")
                time.sleep(3)
                if get_link_state(self.config.interface):
                    self._restart_writer()
                    if self._reader_proc and self._reader_proc.poll() is None:
                        self._reader_proc.terminate()
                        self._reader_proc.wait(timeout=3)
                    time.sleep(1)
                    self._reader_proc = self._start_reader()

            if self._reader_proc and self._reader_proc.poll() is None:
                try:
                    import selectors
                    sel = selectors.DefaultSelector()
                    sel.register(self._reader_proc.stdout, selectors.EVENT_READ)
                    ready = sel.select(timeout=0.1)
                    sel.close()
                    if ready:
                        raw_line = self._reader_proc.stdout.readline()
                        if raw_line:
                            self._parse_line(raw_line.decode(errors="replace"))
                except Exception:
                    pass
            else:
                if self._reader_proc:
                    time.sleep(1)
                    self._reader_proc = self._start_reader()
                time.sleep(0.2)

            last_silence_check = self._check_silence(last_silence_check)

        if self._reader_proc and self._reader_proc.poll() is None:
            self._reader_proc.terminate()
            try:
                self._reader_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._reader_proc.kill()

        if self._writer_proc and self._writer_proc.poll() is None:
            self._writer_proc.terminate()
            try:
                self._writer_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._writer_proc.kill()

    def run(self) -> None:
        log(f"Pcap monitor starting: iface={self.config.interface} pcap={self.config.pcap_path}")

        try:
            from scapy.all import ARP, Ether, IP, IPv6, PcapWriter, Raw, TCP, UDP, sniff
            self._scapy = SimpleNamespace(
                ARP=ARP,
                Ether=Ether,
                IP=IP,
                IPv6=IPv6,
                PcapWriter=PcapWriter,
                Raw=Raw,
                TCP=TCP,
                UDP=UDP,
                sniff=sniff,
            )
            # Test if we can actually sniff (needs root for raw sockets)
            test_sock = None
            try:
                from scapy.all import conf, L2socket
                test_sock = L2socket(iface=self.config.interface)
                test_sock.close()
            except Exception:
                raise PermissionError(
                    f"no permission to capture on {self.config.interface} "
                    f"(need root or CAP_NET_RAW)"
                )
        except PermissionError:
            log(f"scapy: permission denied — trying sudo tcpdump fallback")
            self._run_tcpdump_fallback()
            log("Pcap monitor stopped")
            return
        except Exception as e:
            log(f"scapy unavailable, falling back to tcpdump capture: {e}")
            tcpdump_result = self._run_tcpdump_fallback()
            if tcpdump_result is None:
                log("WARNING: no packet capture available (no root). "
                    "State machine will rely on link monitoring and SSH polling only.")
                return
            log("Pcap monitor stopped")
            return

        try:
            if os.path.exists(self.config.pcap_path):
                os.remove(self.config.pcap_path)
            self._open_pcap_writer(append=False)

            last_silence_check = ts()
            last_link_state: Optional[bool] = None

            while not self._stop.is_set():
                link_up = get_link_state(self.config.interface)
                if link_up != last_link_state:
                    if link_up:
                        log(f"scapy capture active on {self.config.interface}")
                    else:
                        log(f"scapy capture paused, link down on {self.config.interface}")
                    last_link_state = link_up

                if not link_up:
                    time.sleep(0.5)
                    last_silence_check = self._check_silence(last_silence_check)
                    continue

                try:
                    self._scapy.sniff(
                        iface=self.config.interface,
                        store=False,
                        prn=self._handle_packet,
                        timeout=1,
                        stop_filter=lambda _pkt: self._stop.is_set(),
                    )
                except Exception as e:
                    if not self._stop.is_set():
                        log(f"scapy sniff error on {self.config.interface}: {e}")
                        time.sleep(1)

                last_silence_check = self._check_silence(last_silence_check)
        finally:
            self._close_pcap_writer()
            log("Pcap monitor stopped")


class LinkMonitor:
    """Polls link state in a background thread and emits LINK_UP/LINK_DOWN events."""

    def __init__(self, interface: str, event_queue: queue.Queue, poll_interval: float = 0.5):
        self.interface = interface
        self.event_queue = event_queue
        self._stop = threading.Event()
        self._poll_interval = poll_interval
        self._last_state: Optional[bool] = None

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                current = get_link_state(self.interface)
                if self._last_state is not None and current != self._last_state:
                    if current:
                        self.event_queue.put((Event.LINK_UP, ts(), ""))
                    else:
                        self.event_queue.put((Event.LINK_DOWN, ts(), ""))
                self._last_state = current
            except Exception:
                pass
            self._stop.wait(self._poll_interval)


class SSHMonitor:
    """Polls SSH availability in background and emits SSH_UP event."""

    def __init__(self, ip: str, event_queue: queue.Queue, poll_interval: float = 5.0):
        self.ip = ip
        self.event_queue = event_queue
        self._stop = threading.Event()
        self._poll_interval = poll_interval

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                if check_ssh(self.ip):
                    self.event_queue.put((Event.SSH_UP, ts(), ""))
                    return
            except Exception:
                pass
            self._stop.wait(self._poll_interval)


def _setup_monitors(
    interface: str,
    event_queue: queue.Queue,
    pcap_path: str,
    profile: object,
    args: argparse.Namespace,
    pcap_enabled: bool = True,
) -> tuple[Optional[PcapMonitor], Optional[threading.Thread], LinkMonitor, threading.Thread]:
    """Create and start PcapMonitor (optional) and LinkMonitor."""
    pcap_monitor = None
    pcap_thread = None

    if pcap_enabled and not getattr(args, 'no_pcap', False) and has_scapy() and has_tcpdump():
        zycast_group = getattr(profile, 'zycast_multicast_group', '')
        zycast_port = getattr(profile, 'zycast_multicast_port', 0)
        monitor_config = PcapMonitorConfig(
            interface=interface,
            pcap_path=pcap_path,
            recovery_ip=profile.recovery_ip,
            router_mac_openwrt=args.router_mac,
            router_mac_uboot=args.uboot_mac,
            silence_timeout=args.silence_timeout,
            zycast_multicast_group=zycast_group,
            zycast_multicast_port=zycast_port,
        )
        pcap_monitor = PcapMonitor(monitor_config, event_queue)
        pcap_thread = threading.Thread(target=pcap_monitor.run, daemon=True)
        pcap_thread.start()
    elif pcap_enabled:
        log("pcap monitoring disabled (polling-only mode)")

    link_monitor = LinkMonitor(interface, event_queue)
    link_thread = threading.Thread(target=link_monitor.run, daemon=True)
    link_thread.start()

    return pcap_monitor, pcap_thread, link_monitor, link_thread


def _teardown_monitors(
    pcap_monitor: Optional[PcapMonitor],
    pcap_thread: Optional[threading.Thread],
    link_monitor: LinkMonitor,
    link_thread: threading.Thread,
) -> None:
    """Stop and join monitor threads."""
    if pcap_monitor:
        pcap_monitor.stop()
    link_monitor.stop()
    if pcap_thread:
        pcap_thread.join(timeout=5)
    link_thread.join(timeout=5)


def _auto_detect_serial_port() -> str:
    import glob as globmod
    candidates = sorted(globmod.glob("/dev/cu.usbserial*") + globmod.glob("/dev/cu.SLAB_USBtoUART*"))
    if candidates:
        return candidates[0]
    raise FileNotFoundError(
        "No serial adapter found. Checked /dev/cu.usbserial* and /dev/cu.SLAB_USBtoUART*. "
        "Use --serial-port to specify manually."
    )


class TFTPServerManager:
    def __init__(self, tftp_root: str, bind_ip: str = "0.0.0.0"):
        self.tftp_root = tftp_root
        self.bind_ip = bind_ip or "0.0.0.0"
        self._proc: Optional[subprocess.Popen] = None

    def start(self) -> bool:
        if not os.path.isdir(self.tftp_root):
            log(f"ERROR: TFTP root directory not found: {self.tftp_root}")
            return False

        tftp_script = os.path.join(os.path.dirname(__file__), "..", "..", "jtag", "tftp-server.py")
        if not os.path.isfile(tftp_script):
            tftp_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tftp-server.py")

        tftp_cmd = None
        if os.path.isfile(tftp_script):
            tftp_cmd = [sys.executable, tftp_script, self.tftp_root, self.bind_ip]
        else:
            if detect_platform() != "openwrt":
                import shutil
                dnsmasq = shutil.which("dnsmasq")
                if dnsmasq:
                    tftp_cmd = [
                        dnsmasq,
                        f"--tftp-root={self.tftp_root}",
                        "--no-daemon",
                        "--port=0",
                        f"--listen-address={self.bind_ip}",
                    ]
            else:
                log("On OpenWrt: skipping dnsmasq (conflicts with existing DNS/DHCP)")
                log("  Place tftp-server.py in scripts/ directory for TFTP support")

        if not tftp_cmd:
            log("WARNING: No TFTP server script found. U-Boot TFTP commands may fail.")
            log("  Expected: jtag/tftp-server.py or scripts/tftp-server.py")
            return False

        log(f"Starting TFTP server: {' '.join(tftp_cmd)}")
        try:
            self._proc = subprocess.Popen(
                tftp_cmd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            time.sleep(1)
            if self._proc.poll() is not None:
                err = self._proc.stderr.read().decode(errors="replace")
                log(f"TFTP server failed to start: {err.strip()}")
                self._proc = None
                return False
            log(f"TFTP server serving {self.tftp_root} on {self.bind_ip}:69 (PID {self._proc.pid})")
            return True
        except Exception as e:
            log(f"TFTP server error: {e}")
            self._proc = None
            return False

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            log("TFTP server stopped")

    @property
    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None


class SerialUBootDriver:
    ERROR_STRINGS = ["ERROR:", "not found", "Bad CRC", "usage:", "Unknown command"]

    def __init__(self, port: str, baud: int = 115200, timeout: float = 0.1):
        try:
            import serial as _serial
        except ImportError:
            print("ERROR: pyserial is required for serial-tftp flash method.", file=sys.stderr)
            print("  Install with: pip install pyserial", file=sys.stderr)
            sys.exit(1)
        self._serial_mod = _serial
        self.ser = _serial.Serial(port, baud, timeout=timeout)
        self.port = port
        self.baud = baud

    def _drain(self, timeout: float = 0.5) -> bytes:
        time.sleep(timeout)
        data = b""
        while True:
            chunk = self.ser.read(4096)
            if not chunk:
                break
            data += chunk
        return data

    def wait_for_bootmenu(self, timeout: float = 60, interrupt: str = "ctrl-c",
                          console_option: str = "0", say_fn=None) -> bool:
        buf = b""
        start = time.time()
        while time.time() - start < timeout:
            chunk = self.ser.read(4096)
            if chunk:
                buf += chunk
                text = chunk.decode("ascii", errors="replace")
                for line in text.split("\n"):
                    clean = line.strip()
                    if clean:
                        log(f"  [serial] {clean}")

                full_text = buf.decode("ascii", errors="replace")

                if "Hit any key" in full_text or "stop autoboot" in full_text.lower():
                    log("Bootmenu countdown detected — entering U-Boot console")
                    if say_fn:
                        say_fn("Bootmenu detected. Entering U-Boot console.")
                    time.sleep(0.5)
                    self.ser.write(b"\x03")
                    time.sleep(0.3)
                    self.ser.write((console_option + "\r\n").encode())
                    time.sleep(2)
                    remaining = self._drain(2)
                    full_text += remaining.decode("ascii", errors="replace")

                if "=>" in full_text:
                    log("Got U-Boot prompt")
                    self._drain(0.5)
                    return True

                if "login:" in full_text or "init:" in full_text:
                    log("ERROR: Linux already booting — too late to interrupt")
                    return False

        log("ERROR: Timed out waiting for U-Boot bootmenu")
        return False

    def send_command(self, cmd: str, wait: float = 3) -> tuple[bool, str]:
        self._drain(0.2)
        self.ser.write((cmd + "\r\n").encode())
        time.sleep(wait)
        data = self._drain(0.5)
        text = data.decode("ascii", errors="replace")

        output_lines = []
        for line in text.strip().split("\n"):
            clean = line.strip()
            if clean and clean != cmd:
                output_lines.append(clean)

        has_error = any(err in text for err in self.ERROR_STRINGS)

        if "tftpboot" in cmd and "Bytes transferred" not in text and "LOAD ERROR" not in text.upper():
            if "ERROR" in text.upper() or "Retry count exceeded" in text:
                has_error = True

        return has_error, "\n".join(output_lines)

    def run_commands(self, commands: list[str], event_queue: queue.Queue,
                     say_fn=None, flash_time_seconds: int = 120) -> bool:
        total = len(commands)
        for i, cmd in enumerate(commands):
            progress = f"[{i+1}/{total}]"
            log(f"{progress} U-Boot: {cmd}")

            cmd_lower = cmd.lower()

            if "tftpboot" in cmd_lower:
                wait = 15
                if ".bin" in cmd_lower:
                    fn_match = re.search(r'tftpboot\s+\S+\s+(\S+)', cmd)
                    if fn_match:
                        fn = fn_match.group(1)
                        if "chunk" in fn:
                            wait = 300
                say_msg = f"Transferring file {i+1} of {total}"
            elif "nand erase" in cmd_lower or "mtd erase" in cmd_lower:
                wait = 30
                say_msg = f"Erasing flash partition {i+1} of {total}"
            elif "nand write" in cmd_lower or "mtd write" in cmd_lower:
                wait = 30
                say_msg = f"Writing flash partition {i+1} of {total}"
            elif "ubi create" in cmd_lower:
                wait = 5
                say_msg = f"Creating UBI volume {i+1} of {total}"
            elif "reset" in cmd_lower:
                wait = 2
                say_msg = "Rebooting router"
            else:
                wait = 3
                say_msg = ""

            if say_fn and say_msg:
                say_fn(say_msg)

            has_error, output = self.send_command(cmd, wait)

            if output:
                for line in output.split("\n")[:10]:
                    log(f"  {line}")

            if has_error and "reset" not in cmd_lower:
                log(f"ERROR: Command failed: {cmd}")
                log(f"  Output: {output[:300]}")
                event_queue.put((Event.SERIAL_COMMAND_DONE, ts(), f"ERROR: {cmd}"))
                return False

            event_queue.put((Event.SERIAL_COMMAND_DONE, ts(), cmd))

        event_queue.put((Event.SERIAL_ALL_DONE, ts(), ""))
        return True

    def close(self):
        if self.ser and self.ser.is_open:
            self.ser.close()
            log(f"Serial port {self.port} closed")


@dataclass
class RecoveryContext:
    profile: object  # SimpleNamespace loaded from model JSON via model_loader
    image_path: str
    interface: str
    pcap_path: str
    initramfs_path: str = ""
    no_upload: bool = False
    no_voice: bool = False
    router_mac_openwrt: str = ""
    router_mac_uboot: str = ""
    timeline: Timeline = field(default_factory=Timeline)
    state: State = State.WAITING_FOR_POWER_OFF
    sha256_before: str = ""
    sha256_after: str = ""
    generated_password: str = ""
    password_set: bool = False
    auth_type: str = ""          # "key-and-password", "key-only", or "password-only"
    wireguard_pubkey: str = ""
    wan_ssh_enabled: bool = False
    force_uboot: bool = False
    no_pcap: bool = False
    boot_state: str = "unknown"
    ssh_key_path: str = ""
    serial_port: str = ""
    serial_method: str = ""
    serial_baud: int = 115200
    tftp_root: str = ""
    uboot_commands: list = field(default_factory=list)
    request_hash: str = ""
    cache_key: str = ""
    packages: list = field(default_factory=list)
    defaults_script: str = ""
    assume_yes: bool = False
    _say_fn: object = field(default=None, repr=False)

    def __post_init__(self):
        if self._say_fn is None:
            self._say_fn = say


def _generate_random_password() -> str:
    password = secrets.token_urlsafe(16)
    print()
    print("=" * 60)
    print(f"  Generated random password: {password}")
    print("=" * 60)
    print()
    return password


def _validate_args(args: argparse.Namespace) -> Optional[str]:
    if not args.image and not args.request_image:
        return "One of --image or --request-image is required."

    if args.image and args.request_image:
        return "--image and --request-image are mutually exclusive."

    if args.image:
        image_only_flags = []
        if args.ssh_key:
            image_only_flags.append("--ssh-key")
        if args.password:
            image_only_flags.append("--password")
        if args.no_password:
            image_only_flags.append("--no-password")
        if args.wan_ssh:
            image_only_flags.append("--wan-ssh")
        if image_only_flags:
            return (
                f"{', '.join(image_only_flags)} only valid with --request-image, "
                f"not with --image."
            )

    return None


def _resolve_asu_profile(model_id: str) -> str:
    return openwrt_asu_profile(load_model(model_id))


def _request_custom_image(
    model_id: str,
    ssh_key_path: Optional[str],
    password: Optional[str],
    wan_ssh: bool,
    flash_method: str,
    say_fn,
) -> tuple[Optional[str], dict]:
    asu_profile = _resolve_asu_profile(model_id)
    say_fn("Requesting custom firmware image from ASU...")
    log(f"ASU profile: {asu_profile}")

    model = load_model(model_id)
    target = model.get("openwrt", {}).get("target", "")
    version = model.get("openwrt", {}).get("version", "24.10.2")

    request_args = argparse.Namespace(
        profile=asu_profile,
        version=version,
        target=target or None,
        packages=None,
        ssh_key=ssh_key_path,
        password=password,
        wan_ssh=wan_ssh,
    )

    request_buf = io.StringIO()
    with redirect_stdout(request_buf):
        rc = firmware_request(request_args)
    if rc != 0:
        log("ERROR: ASU firmware request failed.")
        return None, {}

    recovery_methods = {
        "recovery-http",
        "uboot-http",
        "uboot-tftp",
        "zycast",
        "dlink-hnap",
        "mtd-write",
        "extreme-rdwr-tftp-initramfs",
        "oem-http",
    }
    if flash_method in recovery_methods:
        preferred_types = ["recovery", "factory", "initramfs"]
    else:
        preferred_types = ["sysupgrade"]

    image_path = None
    for img_type in preferred_types:
        find_args = argparse.Namespace(
            profile=asu_profile,
            type=img_type,
        )
        find_buf = io.StringIO()
        with redirect_stdout(find_buf):
            firmware_find(find_args)
        candidate = find_buf.getvalue().strip()
        if candidate and os.path.isfile(candidate):
            image_path = candidate
            break

    if not image_path:
        find_args = argparse.Namespace(
            profile=asu_profile,
            type=None,
        )
        find_buf = io.StringIO()
        with redirect_stdout(find_buf):
            firmware_find(find_args)
        image_path = find_buf.getvalue().strip()

    if not image_path or not os.path.isfile(image_path):
        profile_dir = IMAGES_DIR / asu_profile
        if profile_dir.exists():
            for hash_dir in sorted(profile_dir.iterdir(), reverse=True):
                if not hash_dir.is_dir():
                    continue
                for f in sorted(hash_dir.iterdir()):
                    if f.is_file() and f.suffix in (".bin", ".img", ".tar"):
                        image_path = str(f)
                        break
                if image_path and os.path.isfile(image_path):
                    break

    if not image_path or not os.path.isfile(image_path):
        log("ERROR: No firmware image file found after ASU request.")
        return None, {}

    metadata = {}
    try:
        image_obj = Path(image_path)
        meta_path = image_obj.parent / "build.metadata.json"
        if meta_path.is_file():
            metadata = json.loads(meta_path.read_text())
    except (OSError, json.JSONDecodeError):
        metadata = {}

    log(f"Firmware image: {image_path}")

    if flash_method in {"edgeos-kernel-swap", "extreme-rdwr-tftp-initramfs", "oem-http"}:
        initramfs_path = ""
        if image_path:
            image_dir = Path(image_path).parent
            for candidate in sorted(image_dir.iterdir()):
                if candidate.is_file() and "initramfs" in candidate.name:
                    initramfs_path = str(candidate)
                    log(f"Initramfs image: {initramfs_path}")
                    break
        if not initramfs_path:
            log("WARNING: No initramfs image found in build directory.")
        metadata["initramfs_path"] = initramfs_path

    return image_path, metadata


def _run_state_machine(
    ctx: RecoveryContext,
    event_queue: queue.Queue,
    pcap_monitor: Optional[PcapMonitor],
    link_monitor: LinkMonitor,
) -> int:
    ctx.timeline.recovery_start = ts()

    while ctx.state not in (State.COMPLETE, State.FAILED):
        if ctx.state == State.DETECTING:
            _handle_detecting(ctx, event_queue)
        elif ctx.state == State.SYSUPGRADE_UPLOADING:
            _handle_sysupgrade_uploading(ctx, event_queue)
        elif ctx.state == State.SYSUPGRADE_REBOOTING:
            _handle_sysupgrade_rebooting(ctx, event_queue)
        elif ctx.state == State.SYSUPGRADE_BOOTING:
            _handle_sysupgrade_booting(ctx, event_queue)
        elif ctx.state == State.WAITING_FOR_POWER_OFF:
            _handle_waiting_for_power_off(ctx, event_queue)
        elif ctx.state == State.WAITING_FOR_UBOOT:
            _handle_waiting_for_uboot(ctx, event_queue, link_monitor)
        elif ctx.state == State.UBOOT_UPLOADING:
            _handle_uboot_uploading(ctx, event_queue)
        elif ctx.state == State.UBOOT_FLASHING:
            _handle_uboot_flashing(ctx, event_queue, pcap_monitor)
        elif ctx.state == State.SERIAL_WAITING_FOR_BOOTMENU:
            _handle_serial_waiting_for_bootmenu(ctx, event_queue)
        elif ctx.state == State.SERIAL_UBOOT_INTERACTING:
            _handle_serial_uboot_interacting(ctx, event_queue)
        elif ctx.state == State.ZYCAST_WAITING_FOR_DEVICE:
            _handle_zycast_waiting(ctx, event_queue)
        elif ctx.state == State.ZYCAST_SENDING:
            _handle_zycast_sending(ctx, event_queue)
        elif ctx.state == State.REBOOTING:
            _handle_rebooting(ctx, event_queue)
        elif ctx.state == State.OPENWRT_BOOTING:
            _handle_openwrt_booting(ctx, event_queue)
        elif ctx.state == State.EDGEOS_STAGE1:
            _handle_edgeos_stage1(ctx, event_queue)
        elif ctx.state == State.EDGEOS_STAGE1_REBOOTING:
            _handle_edgeos_stage1_rebooting(ctx, event_queue)
        elif ctx.state == State.EDGEOS_PORT_SWAP:
            _handle_edgeos_port_swap(ctx, event_queue)
        elif ctx.state == State.EDGEOS_STAGE2_UPLOADING:
            _handle_edgeos_stage2_uploading(ctx, event_queue)
        elif ctx.state == State.EDGEOS_STAGE2_FLASHING:
            _handle_edgeos_stage2_flashing(ctx, event_queue)
        elif ctx.state == State.EXTREME_STOCK_PREFLIGHT:
            _handle_extreme_stock_preflight(ctx, event_queue)
        elif ctx.state == State.EXTREME_STOCK_WRITING_UBOOT:
            _handle_extreme_stock_writing_uboot(ctx, event_queue)
        elif ctx.state == State.EXTREME_STOCK_REBOOTING:
            _handle_extreme_stock_rebooting(ctx, event_queue)
        elif ctx.state == State.EXTREME_OPENWRT_INITRAMFS_WAITING:
            _handle_extreme_openwrt_initramfs_waiting(ctx, event_queue)
        elif ctx.state == State.EXTREME_OPENWRT_BACKUP:
            _handle_extreme_openwrt_backup(ctx, event_queue)
        elif ctx.state == State.EXTREME_BOOTCMD_RESTORE:
            _handle_extreme_bootcmd_restore(ctx, event_queue)
        elif ctx.state == State.EXTREME_SYSUPGRADE_UPLOADING:
            _handle_extreme_sysupgrade_uploading(ctx, event_queue)
        elif ctx.state == State.EXTREME_SYSUPGRADE_FLASHING:
            _handle_extreme_sysupgrade_flashing(ctx, event_queue)
        elif ctx.state == State.OEM_HTTP_LOGIN:
            _handle_oem_http_login(ctx, event_queue)
        elif ctx.state == State.OEM_HTTP_UPLOADING:
            _handle_oem_http_uploading(ctx, event_queue)
        elif ctx.state == State.OEM_HTTP_REBOOTING:
            _handle_oem_http_rebooting(ctx, event_queue)
        else:
            log(f"Unknown state: {ctx.state}")
            ctx.state = State.FAILED

    if ctx.state == State.COMPLETE:
        _print_timeline(ctx)
        if ctx.no_upload:
            return 0
        cfg = _load_config()
        openwrt_ip = ctx.profile.openwrt_ip or ctx.profile.recovery_ip
        openwrt_ip = _apply_profile_post_flash(
            openwrt_ip,
            ssh_key=ctx.ssh_key_path,
            cfg=cfg,
            model_id=ctx.profile.name,
            interface=ctx.interface,
            old_client_ip=ctx.profile.openwrt_client_ip or ctx.profile.client_ip,
        )
        if openwrt_ip != (ctx.profile.openwrt_ip or ctx.profile.recovery_ip):
            ctx.profile = SimpleNamespace(**{**vars(ctx.profile), "openwrt_ip": openwrt_ip})
        _apply_sticker_credentials_post_flash(
            openwrt_ip, ssh_key=ctx.ssh_key_path,
            model_id=ctx.profile.name, cfg=cfg,
        )
        wg_pubkey = _register_wireguard_post_flash(
            openwrt_ip, ssh_key=ctx.ssh_key_path, cfg=cfg,
        )
        ctx.wireguard_pubkey = wg_pubkey
        _record_inventory(ctx)
        return 0

    _print_timeline(ctx)
    if ctx.image_path and ctx.sha256_before:
        log("Recording partial inventory (flash may still succeed).")
        _record_inventory(ctx)
    return 1


def _handle_detecting(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    boot_state = _detect_boot_state(ctx.interface, ctx.profile)
    ctx.boot_state = boot_state
    if boot_state == "openwrt" and not ctx.force_uboot:
        if ctx.profile.flash_method == "mtd-write":
            ctx._say_fn("OpenWrt detected. Using mtd-write for flash.")
            log("Boot state: OpenWrt — using mtd-write path")
        else:
            ctx._say_fn("OpenWrt detected. Using sysupgrade for faster re-flash.")
            log("Boot state: OpenWrt — using sysupgrade path")
        ctx.state = State.SYSUPGRADE_UPLOADING
    elif boot_state == "stock-edgeos":
        ctx._say_fn("EdgeOS detected. Starting kernel swap flash.")
        log("Boot state: EdgeOS stock firmware — using edgeos-kernel-swap")
        ctx.state = State.EDGEOS_STAGE1
    elif boot_state == "stock-extreme":
        ctx._say_fn("Extreme stock firmware detected. Starting TFTP initramfs flash.")
        log("Boot state: Extreme stock firmware — using extreme-rdwr-tftp-initramfs")
        ctx.state = State.EXTREME_STOCK_PREFLIGHT
    elif boot_state == "stock-zyxel" or ctx.profile.flash_method == "oem-http":
        ctx._say_fn("ZyXEL stock firmware detected. Uploading via OEM HTTP.")
        log("Boot state: ZyXEL stock firmware — using oem-http")
        ctx.state = State.OEM_HTTP_LOGIN
    elif boot_state == "stock-hnap" or ctx.profile.flash_method == "dlink-hnap":
        ctx._say_fn("D-Link router detected. Uploading via HNAP.")
        log("Boot state: stock firmware with HNAP API — uploading directly")
        ctx.state = State.UBOOT_UPLOADING
    else:
        if boot_state == "uboot":
            log("Boot state: U-Boot recovery mode detected")
            recovery_ip = ctx.profile.recovery_ip
            found, detail = detect_uboot_http(recovery_ip)
            if found:
                log(f"Recovery HTTP already live at {recovery_ip} ({detail}) — skipping power cycle")
                ctx.timeline.uboot_http_first = ts()
                ctx.state = State.UBOOT_UPLOADING
                return
        if ctx.force_uboot:
            log("Boot state: forced to U-Boot recovery (--force-uboot)")
        else:
            log("Boot state: unknown — proceeding with U-Boot recovery")
        ctx.state = State.WAITING_FOR_POWER_OFF


def _handle_edgeos_stage1(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    """Stage 1: SSH to EdgeOS, swap boot kernel with OpenWrt initramfs."""
    import shutil as _shutil
    profile = ctx.profile
    edgeos_ip = profile.edgeos_ip
    edgeos_user = profile.edgeos_user
    edgeos_password = profile.edgeos_password
    initramfs_path = ctx.initramfs_path

    if not initramfs_path or not os.path.isfile(initramfs_path):
        log(f"ERROR: initramfs image not found: {initramfs_path}")
        ctx.state = State.FAILED
        return

    size_mb = os.path.getsize(initramfs_path) / 1024 / 1024
    log(f"Stage 1: Uploading initramfs ({size_mb:.1f} MB) to EdgeOS at {edgeos_ip}...")

    # SCP initramfs to EdgeOS /tmp (upload: local → remote with password auth)
    sshpass_bin = _shutil.which("sshpass")
    if not sshpass_bin:
        log("ERROR: sshpass not found. Install with: brew install hudochenkov/sshpass/sshpass")
        ctx.state = State.FAILED
        return

    remote_name = os.path.basename(initramfs_path)
    scp_upload_cmd = [
        sshpass_bin, "-p", edgeos_password,
        "scp", "-O",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        initramfs_path,
        f"{edgeos_user}@{edgeos_ip}:/tmp/{remote_name}",
    ]
    try:
        scp_result = subprocess.run(scp_upload_cmd, capture_output=True, text=True, timeout=120, check=False)
    except subprocess.TimeoutExpired:
        log("SCP to EdgeOS timed out.")
        ctx.state = State.FAILED
        return
    if scp_result.returncode != 0:
        log(f"SCP to EdgeOS failed (exit {scp_result.returncode}): {scp_result.stderr[:300]}")
        ctx.state = State.FAILED
        return

    log("Initramfs uploaded. Swapping boot kernel...")

    # Build the kernel swap script — must use sudo on EdgeOS
    boot_partition = profile.boot_partition
    kernel_path = profile.kernel_path
    md5_path = profile.md5_path
    swap_script = (
        f"set -ex; "
        f"mkdir -p /tmp/boot; "
        f"sudo mount -t vfat {boot_partition} /tmp/boot; "
        f"test -f /tmp/boot{kernel_path} || {{ echo 'ERROR: kernel not found'; exit 1; }}; "
        f"cp -a /tmp/boot{kernel_path} /tmp/boot{kernel_path}.bak; "
        f"cp -a /tmp/boot{md5_path} /tmp/boot{md5_path}.bak; "
        f"cp /tmp/{remote_name} /tmp/boot{kernel_path}; "
        f"md5sum /tmp/boot{kernel_path} | cut -d ' ' -f1 > /tmp/boot{md5_path}; "
        f"sync; "
        f"sudo umount /tmp/boot; "
        f"echo 'Kernel swap complete'; "
        f"sudo reboot"
    )
    ssh_result = _ssh_with_password(
        edgeos_ip, edgeos_user, edgeos_password,
        f"bash -c '{swap_script}'",
        timeout=60,
    )
    if ssh_result.returncode != 0:
        combined = (ssh_result.stdout or "") + (ssh_result.stderr or "")
        if "Kernel swap complete" in combined or "Connection closed" in combined:
            log("Kernel swap completed (connection closed during reboot — expected).")
        else:
            log(f"Kernel swap failed (exit {ssh_result.returncode}): {combined[:500]}")
            ctx.state = State.FAILED
            return

    ctx.sha256_before = sha256_file(ctx.image_path)
    ctx.timeline.upload_start = ts()
    ctx._say_fn("Stage 1 complete. Device rebooting into OpenWrt initramfs.")
    log("Stage 1 complete — EdgeOS rebooting into OpenWrt initramfs.")
    ctx.state = State.EDGEOS_STAGE1_REBOOTING


def _handle_edgeos_stage1_rebooting(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    """Wait for EdgeOS to reboot into OpenWrt initramfs."""
    ctx._say_fn("Waiting for device to reboot. This takes about 90 seconds.")
    log("Waiting for initramfs boot (~90 seconds)...")
    time.sleep(10)

    if ctx.profile.port_swap_required:
        ctx.state = State.EDGEOS_PORT_SWAP
    else:
        ctx.state = State.EDGEOS_STAGE2_UPLOADING


def _handle_edgeos_port_swap(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    """Prompt user to move cable from eth0 (WAN) to eth1+ (LAN)."""
    port_note = ctx.profile.port_swap_note or "Move the ethernet cable to a LAN port."
    ctx._say_fn(f"Important! {port_note}")
    log(f"PORT SWAP: {port_note}")
    log("Waiting for SSH on 192.168.1.1...")

    openwrt_ip = ctx.profile.openwrt_ip
    timeout = 120
    start = time.time()
    while time.time() - start < timeout:
        if check_ssh(openwrt_ip):
            ctx.timeline.ssh_available = ts()
            log(f"SSH available at {openwrt_ip} — initramfs booted successfully.")
            ctx._say_fn("Initramfs is up. Starting stage 2.")
            event_queue.put((Event.EDGEOS_PORT_SWAP_DONE, ""))
            ctx.state = State.EDGEOS_STAGE2_UPLOADING
            return
        time.sleep(5)

    ctx._say_fn("Timed out waiting for initramfs SSH.")
    log(f"FAIL: SSH not available at {openwrt_ip} after {timeout}s.")
    ctx.state = State.FAILED


def _handle_edgeos_stage2_uploading(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    """Stage 2a: Upload sysupgrade.tar to OpenWrt initramfs."""
    openwrt_ip = ctx.profile.openwrt_ip
    image_path = ctx.image_path

    if not image_path or not os.path.isfile(image_path):
        log(f"ERROR: sysupgrade.tar not found: {image_path}")
        ctx.state = State.FAILED
        return

    size_mb = os.path.getsize(image_path) / 1024 / 1024
    log(f"Stage 2: Uploading sysupgrade.tar ({size_mb:.1f} MB) to initramfs at {openwrt_ip}...")

    remote_path = "/tmp/sysupgrade.tar"
    scp_command = scp_cmd(openwrt_ip, image_path, f"root@{openwrt_ip}:{remote_path}",
                          key=ctx.ssh_key_path or None, connect_timeout=10)
    try:
        r = subprocess.run(scp_command, capture_output=True, text=True, timeout=120, check=False)
        if r.returncode != 0:
            log(f"SCP to initramfs failed (exit {r.returncode}): {r.stderr[:300]}")
            ctx.state = State.FAILED
            return
    except subprocess.TimeoutExpired:
        log("SCP upload to initramfs timed out.")
        ctx.state = State.FAILED
        return

    log("sysupgrade.tar uploaded. Verifying...")
    # Verify upload via remote md5sum
    ssh_command = ssh_cmd(openwrt_ip,
                          f"md5sum {remote_path}",
                          key=ctx.ssh_key_path or None, connect_timeout=10)
    try:
        r = subprocess.run(ssh_command, capture_output=True, text=True, timeout=15, check=False)
        if r.returncode == 0 and r.stdout.strip():
            remote_hash = r.stdout.strip().split()[0]
            log(f"Remote MD5: {remote_hash}")
        else:
            log(f"Could not verify remote file: {r.stderr[:200]}")
    except Exception:
        pass  # Verification is best-effort

    ctx.timeline.upload_complete = ts()
    ctx._say_fn("Upload complete. Flashing firmware.")
    log("sysupgrade.tar uploaded successfully. Proceeding to flash.")
    ctx.state = State.EDGEOS_STAGE2_FLASHING


def _handle_edgeos_stage2_flashing(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    """Stage 2b: Manual dd — extract kernel+rootfs from tar and write to eMMC."""
    openwrt_ip = ctx.profile.openwrt_ip
    profile = ctx.profile
    model_id = profile.name

    # Build the device-specific tar member paths
    # OpenWrt tar structure: sysupgrade-DEVICE_NAME/kernel and sysupgrade-DEVICE_NAME/root
    # Device name uses underscores: ubnt_edgerouter-6p
    device_name = model_id.replace("-", "_")
    kernel_member = f"sysupgrade-{device_name}/kernel"
    root_member = f"sysupgrade-{device_name}/root"
    boot_partition = profile.boot_partition
    kernel_path = profile.kernel_path
    md5_path = profile.md5_path

    # The flash script — uses sh (not bash — initramfs only has ash)
    flash_script = (
        f"set -ex; "
        f"tar tf /tmp/sysupgrade.tar | head -5; "
        f"mkdir -p /boot; "
        f"mount -t vfat {boot_partition} /boot; "
        f"[ -f /boot{kernel_path} ] && mv /boot{kernel_path} /boot{kernel_path}.previous; "
        f"[ -f /boot{md5_path} ] && mv /boot{md5_path} /boot{md5_path}.previous; "
        f"tar xf /tmp/sysupgrade.tar {kernel_member} -O > /boot{kernel_path}; "
        f"md5sum /boot{kernel_path} | cut -f1 -d ' ' > /boot{md5_path}; "
        f"echo 'Kernel size:'; "
        f"ls -la /boot{kernel_path}; "
        f"echo 'Flashing rootfs to /dev/mmcblk0p2...'; "
        f"tar xf /tmp/sysupgrade.tar {root_member} -O | dd of=/dev/mmcblk0p2 bs=4096; "
        f"sync; "
        f"umount /boot; "
        f"echo 'Flash complete. Rebooting into permanent OpenWrt...'; "
        f"reboot -f"
    )

    log("Stage 2: Flashing squashfs kernel + rootfs to eMMC...")
    ctx._say_fn("Flashing firmware. Do not unplug.")

    ssh_command = ssh_cmd(openwrt_ip,
                          f"sh -c '{flash_script}'",
                          key=ctx.ssh_key_path or None, connect_timeout=10)
    try:
        r = subprocess.run(ssh_command, capture_output=True, text=True, timeout=120, check=False)
        combined = (r.stdout or "") + (r.stderr or "")
        if "Flash complete" in combined:
            log("Flash completed successfully.")
        elif r.returncode != 0 and not r.stdout and not r.stderr:
            log("Flash command sent (connection closed by remote during reboot — expected).")
        else:
            log(f"Flash output (exit {r.returncode}): {combined[:500]}")
    except subprocess.TimeoutExpired:
        log("Flash command timed out (may have started reboot).")

    ctx.timeline.flash_triggered = ts()
    ctx.state = State.OPENWRT_BOOTING


def _handle_sysupgrade_uploading(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    openwrt_ip = ctx.profile.openwrt_ip
    if ctx.profile.flash_method == "mtd-write":
        model = load_model(ctx.profile.name)
        mtd_cfg = model.get("flash_methods", {}).get("mtd-write", {})
        mtd_command = mtd_cfg.get("command", "mtd -r write /tmp/firmware.bin firmware")
        success = _flash_via_mtd_write(openwrt_ip, ctx.image_path, ctx.ssh_key_path or None,
                                       mtd_command=mtd_command)
    else:
        success = _flash_via_sysupgrade(openwrt_ip, ctx.image_path, ctx.ssh_key_path or None)
    if success:
        ctx.sha256_before = sha256_file(ctx.image_path)
        ctx.state = State.SYSUPGRADE_REBOOTING
    else:
        log("sysupgrade upload failed.")
        ctx.state = State.FAILED


def _handle_sysupgrade_rebooting(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    method = "mtd-write" if ctx.profile.flash_method == "mtd-write" else "sysupgrade"
    ctx._say_fn("Firmware flashing. Do not unplug.")
    log(f"{method}: device is rebooting")
    ctx.state = State.SYSUPGRADE_BOOTING


def _handle_sysupgrade_booting(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    openwrt_ip = ctx.profile.openwrt_ip
    method = "mtd-write" if ctx.profile.flash_method == "mtd-write" else "sysupgrade"
    if _wait_for_sysupgrade_reboot(openwrt_ip):
        ctx.timeline.ssh_available = ts()
        ctx._say_fn("Recovery complete! Router is back online.")
        log(f"SUCCESS — {method} recovery complete.")
        verify_router(openwrt_ip,
                     wan_ssh_expected=ctx.wan_ssh_enabled,
                     mgmt_wifi_expected=bool(ctx.defaults_script))
        ctx.state = State.COMPLETE
    else:
        ctx._say_fn("Device did not come back after flash.")
        log(f"FAIL: SSH not available after {method} reboot.")
        ctx.state = State.FAILED


def _handle_waiting_for_power_off(ctx: RecoveryContext, eq: queue.Queue) -> None:
    link_up = get_link_state(ctx.interface)
    if link_up:
        ctx._say_fn("Ready. Please unplug the power cable from the router now.")
        log("STEP 1: Unplug power (keep ethernet in LAN port)")

        _wait_for_event_or_timeout(
            eq, timeout=300,
            target_events={Event.LINK_DOWN},
            success_state=State.WAITING_FOR_UBOOT,
            fail_message="Timed out waiting for power off.",
            fail_say="Timed out. Please unplug the power cable from the router.",
            ctx=ctx,
        )
        if ctx.state == State.WAITING_FOR_UBOOT:
            ctx._say_fn("Power disconnected. Good.")
            ctx.timeline.power_off = ts()
    else:
        log("Router already powered off.")
        ctx._say_fn("Router is off. Good.")
        ctx.timeline.power_off = ts()
        ctx.state = State.WAITING_FOR_UBOOT


def _handle_waiting_for_uboot(ctx: RecoveryContext, eq: queue.Queue, link_monitor: LinkMonitor) -> None:
    print()
    profile = ctx.profile
    ctx._say_fn(profile.reset_instructions)
    log(f"STEP 2: {profile.reset_instructions}")
    time.sleep(4)

    ctx._say_fn("While still holding reset, plug in the power cable.")
    log("STEP 3: Plug in power WHILE STILL HOLDING reset")
    time.sleep(2)

    ctx._say_fn(
        f"Watch the LED. {profile.led_pattern}. "
        "Release reset when the LED shows the recovery pattern."
    )
    log(f"Waiting for recovery LED pattern: {profile.led_pattern}")
    print()

    got_link_up = _wait_for_event_or_timeout(
        eq, timeout=30,
        target_events={Event.LINK_UP},
        success_state=None,
        fail_message="Ethernet link did not come up.",
        fail_say="Ethernet link did not come up. Check the cable is in the LAN port.",
        ctx=ctx,
    )
    if got_link_up is None:
        ctx.state = State.FAILED
        return

    ctx.timeline.link_up = ts()
    ctx._say_fn("Link detected. Waiting for recovery mode.")
    log(f"Link up — waiting for recovery HTTP: {profile.led_pattern}")
    time.sleep(8)

    log("Scanning for recovery HTTP server...")
    uboot_found = False
    probe_start = ts()
    probe_timeout = 90

    while ts() - probe_start < probe_timeout:
        found, detail = detect_uboot_http(profile.recovery_ip)
        if found:
            log(f"Recovery mode detected: {detail}")
            ctx.timeline.uboot_http_first = ts()
            ctx._say_fn("Recovery mode detected. You can release the button now.")
            ctx.state = State.UBOOT_UPLOADING
            uboot_found = True
            break

        _drain_events(eq, ctx)

        time.sleep(1)

    if not uboot_found:
        ctx._say_fn(f"Recovery mode not found. Check the LED pattern: {profile.led_pattern}")
        log("FAIL: Recovery HTTP server not detected.")
        ctx.state = State.FAILED


def _handle_uboot_uploading(ctx: RecoveryContext, eq: queue.Queue) -> None:
    profile = ctx.profile
    if ctx.no_upload:
        ctx._say_fn("Dry run. Recovery server is ready but not uploading.")
        log(f"DRY RUN: Recovery server ready at http://{profile.recovery_ip}")
        log(f"  Upload: curl -F {profile.upload_field}=@{ctx.image_path} http://{profile.recovery_ip}{profile.upload_endpoint}")
        if profile.trigger_flash_endpoint:
            log(f"  Flash:  curl http://{profile.recovery_ip}{profile.trigger_flash_endpoint}")
        ctx.state = State.COMPLETE
        return

    ctx.sha256_before = sha256_file(ctx.image_path)
    log(f"SHA-256 (before upload): {ctx.sha256_before}")

    ctx.timeline.upload_start = ts()

    if profile.flash_method == "dlink-hnap":
        ok, response = _flash_via_dlink_hnap(ctx.image_path, profile)
    else:
        ok, response = upload_firmware(ctx.image_path, profile)
    if not ok:
        ctx._say_fn(f"Upload failed. Try a browser at http://{profile.recovery_ip} instead.")
        ctx.state = State.FAILED
        return

    ctx.timeline.upload_complete = ts()
    eq.put((Event.UPLOAD_COMPLETE, ts(), response))

    ctx.sha256_after = sha256_file(ctx.image_path)
    if ctx.sha256_after != ctx.sha256_before:
        log("WARNING: SHA-256 mismatch! File may have been modified on disk during upload.")
    else:
        log(f"SHA-256 verified (after upload): {ctx.sha256_after}")

    if profile.flash_method != "dlink-hnap" and trigger_flash(profile):
        ctx.timeline.flash_triggered = ts()
        eq.put((Event.FLASH_TRIGGERED, ts(), ""))
    else:
        log("Flash trigger may have failed. Router may still flash on its own.")
        ctx.timeline.flash_triggered = ts()

    ctx._say_fn("Firmware flashing. Do not unplug.")
    ctx.state = State.UBOOT_FLASHING


def _handle_uboot_flashing(ctx: RecoveryContext, eq: queue.Queue, pcap_monitor: Optional[PcapMonitor]) -> None:
    if pcap_monitor is None:
        timeout = ctx.profile.flash_time_seconds + 30
        log(f"Waiting {timeout}s for flash to complete (polling-only mode)...")
        time.sleep(timeout)
        ctx.timeline.flash_complete = ts()
        ctx.state = State.REBOOTING
        return

    profile = ctx.profile
    timeout = profile.flash_time_seconds + 120
    result = _wait_for_event_or_timeout(
        eq, timeout=timeout,
        target_events={Event.UBOOT_ARP_192_168_1_2, Event.LINK_DOWN},
        success_state=State.REBOOTING,
        fail_message=f"Flash did not complete within {timeout}s.",
        fail_say="Flash is taking too long. Something went wrong.",
        ctx=ctx,
    )
    if result is None:
        ctx.state = State.FAILED
        return

    ctx.timeline.flash_complete = ts()
    log(f"Flash complete (event: {result})")
    if result == Event.LINK_DOWN:
        ctx._say_fn("Link down. Router is rebooting.")
    elif result == Event.UBOOT_ARP_192_168_1_2:
        ctx._say_fn("Firmware uploaded. Flashing in progress. Do not unplug.")


def _handle_serial_waiting_for_bootmenu(ctx: RecoveryContext, eq: queue.Queue) -> None:
    profile = ctx.profile
    port = ctx.serial_port
    baud = ctx.serial_baud

    if not port:
        try:
            port = _auto_detect_serial_port()
            log(f"Auto-detected serial port: {port}")
        except FileNotFoundError as e:
            log(f"ERROR: {e}")
            ctx.state = State.FAILED
            return

    ctx._say_fn("Connect serial adapter and Ethernet cable to LAN2.")
    if profile.lan_port:
        log(f"IMPORTANT: Connect Ethernet cable to {profile.lan_port} port")
    log(f"Serial port: {port} at {baud} baud")

    ctx._say_fn("Power cycle the router now.")
    log("Power cycle the router now. Watching for U-Boot bootmenu...")

    driver = SerialUBootDriver(port, baud)
    ctx._serial_driver = driver

    got_prompt = driver.wait_for_bootmenu(
        timeout=profile.bootmenu_timeout,
        interrupt=profile.bootmenu_interrupt,
        console_option=profile.bootmenu_select_console,
        say_fn=ctx._say_fn,
    )

    if not got_prompt:
        ctx._say_fn("Failed to get U-Boot prompt. Check serial connection and try again.")
        driver.close()
        ctx.state = State.FAILED
        return

    eq.put((Event.SERIAL_UBOOT_READY, ts(), ""))
    ctx.timeline.uboot_http_first = ts()
    ctx.state = State.SERIAL_UBOOT_INTERACTING


def _handle_serial_uboot_interacting(ctx: RecoveryContext, eq: queue.Queue) -> None:
    profile = ctx.profile
    driver: SerialUBootDriver = ctx._serial_driver

    tftp_root = ctx.tftp_root
    if not tftp_root:
        tftp_root = os.path.join(os.path.dirname(ctx.image_path), "tftpboot")
        if not os.path.isdir(tftp_root):
            tftp_root = os.path.dirname(ctx.image_path)

    tftp_mgr = TFTPServerManager(tftp_root)
    ctx._tftp_manager = tftp_mgr

    if not tftp_mgr.start():
        log("WARNING: TFTP server not available — commands may fail")

    ctx._say_fn("Setting up network and starting flash process.")

    setup_interface_for_serial(ctx)

    commands = ctx.uboot_commands
    if not commands:
        commands = profile.uboot_commands

    if not commands:
        log("ERROR: No U-Boot commands defined in model JSON")
        ctx.state = State.FAILED
        tftp_mgr.stop()
        driver.close()
        return

    ctx.timeline.upload_start = ts()
    ctx.sha256_before = sha256_file(ctx.image_path) if ctx.image_path else ""

    success = driver.run_commands(
        commands, eq,
        say_fn=ctx._say_fn,
        flash_time_seconds=profile.flash_time_seconds,
    )

    tftp_mgr.stop()

    if success:
        ctx.timeline.flash_complete = ts()
        ctx.timeline.upload_complete = ts()
        log("All U-Boot commands executed successfully")
        ctx.state = State.REBOOTING
        driver.close()
    else:
        ctx._say_fn("Flash failed. Check serial output for details.")
        ctx.state = State.FAILED
        driver.close()


def setup_interface_for_serial(ctx: RecoveryContext) -> None:
    profile = ctx.profile
    interface = ctx.interface
    if not interface:
        return

    if profile.client_ip:
        configure_interface_ip(interface, profile.client_ip, "24")


def _handle_zycast_waiting(ctx: RecoveryContext, eq: queue.Queue) -> None:
    profile = ctx.profile
    ctx._say_fn("Power cycle the router now. Multicast flash will start automatically.")
    log("Waiting for ZyXEL Multiboot multicast packets...")

    multicast_group = getattr(profile, 'zycast_multicast_group', '225.0.0.0')
    multicast_port = getattr(profile, 'zycast_multicast_port', 5631)
    probe_timeout = 120
    probe_start = ts()

    while ts() - probe_start < probe_timeout:
        try:
            event, event_ts, detail = eq.get(timeout=1.0)
            if event == Event.ZYCAST_MULTICAST_DETECTED:
                ctx.timeline.uboot_http_first = ts()
                log(f"ZyXEL Multiboot detected: {detail}")
                ctx._say_fn("Multiboot detected. Starting multicast flash.")
                ctx.state = State.ZYCAST_SENDING
                return
            if event == Event.LINK_UP and ctx.timeline.link_up is None:
                ctx.timeline.link_up = event_ts
                log("Link up — watching for multicast")
            elif event == Event.LINK_DOWN and ctx.timeline.power_off is None:
                ctx.timeline.power_off = event_ts
        except queue.Empty:
            pass

        _drain_events(eq, ctx)

    ctx._say_fn("No Multiboot detected. Check that the router is powered on.")
    log(f"FAIL: No multicast packets from ZyXEL bootloader within {probe_timeout}s")
    ctx.state = State.FAILED


def _handle_zycast_sending(ctx: RecoveryContext, eq: queue.Queue) -> None:
    if ctx.no_upload:
        ctx._say_fn("Dry run. Multiboot detected but not flashing.")
        log("DRY RUN: Would flash via zycast multicast")
        ctx.state = State.COMPLETE
        return

    profile = ctx.profile
    ctx.sha256_before = sha256_file(ctx.image_path)
    log(f"SHA-256 (before zycast): {ctx.sha256_before}")

    multicast_group = getattr(profile, 'zycast_multicast_group', '225.0.0.0')
    multicast_port = getattr(profile, 'zycast_multicast_port', 5631)
    image_type = getattr(profile, 'zycast_image_type', 'ras')

    ctx.timeline.upload_start = ts()
    ctx._say_fn("Sending firmware via multicast. Do not unplug.")
    log(f"Starting zycast: {ctx.image_path} -> {multicast_group}:{multicast_port}")

    try:
        proc = run_zycast_auto(
            image_path=ctx.image_path,
            interface=ctx.interface,
            multicast_group=multicast_group,
            multicast_port=multicast_port,
            image_type=image_type,
        )
    except Exception as e:
        log(f"ERROR: Failed to start zycast: {e}")
        ctx.state = State.FAILED
        return

    ctx._zycast_proc = proc

    flash_timeout = getattr(profile, 'flash_time_seconds', 180) + 60
    start = ts()
    while ts() - start < flash_timeout:
        retcode = proc.poll()
        if retcode is not None:
            break
        try:
            event, event_ts, detail = eq.get(timeout=2.0)
            if event == Event.ZYCAST_MULTICAST_DETECTED:
                log(f"  multicast activity: {detail[:80]}")
        except queue.Empty:
            pass

    if proc.poll() is None:
        log("zycast still running after timeout — terminating")
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    stdout_data = proc.stdout.read() if proc.stdout else ""
    stderr_data = proc.stderr.read() if proc.stderr else ""

    if stdout_data:
        for line in stdout_data.strip().split("\n")[:10]:
            log(f"  [zycast stdout] {line}")
    if stderr_data:
        for line in stderr_data.strip().split("\n")[:10]:
            log(f"  [zycast stderr] {line}")

    retcode = proc.returncode
    if retcode == 0:
        ctx.timeline.upload_complete = ts()
        ctx.timeline.flash_complete = ts()
        ctx.timeline.flash_triggered = ts()
        log("zycast completed successfully")
        ctx._say_fn("Multicast flash complete. Waiting for router to reboot.")
        ctx.state = State.REBOOTING
    else:
        log(f"zycast exited with code {retcode}")
        ctx._say_fn("Multicast flash may have failed. Check the console output.")
        ctx.timeline.flash_complete = ts()
        ctx.state = State.REBOOTING


def _oem_http_login(stock_ip: str, username: str, password: str) -> tuple[bool, str]:
    """Login to ZyXEL OEM web UI via curl. Returns (success, cookie_header_value)."""
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


def _oem_http_upload(stock_ip: str, cookie: str, firmware_path: str,
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


def _oem_http_accept_reboot(stock_ip: str, cookie: str) -> bool:
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


def _handle_oem_http_login(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    profile = ctx.profile
    stock_ip = profile.stock_default_ip
    username = profile.stock_default_user
    password = profile.stock_default_password

    if not password:
        model_data = load_model(profile.name)
        creds = model_data.get("stock_default_creds", {})
        username = creds.get("username", "admin")
        password = creds.get("password", "1234")

    if not ctx.initramfs_path or not os.path.isfile(ctx.initramfs_path):
        log(f"ERROR: initramfs image not found: {ctx.initramfs_path}")
        ctx.state = State.FAILED
        return

    log(f"Logging into ZyXEL OEM web UI at {stock_ip} (user={username})...")
    success, cookie = _oem_http_login(stock_ip, username, password)
    if not success:
        log(f"ERROR: OEM HTTP login failed: {cookie}")
        ctx.state = State.FAILED
        return

    log("OEM HTTP login successful")
    ctx._oem_http_cookie = cookie
    ctx.state = State.OEM_HTTP_UPLOADING


def _handle_oem_http_uploading(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    profile = ctx.profile
    stock_ip = profile.stock_default_ip
    cookie = getattr(ctx, "_oem_http_cookie", "")
    upload_endpoint = profile.oem_http_upload_endpoint

    initramfs_path = ctx.initramfs_path
    filename = os.path.basename(initramfs_path)
    upload_path = initramfs_path

    if len(filename) > 64:
        upload_path = os.path.join(tempfile.gettempdir(), "openwrt-initramfs.bin")
        shutil.copy2(initramfs_path, upload_path)
        log(f"Renamed initramfs (>{len(filename)} chars) to {os.path.basename(upload_path)} for v2.90 compatibility")

    timeout = profile.flash_time_seconds + 60
    success, response = _oem_http_upload(stock_ip, cookie, upload_path, upload_endpoint, timeout=timeout)
    if upload_path != initramfs_path and os.path.exists(upload_path):
        os.unlink(upload_path)

    if not success:
        log(f"ERROR: OEM HTTP upload failed: {response}")
        ctx.state = State.FAILED
        return

    ctx.timeline.upload_start = ts()
    ctx.timeline.upload_complete = ts()
    log("Firmware uploaded. Accepting reboot dialog...")

    _oem_http_accept_reboot(stock_ip, cookie)
    ctx.timeline.flash_triggered = ts()
    ctx._say_fn("Firmware uploaded. Waiting for device to reboot.")
    ctx.state = State.OEM_HTTP_REBOOTING


def _handle_oem_http_rebooting(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    profile = ctx.profile
    openwrt_ip = profile.openwrt_ip or "192.168.1.1"
    flash_time = profile.flash_time_seconds

    log(f"Waiting for device to reboot (~{flash_time}s)...")
    ctx._say_fn("Device is rebooting into OpenWrt initramfs.")

    deadline = ts() + flash_time
    while ts() < deadline:
        time.sleep(5)
        if check_ssh(openwrt_ip):
            log("OpenWrt initramfs booted — SSH available")
            ctx.timeline.ssh_available = ts()
            ctx.timeline.first_openwrt_packet = ts()
            ctx.sha256_after = sha256_file(ctx.image_path) if ctx.image_path and os.path.isfile(ctx.image_path) else ""
            log("Initramfs booted. Starting sysupgrade for permanent install...")
            ctx._say_fn("Initramfs booted. Installing permanently via sysupgrade.")

            sysupgrade_path = ctx.image_path
            if not sysupgrade_path or not os.path.isfile(sysupgrade_path):
                log("No sysupgrade image found — initramfs only, skipping permanent install")
                ctx.state = State.COMPLETE
                return

            remote_name = os.path.basename(sysupgrade_path)
            size_mb = os.path.getsize(sysupgrade_path) / 1024 / 1024
            log(f"Uploading sysupgrade image ({size_mb:.1f} MB) via SCP...")
            scp_result = subprocess.run(
                scp_cmd(openwrt_ip, sysupgrade_path, f"/tmp/{remote_name}", key=ctx.ssh_key_path),
                capture_output=True, text=True, timeout=120, check=False,
            )
            if scp_result.returncode != 0:
                log(f"SCP failed: {scp_result.stderr[:300]}")
                ctx.state = State.FAILED
                return

            log("Sysupgrade image uploaded. Running sysupgrade -n...")
            ssh_result = subprocess.run(
                ssh_cmd(openwrt_ip, f"sysupgrade -n /tmp/{remote_name}", key=ctx.ssh_key_path),
                capture_output=True, text=True, timeout=30, check=False,
            )
            ctx.state = State.OPENWRT_BOOTING
            return
        elapsed = int(ts() - (ctx.timeline.flash_triggered or ts()))
        log(f"Waiting for initramfs boot... ({elapsed}s elapsed)")

    log(f"ERROR: Device did not boot within {flash_time}s")
    ctx.state = State.FAILED


def _handle_rebooting(ctx: RecoveryContext, eq: queue.Queue) -> None:
    ctx._say_fn("Router is rebooting. Waiting for it to come back online.")

    # Phase 1: Wait for link to come back up (pcap may be dead, but LinkMonitor still works)
    link_result = _wait_for_event_or_timeout(
        eq, timeout=REBOOT_TIMEOUT,
        target_events={Event.LINK_UP},
        success_state=None,
        fail_message="Link did not come back up after reboot.",
        fail_say="Link did not come back up. Check the ethernet cable.",
        ctx=ctx,
    )
    if link_result is None:
        ctx.state = State.FAILED
        return

    ctx._say_fn("Link detected. Waiting for OpenWrt to boot.")
    log("Link up after reboot — waiting for OpenWrt")

    # Phase 2: Wait for ICMPv6/SSH via pcap events, with active SSH polling fallback.
    # First boot with luci on MIPS can take several minutes, so use a generous timeout
    # and actively poll SSH in case pcap events are missed.
    timeout_after_link = 600
    openwrt_ip = ctx.profile.openwrt_ip or ctx.profile.recovery_ip
    start = ts()
    while ts() - start < timeout_after_link:
        try:
            event, event_ts, detail = eq.get(timeout=5.0)
            if event == Event.ICMPV6_FROM_ROUTER:
                ctx.timeline.first_openwrt_packet = event_ts
                ctx._say_fn("OpenWrt is booting.")
                log("ICMPv6 from router MAC detected — OpenWrt is booting")
                break
            elif event == Event.SSH_UP:
                ctx.timeline.ssh_available = event_ts
                ctx._say_fn("Recovery complete! Router is back online.")
                log("SUCCESS — router recovered (SSH detected during reboot phase).")
                verify_router(openwrt_ip,
                             wan_ssh_expected=ctx.wan_ssh_enabled,
                             mgmt_wifi_expected=bool(ctx.defaults_script))
                ctx.state = State.COMPLETE
                return
            elif event == Event.LINK_UP and ctx.state == State.REBOOTING:
                pass
        except queue.Empty:
            pass
        if check_ssh(openwrt_ip):
            ctx.timeline.ssh_available = ts()
            ctx._say_fn("Recovery complete! Router is back online.")
            log("SUCCESS — router recovered (SSH poll detected).")
            verify_router(openwrt_ip,
                         wan_ssh_expected=ctx.wan_ssh_enabled,
                         mgmt_wifi_expected=bool(ctx.defaults_script))
            ctx.state = State.COMPLETE
            return
    else:
        log(f"OpenWrt did not appear within {timeout_after_link}s after link up.")
        ctx._say_fn("OpenWrt is taking longer than expected. Check the router.")
        ctx.state = State.FAILED
        return

    ctx.state = State.OPENWRT_BOOTING


def _handle_openwrt_booting(ctx: RecoveryContext, eq: queue.Queue) -> None:
    openwrt_ip = ctx.profile.openwrt_ip or ctx.profile.recovery_ip
    ssh_monitor = SSHMonitor(openwrt_ip, eq, poll_interval=5.0)
    ssh_thread = threading.Thread(target=ssh_monitor.run, daemon=True)
    ssh_thread.start()

    timeout = 120
    result = _wait_for_event_or_timeout(
        eq, timeout=timeout,
        target_events={Event.SSH_UP, Event.LINK_UP},
        success_state=None,
        fail_message=f"SSH not available within {timeout}s.",
        fail_say="Router is taking longer than expected. Check SSH in a few minutes.",
        ctx=ctx,
    )

    ssh_monitor.stop()

    if result == Event.SSH_UP:
        ctx.timeline.ssh_available = ts()
        ctx._say_fn("Recovery complete! Router is back online.")
        log("SUCCESS — router recovered.")
        verify_router(openwrt_ip,
                     wan_ssh_expected=ctx.wan_ssh_enabled,
                     mgmt_wifi_expected=bool(ctx.defaults_script))
        ctx.state = State.COMPLETE
    else:
        if check_ssh(openwrt_ip):
            ctx.timeline.ssh_available = ts()
            ctx._say_fn("Recovery complete! Router is back online.")
            log("SUCCESS — router recovered (SSH fallback check).")
            verify_router(openwrt_ip,
                         wan_ssh_expected=ctx.wan_ssh_enabled,
                         mgmt_wifi_expected=bool(ctx.defaults_script))
            ctx.state = State.COMPLETE
        else:
            ctx.state = State.FAILED


def _wait_for_event_or_timeout(
    eq: queue.Queue,
    timeout: int,
    target_events: set[Event],
    success_state: Optional[State],
    fail_message: str,
    fail_say: str,
    ctx: RecoveryContext,
) -> Optional[Event]:
    """Wait for one of the target events or timeout.

    Returns the Event that was found, or None on timeout.
    Sets ctx.state to success_state on success, or State.FAILED on timeout.
    """
    start = ts()
    while ts() - start < timeout:
        try:
            event, event_ts, detail = eq.get(timeout=1.0)

            if event in target_events:
                if success_state is not None:
                    ctx.state = success_state
                return event

            if event == Event.LINK_UP and ctx.timeline.link_up is None:
                ctx.timeline.link_up = event_ts
                if ctx.state in (State.REBOOTING, State.OPENWRT_BOOTING):
                    ctx._say_fn("Link up. Waiting for OpenWrt to boot.")
            elif event == Event.LINK_DOWN and ctx.timeline.power_off is None:
                ctx.timeline.power_off = event_ts
            elif event == Event.ICMPV6_FROM_ROUTER and ctx.timeline.first_openwrt_packet is None:
                ctx.timeline.first_openwrt_packet = event_ts
                ctx._say_fn("OpenWrt is booting.")
            elif event == Event.SSH_UP:
                ctx.timeline.ssh_available = event_ts
                if success_state is not None:
                    ctx.state = success_state
                return event
            elif event == Event.UBOOT_HTTP and ctx.timeline.uboot_http_first is None:
                ctx.timeline.uboot_http_first = event_ts

        except queue.Empty:
            pass

    log(fail_message)
    ctx._say_fn(fail_say)
    if success_state is not None:
        ctx.state = State.FAILED
    return None


def _drain_events(eq: queue.Queue, ctx: RecoveryContext) -> None:
    """Non-blocking drain of any pending events to update timeline."""
    while True:
        try:
            event, event_ts, detail = eq.get_nowait()
            if event == Event.LINK_UP and ctx.timeline.link_up is None:
                ctx.timeline.link_up = event_ts
            elif event == Event.LINK_DOWN and ctx.timeline.power_off is None:
                ctx.timeline.power_off = event_ts
            elif event == Event.UBOOT_HTTP and ctx.timeline.uboot_http_first is None:
                ctx.timeline.uboot_http_first = event_ts
        except queue.Empty:
            break


def _print_timeline(ctx: RecoveryContext) -> None:
    print()
    log("=" * 50)
    log("RECOVERY TIMELINE")
    log("=" * 50)

    tl = ctx.timeline
    start = tl.recovery_start or tl.power_off or ts()

    def elapsed(t: Optional[float]) -> str:
        if t is None:
            return "N/A"
        return f"+{int(t - start)}s ({ts_str(t)})"

    log(f"  Recovery start:    {ts_str(start)}")
    log(f"  Power off:         {elapsed(tl.power_off)}")
    log(f"  Link up:           {elapsed(tl.link_up)}")
    log(f"  U-Boot HTTP:       {elapsed(tl.uboot_http_first)}")
    log(f"  Upload start:      {elapsed(tl.upload_start)}")
    log(f"  Upload complete:   {elapsed(tl.upload_complete)}")
    log(f"  Flash triggered:   {elapsed(tl.flash_triggered)}")
    log(f"  Flash complete:    {elapsed(tl.flash_complete)}")
    log(f"  First OpenWrt pkt: {elapsed(tl.first_openwrt_packet)}")
    log(f"  SSH available:     {elapsed(tl.ssh_available)}")

    if tl.ssh_available and start:
        total = int(tl.ssh_available - start)
        log(f"  TOTAL TIME:        {total}s ({total // 60}m {total % 60}s)")

    log(f"  SHA-256:           {ctx.sha256_before}")
    log("=" * 50)

    if ctx.pcap_path and os.path.isfile(ctx.pcap_path):
        size_kb = os.path.getsize(ctx.pcap_path) / 1024
        log(f"  Pcap: {ctx.pcap_path} ({size_kb:.1f} KB)")


def _record_inventory(ctx: RecoveryContext) -> None:
    ip = ctx.profile.openwrt_ip or ctx.profile.recovery_ip
    cfg = _load_config()

    fp = fingerprint_router(ip)
    if not fp:
        log("Could not fingerprint router for inventory.")
        return

    ident = fp.get("identity", {})
    fw = fp.get("firmware", {})
    net = fp.get("network", {})
    sec = fp.get("security", {})
    diag = fp.get("diagnostics", {})
    macs = net.get("macs", {})

    for key in ["hostname", "board", "serial"]:
        val = ident.get(key, "")
        if val:
            log(f"  inventory: {key}={val}")
    for iface, mac in sorted(macs.items()):
        if iface != "lo" and mac:
            log(f"  inventory: mac_{iface}={mac}")

    modem_data = fp.get("modem", {})
    if modem_data:
        for key in ["model", "firmware", "imei", "iccid"]:
            val = modem_data.get(key, "")
            if val:
                log(f"  inventory: modem_{key}={val}")

    tl = ctx.timeline
    start = tl.recovery_start or ts()
    timeline_durations = {}
    if tl.power_off:
        timeline_durations["power_off"] = int(tl.power_off - start)
    if tl.link_up:
        timeline_durations["link_up"] = int(tl.link_up - start)
    if tl.uboot_http_first:
        timeline_durations["uboot_http"] = int(tl.uboot_http_first - start)
    if tl.upload_start:
        timeline_durations["upload_start"] = int(tl.upload_start - start)
    if tl.upload_complete:
        timeline_durations["upload_complete"] = int(tl.upload_complete - start)
    if tl.flash_triggered:
        timeline_durations["flash_triggered"] = int(tl.flash_triggered - start)
    if tl.flash_complete:
        timeline_durations["flash_complete"] = int(tl.flash_complete - start)
    if tl.first_openwrt_packet:
        timeline_durations["first_openwrt_packet"] = int(tl.first_openwrt_packet - start)
    if tl.ssh_available:
        timeline_durations["ssh_available"] = int(tl.ssh_available - start)
        timeline_durations["total_seconds"] = int(tl.ssh_available - start)

    model_id = getattr(ctx.profile, 'name', '')
    openwrt_target = ""
    try:
        model = load_model(model_id)
        openwrt_target = model.get("openwrt", {}).get("target", "")
    except Exception:
        pass

    board = ident.get("board", "")
    fp_path = save_fingerprint(fp, board_id=board)

    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "device_serial": ident.get("serial", ""),
        "model": ident.get("model", ""),
        "model_id": model_id,
        "vendor": fp.get("firmware", {}).get("DISTRIB_ID", "").strip("'\"") or ident.get("vendor", ""),
        "firmware_version": fw.get("version", "").strip("'\""),
        "openwrt_target": openwrt_target,
        "hostname": ident.get("hostname", ""),
        "board": board,
        "kernel": fw.get("kernel", ""),
        "mac_addresses": {k: v for k, v in macs.items() if v and k != "lo"},
        "ssh_key_fingerprint": sec.get("ssh_fingerprint", ""),
        "ssh_key_count": sec.get("ssh_key_count", 0),
        "wan_ssh_rules": sec.get("wan_ssh_rules", 0),
        "packages_installed": sec.get("packages_installed", 0),
        "request_hash": ctx.request_hash or "",
        "cache_key": ctx.cache_key or "",
        "packages": ctx.packages or [],
        "defaults_script_hash": hashlib.sha256(ctx.defaults_script.encode()).hexdigest()[:16] if ctx.defaults_script else "",
        "ssh_keys_installed": len(cfg.ssh_all_keys) if cfg else 0,
        "password_set": ctx.password_set,
        "auth_type": ctx.auth_type,
        "wan_ssh_enabled": ctx.wan_ssh_enabled,
        "wireguard_pubkey": ctx.wireguard_pubkey,
        "sha256_firmware": ctx.sha256_before,
        "flashed_by": os.environ.get("USER", ""),
        "timeline": timeline_durations,
        "fingerprint_file": str(fp_path) if fp_path else "",
        "notes": "Flashed via conwrt",
    }
    if modem_data:
        entry["modem"] = modem_data

    inventory_path = Path(__file__).resolve().parent.parent / "data" / "inventory.jsonl"
    try:
        inventory_path.parent.mkdir(parents=True, exist_ok=True)
        with open(inventory_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
        log(f"Inventory entry appended to {inventory_path}")
    except Exception as e:
        log(f"Failed to write inventory: {e}")


def auto_detect_interface(subnet_prefix: str = "") -> Optional[str]:
    """Find the single active physical ethernet interface.

    On OpenWrt, returns br-lan directly (all LAN ports are bridged).
    On Linux, looks for enp*/eth*/en* interfaces with carrier UP.
    On macOS, scans en1..en20 skipping WiFi/Thunderbolt.
    """
    import platform
    if platform.system() == "Linux":
        # On OpenWrt, all LAN ports are bridged under br-lan
        if detect_platform() == "openwrt":
            if (Path("/sys/class/net/br-lan")).exists():
                log("OpenWrt detected — using br-lan as default interface")
                return "br-lan"
        candidates = []
        iface_dir = Path("/sys/class/net")
        if iface_dir.exists():
            for iface_path in sorted(iface_dir.iterdir()):
                name = iface_path.name
                if name.startswith(("lo", "wl", "docker", "br-", "virbr", "veth")):
                    continue
                if not name.startswith(("en", "eth")):
                    continue
                try:
                    carrier = (iface_path / "carrier").read_text().strip()
                    operstate = (iface_path / "operstate").read_text().strip()
                    if carrier == "1" and operstate == "up":
                        candidates.append(name)
                except (OSError, PermissionError):
                    continue
        if len(candidates) == 0:
            relaxed = []
            for iface_path in sorted(iface_dir.iterdir()):
                name = iface_path.name
                if name.startswith(("lo", "wl", "docker", "br-", "virbr", "veth")):
                    continue
                if not name.startswith(("en", "eth")):
                    continue
                relaxed.append(name)
            if len(relaxed) == 1:
                log(f"No carrier on {relaxed[0]}, but it's the only ethernet interface — using it")
                return relaxed[0]
            return None
        if len(candidates) > 1:
            log(f"WARNING: multiple ethernet interfaces active: {candidates}, using first")
        return candidates[0]
    else:
        bridge_members = set()
        br_r = subprocess.run(["ifconfig", "bridge0"], capture_output=True, text=True, check=False)
        for line in br_r.stdout.splitlines():
            if "member:" in line.lower():
                bridge_members.add(line.strip().split()[1])

        candidates = []
        for n in range(1, 21):
            iface = f"en{n}"
            r = subprocess.run(
                ["ifconfig", iface], capture_output=True, text=True, check=False,
            )
            if r.returncode != 0:
                continue
            if "status: active" not in r.stdout.lower():
                continue
            if iface in bridge_members:
                continue
            if "mtu 16000" in r.stdout:
                continue
            if "base" not in r.stdout or "duplex" not in r.stdout:
                continue
            candidates.append(iface)

        if len(candidates) == 0:
            return None
        if len(candidates) > 1:
            log(f"WARNING: multiple ethernet interfaces active: {candidates}, using first")
        return candidates[0]


def _build_parser() -> argparse.ArgumentParser:
    try:
        available_ids = [m["id"] for m in list_models()]
    except Exception:
        available_ids = []

    parser = argparse.ArgumentParser(
        description="conwrt — flash OpenWrt firmware to routers",
    )
    subparsers = parser.add_subparsers(dest="command")

    flash_parser = subparsers.add_parser("flash",
        help="Flash firmware to device (default if no subcommand given)")
    flash_parser.add_argument("--model-id", required=False,
                        help=f"Model ID from models/ directory (e.g. glinet-mt3000, dlink-covr-x1860-a1). "
                             f"Auto-detected if device is running OpenWrt. "
                             f"Use 'conwrt list' to see all available. "
                             f"Known: {', '.join(sorted(available_ids)) or 'none loaded'}")

    firmware_group = flash_parser.add_mutually_exclusive_group()
    firmware_group.add_argument("--image", default=None,
                                help="Path to firmware image (vanilla or custom)")
    firmware_group.add_argument("--request-image", action="store_true",
                                help="Request custom image from ASU with baked-in settings")

    flash_parser.add_argument("--ssh-key", default=None,
                        help="Path to SSH public key (default: [ssh].key from config.toml)")
    flash_parser.add_argument("--password", default=None,
                        help="Set root password (default: random, printed once)")
    flash_parser.add_argument("--no-password", action="store_true",
                        help="Skip password (key-only auth)")
    flash_parser.add_argument("--wan-ssh", action="store_true",
                        help="Open SSH on WAN port (requires --ssh-key, disables password auth)")
    flash_parser.add_argument("--interface", default=None,
                        help="Ethernet interface (auto-detected if omitted)")
    flash_parser.add_argument("--no-voice", action="store_true", help="Disable voice guidance")
    flash_parser.add_argument("--no-upload", action="store_true",
                        help="Stop after detecting U-Boot (dry run)")
    flash_parser.add_argument("--yes", action="store_true",
                        help="Skip destructive-operation confirmations")
    flash_parser.add_argument("--no-pcap", action="store_true",
                        help="Disable pcap monitoring (polling-only mode, no scapy needed)")
    flash_parser.add_argument("--force-uboot", action="store_true",
                        help="Force U-Boot recovery mode even if OpenWrt is detected")
    flash_parser.add_argument("--capture", default=None,
                        help="Save pcap capture to file (auto-degrades if no root)")
    flash_parser.add_argument("--router-mac", default="",
                        help="Router's OpenWrt MAC address (for ICMPv6 detection)")
    flash_parser.add_argument("--uboot-mac", default="",
                        help="Router's U-Boot MAC address (for ARP detection)")
    flash_parser.add_argument("--silence-timeout", type=int, default=SILENCE_TIMEOUT_DEFAULT,
                        help="Seconds of no packets before silence event")
    flash_parser.add_argument("--serial-port", default=None,
                        help="Serial port for serial-tftp method (e.g. /dev/cu.usbserial-A50285BI). "
                             "Auto-detected if omitted.")
    flash_parser.add_argument("--flash-method", default=None,
                        help="Flash method to use (e.g. recovery-http, dlink-hnap, sysupgrade, mtd-write, zycast, extreme-rdwr-tftp-initramfs). "
                             "Auto-detected if omitted: sysupgrade if OpenWrt is running, "
                             "otherwise the first recovery method in the model JSON.")
    flash_parser.add_argument("--initramfs", default=None,
                        help="Path to OpenWrt initramfs image (for two-stage flash methods like extreme-rdwr-tftp-initramfs)")
    flash_parser.add_argument("--serial-method", default=None,
                        help="Serial flash method variant (e.g. openwrt-flash, stock-restore). "
                             "Selects the serial-tftp-{method} flash_method from model JSON.")
    flash_parser.add_argument("--serial-baud", type=int, default=115200,
                        help="Serial baud rate (default: 115200)")
    flash_parser.add_argument("--tftp-root", default=None,
                        help="TFTP server root directory. Defaults to image directory.")

    subparsers.add_parser("list", help="List available device models")

    uc_parser = subparsers.add_parser("list-use-cases",
        help="List available use case presets")
    uc_parser.add_argument("--model-id", default=None,
        help="Show compatibility for a specific model")

    cache_parser = subparsers.add_parser("cache", help="Manage cached firmware images")
    cache_sub = cache_parser.add_subparsers(dest="cache_command")
    cache_sub.add_parser("list", help="List cached firmware images")
    cache_clean = cache_sub.add_parser("clean", help="Remove cached firmware images")
    cache_clean.add_argument("--model-id", default=None,
                        help="Only clean images for this model")
    cache_clean.add_argument("--keep-latest", action="store_true",
                        help="Keep only the latest build per model")
    cache_clean.add_argument("--yes", action="store_true",
                        help="Skip confirmation prompt")

    mgmt_parser = subparsers.add_parser("setup-mgmt-wifi",
        help="Configure management WiFi on a running router")
    mgmt_parser.add_argument("--ip", default="192.168.1.1",
        help="Router IP address")
    mgmt_parser.add_argument("--model-id", default=None,
        help="Model ID (for SSH key detection)")

    backup_parser = subparsers.add_parser("backup",
        help="Backup MTD flash partitions from a stock ZyXEL router via SSH")
    backup_parser.add_argument("--model-id", default="zyxel-nr7101",
        help="Model ID (default: zyxel-nr7101)")
    backup_parser.add_argument("--ip", default="192.168.1.1",
        help="Router IP address (default: 192.168.1.1)")
    backup_parser.add_argument("--serial", default=None,
        help="Device serial number (printed on unit label). Used to generate stock SSH password.")
    backup_parser.add_argument("--password", default=None,
        help="Stock SSH password (overrides --serial). Use if zyxel_pwgen is unavailable.")
    backup_parser.add_argument("--output-dir", default=None,
        help="Output directory for partition dumps (default: data/backups/<serial>)")
    backup_parser.add_argument("--partitions", default=None,
        help="Comma-separated list of MTD partitions to dump (e.g. '0,1,2'). Default: all partitions.")
    backup_parser.add_argument("--user", default="root",
        help="SSH username (default: root)")

    auto_parser = subparsers.add_parser("auto",
        help="Auto-detect connected router and offer to flash it")
    auto_parser.add_argument("--interface", default=None,
        help="Ethernet interface (auto-detected if omitted)")
    auto_parser.add_argument("--passive-timeout", type=int, default=10,
        help="Seconds to listen for passive detection (default: 10)")
    auto_parser.add_argument("--no-menu", action="store_true",
        help="Print detection results and exit (non-interactive)")

    nor_parser = subparsers.add_parser("setup-nor-recovery",
        help="Set up NOR flash as recovery partition on dual-flash devices (e.g. GL.iNet AR300M)")
    nor_parser.add_argument("--model-id", required=True,
        help="Model ID (e.g. glinet_gl-ar300m-nand)")
    nor_parser.add_argument("--i-want-a-brick", action="store_true",
        help="Safety acknowledgment: required to actually flash (not needed with --dry-run)")
    nor_parser.add_argument("--dry-run", action="store_true",
        help="Download and verify only, do not flash anything")
    nor_parser.add_argument("--skip-uboot", action="store_true",
        help="Skip U-Boot upgrade (only flash NOR firmware and set boot_env)")
    nor_parser.add_argument("--ip", default=None,
        help="Router IP address (default: from model JSON openwrt.default_ip)")
    nor_parser.add_argument("--no-voice", action="store_true",
        help="Disable voice guidance")

    cfg_parser = subparsers.add_parser("configure",
        help="Apply config.toml settings to a running OpenWrt router via SSH")
    cfg_parser.add_argument("--ip", default="192.168.1.1",
        help="Router IP address (default: 192.168.1.1)")
    cfg_parser.add_argument("--model-id", default=None,
        help="Model ID for capability filtering (auto-detected if omitted)")
    cfg_parser.add_argument("--interface", default=None,
        help="Ethernet interface (needed for LAN IP change; auto-detected if omitted)")
    cfg_parser.add_argument("--ssh-key", default=None,
        help="Path to SSH public key (default: [ssh].key from config.toml)")
    cfg_parser.add_argument("--password", default=None,
        help="Set root password (default: from config.toml)")
    cfg_parser.add_argument("--no-password", action="store_true",
        help="Skip password, key-only auth")
    cfg_parser.add_argument("--wan-ssh", action="store_true",
        help="Open SSH on WAN port")
    cfg_parser.add_argument("--dry-run", action="store_true",
        help="Print commands without executing")

    profile_parser = subparsers.add_parser("profile",
        help="Inspect operator profile (config.toml) plans")
    profile_sub = profile_parser.add_subparsers(dest="profile_command")
    plan_parser = profile_sub.add_parser("plan",
        help="Show what would be applied (ASU + post-install)")
    plan_parser.add_argument("--model-id", default=None,
        help="Model ID for capability filtering")
    profile_parser.set_defaults(profile_command="plan")

    return parser


def _ssh_run(ip: str, command: str, key: str = "", timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ssh_cmd(ip, command, key=key or None, connect_timeout=10),
        capture_output=True, text=True, timeout=timeout, check=False,
    )


def _cfg_install_ssh_key(ip: str, key_path: str, auth_key: str = "", ssh_key: str = "") -> bool:
    """Idempotent SSH key installation. Skips if key already present.

    key_path: path to public key file (for reading the key to install).
    auth_key: private key path used for SSH authentication.
    ssh_key: public key text (alternative to key_path).
    """
    pub_key = ""
    if ssh_key and ssh_key.startswith("ssh-"):
        pub_key = ssh_key.split("\n")[0].strip()
        parts = pub_key.split()
        if len(parts) >= 2:
            pub_key = f"{parts[0]} {parts[1]}"
    elif key_path:
        from pathlib import Path as _P
        raw = _P(key_path).expanduser().read_text().strip()
        parts = raw.split()
        if len(parts) >= 2:
            pub_key = f"{parts[0]} {parts[1]}"
    if not pub_key:
        log("  ⚠ SSH key: no key provided — skipping")
        return False

    log("  SSH key: checking current state...")
    r = _ssh_run(ip, "cat /etc/dropbear/authorized_keys 2>/dev/null || echo ''", key=auth_key)
    current_keys = r.stdout.strip()
    if pub_key in current_keys:
        log("  ✓ SSH key: already installed")
        return True

    log("  SSH key: installing...")
    needs_create = "No such file" in r.stderr or not current_keys
    op = ">" if needs_create or not current_keys else ">>"
    escaped = pub_key.replace("'", "'\\''")
    install_r = _ssh_run(
        ip,
        f"mkdir -p /etc/dropbear && echo '{escaped}' {op} /etc/dropbear/authorized_keys && chmod 600 /etc/dropbear/authorized_keys",
        key=auth_key,
    )
    if install_r.returncode != 0:
        log(f"  ⚠ SSH key: install failed (rc={install_r.returncode})")
        return False

    verify_r = _ssh_run(ip, "cat /etc/dropbear/authorized_keys 2>/dev/null || echo ''", key=auth_key)
    if pub_key in verify_r.stdout:
        log("  ✓ SSH key: installed and verified")
        return True
    log("  ⚠ SSH key: verification failed")
    return False


def _cfg_set_password(ip: str, password: str, ssh_key: str = "") -> bool:
    """Set root password. Always runs (idempotent — setting same password is fine)."""
    if not password:
        log("  Password: no password provided — skipping")
        return False

    log("  Password: setting...")
    import base64
    pw_b64 = base64.b64encode(password.encode()).decode()
    r = _ssh_run(
        ip,
        f"printf '%s\\n%s\\n' \"$(echo '{pw_b64}' | base64 -d)\" \"$(echo '{pw_b64}' | base64 -d)\" | passwd root",
        key=ssh_key,
    )
    if r.returncode != 0:
        log(f"  ⚠ Password: failed (rc={r.returncode})")
        return False
    log("  ✓ Password: set")
    return True


def _cfg_enable_wan_ssh(ip: str, ssh_key: str = "") -> bool:
    """Idempotent WAN SSH enable. Skips if rule already exists."""
    log("  WAN SSH: checking current state...")
    r = _ssh_run(ip, "uci show firewall | grep Allow-SSH-WAN | wc -l", key=ssh_key)
    if r.stdout.strip() != "0":
        log("  ✓ WAN SSH: rule already exists")
        r2 = _ssh_run(ip, "uci get dropbear.@dropbear[0].PasswordAuth", key=ssh_key)
        if r2.stdout.strip() == "off":
            log("  ✓ WAN SSH: password auth already disabled")
            return True
        log("  WAN SSH: ensuring password auth is off...")

    log("  WAN SSH: configuring...")
    commands = " && ".join([
        "idx=0; while uci -q get firewall.@rule[$idx] >/dev/null 2>&1; do name=$(uci -q get firewall.@rule[$idx].name); if [ \"$name\" = 'Allow-SSH-WAN' ]; then uci delete firewall.@rule[$idx]; else idx=$((idx+1)); fi; done",
        "uci add firewall rule",
        "uci set firewall.@rule[-1].name='Allow-SSH-WAN'",
        "uci set firewall.@rule[-1].src='wan'",
        "uci set firewall.@rule[-1].dest_port='22'",
        "uci set firewall.@rule[-1].proto='tcp'",
        "uci set firewall.@rule[-1].target='ACCEPT'",
        "uci commit firewall",
        "uci set dropbear.@dropbear[0].PasswordAuth='off'",
        "uci set dropbear.@dropbear[0].RootPasswordAuth='off'",
        "uci commit dropbear",
    ])
    r = _ssh_run(ip, commands, key=ssh_key)
    if r.returncode != 0:
        log(f"  ⚠ WAN SSH: failed (rc={r.returncode})")
        return False

    verify_r = _ssh_run(ip, "uci show firewall | grep Allow-SSH-WAN | wc -l", key=ssh_key)
    if verify_r.stdout.strip() != "0":
        log("  ✓ WAN SSH: enabled and verified")
        return True
    log("  ⚠ WAN SSH: verification failed")
    return False


def _resolve_configure_options(
    args: argparse.Namespace, cfg: object,
) -> tuple[str, str, str, str, bool]:
    """Resolve effective configure options (CLI overrides config.toml).

    Returns (password, ssh_private_key_path, ssh_pub_path, ssh_key_text, wan_ssh).
    Password is empty when --no-password or when not configured.
    """
    from config import ConwrtConfig
    if not isinstance(cfg, ConwrtConfig):
        return "", "", "", "", False

    ssh_key_path = args.ssh_key or cfg.ssh_private_key_path or ""
    ssh_pub_path = cfg.ssh_public_key_path
    ssh_key_text = cfg.ssh_public_key_text
    if args.ssh_key:
        from pathlib import Path as _P
        p = _P(args.ssh_key).expanduser()
        if p.is_file() and p.suffix == ".pub":
            ssh_pub_path = str(p)

    if args.no_password:
        password = ""
    elif args.password:
        password = args.password
    elif cfg.password_is_random:
        password = _generate_random_password()
    else:
        password = cfg.password_literal or ""

    wan_ssh = cfg.wan_ssh
    if args.wan_ssh:
        wan_ssh = True

    return password, ssh_key_path, ssh_pub_path, ssh_key_text, wan_ssh


def cmd_configure(args: argparse.Namespace) -> int:
    """Apply config.toml settings to a running OpenWrt router via SSH."""
    ip = args.ip
    cfg = _load_config()

    password, ssh_key_path, ssh_pub_path, ssh_key_text, wan_ssh = _resolve_configure_options(
        args, cfg,
    )
    model_id = args.model_id
    interface = args.interface or auto_detect_interface() or ""

    log(f"Configuring router at {ip}...")

    old_client_ip = ""
    if interface and not args.dry_run:
        from pathlib import Path as _P
        if _P(f"/sys/class/net/{interface}").exists():
            r = _ssh_run(ip, "uci get network.lan.ipaddr 2>/dev/null || echo ''", key=ssh_key_path)
            current_lan = r.stdout.strip().split("/")[0]
            old_client_ip = _client_ip_for_subnet(current_lan)

    if args.dry_run:
        log("  (dry run — no changes will be made)")
        ip = _apply_profile_post_flash(
            ip, ssh_key=ssh_key_path, cfg=cfg, model_id=model_id or "",
            interface=interface, old_client_ip=old_client_ip,
            password=password or None,
            wan_ssh=wan_ssh,
            ssh_key_path=ssh_pub_path or None,
            dry_run=True,
        )
        if ssh_pub_path or ssh_key_text:
            print("  # SSH key: idempotent install via authorized_keys check")
        return 0

    if ssh_pub_path or ssh_key_text:
        _cfg_install_ssh_key(ip, key_path=ssh_pub_path, auth_key=ssh_key_path, ssh_key=ssh_key_text)

    ip = _apply_profile_post_flash(
        ip, ssh_key=ssh_key_path, cfg=cfg, model_id=model_id or "",
        interface=interface, old_client_ip=old_client_ip,
        password=password or None,
        wan_ssh=wan_ssh,
        ssh_key_path=ssh_pub_path or None,
        dry_run=False,
    )

    log(f"Configuration complete. Router at {ip}")
    return 0


def cmd_profile_plan(args: argparse.Namespace) -> int:
    """Print the profile plan from config.toml (dry-run preview)."""
    cfg = _load_config()
    model_caps: list[str] = []
    if args.model_id:
        try:
            model = load_model(args.model_id)
            model_caps = model.get("capabilities", [])
        except FileNotFoundError as exc:
            print(f"Warning: {exc}", file=sys.stderr)
    plan = build_plan(cfg, mode="preview", model_capabilities=model_caps)
    print_plan(plan)
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    models = list_models()
    if not models:
        print("No models found in models/ directory.", file=sys.stderr)
        return 1

    print(f"{'Model ID':<40s}  {'Vendor':<12s}  {'Target':<22s}  {'Flash Methods':<20s}  Description")
    print("-" * 140)
    for model in models:
        model_id = model.get("id", "?")
        vendor = model.get("vendor", "?")
        target = model.get("openwrt", {}).get("target", "?")
        methods = ", ".join(model.get("flash_methods", {}).keys()) or "none"
        desc = model.get("description", "")
        print(f"{model_id:<40s}  {vendor:<12s}  {target:<22s}  [{methods}]  {desc}")
    return 0


def cmd_list_use_cases(args: argparse.Namespace) -> int:
    """List all available use case presets with optional model compatibility."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from use_cases import registry as _uc_registry

    uc_reg = _uc_registry()
    if not uc_reg:
        print("No use case presets found in scripts/use_cases/.", file=sys.stderr)
        return 1

    model_caps: list[str] = []
    model_name = ""
    if args.model_id:
        try:
            model = load_model(args.model_id)
            model_caps = model.get("capabilities", [])
            model_name = model.get("id", args.model_id)
        except Exception as e:
            print(f"Warning: could not load model '{args.model_id}': {e}", file=sys.stderr)

    print(f"{'Use Case':<25s}  {'Status':<14s}  {'Description':<40s}  {'Pkgs':<5s}  {'Caps':<12s}  Post")
    print("-" * 120)
    for name in sorted(uc_reg.keys()):
        uc = uc_reg[name]
        pkg_count = len(uc.packages)
        caps = ", ".join(uc.requires_capabilities) if uc.requires_capabilities else "-"
        post_flash = "yes" if uc.configure_via == "ssh" or uc.requires_post_flash else "-"
        status = uc.test_status

        if model_caps and uc.requires_capabilities:
            missing = set(uc.requires_capabilities) - set(model_caps)
            status = "INCOMPAT" if missing else "ok"
        elif model_caps and not uc.requires_capabilities:
            status = "ok"
        else:
            status = ""

        line = f"{name:<25s}  {status:<14s}  {uc.description[:40]:<40s}  {pkg_count:<5d}  {caps:<12s}  {post_flash}"
        if status == "INCOMPAT":
            line += f"  ** incompatible with {model_name} **"
        elif status == "ok":
            line += f"  compatible"
        print(line)

    if model_name:
        print(f"\nModel: {model_name}  Capabilities: {', '.join(sorted(model_caps)) or 'none'}")

    print("\nConfig snippet:")
    print("  [use_cases]")
    names = ", ".join(f'"{n}"' for n in sorted(uc_reg.keys())[:3])
    print(f"  enabled = [{names}, ...]")
    for name in sorted(uc_reg.keys())[:3]:
        uc = uc_reg[name]
        required = [p for p, d in uc.params.items() if d.required]
        if required:
            print(f"  [use_cases.{name}]")
            for p in required:
                print(f"  # {p} = \"...\"  # {uc.params[p].description}")

    return 0


def cmd_cache(args: argparse.Namespace) -> int:
    images_dir = Path(__file__).resolve().parent.parent / "images"

    if args.cache_command == "list":
        return _cache_list(images_dir)
    elif args.cache_command == "clean":
        return _cache_clean(images_dir, args)
    else:
        print("Usage: conwrt cache <list|clean>", file=sys.stderr)
        return 1


def _cache_list(images_dir: Path) -> int:
    if not images_dir.is_dir():
        print("No images/ directory found.", file=sys.stderr)
        return 1

    entries = []
    for model_dir in sorted(images_dir.iterdir()):
        if not model_dir.is_dir():
            continue
        for hash_dir in sorted(model_dir.iterdir()):
            if not hash_dir.is_dir():
                continue
            model_id = model_dir.name
            cache_key = hash_dir.name
            metadata_files = list(hash_dir.glob("*.metadata.json"))
            metadata = {}
            if metadata_files:
                try:
                    with open(metadata_files[0]) as f:
                        metadata = json.load(f)
                except (json.JSONDecodeError, OSError):
                    pass

            bin_files = list(hash_dir.glob("*.bin"))
            image_types = []
            total_size = 0
            for bf in bin_files:
                if "sysupgrade" in bf.name:
                    image_types.append("sysupgrade")
                elif "recovery" in bf.name:
                    image_types.append("recovery")
                elif "factory" in bf.name:
                    image_types.append("factory")
                else:
                    image_types.append(bf.stem)
                total_size += bf.stat().st_size

            build_info = metadata.get("version", "?")
            if metadata.get("version_code"):
                build_info += f" ({metadata.get('version_code', '')[:20]})"

            entries.append({
                "model": model_id,
                "hash": cache_key[:12],
                "version": build_info,
                "types": ", ".join(sorted(set(image_types))) or "none",
                "size_mb": f"{total_size / 1024 / 1024:.1f}",
            })

    if not entries:
        print("No cached firmware images found.")
        return 0

    print(f"{'Model':<30s}  {'Hash':<14s}  {'Version':<35s}  {'Types':<30s}  {'Size':>8s}")
    print("-" * 130)
    for e in entries:
        print(f"{e['model']:<30s}  {e['hash']:<14s}  {e['version']:<35s}  {e['types']:<30s}  {e['size_mb']:>7s} MB")
    print(f"\nTotal: {len(entries)} cached build(s)")
    return 0


def _cache_clean(images_dir: Path, args: argparse.Namespace) -> int:
    if not images_dir.is_dir():
        print("No images/ directory found.", file=sys.stderr)
        return 1

    targets = []
    for model_dir in sorted(images_dir.iterdir()):
        if not model_dir.is_dir():
            continue
        if args.model_id and model_dir.name != args.model_id and model_dir.name != args.model_id.replace("-", "_"):
            continue

        hash_dirs = sorted(model_dir.iterdir(), key=lambda d: d.stat().st_mtime)
        hash_dirs = [h for h in hash_dirs if h.is_dir()]

        if args.keep_latest and len(hash_dirs) > 1:
            targets.extend(hash_dirs[:-1])
        elif not args.keep_latest:
            targets.extend(hash_dirs)

    if not targets:
        if args.model_id:
            print(f"No cached images found for model '{args.model_id}'.")
        else:
            print("No cached images found.")
        return 0

    total_size = sum(
        f.stat().st_size
        for d in targets
        for f in d.iterdir()
        if f.is_file()
    )
    print(f"Will remove {len(targets)} cached build(s) ({total_size / 1024 / 1024:.1f} MB):")
    for d in targets:
        print(f"  {d.parent.name}/{d.name[:12]}...")

    if not args.yes:
        try:
            response = input("Continue? [y/N] ")
            if response.lower() not in ("y", "yes"):
                print("Cancelled.")
                return 0
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

    removed = 0
    for d in targets:
        shutil.rmtree(d)
        removed += 1

    print(f"Removed {removed} cached build(s) ({total_size / 1024 / 1024:.1f} MB freed).")
    return 0


def cmd_setup_nor_recovery(args: argparse.Namespace) -> int:
    """Set up NOR flash as a recovery OpenWrt partition on dual-flash devices."""
    model_id = args.model_id

    # Load model JSON
    try:
        model = load_model(model_id)
    except FileNotFoundError:
        print(f"ERROR: Model '{model_id}' not found in models/ directory.", file=sys.stderr)
        print("Use 'conwrt list' to see available models.", file=sys.stderr)
        return 1

    nor = model.get("nor_recovery")
    if not nor:
        print(f"ERROR: Model '{model_id}' does not have a 'nor_recovery' section.", file=sys.stderr)
        print("This device may not support dual-flash recovery setup.", file=sys.stderr)
        return 1

    # Resolve IP
    default_ip = model.get("openwrt", {}).get("default_ip", "192.168.1.1")
    ip = args.ip or default_ip

    # Safety check: --i-want-a-brick required unless --dry-run
    dry_run = args.dry_run
    if not dry_run and not args.i_want_a_brick:
        print("ERROR: NOR recovery involves flashing U-Boot (mtd0) which can brick the device.", file=sys.stderr)
        print("Add --i-want-a-brick to acknowledge this risk, or use --dry-run.", file=sys.stderr)
        return 1

    skip_uboot = args.skip_uboot
    no_voice = args.no_voice

    def _say(msg: str) -> None:
        if not no_voice:
            say(msg)

    uboot_cfg = nor.get("uboot_upgrade", {})
    nor_fw_cfg = nor.get("nor_firmware", {})
    boot_env_cfg = nor.get("boot_env", {})
    requires_kmod = nor.get("requires_kmod_mtd_rw", False)
    mtd_rw_param = nor.get("mtd_rw_module_param", "")

    # Print header
    log(f"NOR Recovery Setup — {model.get('vendor', '?')} {model.get('description', model_id)}")
    log(f"Router IP: {ip}")
    if dry_run:
        log("DRY RUN — no changes will be written to the router")
    if skip_uboot:
        log("Skipping U-Boot upgrade (--skip-uboot)")
    print()

    # Step 1: Verify SSH access
    log("Step 1: Verifying SSH access...")
    ssh_key = _detect_ssh_key_path()
    if not ssh_key:
        print("ERROR: No SSH private key found. Set [ssh].key in config.toml or install ~/.ssh/id_ed25519 or ~/.ssh/id_rsa.", file=sys.stderr)
        return 1

    try:
        r = subprocess.run(
            ssh_cmd(ip, "echo SSH_OK", key=ssh_key, connect_timeout=10),
            capture_output=True, text=True, timeout=15, check=False,
        )
    except subprocess.TimeoutExpired:
        print(f"ERROR: SSH connection to {ip} timed out.", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"ERROR: SSH connection to {ip} failed: {exc}", file=sys.stderr)
        return 1

    if "SSH_OK" not in r.stdout:
        print(f"ERROR: Cannot reach router via SSH at {ip}.", file=sys.stderr)
        if r.stderr:
            print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
        return 1
    log("SSH access OK")

    # Step 2: Verify correct model (check board name)
    log("Step 2: Verifying device model...")
    try:
        r = subprocess.run(
            ssh_cmd(ip, "cat /tmp/sysinfo/board_name", key=ssh_key, connect_timeout=10),
            capture_output=True, text=True, timeout=15, check=False,
        )
    except Exception as exc:
        print(f"ERROR: Failed to check board name: {exc}", file=sys.stderr)
        return 1

    board_name = r.stdout.strip()
    expected_device = model.get("openwrt", {}).get("device", "")
    if expected_device and board_name != expected_device:
        print(f"WARNING: Board name mismatch!", file=sys.stderr)
        print(f"  Expected: {expected_device}", file=sys.stderr)
        print(f"  Got:      {board_name}", file=sys.stderr)
        if not dry_run:
            print("Aborting. Use a different --model-id or verify the device.", file=sys.stderr)
            return 1
    log(f"Board: {board_name} — matches model")

    # Step 3: nor_recovery section already checked above
    log("Step 3: Model has nor_recovery section ✓")

    if dry_run:
        print()
        log("=== DRY RUN — would perform the following steps ===")
        if not skip_uboot and uboot_cfg:
            log(f"  4. Download U-Boot from: {uboot_cfg.get('url', '?')}")
            log(f"     Expected SHA256: {uboot_cfg.get('sha256', '?')}")
            log(f"     Flash: {uboot_cfg.get('flash_command', '?')}")
            log(f"     (reboot after, ~60-90s wait)")
        if nor_fw_cfg:
            log(f"  10. Download NOR firmware from: {nor_fw_cfg.get('url', '?')}")
            log(f"      Expected SHA256: {nor_fw_cfg.get('sha256', '?')}")
            log(f"      Flash: mtd write /tmp/nor-firmware.bin {nor_fw_cfg.get('mtd_partition', '?')}")
        if boot_env_cfg:
            log(f"  13. Set boot_dev={boot_env_cfg.get('boot_dev', '?')} via fw_setenv")

        # In dry-run, download locally and verify hashes
        print()
        log("Downloading files locally to verify hashes...")
        tmp_dir = "/tmp/conwrt-nor-dryrun"
        os.makedirs(tmp_dir, exist_ok=True)

        if not skip_uboot and uboot_cfg:
            uboot_url = uboot_cfg["url"]
            uboot_local = os.path.join(tmp_dir, "uboot-recovery.bin")
            log(f"  Downloading U-Boot to {uboot_local}...")
            try:
                urllib.request.urlretrieve(uboot_url, uboot_local)
                actual_sha256 = sha256_file(uboot_local)
                expected_sha256 = uboot_cfg["sha256"]
                if actual_sha256 == expected_sha256:
                    log(f"  U-Boot SHA256 verified ✓")
                else:
                    print(f"  WARNING: U-Boot SHA256 mismatch!", file=sys.stderr)
                    print(f"    Expected: {expected_sha256}", file=sys.stderr)
                    print(f"    Got:      {actual_sha256}", file=sys.stderr)
            except Exception as exc:
                log(f"  Failed to download U-Boot: {exc}")

        if nor_fw_cfg:
            nor_url = nor_fw_cfg["url"]
            nor_local = os.path.join(tmp_dir, "nor-firmware.bin")
            log(f"  Downloading NOR firmware to {nor_local}...")
            try:
                urllib.request.urlretrieve(nor_url, nor_local)
                actual_sha256 = sha256_file(nor_local)
                expected_sha256 = nor_fw_cfg["sha256"]
                if actual_sha256 == expected_sha256:
                    log(f"  NOR firmware SHA256 verified ✓")
                else:
                    print(f"  WARNING: NOR firmware SHA256 mismatch!", file=sys.stderr)
                    print(f"    Expected: {expected_sha256}", file=sys.stderr)
                    print(f"    Got:      {actual_sha256}", file=sys.stderr)
            except Exception as exc:
                log(f"  Failed to download NOR firmware: {exc}")

        print()
        log("DRY RUN complete. No changes were made to the router.")
        return 0

    # === LIVE MODE ===
    print()

    def _run_ssh(command: str, timeout: int = 60) -> subprocess.CompletedProcess:
        """Run SSH command on router, return CompletedProcess."""
        return subprocess.run(
            ssh_cmd(ip, command, key=ssh_key, connect_timeout=10),
            capture_output=True, text=True, timeout=timeout, check=False,
        )

    def _install_kmod_mtd_rw() -> bool:
        """Install kmod-mtd-rw with required module parameter. Returns True on success."""
        if not requires_kmod:
            return True
        log("  Installing kmod-mtd-rw...")
        r = _run_ssh("opkg update && opkg install kmod-mtd-rw")
        if r.returncode != 0:
            # Maybe already installed, try to load
            pass
        # Insert module with required param
        if mtd_rw_param:
            insmod_cmd = f"insmod mtd-rw {mtd_rw_param} 2>/dev/null || echo module_load_attempted"
            r = _run_ssh(insmod_cmd)
            if "module_load_attempted" not in r.stdout and r.returncode != 0:
                # Try rmmod then insmod in case it's already loaded without the param
                _run_ssh("rmmod mtd-rw 2>/dev/null")
                r = _run_ssh(f"insmod mtd-rw {mtd_rw_param}")
                if r.returncode != 0:
                    print(f"ERROR: Failed to load mtd-rw module with param '{mtd_rw_param}'.", file=sys.stderr)
                    if r.stderr:
                        print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
                    return False
        log("  kmod-mtd-rw installed and loaded")
        return True

    def _download_and_scp(url: str, local_name: str, remote_path: str,
                          expected_sha256: str) -> bool:
        """Download file locally, verify hash, SCP to router. Returns True on success."""
        local_path = os.path.join("/tmp", local_name)
        log(f"  Downloading {local_name}...")
        try:
            urllib.request.urlretrieve(url, local_path)
        except Exception as exc:
            print(f"ERROR: Failed to download {local_name}: {exc}", file=sys.stderr)
            return False
        actual = sha256_file(local_path)
        if actual != expected_sha256:
            print(f"ERROR: {local_name} SHA256 mismatch!", file=sys.stderr)
            print(f"  Expected: {expected_sha256}", file=sys.stderr)
            print(f"  Got:      {actual}", file=sys.stderr)
            return False
        log(f"  SHA256 verified ✓ ({actual[:16]}...)")
        scp_argv = ["scp", "-O", "-o", "StrictHostKeyChecking=no",
                     "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes",
                     "-i", ssh_key, local_path, f"root@{ip}:{remote_path}"]
        try:
            r = subprocess.run(scp_argv, capture_output=True, text=True, timeout=120, check=False)
        except subprocess.TimeoutExpired:
            print(f"ERROR: SCP of {local_name} timed out.", file=sys.stderr)
            return False
        if r.returncode != 0:
            print(f"ERROR: SCP of {local_name} failed.", file=sys.stderr)
            if r.stderr:
                print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
            return False
        log(f"  Uploaded to {remote_path}")
        return True

    # Steps 4-8: U-Boot upgrade (unless --skip-uboot)
    if not skip_uboot and uboot_cfg:
        _say("Preparing to flash U-Boot. Do not disconnect power.")
        log("Step 4: Downloading U-Boot binary...")
        if not _download_and_scp(
            uboot_cfg["url"], "uboot-recovery.bin", "/tmp/uboot-recovery.bin",
            uboot_cfg["sha256"],
        ):
            return 1

        # Step 6: Install kmod-mtd-rw
        log("Step 6: Installing kmod-mtd-rw...")
        if not _install_kmod_mtd_rw():
            return 1

        # Step 7: Flash U-Boot
        _say("Flashing U-Boot. This is dangerous. Do not disconnect power.")
        flash_cmd = uboot_cfg.get("flash_command", "mtd -r write /tmp/uboot-recovery.bin /dev/mtd0")
        log(f"Step 7: Flashing U-Boot via: {flash_cmd}")
        print()
        print("  ⚠️  FLASHING U-BOOT — DO NOT DISCONNECT POWER ⚠️")
        print()
        try:
            # mtd -r causes reboot, so the SSH connection will be dropped
            r = subprocess.run(
                ssh_cmd(ip, flash_cmd, key=ssh_key, connect_timeout=10),
                capture_output=True, text=True, timeout=120, check=False,
            )
        except subprocess.TimeoutExpired:
            # Expected: mtd -r reboots the router, SSH drops
            pass
        except Exception as exc:
            # Connection reset is expected during reboot
            if "reset" not in str(exc).lower() and "broken" not in str(exc).lower():
                print(f"WARNING: Unexpected error during U-Boot flash: {exc}", file=sys.stderr)

        # Step 8: Wait for reboot
        _say("Waiting for router to reboot. This takes about 90 seconds.")
        log("Step 8: Waiting for router to reboot (60-90s)...")
        time.sleep(10)  # Brief wait before starting to poll
        reboot_timeout = 120
        reboot_start = time.time()
        ssh_back = False
        while time.time() - reboot_start < reboot_timeout:
            if check_ssh(ip):
                ssh_back = True
                break
            time.sleep(5)
        if not ssh_back:
            print(f"ERROR: Router did not come back after U-Boot flash within {reboot_timeout}s.", file=sys.stderr)
            print("The device may be bricked. Check via serial/UART.", file=sys.stderr)
            return 1
        elapsed = int(time.time() - reboot_start)
        log(f"  Router back online after {elapsed}s")

        # Step 9: Re-install kmod-mtd-rw (lost after reboot)
        log("Step 9: Re-installing kmod-mtd-rw (lost after reboot)...")
        if not _install_kmod_mtd_rw():
            return 1
    else:
        if skip_uboot:
            log("Steps 4-9: Skipped (--skip-uboot)")
        # Still need kmod-mtd-rw for NOR flash
        if requires_kmod:
            log("Installing kmod-mtd-rw...")
            if not _install_kmod_mtd_rw():
                return 1

    # Step 10: Download NOR sysupgrade image
    log("Step 10: Downloading NOR sysupgrade image...")
    if not _download_and_scp(
        nor_fw_cfg["url"], "nor-firmware.bin", "/tmp/nor-firmware.bin",
        nor_fw_cfg["sha256"],
    ):
        return 1

    log("Step 11: Verifying NOR firmware SHA256 on router...")
    r = _run_ssh("sha256sum /tmp/nor-firmware.bin")
    if r.returncode != 0:
        print("ERROR: Failed to compute SHA256 on router.", file=sys.stderr)
        return 1
    actual_hash = r.stdout.strip().split()[0]
    expected_hash = nor_fw_cfg["sha256"]
    if actual_hash != expected_hash:
        print("ERROR: NOR firmware SHA256 hash mismatch!", file=sys.stderr)
        print(f"  Expected: {expected_hash}", file=sys.stderr)
        print(f"  Got:      {actual_hash}", file=sys.stderr)
        return 1
    log(f"  SHA256 verified ✓")

    # Step 12: Flash NOR firmware (no -r, no reboot)
    _say("Flashing NOR recovery partition.")
    nor_mtd_partition = nor_fw_cfg.get("mtd_partition", "nor_firmware")
    log(f"Step 12: Flashing NOR firmware to '{nor_mtd_partition}' partition...")
    flash_nor_cmd = f"mtd write /tmp/nor-firmware.bin {nor_mtd_partition}"
    r = _run_ssh(flash_nor_cmd, timeout=120)
    if r.returncode != 0:
        print("ERROR: Failed to flash NOR firmware.", file=sys.stderr)
        if r.stderr:
            print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
        return 1
    log("  NOR firmware flashed ✓")

    # Step 12b: Note the recovery hostname for first NOR boot
    recovery_hostname = nor.get("recovery_hostname", "")

    # Step 12c: Fix bootargs for dual-boot compatibility
    bootargs_fix = nor.get("bootargs_fix")
    if bootargs_fix:
        log("Step 12c: Fixing U-Boot bootargs for dual-boot...")
        r = _run_ssh(f"fw_setenv bootargs '{bootargs_fix}'")
        if r.returncode != 0:
            print("ERROR: Failed to set bootargs via fw_setenv.", file=sys.stderr)
            if r.stderr:
                print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
            return 1
        r = _run_ssh("fw_printenv bootargs")
        log(f"  bootargs: {r.stdout.strip()} ✓")

    # Step 12d: Set boot_local override for NOR boot selection
    boot_local_val = nor.get("boot_local", "")
    if boot_local_val:
        log(f"Step 12d: Setting boot_local={boot_local_val}...")
        r = _run_ssh(f"fw_setenv boot_local {boot_local_val}")
        if r.returncode != 0:
            print("ERROR: Failed to set boot_local via fw_setenv.", file=sys.stderr)
            if r.stderr:
                print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
            return 1
        r = _run_ssh("fw_printenv boot_local")
        log(f"  {r.stdout.strip()} ✓")

    # Step 13: Set boot_env
    if boot_env_cfg:
        boot_dev_val = boot_env_cfg.get("boot_dev")
        if boot_dev_val:
            log(f"Step 13: Setting boot_dev={boot_dev_val} via fw_setenv...")
            r = _run_ssh(f"fw_setenv boot_dev {boot_dev_val}")
            if r.returncode != 0:
                print("ERROR: Failed to set boot_dev via fw_setenv.", file=sys.stderr)
                if r.stderr:
                    print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
                return 1
            log("  boot_dev set ✓")

            # Step 14: Verify
            log("Step 14: Verifying fw_printenv boot_dev...")
            r = _run_ssh("fw_printenv boot_dev")
            if r.returncode != 0:
                print("WARNING: fw_printenv boot_dev failed.", file=sys.stderr)
                if r.stderr:
                    print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
            else:
                output = r.stdout.strip()
                if f"boot_dev={boot_dev_val}" in output:
                    log(f"  Verified: {output} ✓")
                else:
                    print(f"WARNING: boot_dev value unexpected: {output}", file=sys.stderr)
                    print(f"  Expected: boot_dev={boot_dev_val}", file=sys.stderr)
    else:
        log("Steps 13-14: No boot_env config in model JSON, skipping")

    # Step 15: Set bootcount to trigger NOR boot on next power cycle
    boot_method = nor.get("boot_method", {})
    if boot_method.get("recommended") == "bootcount":
        _say("Setting bootcount to trigger NOR boot on next power cycle.")
        log("Step 15: Setting bootcount=3 to trigger NOR boot on next power cycle...")
        r = _run_ssh("fw_setenv bootcount 3")
        if r.returncode != 0:
            print("WARNING: Failed to set bootcount via fw_setenv.", file=sys.stderr)
            if r.stderr:
                print(f"  stderr: {r.stderr.strip()}", file=sys.stderr)
        else:
            r = _run_ssh("fw_printenv bootcount")
            log(f"  {r.stdout.strip()} ✓")
            log("  On next power cycle: U-Boot will increment bootcount to 4,")
            log("  exceed bootlimit=3, set nand_boot_failed=1, and boot NOR.")
            log("  After NOR boot, reset with: fw_setenv bootcount 0 && reboot")
    else:
        log("Step 15: No bootcount method configured in model JSON, skipping")

    # Step 16: Summary
    print()
    print("=" * 60)
    log("NOR Recovery Setup Complete!")
    print("=" * 60)
    if not skip_uboot and uboot_cfg:
        print(f"  U-Boot:   upgraded to {uboot_cfg.get('version', 'unknown')}")
    else:
        print(f"  U-Boot:   skipped (--skip-uboot)")
    print(f"  NOR:      flashed {nor_fw_cfg.get('description', 'recovery firmware')}")
    if boot_env_cfg:
        print(f"  boot_dev: {boot_env_cfg.get('boot_dev', 'not set')}")
    if bootargs_fix:
        print(f"  bootargs: fixed for dual-boot")
    if boot_local_val:
        print(f"  boot_local: {boot_local_val}")
    print()
    print("Verification:")
    post = nor.get("post_setup_verification", {})
    for label, desc in post.items():
        print(f"  {label}: {desc}")
    print()
    print("To switch boot source:")
    print("  NAND (primary):  switch LEFT + fw_setenv bootcount 0 && reboot")
    print("  NOR  (recovery): fw_setenv bootcount 3 && reboot")
    print("                   (switch position does NOT reliably control boot — use bootcount)")
    if recovery_hostname:
        print()
        print(f"On first NOR boot, set the recovery hostname:")
        print(f"  uci set system.@system[0].hostname='{recovery_hostname}' && uci commit system")
    print()

    _say("NOR recovery setup is complete.")
    return 0


def cmd_flash(args: argparse.Namespace) -> int:
    parser = _build_parser()
    validation_error = _validate_args(args)
    if validation_error:
        parser.error(validation_error)

    # Platform detection — warn about missing deps on OpenWrt
    if detect_platform() == "openwrt":
        missing = check_external_deps()
        if missing:
            log(f"WARNING: missing dependencies: {', '.join(missing)}")
            log("Install via: opkg update && opkg install " + " ".join(missing))

    if args.request_image and not args.ssh_key:
        cfg = _load_config()
        if cfg.ssh_public_key_path:
            args.ssh_key = cfg.ssh_public_key_path
        else:
            parser.error("No SSH public key found. Set [ssh].key in config.toml or use --ssh-key.")

    _say_fn = (lambda m: None) if args.no_voice else say

    ssh_key_path = _detect_ssh_key_path()

    if not args.model_id:
        for probe_ip in ["192.168.1.1", "192.168.0.1"]:
            fp = fingerprint_router(probe_ip)
            if fp:
                board = fp.get("identity", {}).get("board", "")
                if board:
                    detected_id = _find_model_id_by_board(board)
                    if detected_id:
                        args.model_id = detected_id
                        log(f"Auto-detected model: {detected_id} (board={board})")
                        break
        if not args.model_id:
            parser.error("--model-id is required when device is not reachable via SSH.")

    try:
        profile = _build_profile_from_model(args.model_id,
                                             serial_method=args.serial_method or "",
                                             flash_method=getattr(args, 'flash_method', '') or "")
    except (FileNotFoundError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    is_serial_tftp = getattr(profile, 'is_serial_tftp', False)
    is_zycast = getattr(profile, 'is_zycast', False)
    is_edgeos_ks = getattr(profile, 'is_edgeos_kernel_swap', False)
    is_extreme_rdwr_tftp = getattr(profile, 'is_extreme_rdwr_tftp', False)

    if is_serial_tftp and not args.serial_method:
        serial_methods = [k for k in load_model(args.model_id).get("flash_methods", {}).keys()
                          if k.startswith("serial-tftp-")]
        if len(serial_methods) == 1:
            method_suffix = serial_methods[0].replace("serial-tftp-", "")
            profile = _build_profile_from_model(args.model_id, serial_method=method_suffix,
                                                 flash_method=getattr(args, 'flash_method', '') or "")
            log(f"Auto-selected serial method: {serial_methods[0]}")
        elif len(serial_methods) > 1:
            print(f"ERROR: Multiple serial methods available: {serial_methods}. "
                  f"Use --serial-method to select one.", file=sys.stderr)
            return 1

    openwrt_ip = profile.openwrt_ip or profile.recovery_ip

    if is_serial_tftp or is_zycast:
        boot_state = "unknown"
        use_sysupgrade = False
    else:
        boot_state = _detect_boot_state("", profile)
        use_sysupgrade = boot_state == "openwrt" and not args.force_uboot

    generated_password = ""
    password_set = False
    auth_type = ""
    wan_ssh_enabled = False
    image_path = args.image
    request_metadata: dict = {}

    if args.request_image:
        cfg = _load_config()
        password = args.password
        if not args.no_password and not args.password:
            if cfg.password_is_key_only:
                password = None
                password_set = False
                auth_type = "key-only"
            elif cfg.password_is_random:
                generated_password = _generate_random_password()
                _say_fn("Random password generated. Check the console.")
                password = generated_password
                password_set = True
                auth_type = "key-and-password"
            elif cfg.password_literal:
                password = cfg.password_literal
                password_set = True
                auth_type = "key-and-password"
        elif args.password:
            password_set = True
            auth_type = "key-and-password"
        elif args.no_password:
            password_set = False
            auth_type = "key-only"

        wan_ssh_enabled = args.wan_ssh or cfg.wan_ssh

        if wan_ssh_enabled:
            if not args.ssh_key and not cfg.ssh_public_key_path:
                parser.error("--wan-ssh requires an SSH key. Set [ssh].key in config.toml or use --ssh-key.")
            if args.no_password and not args.ssh_key:
                parser.error("--wan-ssh with --no-password requires --ssh-key (no way to log in otherwise).")

        effective_flash_method = profile.flash_method
        if use_sysupgrade and effective_flash_method != "mtd-write":
            effective_flash_method = "sysupgrade"
        image_path, request_metadata = _request_custom_image(
            model_id=args.model_id,
            ssh_key_path=args.ssh_key,
            password=password,
            wan_ssh=wan_ssh_enabled,
            flash_method=effective_flash_method,
            say_fn=_say_fn,
        )
        if not image_path:
            print("ERROR: Failed to obtain firmware image.", file=sys.stderr)
            return 1

    if args.initramfs:
        request_metadata["initramfs_path"] = args.initramfs

    if not image_path:
        parser.error("One of --image or --request-image is required.")

    if not os.path.isfile(image_path):
        print(f"ERROR: image not found: {image_path}", file=sys.stderr)
        return 1

    initramfs_path = request_metadata.get("initramfs_path", "")
    if is_extreme_rdwr_tftp or is_edgeos_ks:
        if args.initramfs:
            initramfs_path = args.initramfs
        if not initramfs_path:
            print("ERROR: initramfs image required for this flash method. Use --initramfs or --request-image.", file=sys.stderr)
            return 1
        if not os.path.isfile(initramfs_path):
            print(f"ERROR: initramfs image not found: {initramfs_path}", file=sys.stderr)
            return 1

    interface = args.interface or auto_detect_interface()
    if not interface:
        print("ERROR: no active ethernet interface found. Use --interface.", file=sys.stderr)
        return 1

    if args.capture:
        pcap_path = args.capture
    else:
        captures_dir = Path(__file__).resolve().parent.parent / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d-%H%M%S")
        pcap_path = str(captures_dir / f"{args.model_id}-{ts}.pcap")

    log(f"{profile.description} Recovery")
    log(f"Model:      {profile.name} ({profile.vendor})")
    log(f"Image:      {image_path}")
    log(f"Interface:  {interface}")
    log(f"Pcap:       {pcap_path}")
    log(f"Boot state: {boot_state}")
    if is_serial_tftp:
        log(f"Flash path: serial-tftp ({profile.flash_method})")
        log(f"Serial:     {args.serial_port or 'auto-detect'} @ {getattr(profile, 'serial_baud', 115200)} baud")
        if getattr(profile, 'lan_port', ''):
            log(f"LAN port:   {profile.lan_port} (for TFTP)")
    elif is_zycast and not use_sysupgrade:
        log(f"Flash path: zycast multicast ({profile.zycast_multicast_group}:{profile.zycast_multicast_port})")
    elif is_edgeos_ks and not use_sysupgrade:
        log(f"Flash path: edgeos-kernel-swap (2-stage SSH)")
    elif is_extreme_rdwr_tftp and not use_sysupgrade:
        log("Flash path: extreme-rdwr-tftp-initramfs (stock SSH + TFTP + initramfs sysupgrade)")
    else:
        log(f"Flash path: {'sysupgrade' if use_sysupgrade else 'U-Boot recovery'}")
    if not use_sysupgrade and not is_serial_tftp and not is_zycast:
        log(f"LED signal: {profile.led_pattern}")
    if args.request_image:
        log(f"Auth type:  {auth_type}")
        log(f"WAN SSH:    {wan_ssh_enabled}")
    print()

    fp = fingerprint_router(openwrt_ip) if use_sysupgrade else None
    if fp:
        ident = fp.get("identity", {})
        fw = fp.get("firmware", {})
        hw = fp.get("hardware", {})
        net = fp.get("network", {})
        sec = fp.get("security", {})
        log(f"Detected:   {ident.get('model', '?')} (board={ident.get('board', '?')})")
        log(f"Firmware:   {fw.get('version', '?')} {fw.get('target', '')}")
        log(f"Kernel:     {fw.get('kernel', '?')}")
        br_mac = net.get("macs", {}).get("br-lan", "")
        if br_mac:
            log(f"MAC:        {br_mac}")
            if not args.router_mac:
                args.router_mac = br_mac
        mem = hw.get("memory_mb", {})
        if mem:
            log(f"Memory:     {mem.get('total', '?')} kB total, {mem.get('free', '?')} kB free")
        pkgs = sec.get("packages_installed", 0)
        if pkgs:
            log(f"Packages:   {pkgs} installed")
        uptime = fp.get("diagnostics", {}).get("uptime", "")
        if uptime:
            log(f"Uptime:     {uptime}")
        print()
    else:
        log("No running router detected at this IP (expected — device needs recovery)")
        print()

    if is_serial_tftp:
        initial_state = State.SERIAL_WAITING_FOR_BOOTMENU
    elif is_zycast and not use_sysupgrade:
        initial_state = State.ZYCAST_WAITING_FOR_DEVICE
    elif is_edgeos_ks and not use_sysupgrade:
        initial_state = State.EDGEOS_STAGE1
    elif is_extreme_rdwr_tftp and not use_sysupgrade:
        initial_state = State.EXTREME_STOCK_PREFLIGHT if boot_state == "stock-extreme" else State.DETECTING
    elif use_sysupgrade:
        initial_state = State.SYSUPGRADE_UPLOADING
    elif boot_state == "uboot":
        found, detail = detect_uboot_http(profile.recovery_ip)
        if found:
            log(f"Recovery HTTP already live at {profile.recovery_ip} ({detail}) — skipping power cycle")
            initial_state = State.UBOOT_UPLOADING
        else:
            initial_state = State.WAITING_FOR_POWER_OFF
    else:
        initial_state = State.WAITING_FOR_POWER_OFF

    ctx = RecoveryContext(
        profile=profile,
        image_path=image_path,
        initramfs_path=initramfs_path,
        interface=interface,
        pcap_path=pcap_path,
        no_upload=args.no_upload,
        no_voice=args.no_voice,
        router_mac_openwrt=args.router_mac,
        router_mac_uboot=args.uboot_mac,
        generated_password=generated_password,
        password_set=password_set,
        auth_type=auth_type,
        wan_ssh_enabled=wan_ssh_enabled,
        force_uboot=args.force_uboot,
        no_pcap=getattr(args, 'no_pcap', False),
        boot_state=boot_state,
        ssh_key_path=ssh_key_path,
        serial_port=args.serial_port or "",
        serial_method=args.serial_method or "",
        serial_baud=args.serial_baud or getattr(profile, 'serial_baud', 115200),
        tftp_root=args.tftp_root or "",
        uboot_commands=getattr(profile, 'uboot_commands', []),
        request_hash=request_metadata.get("request_hash", ""),
        cache_key=request_metadata.get("cache_key", ""),
        packages=request_metadata.get("packages", []),
        defaults_script=request_metadata.get("defaults") or "",
        assume_yes=bool(getattr(args, "yes", False)),
        _say_fn=_say_fn,
        state=initial_state,
    )

    event_queue: queue.Queue = queue.Queue()

    if use_sysupgrade:
        _say_fn(f"Starting {profile.description} sysupgrade recovery.")
        _, _, link_mon, link_thr = _setup_monitors(
            interface, event_queue, pcap_path, profile, args, pcap_enabled=False)
        try:
            rc = _run_state_machine(ctx, event_queue, None, link_mon)
        except KeyboardInterrupt:
            log("Interrupted by user.")
            rc = 1
        finally:
            _teardown_monitors(None, None, link_mon, link_thr)
        return rc

    if is_edgeos_ks and not use_sysupgrade:
        _say_fn(f"Starting {profile.description} edgeos-kernel-swap flash.")
        _, _, link_mon, link_thr = _setup_monitors(
            interface, event_queue, pcap_path, profile, args, pcap_enabled=False)
        try:
            rc = _run_state_machine(ctx, event_queue, None, link_mon)
        except KeyboardInterrupt:
            log("Interrupted by user.")
            rc = 1
        finally:
            _teardown_monitors(None, None, link_mon, link_thr)
        return rc

    if is_extreme_rdwr_tftp and not use_sysupgrade:
        _say_fn(f"Starting {profile.description} extreme stock flash.")
        _, _, link_mon, link_thr = _setup_monitors(
            interface, event_queue, pcap_path, profile, args, pcap_enabled=False)
        try:
            rc = _run_state_machine(ctx, event_queue, None, link_mon)
        except KeyboardInterrupt:
            log("Interrupted by user.")
            rc = 1
        finally:
            _cleanup_extreme_tftp_assets(ctx)
            _teardown_monitors(None, None, link_mon, link_thr)
            openwrt_client_ip = getattr(profile, "openwrt_client_ip", "")
            if openwrt_client_ip and openwrt_client_ip != getattr(profile, "client_ip", ""):
                remove_interface_ip(interface, openwrt_client_ip, "24")
        return rc

    if is_serial_tftp:
        _say_fn(f"Starting {profile.description} serial recovery.")
        if getattr(profile, 'lan_port', ''):
            log(f"IMPORTANT: Connect Ethernet cable to {profile.lan_port} port")
        try:
            rc = _run_state_machine(ctx, event_queue, None, None)
        except KeyboardInterrupt:
            log("Interrupted by user.")
            rc = 1
        finally:
            driver = getattr(ctx, '_serial_driver', None)
            if driver:
                driver.close()
            tftp_mgr = getattr(ctx, '_tftp_manager', None)
            if tftp_mgr:
                tftp_mgr.stop()
        return rc

    if is_zycast:
        _say_fn(f"Starting {profile.description} multicast recovery.")
        log(f"Flash path: zycast multicast ({profile.zycast_multicast_group}:{profile.zycast_multicast_port})")

        pcap_mon, pcap_thr, link_mon, link_thr = _setup_monitors(
            interface, event_queue, pcap_path, profile, args, pcap_enabled=True)

        try:
            rc = _run_state_machine(ctx, event_queue, pcap_mon, link_mon)
        except KeyboardInterrupt:
            log("Interrupted by user.")
            rc = 1
        finally:
            _teardown_monitors(pcap_mon, pcap_thr, link_mon, link_thr)
            zycast_proc = getattr(ctx, '_zycast_proc', None)
            if zycast_proc and zycast_proc.poll() is None:
                zycast_proc.terminate()
        return rc

    _setup_interface_ips(interface, profile)

    pcap_mon, pcap_thr, link_mon, link_thr = _setup_monitors(
        interface, event_queue, pcap_path, profile, args, pcap_enabled=True)

    _say_fn(f"Starting {profile.description} recovery. Listen for instructions.")

    try:
        rc = _run_state_machine(ctx, event_queue, pcap_mon, link_mon)
    except KeyboardInterrupt:
        log("Interrupted by user.")
        rc = 1
    finally:
        _teardown_monitors(pcap_mon, pcap_thr, link_mon, link_thr)

    return rc


def _generate_zyxel_password(serial: str) -> Optional[str]:
    import shutil
    pwgen = shutil.which("zyxel_pwgen")
    if not pwgen:
        return None
    try:
        result = subprocess.run(
            [pwgen, serial],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split("\n")[-1].strip()
    except Exception:
        pass
    return None


def _ssh_with_password(ip: str, user: str, password: str, command: str,
                        timeout: int = 30) -> subprocess.CompletedProcess:
    import shutil
    sshpass = shutil.which("sshpass")
    if not sshpass:
        return subprocess.CompletedProcess(
            args=[], returncode=127,
            stdout="", stderr="sshpass not found. Install with: brew install hudochenkov/sshpass/sshpass",
        )
    cmd = [
        sshpass, "-p", password,
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", f"ConnectTimeout=10",
        f"{user}@{ip}",
        command,
    ]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def _scp_with_password(ip: str, user: str, password: str,
                       remote_src: str, local_dst: str,
                       timeout: int = 120) -> subprocess.CompletedProcess:
    import shutil
    sshpass = shutil.which("sshpass")
    if not sshpass:
        return subprocess.CompletedProcess(
            args=[], returncode=127,
            stdout="", stderr="sshpass not found.",
        )
    cmd = [
        sshpass, "-p", password,
        "scp", "-O",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        f"{user}@{ip}:{remote_src}",
        local_dst,
    ]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def _parse_key_value_lines(output: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def _sanitize_filename_part(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    return cleaned.strip("-._") or "unknown"


def _extreme_tftp_server_ip(profile: SimpleNamespace) -> str:
    return getattr(profile, "openwrt_client_ip", "") or getattr(profile, "client_ip", "") or ""


def _ensure_extreme_backup_dir(ctx: RecoveryContext, preflight_data: Optional[dict] = None) -> Path:
    existing = getattr(ctx, "_extreme_backup_dir", "")
    if existing:
        backup_dir = Path(existing)
        backup_dir.mkdir(parents=True, exist_ok=True)
        return backup_dir

    device_id = "unknown-device"
    if preflight_data:
        for candidate in (
            preflight_data.get("serial", ""),
            preflight_data.get("hostname", ""),
            preflight_data.get("primary_mac", ""),
        ):
            if candidate:
                device_id = _sanitize_filename_part(candidate)
                break
    base = Path(__file__).resolve().parent.parent / "data" / "backups" / ctx.profile.name / device_id
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    backup_dir = base / timestamp
    backup_dir.mkdir(parents=True, exist_ok=True)
    ctx._extreme_backup_dir = str(backup_dir)
    ctx._extreme_device_id = device_id
    return backup_dir


def _extreme_confirm_or_fail(ctx: RecoveryContext, prompt: str) -> bool:
    if ctx.no_upload:
        return True
    if ctx.assume_yes:
        return True
    print()
    try:
        response = input(f"{prompt} [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        log("Cancelled before destructive Extreme flash step.")
        ctx.state = State.FAILED
        return False
    if response not in ("y", "yes"):
        log("Cancelled. Re-run with --yes to allow destructive Extreme flash steps.")
        ctx.state = State.FAILED
        return False
    return True


def _extreme_openwrt_ssh(ctx: RecoveryContext, command: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """SSH to OpenWrt initramfs (root, no password). Uses sshpass for reliability."""
    import shutil

    sshpass = shutil.which("sshpass")
    if not sshpass:
        return subprocess.run(
            ssh_cmd(ctx.profile.openwrt_ip, command, key=ctx.ssh_key_path or None, connect_timeout=10),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    return subprocess.run(
        [
            sshpass,
            "-p",
            "",
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=10",
            f"root@{ctx.profile.openwrt_ip}",
            command,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _extreme_openwrt_scp_from_remote(ctx: RecoveryContext, remote_src: str, local_dst: str,
                                     timeout: int = 120) -> subprocess.CompletedProcess:
    """SCP from OpenWrt initramfs (root, no password)."""
    import shutil

    sshpass = shutil.which("sshpass")
    if not sshpass:
        return subprocess.run(
            scp_cmd(
                ctx.profile.openwrt_ip,
                f"root@{ctx.profile.openwrt_ip}:{remote_src}",
                local_dst,
                key=ctx.ssh_key_path or None,
                connect_timeout=10,
            ),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    return subprocess.run(
        [
            sshpass,
            "-p",
            "",
            "scp",
            "-O",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=10",
            f"root@{ctx.profile.openwrt_ip}:{remote_src}",
            local_dst,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _extreme_openwrt_scp_to_remote(ctx: RecoveryContext, local_src: str, remote_dst: str,
                                    timeout: int = 120) -> subprocess.CompletedProcess:
    """SCP to OpenWrt initramfs (root, no password)."""
    import shutil

    sshpass = shutil.which("sshpass")
    if not sshpass:
        return subprocess.run(
            scp_cmd(
                ctx.profile.openwrt_ip,
                local_src,
                f"root@{ctx.profile.openwrt_ip}:{remote_dst}",
                key=ctx.ssh_key_path or None,
                connect_timeout=10,
            ),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    return subprocess.run(
        [
            sshpass,
            "-p",
            "",
            "scp",
            "-O",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=10",
            local_src,
            f"root@{ctx.profile.openwrt_ip}:{remote_dst}",
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _write_json_file(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def _prepare_extreme_tftp_root(ctx: RecoveryContext) -> tuple[Optional[Path], Optional[Path]]:
    initramfs_path = ctx.initramfs_path
    if not initramfs_path or not os.path.isfile(initramfs_path):
        log(f"ERROR: initramfs image not found: {initramfs_path}")
        return None, None

    temp_root = Path(tempfile.mkdtemp(prefix="conwrt-extreme-tftp-"))
    primary_name = ctx.profile.initramfs_tftp_name
    primary_path = temp_root / primary_name
    try:
        os.symlink(os.path.abspath(initramfs_path), primary_path)
    except OSError:
        shutil.copy2(initramfs_path, primary_path)

    alt_name = getattr(ctx.profile, "optional_alt_tftp_name", "")
    if alt_name and alt_name != primary_name:
        alt_path = temp_root / alt_name
        try:
            os.symlink(os.path.abspath(initramfs_path), alt_path)
        except OSError:
            shutil.copy2(initramfs_path, alt_path)

    return temp_root, primary_path


def _cleanup_extreme_tftp_assets(ctx: RecoveryContext) -> None:
    tftp_mgr = getattr(ctx, "_extreme_tftp_manager", None)
    if tftp_mgr:
        tftp_mgr.stop()
        ctx._extreme_tftp_manager = None
    tftp_root = getattr(ctx, "_extreme_tftp_root", "")
    if tftp_root:
        shutil.rmtree(tftp_root, ignore_errors=True)
        ctx._extreme_tftp_root = ""


def _handle_extreme_stock_preflight(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    profile = ctx.profile
    stock_ip = profile.stock_default_ip
    stock_user = profile.stock_default_user
    stock_password = profile.stock_default_password

    if not _extreme_confirm_or_fail(ctx, "Extreme flash will modify U-Boot variables and reboot the AP. Continue?"):
        return

    import shutil as _shutil_dep

    missing_deps = []
    if not _shutil_dep.which("sshpass"):
        missing_deps.append("sshpass (required for stock firmware SSH and initramfs access)")
    if not ctx.initramfs_path or not os.path.isfile(ctx.initramfs_path):
        missing_deps.append(f"initramfs image not found: {ctx.initramfs_path}")
    if not ctx.image_path or not os.path.isfile(ctx.image_path):
        missing_deps.append(f"sysupgrade image not found: {ctx.image_path}")
    if missing_deps:
        for dep in missing_deps:
            log(f"MISSING: {dep}")
        log("Cannot proceed without required dependencies.")
        ctx.state = State.FAILED
        return

    which_result = _ssh_with_password(
        stock_ip,
        stock_user,
        stock_password,
        f"which {shlex.quote(profile.rdwr_boot_cfg_binary)}",
        timeout=15,
    )
    if which_result.returncode != 0:
        log(f"ERROR: {profile.rdwr_boot_cfg_binary} not found on stock firmware: {which_result.stderr[:300]}")
        ctx.state = State.FAILED
        return

    read_all_result = _ssh_with_password(
        stock_ip,
        stock_user,
        stock_password,
        f"{shlex.quote(profile.rdwr_boot_cfg_binary)} read_all",
        timeout=30,
    )
    if read_all_result.returncode != 0 or not read_all_result.stdout.strip():
        log(f"ERROR: rdwr_boot_cfg read_all failed: {(read_all_result.stderr or read_all_result.stdout)[:400]}")
        ctx.state = State.FAILED
        return

    info_commands = {
        "hostname": "hostname",
        "mac_addresses": "for f in /sys/class/net/*/address; do printf '%s=%s\\n' $(basename $(dirname \"$f\")) $(cat \"$f\" 2>/dev/null); done",
        "serial": "cat /sys/devices/platform/qca-ssdk.0/serial_number 2>/dev/null || cat /proc/device-tree/serial-number 2>/dev/null || getserialno 2>/dev/null || echo ''",
        "firmware_version": "cat /etc/version 2>/dev/null || cat /etc/banner 2>/dev/null || echo ''",
        "uname": "uname -a",
        "mount": "mount",
        "proc_mtd": "cat /proc/mtd",
        "dmesg_tail": "dmesg | tail -n 200",
    }
    collected: dict[str, str] = {}
    for name, command in info_commands.items():
        result = _ssh_with_password(stock_ip, stock_user, stock_password, command, timeout=30)
        collected[name] = (result.stdout or "").strip()

    mac_lines = _parse_key_value_lines(collected.get("mac_addresses", ""))
    preflight_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "stock_ip": stock_ip,
        "hostname": collected.get("hostname", "").strip(),
        "serial": collected.get("serial", "").strip(),
        "primary_mac": next(iter(mac_lines.values()), ""),
        "mac_addresses": mac_lines,
        "firmware_version": collected.get("firmware_version", "").strip(),
        "uname": collected.get("uname", "").strip(),
        "mount": collected.get("mount", ""),
        "proc_mtd": collected.get("proc_mtd", ""),
        "dmesg_tail": collected.get("dmesg_tail", ""),
        "rdwr_boot_cfg_read_all": read_all_result.stdout,
        "initramfs_path": ctx.initramfs_path,
    }
    backup_dir = _ensure_extreme_backup_dir(ctx, preflight_data)
    _write_json_file(backup_dir / "preflight.json", preflight_data)
    event_queue.put((Event.EXTREME_UBOOT_ENV_SAVED, ts(), str(backup_dir / "preflight.json")))

    if ctx.no_upload:
        log("DRY RUN: Extreme stock firmware reachable and preflight data saved.")
        log(f"  Backup dir: {backup_dir}")
        log(f"  Initramfs:  {ctx.initramfs_path}")
        log(f"  Sysupgrade: {ctx.image_path}")
        ctx.state = State.COMPLETE
        return

    _setup_interface_ips(ctx.interface, profile)
    tftp_ip = _extreme_tftp_server_ip(profile)
    if not tftp_ip:
        log("ERROR: No local TFTP server IP configured in profile.")
        ctx.state = State.FAILED
        return
    if not configure_interface_ip(ctx.interface, tftp_ip, "24"):
        log(f"ERROR: failed to configure {tftp_ip}/24 on {ctx.interface}")
        ctx.state = State.FAILED
        return

    for disable_cmd in getattr(profile, "stock_ssh_timeout_disable_commands", []):
        result = _ssh_with_password(stock_ip, stock_user, stock_password, disable_cmd, timeout=20)
        if result.returncode != 0:
            log(f"ERROR: failed to run stock timeout-disable command '{disable_cmd}': {result.stderr[:300]}")
            ctx.state = State.FAILED
            return

    tftp_root, _ = _prepare_extreme_tftp_root(ctx)
    if tftp_root is None:
        ctx.state = State.FAILED
        return
    tftp_mgr = TFTPServerManager(str(tftp_root), bind_ip=tftp_ip)
    if not tftp_mgr.start():
        shutil.rmtree(tftp_root, ignore_errors=True)
        ctx.state = State.FAILED
        return
    tftp_test_file = tftp_root / profile.initramfs_tftp_name
    if not tftp_test_file.exists():
        log(f"ERROR: TFTP root does not contain {profile.initramfs_tftp_name}")
        log(f"  TFTP root contents: {list(tftp_root.iterdir()) if tftp_root.exists() else '(missing)'}")
        tftp_mgr.stop()
        shutil.rmtree(tftp_root, ignore_errors=True)
        ctx.state = State.FAILED
        return
    log(f"TFTP verified: {profile.initramfs_tftp_name} ({tftp_test_file.stat().st_size} bytes)")
    ctx._extreme_tftp_manager = tftp_mgr
    ctx._extreme_tftp_root = str(tftp_root)
    event_queue.put((Event.EXTREME_TFTP_INITRAMFS_READY, ts(), tftp_ip))
    log(f"Extreme preflight complete. TFTP serving {profile.initramfs_tftp_name} from {tftp_ip}.")
    ctx.state = State.EXTREME_STOCK_WRITING_UBOOT


def _handle_extreme_stock_writing_uboot(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    profile = ctx.profile
    stock_ip = profile.stock_default_ip
    stock_user = profile.stock_default_user
    stock_password = profile.stock_default_password
    tftp_ip = _extreme_tftp_server_ip(profile)
    ap_ip = profile.stock_default_ip

    if not _extreme_confirm_or_fail(ctx, "Write temporary Extreme U-Boot variables now?"):
        return

    vars_to_write: dict[str, str] = {}
    for key, value in profile.required_uboot_vars.items():
        resolved = value
        if value == "<CONWRT_TFTP_SERVER_IP>":
            resolved = tftp_ip
        elif value == "<TEMP_AP_IP>":
            resolved = ap_ip
        vars_to_write[key] = resolved

    log("WARNING: Stock firmware reboots every ~5 minutes without a controller.")
    log("Writing all U-Boot variables in a single batch to minimize time window.")
    log("If the AP reboots during this step, serial console may be required for recovery.")
    write_commands = []
    for key, value in vars_to_write.items():
        write_commands.append(f"{shlex.quote(profile.rdwr_boot_cfg_binary)} write_var {shlex.quote(f'{key}={value}')}")
    batch_script = " && ".join(write_commands)
    log(f"Writing {len(vars_to_write)} U-Boot variables in single batch...")
    batch_result = _ssh_with_password(stock_ip, stock_user, stock_password, batch_script, timeout=30)
    if batch_result.returncode != 0:
        log(f"ERROR: batch write_var failed: {batch_result.stderr[:500]}")
        ctx.state = State.FAILED
        return

    verify_result = _ssh_with_password(
        stock_ip,
        stock_user,
        stock_password,
        f"{shlex.quote(profile.rdwr_boot_cfg_binary)} read_all",
        timeout=20,
    )
    parsed = _parse_key_value_lines((verify_result.stdout or "") + "\n" + (verify_result.stderr or ""))
    for key, value in vars_to_write.items():
        if parsed.get(key) != value:
            log(f"ERROR: verification failed for {key}: expected {value!r}, got {parsed.get(key)!r}")
            ctx.state = State.FAILED
            return
        log(f"Verified stock U-Boot var {key}={value}")

    ctx.state = State.EXTREME_STOCK_REBOOTING


def _handle_extreme_stock_rebooting(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    profile = ctx.profile
    log("Rebooting AP to TFTP boot OpenWrt initramfs...")
    try:
        _ssh_with_password(
            profile.stock_default_ip,
            profile.stock_default_user,
            profile.stock_default_password,
            "reboot",
            timeout=10,
        )
    except Exception:
        pass
    ctx._say_fn("AP rebooting. Waiting for OpenWrt initramfs. This takes about 90 seconds.")
    time.sleep(10)
    ctx.state = State.EXTREME_OPENWRT_INITRAMFS_WAITING


def _handle_extreme_openwrt_initramfs_waiting(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    openwrt_ip = ctx.profile.openwrt_ip
    timeout = ctx.profile.flash_time_seconds
    start = ts()
    while ts() - start < timeout:
        if check_ssh(openwrt_ip):
            verify = _extreme_openwrt_ssh(ctx, "test -f /etc/openwrt_release && cat /proc/mtd", timeout=20)
            if verify.returncode == 0:
                ctx.timeline.ssh_available = ts()
                log(f"SSH available at {openwrt_ip} — OpenWrt initramfs booted.")
                ctx._say_fn("OpenWrt initramfs booted. Starting backup.")
                ctx.state = State.EXTREME_OPENWRT_BACKUP
                return
        time.sleep(5)
    log(f"FAIL: OpenWrt initramfs SSH not available at {openwrt_ip} after {timeout}s.")
    ctx.state = State.FAILED


def _handle_extreme_openwrt_backup(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    backup_dir = _ensure_extreme_backup_dir(ctx)
    info_result = _extreme_openwrt_ssh(ctx, "cat /proc/mtd", timeout=20)
    if info_result.returncode != 0 or not info_result.stdout.strip():
        log(f"ERROR: failed to read /proc/mtd from initramfs: {info_result.stderr[:300]}")
        ctx.state = State.FAILED
        return

    mtd_parts: list[tuple[str, str]] = []
    for line in info_result.stdout.splitlines():
        match = re.match(r"^(mtd\d+):\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+\"([^\"]+)\"", line.strip())
        if match:
            mtd_parts.append((match.group(1), _sanitize_filename_part(match.group(2))))

    commands = [
        "rm -rf /tmp/conwrt-backup /tmp/conwrt-backup.tar.gz",
        "mkdir -p /tmp/conwrt-backup",
        "cat /proc/mtd > /tmp/conwrt-backup/proc_mtd.txt",
        "dmesg > /tmp/conwrt-backup/dmesg.txt",
        "mount > /tmp/conwrt-backup/mount.txt",
        "ubus call system board > /tmp/conwrt-backup/system_board.json 2>/dev/null || true",
        "fw_printenv > /tmp/conwrt-backup/fw_printenv.txt 2>/dev/null || true",
    ]
    for mtd_name, label in mtd_parts:
        commands.append(
            f"dd if=/dev/{mtd_name} of=/tmp/conwrt-backup/{mtd_name}_{label}.bin bs=64k"
        )
    commands.extend([
        "(cd /tmp/conwrt-backup && sha256sum * > SHA256SUMS.txt)",
        "tar czf /tmp/conwrt-backup.tar.gz -C /tmp conwrt-backup",
    ])
    script = "set -e; " + "; ".join(commands)
    backup_result = _extreme_openwrt_ssh(ctx, script, timeout=max(120, len(mtd_parts) * 45))
    if backup_result.returncode != 0:
        log(f"ERROR: failed creating Extreme backup on initramfs: {(backup_result.stderr or backup_result.stdout)[:500]}")
        ctx.state = State.FAILED
        return

    local_tar = backup_dir / "conwrt-backup.tar.gz"
    scp_result = _extreme_openwrt_scp_from_remote(ctx, "/tmp/conwrt-backup.tar.gz", str(local_tar), timeout=180)
    if scp_result.returncode != 0:
        log(f"ERROR: failed downloading Extreme backup tarball: {scp_result.stderr[:300]}")
        ctx.state = State.FAILED
        return
    if not local_tar.is_file() or local_tar.stat().st_size == 0:
        log(f"ERROR: local backup tarball missing or empty: {local_tar}")
        ctx.state = State.FAILED
        return

    extracted_dir = backup_dir / "files"
    extracted_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(local_tar, "r:gz") as tar:
        tar.extractall(extracted_dir)

    extracted_root = extracted_dir / "conwrt-backup"
    hashes: dict[str, str] = {}
    sha_file = extracted_root / "SHA256SUMS.txt"
    if sha_file.is_file():
        for line in sha_file.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                hashes[parts[1].lstrip("*./")] = parts[0]
    _write_json_file(
        backup_dir / "backup-manifest.json",
        {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "tarball": str(local_tar),
            "tarball_sha256": sha256_file(str(local_tar)),
            "hashes": hashes,
            "mtd_partitions": [mtd for mtd, _ in mtd_parts],
        },
    )
    event_queue.put((Event.EXTREME_BACKUP_COMPLETE, ts(), str(local_tar)))
    ctx.state = State.EXTREME_BOOTCMD_RESTORE


def _handle_extreme_bootcmd_restore(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    profile = ctx.profile
    have_fw_setenv = _extreme_openwrt_ssh(ctx, "which fw_setenv && which fw_printenv", timeout=15)
    have_fw_env_config = _extreme_openwrt_ssh(ctx, "test -f /etc/fw_env.config", timeout=10)
    restored = False

    if have_fw_setenv.returncode == 0 and have_fw_env_config.returncode == 0:
        restored = True
        for key, value in profile.final_uboot_vars.items():
            set_result = _extreme_openwrt_ssh(ctx, f"fw_setenv {shlex.quote(key)} {shlex.quote(value)}", timeout=20)
            if set_result.returncode != 0:
                log(f"ERROR: fw_setenv failed for {key}: {set_result.stderr[:300]}")
                restored = False
                break
            verify_result = _extreme_openwrt_ssh(ctx, f"fw_printenv {shlex.quote(key)}", timeout=15)
            parsed = _parse_key_value_lines(verify_result.stdout or "")
            if parsed.get(key) != value:
                log(f"ERROR: fw_printenv verification failed for {key}: expected {value!r}, got {parsed.get(key)!r}")
                restored = False
                break
            log(f"Restored final U-Boot var {key}={value}")

    if restored:
        event_queue.put((Event.EXTREME_BOOTCMD_RESTORED, ts(), "fw_setenv"))
        _cleanup_extreme_tftp_assets(ctx)
    else:
        log("WARNING: could not safely restore bootcmd via fw_setenv. Extreme TFTP detour fallback will be required if the AP keeps booting from network.")

    ctx.state = State.EXTREME_SYSUPGRADE_UPLOADING


def _handle_extreme_sysupgrade_uploading(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    image_path = ctx.image_path
    if not image_path or not os.path.isfile(image_path):
        log(f"ERROR: sysupgrade image not found: {image_path}")
        ctx.state = State.FAILED
        return

    remote_name = os.path.basename(image_path)
    remote_path = f"/tmp/{remote_name}"
    size_mb = os.path.getsize(image_path) / 1024 / 1024
    ctx.timeline.upload_start = ts()
    if not ctx.sha256_before:
        ctx.sha256_before = sha256_file(image_path)
    log(f"Uploading sysupgrade ({size_mb:.1f} MB) to initramfs at {ctx.profile.openwrt_ip}...")
    scp_result = _extreme_openwrt_scp_to_remote(ctx, image_path, remote_path, timeout=180)
    if scp_result.returncode != 0:
        log(f"ERROR: SCP to initramfs failed: {scp_result.stderr[:300]}")
        ctx.state = State.FAILED
        return

    verify_result = _extreme_openwrt_ssh(
        ctx,
        f"test -s {shlex.quote(remote_path)} && sha256sum {shlex.quote(remote_path)}",
        timeout=30,
    )
    if verify_result.returncode != 0 or not verify_result.stdout.strip():
        log(f"ERROR: remote sysupgrade verification failed: {(verify_result.stderr or verify_result.stdout)[:300]}")
        ctx.state = State.FAILED
        return
    remote_hash = verify_result.stdout.strip().split()[0]
    log(f"Remote SHA-256: {remote_hash}")
    ctx.timeline.upload_complete = ts()
    ctx.state = State.EXTREME_SYSUPGRADE_FLASHING


def _handle_extreme_sysupgrade_flashing(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    remote_name = os.path.basename(ctx.image_path)
    remote_path = f"/tmp/{remote_name}"
    ctx._say_fn("Flashing firmware. Do not unplug.")
    log("Running sysupgrade -n from OpenWrt initramfs...")
    try:
        result = _extreme_openwrt_ssh(ctx, f"sysupgrade -n {shlex.quote(remote_path)}", timeout=60)
        combined = (result.stdout or "") + (result.stderr or "")
        if result.returncode == 0 or "Commencing upgrade" in combined or "Rebooting system" in combined:
            log("Extreme sysupgrade initiated successfully.")
        elif result.returncode != 0 and not result.stdout and not result.stderr:
            log("Extreme sysupgrade initiated (connection closed by remote — expected).")
        else:
            log(f"Extreme sysupgrade output (exit {result.returncode}): {combined[:500]}")
    except subprocess.TimeoutExpired:
        log("Extreme sysupgrade command timed out (may have started reboot).")
    ctx.timeline.flash_triggered = ts()
    _cleanup_extreme_tftp_assets(ctx)
    ctx.state = State.OPENWRT_BOOTING


def cmd_backup(args: argparse.Namespace) -> int:
    model = load_model(args.model_id)
    backup_config = model.get("backup", {})
    partition_layout = model.get("partition_layout", {})

    if not backup_config.get("method") == "ssh":
        print(f"ERROR: Model '{args.model_id}' does not support SSH backup.", file=sys.stderr)
        return 1

    password = args.password
    serial = args.serial

    if not password and serial:
        password = _generate_zyxel_password(serial)
        if password:
            log(f"Generated stock SSH password from serial {serial}")
        else:
            print("ERROR: --serial provided but zyxel_pwgen not found.", file=sys.stderr)
            print("  Install zyxel_pwgen or use --password to provide the password manually.", file=sys.stderr)
            return 1

    if not password:
        print("ERROR: Provide --serial (for auto password generation) or --password.", file=sys.stderr)
        return 1

    ip = args.ip
    user = args.user

    log(f"Connecting to {user}@{ip} (stock firmware SSH)...")

    list_result = _ssh_with_password(ip, user, password, "cat /proc/mtd", timeout=15)
    if list_result.returncode != 0:
        print(f"ERROR: SSH connection failed: {list_result.stderr.strip()}", file=sys.stderr)
        if "sshpass not found" in list_result.stderr:
            print("  Install sshpass: brew install hudochenkov/sshpass/sshpass", file=sys.stderr)
        return 1

    mtd_output = list_result.stdout.strip()
    if not mtd_output:
        print("ERROR: No MTD partitions found on device.", file=sys.stderr)
        return 1

    mtd_partitions = []
    for line in mtd_output.split("\n"):
        parts = line.split()
        if len(parts) >= 3:
            mtd_name = parts[0]
            mtd_size = parts[1]
            mtd_label = parts[2].strip('"')
            mtd_index = mtd_name.replace("mtd", "").replace(":", "")
            mtd_partitions.append({
                "index": mtd_index,
                "name": mtd_name.rstrip(":"),
                "size": mtd_size,
                "label": mtd_label,
                "device": f"/dev/{mtd_name.rstrip(':')}",
            })

    if args.partitions:
        requested = set(args.partitions.split(","))
        mtd_partitions = [p for p in mtd_partitions if p["index"] in requested]

    critical_names = set(backup_config.get("critical_partitions", []))

    output_dir = args.output_dir
    if not output_dir:
        base_dir = Path(__file__).resolve().parent.parent / "data" / "backups"
        device_id = serial or model.get("id", "unknown")
        output_dir = str(base_dir / device_id)

    os.makedirs(output_dir, exist_ok=True)
    log(f"Backing up {len(mtd_partitions)} MTD partitions to {output_dir}")

    print()
    print(f"{'MTD':<10s} {'Label':<15s} {'Size':<12s} {'Critical':<10s} {'Status'}")
    print("-" * 70)

    failed = []
    for part in mtd_partitions:
        label = part["label"]
        is_critical = label in critical_names
        critical_str = "*** YES ***" if is_critical else ""
        local_path = os.path.join(output_dir, f"mtd{part['index']}_{label}.bin")
        remote_path = f"/tmp/mtd{part['index']}.bin"

        dump_cmd = f"nanddump -f {remote_path} {part['device']}"
        if is_critical:
            log(f"Dumping CRITICAL partition {part['name']} ({label})...")

        dump_result = _ssh_with_password(ip, user, password, dump_cmd, timeout=60)
        if dump_result.returncode != 0:
            print(f"{part['name']:<10s} {label:<15s} {part['size']:<12s} {critical_str:<10s} FAILED (nanddump)")
            if dump_result.stderr:
                log(f"  nanddump error: {dump_result.stderr[:200]}")
            failed.append(part)
            continue

        scp_result = _scp_with_password(ip, user, password, remote_path, local_path, timeout=120)
        if scp_result.returncode != 0:
            print(f"{part['name']:<10s} {label:<15s} {part['size']:<12s} {critical_str:<10s} FAILED (scp)")
            if scp_result.stderr:
                log(f"  scp error: {scp_result.stderr[:200]}")
            failed.append(part)
            continue

        file_size = os.path.getsize(local_path)
        print(f"{part['name']:<10s} {label:<15s} {part['size']:<12s} {critical_str:<10s} OK ({file_size} bytes)")

        _ssh_with_password(ip, user, password, f"rm -f {remote_path}", timeout=10)

    print()
    if failed:
        log(f"WARNING: {len(failed)} partition(s) failed to backup:")
        for p in failed:
            log(f"  mtd{p['index']} ({p['label']})")
    else:
        log(f"All {len(mtd_partitions)} partitions backed up successfully to {output_dir}")

    if critical_names:
        missing_critical = critical_names - {p["label"] for p in mtd_partitions if p not in failed}
        if missing_critical:
            log(f"WARNING: Critical partitions NOT backed up: {missing_critical}")
            log("DO NOT flash this device until these partitions are backed up!")
            return 1

    return 1 if failed else 0


def cmd_auto(args: argparse.Namespace) -> int:
    from auto_detect import auto_detect, interactive_menu

    interface = args.interface or auto_detect_interface()
    if not interface:
        print("ERROR: no active ethernet interface found. Use --interface.", file=sys.stderr)
        return 1

    print(f"Auto-detecting routers on {interface}...")
    print()

    routers = auto_detect(interface, passive_timeout=args.passive_timeout)

    if not routers:
        print("No routers detected. Check that:")
        print("  - Ethernet cable is connected")
        print("  - Router is powered on")
        print("  - Interface is correct (use --interface)")
        return 1

    if args.no_menu:
        for r in routers:
            print(f"  IP: {r.ip}  MAC: {r.mac}  Vendor: {r.vendor}  "
                  f"Model: {r.model_name or '?'}  State: {r.firmware_state}  "
                  f"Confidence: {r.confidence}")
        return 0

    interactive_menu(routers)
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] not in (
        "flash", "list", "list-use-cases", "cache", "setup-mgmt-wifi", "backup",
        "auto", "setup-nor-recovery", "configure", "profile", "-h", "--help",
    ):
        sys.argv.insert(1, "flash")

    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "list":
        return cmd_list(args)
    elif args.command == "list-use-cases":
        return cmd_list_use_cases(args)
    elif args.command == "cache":
        return cmd_cache(args)
    elif args.command == "setup-mgmt-wifi":
        return cmd_setup_mgmt_wifi(args)
    elif args.command == "configure":
        return cmd_configure(args)
    elif args.command == "profile":
        if getattr(args, "profile_command", None) == "plan":
            return cmd_profile_plan(args)
        _build_parser().print_help(sys.stderr)
        return 1
    elif args.command == "backup":
        return cmd_backup(args)
    elif args.command == "auto":
        return cmd_auto(args)
    elif args.command == "setup-nor-recovery":
        return cmd_setup_nor_recovery(args)
    else:
        return cmd_flash(args)


if __name__ == "__main__":
    sys.exit(main())
