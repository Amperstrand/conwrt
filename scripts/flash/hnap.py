"""D-Link HNAP firmware-upload flash method.

Self-contained implementation of the D-Link HNAP SOAP API used to push
firmware to stock D-Link routers (e.g. COVR-X1860). Includes the vendor's
simplified AES-128 (no MixColumns) used for the HNAP_CONTENT header and the
3-step HMAC-MD5 challenge-response login.

Extracted verbatim from conwrt.py to keep the CLI module focused; behavior is
unchanged. The only external dependency is flash.context.log.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from types import SimpleNamespace
from typing import Optional

from flash.context import log

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
