#!/usr/bin/env python3
"""Change the stock GS1900-8HP switch management IP via the web UI.

Handles the V2.90 mandatory password change flow: if the password is still
the default '1234', changes it first, then proceeds to IP configuration.

Usage:
    python3 scripts/change-stock-ip.py --ip 192.168.1.1 --new-ip 192.168.13.3
    python3 scripts/change-stock-ip.py --ip 192.168.1.1 --new-ip 192.168.13.3 --gateway 192.168.13.1
"""
import argparse
import os
import re
import subprocess
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))
from flash.oem_handlers import oem_http_login, zyxel_encode_password

PASSWORD_CHANGE_CMD = 30
PASSWORD_SUBMIT_CMD = 31
IP_CONFIG_CMD = 516
IP_SUBMIT_CMD = 517


def _curl_get(url: str, cookie: str, max_time: int = 10) -> str:
    r = subprocess.run(
        ["curl", "-s", "--max-time", str(max_time), "-b", cookie, url],
        capture_output=True, text=True, timeout=max_time + 5, check=False,
    )
    return r.stdout


def _curl_post(url: str, data: str, cookie: str, max_time: int = 15) -> str:
    r = subprocess.run(
        ["curl", "-s", "--max-time", str(max_time), "-L",
         "-b", cookie, "-X", "POST", "-d", data, url],
        capture_output=True, text=True, timeout=max_time + 5, check=False,
    )
    return r.stdout


def _extract_xssid(html: str) -> str:
    for pattern in [
        r'name=["\']XSSID["\'][^>]*value=["\']([^"\']+)["\']',
        r'value=["\']([^"\']+)["\'][^>]*name=["\']XSSID["\']',
    ]:
        m = re.search(pattern, html)
        if m:
            return m.group(1)
    return ""


def _extract_form_fields(html: str) -> dict:
    fields = {}
    for match in re.finditer(r'<input[^>]+>', html, re.IGNORECASE):
        tag = match.group(0)
        name_match = re.search(r'name=["\']([^"\']+)["\']', tag)
        value_match = re.search(r'value=["\']([^"\']*)["\']', tag)
        type_match = re.search(r'type=["\']([^"\']+)["\']', tag)
        if name_match and name_match.group(1) not in fields:
            input_type = type_match.group(1) if type_match else "text"
            if input_type in ("text", "password", "radio", "checkbox", "hidden"):
                fields[name_match.group(1)] = value_match.group(1) if value_match else ""
    return fields


def _is_redirect(html: str, target_cmd: int) -> bool:
    redirect = re.search(r'location\.replace\("[^"]*cmd=(\d+)"\)', html)
    if redirect and redirect.group(1) != str(target_cmd):
        return True
    if len(html) < 800 and "cmd=0" in html[:500]:
        return True
    return False


def change_password(stock_ip: str, cookie: str, old_password: str, new_password: str) -> bool:
    dispatcher = f"http://{stock_ip}/cgi-bin/dispatcher.cgi"
    print(f"  Fetching password change page (cmd={PASSWORD_CHANGE_CMD})...")
    html = _curl_get(f"{dispatcher}?cmd={PASSWORD_CHANGE_CMD}", cookie)

    if _is_redirect(html, PASSWORD_CHANGE_CMD):
        print("  Session expired during password change")
        return False

    xssid = _extract_xssid(html)
    fields = _extract_form_fields(html)
    print(f"  Form fields: {list(fields.keys())}")
    print(f"  XSSID: {xssid[:20]}..." if xssid else "  XSSID: (not found)")

    encoded_old = zyxel_encode_password(old_password)
    encoded_new = zyxel_encode_password(new_password)
    print(f"  Encoded old: {len(encoded_old)} chars, new: {len(encoded_new)} chars")

    # V2.90 fields: usrOldPass/usrPass/usrPass2 (encoded), usrPassEncode=1
    post_fields = {k: v for k, v in fields.items() if k in ("XSSID", "cmd", "usrName")}
    post_fields["XSSID"] = xssid
    post_fields["cmd"] = str(PASSWORD_SUBMIT_CMD)
    post_fields["usrOldPass"] = encoded_old
    post_fields["usrPass"] = encoded_new
    post_fields["usrPass2"] = encoded_new
    post_fields["usrPassEncode"] = "1"

    post_body = "&".join(f"{k}={urllib.parse.quote_plus(v)}" for k, v in post_fields.items())
    print(f"  Submitting password change...")

    result = _curl_post(dispatcher, post_body, cookie)
    print(f"  Response: {len(result)} bytes, preview: {result[:200]}")

    if "error" in result.lower() and "cmd=5" not in result.lower():
        return False

    return True


def change_ip(stock_ip: str, username: str, password: str,
              new_ip: str, new_mask: str = "255.255.255.0",
              gateway: str = "", new_password: str = "") -> bool:
    dispatcher = f"http://{stock_ip}/cgi-bin/dispatcher.cgi"

    print(f"[1/6] Logging in to {stock_ip}...")
    success, cookie = oem_http_login(stock_ip, username, password)
    if not success:
        print(f"ERROR: Login failed: {cookie}")
        return False
    if not cookie:
        cookie = ""

    print(f"[2/6] Checking if mandatory password change is needed...")
    html = _curl_get(f"{dispatcher}?cmd={IP_CONFIG_CMD}", cookie)
    effective_password = password

    if _is_redirect(html, IP_CONFIG_CMD):
        redirect_match = re.search(r'cmd=(\d+)', html)
        redirect_cmd = redirect_match.group(1) if redirect_match else "?"

        if redirect_cmd == str(PASSWORD_CHANGE_CMD) or "cmd=30" in html:
            pw_to_set = new_password if new_password else "Conwrt2026!"
            print(f"  V2.90 mandatory password change detected. Changing to '{pw_to_set}'...")
            if not change_password(stock_ip, cookie, password, pw_to_set):
                print("ERROR: Password change failed")
                return False
            effective_password = pw_to_set
            time.sleep(2)

            print(f"[3/6] Re-logging in with new password...")
            success, cookie = oem_http_login(stock_ip, username, effective_password)
            if not success:
                print(f"ERROR: Re-login failed after password change: {cookie}")
                return False
            html = ""
        elif redirect_cmd == "0":
            print("ERROR: Session expired immediately after login")
            return False
        else:
            print(f"  Unexpected redirect to cmd={redirect_cmd}")
    else:
        print("  No password change required")
        print(f"[3/6] Skipping (password already set)")

    print(f"[4/6] Fetching IP config page (cmd={IP_CONFIG_CMD})...")
    if not html or len(html) < 200 or _is_redirect(html, IP_CONFIG_CMD):
        html = _curl_get(f"{dispatcher}?cmd={IP_CONFIG_CMD}", cookie)

    if not html or len(html) < 200:
        print(f"ERROR: Empty response from cmd={IP_CONFIG_CMD}")
        return False
    if _is_redirect(html, IP_CONFIG_CMD):
        print(f"ERROR: Still redirected after login. Response: {html[:500]}")
        return False

    print(f"  Page size: {len(html)} bytes")
    fields = _extract_form_fields(html)
    print(f"  Form fields: {list(fields.keys())}")

    # Find IP address field
    ip_field = None
    for candidate in ["sysIpAddr", "ipAddr", "IPAddr", "sysIpAddress", "ipAddress",
                       "sysIp", "SystemIP", "sysIP", "IP"]:
        if candidate in fields:
            ip_field = candidate
            break
    if not ip_field:
        ip_named = [f for f in fields if any(kw in f.lower() for kw in ("ip", "addr"))]
        if ip_named:
            ip_field = ip_named[0]

    if not ip_field:
        print(f"\nERROR: Could not find IP address field in form.")
        form_match = re.search(r'<form[^>]*>.*?</form>', html, re.DOTALL | re.IGNORECASE)
        print(form_match.group(0)[:3000] if form_match else html[:3000])
        return False

    current_ip = fields.get(ip_field, "(unknown)")
    print(f"  IP field: {ip_field} = {current_ip}")

    fields[ip_field] = new_ip

    for candidate in ["sysSubnet", "subnetMask", "SubnetMask", "sysSubnetMask",
                       "sysIpSubnet", "ipSubnet", "sysSubnetMaskIp"]:
        if candidate in fields:
            fields[candidate] = new_mask
            print(f"  Mask field: {candidate} = {new_mask}")
            break

    if gateway:
        for candidate in ["sysGateway", "gateway", "Gateway", "sysGatewayIp",
                           "defaultGateway", "defGateway"]:
            if candidate in fields:
                fields[candidate] = gateway
                print(f"  Gateway field: {candidate} = {gateway}")
                break

    xssid = _extract_xssid(html)
    if xssid:
        fields["XSSID"] = xssid
    fields["cmd"] = str(IP_SUBMIT_CMD)
    fields["sysSubmit"] = "Apply"

    post_body = "&".join(f"{k}={urllib.parse.quote_plus(v)}" for k, v in fields.items())

    print(f"[5/6] Submitting IP change: {current_ip} → {new_ip}/{new_mask}")
    if gateway:
        print(f"  Gateway: {gateway}")

    result = _curl_post(dispatcher, post_body, cookie)
    print(f"  Response: {len(result)} bytes")

    if "cmd=4" in result or "save" in result.lower() or len(result) > 1000:
        print(f"[6/6] IP change submitted. Waiting for switch to apply...")
        time.sleep(5)

        print(f"  Testing connectivity at {new_ip}...")
        for attempt in range(8):
            r_test = subprocess.run(
                ["curl", "-s", "--max-time", "5",
                 f"http://{new_ip}/cgi-bin/dispatcher.cgi?cmd=5"],
                capture_output=True, text=True, timeout=8, check=False,
            )
            if r_test.stdout and len(r_test.stdout) > 100:
                print(f"  Switch is responding at {new_ip}!")
                return True
            time.sleep(3)

        print(f"  Switch not responding at {new_ip} yet (may need manual check)")
        return True

    print(f"ERROR: Unexpected response")
    print(f"  {result[:500]}")
    return False


def main():
    parser = argparse.ArgumentParser(
        description="Change stock GS1900-8HP management IP via web UI",
    )
    parser.add_argument("--ip", default="192.168.1.1",
                        help="Current switch IP (default: 192.168.1.1)")
    parser.add_argument("--new-ip", default="192.168.13.3",
                        help="New management IP (default: 192.168.13.3)")
    parser.add_argument("--mask", default="255.255.255.0",
                        help="Subnet mask (default: 255.255.255.0)")
    parser.add_argument("--gateway", default="",
                        help="Default gateway (e.g. 192.168.13.1)")
    parser.add_argument("--username", default="admin",
                        help="Web UI username (default: admin)")
    parser.add_argument("--password", default="1234",
                        help="Current web UI password (default: 1234)")
    parser.add_argument("--new-password", default="Conwrt2026!",
                        help="New password if mandatory change required (default: Conwrt2026!)")
    args = parser.parse_args()

    print(f"Stock switch IP change: {args.ip} → {args.new_ip}")
    if args.gateway:
        print(f"Gateway: {args.gateway}")
    print(f"Credentials: {args.username}/{args.password[:4]}...")
    print()

    success = change_ip(
        args.ip, args.username, args.password,
        args.new_ip, args.mask, args.gateway, args.new_password,
    )
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
