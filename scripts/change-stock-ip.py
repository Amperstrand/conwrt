#!/usr/bin/env python3
"""Change the stock GS1900-8HP switch management IP via the web UI.

Usage:
    python3 scripts/change-stock-ip.py --ip 192.168.1.1 --new-ip 192.168.1.254

This removes the IP conflict with AP#3 (which boots OpenWrt at 192.168.1.1 by default).
"""
import argparse
import re
import subprocess
import sys
import time
import urllib.parse

sys.path.insert(0, "scripts")
from flash.oem_handlers import oem_http_login, zyxel_encode_password


def fetch_ip_config_page(stock_ip: str, cookie: str) -> str:
    """Fetch cmd=516 (IP Configuration) page HTML."""
    r = subprocess.run(
        ["curl", "-s", "--max-time", "10", "-b", cookie,
         f"http://{stock_ip}/cgi-bin/dispatcher.cgi?cmd=516"],
        capture_output=True, text=True, timeout=15, check=False,
    )
    return r.stdout


def extract_form_fields(html: str) -> dict:
    """Extract hidden fields and input names from the IP config form."""
    fields = {}

    # Find XSSID token
    xssid_match = re.search(r'name=["\']XSSID["\'][^>]*value=["\']([^"\']+)["\']', html)
    if not xssid_match:
        xssid_match = re.search(r'value=["\']([^"\']+)["\'][^>]*name=["\']XSSID["\']', html)
    if xssid_match:
        fields["XSSID"] = xssid_match.group(1)

    # Find all hidden inputs
    for match in re.finditer(r'<input[^>]+type=["\']hidden["\'][^>]*>', html, re.IGNORECASE):
        tag = match.group(0)
        name_match = re.search(r'name=["\']([^"\']+)["\']', tag)
        value_match = re.search(r'value=["\']([^"\']*)["\']', tag)
        if name_match:
            fields[name_match.group(1)] = value_match.group(1) if value_match else ""

    # Find IP address input fields
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


def find_ip_field_names(html: str) -> list[str]:
    """Find field names that contain IP addresses in the form."""
    ip_fields = []
    for match in re.finditer(r'name=["\']([^"\']*(?:ip|IP|addr|Addr|Ip)[^"\']*)["\']', html):
        ip_fields.append(match.group(1))
    return ip_fields


def change_ip(stock_ip: str, username: str, password: str, new_ip: str, new_mask: str = "255.255.255.0") -> bool:
    """Change the switch management IP."""
    dispatcher = f"http://{stock_ip}/cgi-bin/dispatcher.cgi"

    print(f"[1/4] Logging in to {stock_ip}...")
    success, cookie = oem_http_login(stock_ip, username, password)
    if not success:
        print(f"ERROR: Login failed: {cookie}")
        return False

    if not cookie:
        print("WARNING: No cookie returned, trying without cookie")

    print(f"[2/4] Fetching IP config page (cmd=516)...")
    html = fetch_ip_config_page(stock_ip, cookie)

    if not html or len(html) < 100:
        print(f"ERROR: Empty response from cmd=516")
        print(f"  Response: {html[:500] if html else '(empty)'}")
        return False

    # Check if we got redirected to login
    if "cmd=0" in html or "login" in html.lower()[:500]:
        print("ERROR: Session expired or redirect to login")
        return False

    print(f"  Page size: {len(html)} bytes")

    # Find IP-related field names
    ip_fields = find_ip_field_names(html)
    print(f"  IP-related fields found: {ip_fields}")

    # Extract all form fields
    all_fields = extract_form_fields(html)
    print(f"  All form fields: {list(all_fields.keys())}")

    # Look for the IP address field - common ZyXEL names:
    # sysIpAddr, ipAddr, IPAddr, sysIpAddress, etc.
    ip_field = None
    for candidate in ["sysIpAddr", "ipAddr", "IPAddr", "sysIpAddress", "ipAddress",
                       "sysIp", "SystemIP", "sysIP", "IP"]:
        if candidate in all_fields:
            ip_field = candidate
            break

    if not ip_field and ip_fields:
        # Use the first IP field we found
        ip_field = ip_fields[0]

    if not ip_field:
        # Dump the form area for debugging
        print("\n  --- FORM HTML (first 3000 chars with 'form' context) ---")
        form_match = re.search(r'<form[^>]*>.*?</form>', html, re.DOTALL | re.IGNORECASE)
        if form_match:
            print(form_match.group(0)[:3000])
        else:
            print(html[:3000])
        print("\nERROR: Could not find IP address field. Dumped form HTML above.")
        return False

    current_ip = all_fields.get(ip_field, "(unknown)")
    print(f"  IP field: {ip_field} = {current_ip}")

    # Build the POST body
    all_fields[ip_field] = new_ip

    # Look for subnet mask field
    mask_field = None
    for candidate in ["sysSubnet", "subnetMask", "SubnetMask", "sysSubnetMask",
                       "sysIpSubnet", "ipSubnet"]:
        if candidate in all_fields:
            mask_field = candidate
            break
    if mask_field:
        all_fields[mask_field] = new_mask
        print(f"  Mask field: {mask_field} = {new_mask}")

    # Build POST body
    post_parts = []
    for k, v in all_fields.items():
        post_parts.append(f"{k}={urllib.parse.quote_plus(v)}")

    # Add submit action
    post_parts.append("cmd=517")  # cmd=516 is the page, cmd=517 is likely the submit
    post_parts.append("sysSubmit=Apply")
    post_body = "&".join(post_parts)

    print(f"[3/4] Submitting IP change to {new_ip}...")
    print(f"  POST body preview: {post_body[:200]}...")

    r = subprocess.run(
        ["curl", "-s", "--max-time", "15", "-L",
         "-b", cookie,
         "-X", "POST", "-d", post_body, dispatcher],
        capture_output=True, text=True, timeout=20, check=False,
    )

    response = r.stdout
    print(f"  Response size: {len(response)} bytes")

    # Check for success indicators
    if "cmd=4" in response or "save" in response.lower() or len(response) > 1000:
        print(f"[4/4] IP change submitted. Waiting for switch to apply...")

        # Wait for switch to restart networking
        time.sleep(5)

        # Try to reach the switch at the new IP
        print(f"  Testing connectivity at {new_ip}...")
        for attempt in range(6):
            r_test = subprocess.run(
                ["curl", "-s", "--max-time", "5",
                 f"http://{new_ip}/cgi-bin/dispatcher.cgi?cmd=5"],
                capture_output=True, text=True, timeout=8, check=False,
            )
            if r_test.stdout and len(r_test.stdout) > 100:
                print(f"  ✅ Switch is responding at {new_ip}!")
                return True
            time.sleep(3)

        print(f"  ⚠️  Switch not responding at {new_ip} yet (may need reboot)")
        print(f"  Try: ping {new_ip}")
        print(f"  Or: curl http://{new_ip}/cgi-bin/dispatcher.cgi?cmd=5")
        return True  # Submitted successfully, just not confirmed yet

    print(f"ERROR: Unexpected response")
    print(f"  Response: {response[:500]}")
    return False


def main():
    parser = argparse.ArgumentParser(description="Change stock GS1900-8HP management IP")
    parser.add_argument("--ip", default="192.168.1.1", help="Current switch IP (default: 192.168.1.1)")
    parser.add_argument("--new-ip", default="192.168.1.254", help="New management IP (default: 192.168.1.254)")
    parser.add_argument("--mask", default="255.255.255.0", help="Subnet mask (default: 255.255.255.0)")
    parser.add_argument("--username", default="admin", help="Web UI username (default: admin)")
    parser.add_argument("--password", default="Conwrt2026!", help="Web UI password")
    args = parser.parse_args()

    print(f"Changing stock switch IP: {args.ip} → {args.new_ip}")
    print(f"Credentials: {args.username}/{args.password[:4]}...")
    print()

    success = change_ip(args.ip, args.username, args.password, args.new_ip, args.mask)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
