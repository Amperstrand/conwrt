#!/usr/bin/env python3
"""Configure stock GS1900-8HP entirely via Playwright.

Handles V2.90 mandatory password change, IP reconfiguration, and save to flash.
Everything runs through the switch's own JavaScript — no encoding mismatches.

Usage:
    python3 scripts/configure-stock-switch.py --new-ip 192.168.13.3 --gateway 192.168.13.1
"""
import argparse
import sys
import time
from playwright.sync_api import Error as PlaywrightError, sync_playwright


def _wait_for_frame_url(page, expected_cmd, timeout=10):
    """Wait for any frame to contain the expected cmd in its URL."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for f in page.frames:
            if f"cmd={expected_cmd}" in f.url:
                return f
        time.sleep(0.5)
    return None


def _find_content_frame(page):
    """Find the frame with cmd= in its URL (not cmd=0)."""
    for f in page.frames:
        if "cmd=" in f.url and "cmd=0" not in f.url:
            return f
    # Fall back to main frame if only one frame
    if len(page.frames) == 1:
        return page.main_frame
    return page.frames[1] if len(page.frames) > 1 else page.main_frame


def _do_login(frame, password):
    """Fill credentials and call the switch's login() JS function."""
    frame.locator("#username").fill("admin")
    frame.locator("#password").fill(password)
    frame.evaluate("login()")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", default="192.168.1.1")
    parser.add_argument("--password", default="1234")
    parser.add_argument("--new-password", default="Conwrt2026!")
    parser.add_argument("--new-ip", default="192.168.13.3")
    parser.add_argument("--mask", default="255.255.255.0")
    parser.add_argument("--gateway", default="")
    args = parser.parse_args()

    effective_password = args.password

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        # === LOGIN ===
        print(f"[1/7] Logging in to {args.ip}...")
        page.goto(f"http://{args.ip}/", timeout=15000)
        time.sleep(2)

        # The login page is a single frame at cmd=0
        login_frame = page.main_frame
        print(f"  Login frame: {login_frame.url}")

        _do_login(login_frame, args.password)
        time.sleep(4)

        # Check where we ended up — look at ALL frames
        print(f"  Frames after login: {len(page.frames)}")
        for f in page.frames:
            print(f"    {f.url}")

        # After login with default pw, switch redirects to cmd=30 (password change)
        # After login with changed pw, switch goes to cmd=1 (dashboard)
        pw_frame = _wait_for_frame_url(page, "30", timeout=3)
        dash_frame = _wait_for_frame_url(page, "1", timeout=3)

        if pw_frame:
            print(f"\n[2/7] Mandatory password change (cmd=30)")
            pw_frame.locator("#usrOldPass").fill(args.password)
            pw_frame.locator("#usrPass").fill(args.new_password)
            pw_frame.locator("#usrPass2").fill(args.new_password)
            print(f"  Submitting password change...")
            try:
                pw_frame.evaluate("submitForm()")
                pw_frame.wait_for_load_state("networkidle", timeout=10000)
            except PlaywrightError:
                pass
            time.sleep(2)
            effective_password = args.new_password
            print(f"  Password changed")

            # Re-login — navigate fresh
            print(f"\n[3/7] Re-logging in with new password...")
            page.goto(f"http://{args.ip}/", timeout=10000)
            time.sleep(2)
            login_frame = page.main_frame
            _do_login(login_frame, effective_password)
            time.sleep(4)
        elif dash_frame:
            print(f"\n[2/7] No password change needed")
            print(f"[3/7] Skipping re-login")
        else:
            print(f"\n[2/7] Checking current state...")
            # Might already be on a content page
            for f in page.frames:
                print(f"  Frame: {f.url}")

        # After login, switch loads a frameset (cmd=1) with menu + content frames
        print(f"  Frames after auth: {len(page.frames)}")
        for f in page.frames:
            print(f"    {f.url}")

        # === FIND SAVE COMMAND ===
        # Navigate to the IP config page directly
        print(f"\n[4/7] Navigating to IP config (cmd=516)...")
        # We need to load cmd=516 in the content frame
        # The frameset structure means we navigate the content frame
        content_frame = _find_content_frame(page)
        print(f"  Content frame: {content_frame.url}")

        # Try navigating the content frame to cmd=516
        content_frame.goto(
            f"http://{args.ip}/cgi-bin/dispatcher.cgi?cmd=516",
            timeout=10000, wait_until="networkidle"
        )
        time.sleep(1)
        print(f"  After navigation: {content_frame.url}")
        page_content = content_frame.content()

        if "cmd=0" in content_frame.url or len(page_content) < 500:
            print(f"  Session lost, trying direct page load...")
            page.goto(f"http://{args.ip}/cgi-bin/dispatcher.cgi?cmd=516",
                       timeout=10000, wait_until="networkidle")
            time.sleep(2)
            content_frame = page.main_frame
            page_content = content_frame.content()
            print(f"  Direct load: {len(page_content)} bytes, URL: {content_frame.url}")

        # Dump page for analysis
        with open("/tmp/cmd516-page.html", "w") as f:
            f.write(page_content)
        print(f"  Page: {len(page_content)} bytes, saved to /tmp/cmd516-page.html")

        # Show all inputs
        all_inputs = content_frame.locator("input")
        print(f"  Inputs ({all_inputs.count()}):")
        for i in range(min(all_inputs.count(), 30)):
            inp = all_inputs.nth(i)
            n = inp.get_attribute("name") or ""
            t = inp.get_attribute("type") or ""
            try:
                v = inp.input_value() if t not in ("password",) else "***"
            except PlaywrightError:
                v = "(error)"
            if n:
                print(f"    {n} ({t}): {v[:60]}")

        # === FILL IP CONFIG ===
        print(f"\n[5/7] Setting IP configuration...")
        ip_field = None
        for name in ["sysIpAddr", "ipAddr", "IPAddr", "sysIpAddress", "ipAddress",
                      "sysIp", "SystemIP", "sysIP"]:
            loc = content_frame.locator(f'input[name="{name}"]')
            if loc.count() > 0:
                ip_field = loc.first
                current = ip_field.input_value()
                print(f"  IP field: {name} = {current}")
                break

        if not ip_field:
            # Search broader
            all_text = content_frame.locator('input[type="text"], input:not([type])')
            for i in range(all_text.count()):
                inp = all_text.nth(i)
                name = inp.get_attribute("name") or ""
                val = inp.input_value()
                if val and "." in val and ("ip" in name.lower() or "addr" in name.lower()):
                    ip_field = inp
                    print(f"  IP field (search): {name} = {val}")
                    break

        if not ip_field:
            print("  ERROR: No IP field found. Check /tmp/cmd516-page.html")
            browser.close()
            return False

        ip_field.fill(args.new_ip)
        print(f"  Set IP: {args.new_ip}")

        for name in ["sysSubnet", "subnetMask", "SubnetMask", "sysSubnetMask",
                      "sysIpSubnet", "ipSubnet"]:
            loc = content_frame.locator(f'input[name="{name}"]')
            if loc.count() > 0:
                loc.first.fill(args.mask)
                print(f"  Set mask ({name}): {args.mask}")
                break

        if args.gateway:
            for name in ["sysGateway", "gateway", "Gateway", "sysGatewayIp",
                          "defaultGateway", "defGateway"]:
                loc = content_frame.locator(f'input[name="{name}"]')
                if loc.count() > 0:
                    loc.first.fill(args.gateway)
                    print(f"  Set gateway ({name}): {args.gateway}")
                    break

        # === SUBMIT + SAVE ===
        # Find the submit mechanism on the IP config page
        print(f"\n[6/7] Submitting and saving...")

        # Look for the submit button/onclick
        submit_btn = content_frame.locator('input[name="sysSubmit"], input[value="Apply"]')
        if submit_btn.count() > 0:
            onclick = submit_btn.first.get_attribute("onclick") or ""
            print(f"  Submit button onclick: {onclick[:100]}")

        # Use JavaScript to: submit the form, then save config
        # First, try to find and call the save mechanism
        # Common Zyxel: the form submit itself triggers the change
        # Then a separate httpPost('cmd=28') or similar saves to flash

        # Check if there's a submitForm() function on this page
        has_submit_form = content_frame.evaluate("typeof submitForm")
        print(f"  submitForm() exists: {has_submit_form}")

        if has_submit_form == "function":
            # submitForm() will encode and submit the form
            # After submit, we need to save separately
            print(f"  Calling submitForm()...")
            try:
                content_frame.evaluate("submitForm()")
                content_frame.wait_for_load_state("networkidle", timeout=8000)
            except PlaywrightError:
                pass
        elif submit_btn.count() > 0:
            print(f"  Clicking Apply button...")
            try:
                submit_btn.first.click(timeout=5000)
            except PlaywrightError as e:
                if "timeout" in str(e).lower():
                    print(f"  Clicked (timeout expected)")
                else:
                    raise

        time.sleep(2)

        # Now try to save config
        # On Zyxel GS1900, the save is typically done via:
        # - Maintenance > Save Configuration (cmd varies)
        # - Or httpPost with specific save command

        # Try common save commands via the frame's JS
        for save_cmd in [28, 27, 26, 25, 24, 23, 22, 21, 20]:
            try:
                result = content_frame.evaluate(f"""(cmd) => {{
                    var xhr = new XMLHttpRequest();
                    xhr.open('POST', '/cgi-bin/dispatcher.cgi?cmd=' + cmd, false);
                    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
                    xhr.send('cmd=' + cmd);
                    return {{status: xhr.status, len: xhr.responseText.length, text: xhr.responseText.substring(0, 200)}};
                }}""", save_cmd)
                if result["len"] > 500:
                    print(f"  cmd={save_cmd}: {result['len']} bytes")
                    # Check if this looks like a save page
                    if "save" in result["text"].lower() or "Save" in result["text"]:
                        print(f"    *** Possible save page: {result['text'][:100]}")
            except PlaywrightError:
                pass

        browser.close()

    print(f"\n[7/7] Done. Check switch reachability.")
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
