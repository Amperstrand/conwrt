#!/usr/bin/env python3
"""
OpenWrt Failsafe Trigger Helper.

Watches en6 for device boot packets, tells you exactly when to press reset.
"""

import subprocess
import sys
import time

INTERFACE = "en6"
TARGET_IP = "192.168.1.1"

try:
    _mac_result = subprocess.run(
        ["ifconfig", INTERFACE], capture_output=True, text=True, check=False,
    )
    _mac_line = [l for l in _mac_result.stdout.splitlines() if "ether " in l]
    LOCAL_MAC = _mac_line[0].split("ether ")[1].split()[0] if _mac_line else ""
except Exception:
    LOCAL_MAC = ""

if not LOCAL_MAC:
    print(f"[!] WARNING: Could not detect MAC for {INTERFACE}, using no filter")
    LOCAL_MAC = "00:00:00:00:00:00"

print(f"[*] Watching {INTERFACE} for boot packets...")
print(f"[*] Power cycle the device now. Plug into eth0.")
print()

seen_device_macs = set()
boot_detected = False
failsafe_deadline = 0

proc = subprocess.Popen(
    ["sudo", "tcpdump", "-i", INTERFACE, "-n", "-e", "--immediate-mode",
     "-l", f"not", "ether", "src", LOCAL_MAC],
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True,
    bufsize=1,
)

try:
    if proc.stdout is None:
        raise RuntimeError("tcpdump produced no stdout")
    for line in proc.stdout:
        line = line.strip()
        if not line or line.startswith("tcpdump:"):
            continue

        # Extract source MAC from tcpdump output: "XX:XX:XX:..."
        parts = line.split()
        if len(parts) < 3:
            continue

        src_mac = parts[0].lower()
        if src_mac == LOCAL_MAC.lower():
            continue
        # Skip broadcast/multicast MACs as source identifiers
        if src_mac.startswith("33:33:") or src_mac.startswith("01:00:5e"):
            continue

        timestamp = parts[-1] if parts else ""

        if not boot_detected:
            # First packet from a new device = boot started
            if src_mac not in seen_device_macs:
                seen_device_macs.add(src_mac)
                print(f"\n{'='*60}")
                print(f"[!] BOOT DETECTED from {src_mac}")
                print(f"[!] PRESS AND HOLD RESET BUTTON NOW!")
                print(f"[!] Hold for 2-3 seconds, then release")
                print(f"{'='*60}\n")
                sys.stdout.flush()
                boot_detected = True
                failsafe_deadline = time.time() + 5  # 5 second window
        else:
            # Still in failsafe window
            if time.time() < failsafe_deadline:
                print(f"  ...still in failsafe window ({src_mac}: {parts[2] if len(parts) > 2 else ''})")
                sys.stdout.flush()

    # After tcpdump ends or we break out, check if device responds
except KeyboardInterrupt:
    pass
finally:
    proc.terminate()
    print("\n[*] Checking if device is in failsafe (pinging 192.168.1.1)...")
    result = subprocess.run(
        ["ping", "-c", "3", "-t", "2", TARGET_IP],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        print(f"[+] DEVICE RESPONDS TO PING — likely in failsafe mode!")
        print(f"[+] Try: ssh -o StrictHostKeyChecking=no root@{TARGET_IP}")
    else:
        print(f"[-] No ping response — device may have booted normally.")
        print(f"[-] Try power cycling again and press reset sooner.")
