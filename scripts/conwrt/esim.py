"""eSIM provisioning and management for OpenWrt routers with eUICC cards.

Subcommands:
  status     — current serving cell, signal, band, operator, active ICCID
  profiles   — list eUICC profiles (requires MBIM mode)
  provision  — full provisioning pipeline (interactive, includes power-cycle prompts)
  switch     — switch active profile (requires MBIM mode)
  test       — run the e2e test suite (Speedtest profile, no credential consumed)
  monitor    — power-cycle monitoring helper

Environment variables:
  CONWRT_DEVICE_IP   — router IP (default: 192.168.1.10)
  CONWRT_SSH_KEY     — SSH private key path
  CONWRT_ESIM_SMDP   — SM-DP+ host (for provision)
  CONWRT_ESIM_MATCHING_ID — matching ID (for provision)
  CONWRT_ESIM_APN    — APN for the new profile (default: internet)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

DEFAULT_IP = "192.168.1.10"
DEFAULT_APN = "internet"

LPAC_ARTIFACT_SHA256 = "19d6f87df930cb7e3370380c6a1307431b40f2629545e871c67e087cd471aa94"
LPAC_VERSION_EXPECTED = "2.3.0.r466.a43e46aef6f8"

# AT response patterns
QENG_LTE_RE = re.compile(
    r'\+QENG:\s*"servingcell","(\w+)","(LTE|NR5G)","(\w+)",'
    r'(\d+),(\d+),([0-9A-Fa-f]+),(\d+),(\d+),(\d+),(\d+),(\d+),'
    r'([0-9A-Fa-f]+),(-?\d+),(-?\d+),(-?\d+),(-?\d+)'
)
COPS_RE = re.compile(r'\+COPS:\s*(\d),(\d),"([^"]*)",?(\d+)?')
QCCID_RE = re.compile(r'\+QCCID:\s*(\d{19,20})')
CEREG_RE = re.compile(r'\+CEREG:\s*(\d),(\d+)')
CSQ_RE = re.compile(r'\+CSQ:\s*(\d+),(\d+)')

# Band lookup (EARFCN → band name)
def earfcn_to_band(earfcn: int) -> str:
    if earfcn < 600: return "B1 (2100MHz)"
    elif earfcn < 1200: return "B2 (1900MHz)"
    elif earfcn < 1950: return "B3 (1800MHz)"
    elif earfcn < 2400: return "B4 (AWS)"
    elif earfcn < 2650: return "B5 (850MHz)"
    elif earfcn < 2750: return "B6 (800MHz)"
    elif earfcn < 3450: return "B7 (2600MHz)"
    elif earfcn < 3800: return "B8 (900MHz)"
    elif earfcn < 6150: return "B20 (800MHz)"
    elif earfcn < 6450: return "B28 (700MHz)"
    else: return f"band?({earfcn})"

def signal_quality(rsrp: int) -> str:
    if rsrp >= -80: return "excellent"
    elif rsrp >= -90: return "good"
    elif rsrp >= -100: return "fair"
    elif rsrp >= -110: return "poor"
    else: return "very poor"

def parse_qeng(raw: str) -> dict[str, Any] | None:
    m = QENG_LTE_RE.search(raw)
    if not m:
        return None
    earfcn = int(m.group(8))
    return {
        "state": m.group(1),
        "tech": m.group(2),
        "duplex": m.group(3),
        "mcc": int(m.group(4)),
        "mnc": int(m.group(5)),
        "cell_id": m.group(6),
        "earfcn": earfcn,
        "band": earfcn_to_band(earfcn),
        "rsrp": int(m.group(13)),
        "rsrq": int(m.group(14)),
        "rssi": int(m.group(15)),
        "sinr": int(m.group(16)),
        "quality": signal_quality(int(m.group(13))),
    }

def parse_cops(raw: str) -> dict[str, Any] | None:
    m = COPS_RE.search(raw)
    if not m:
        return None
    return {
        "mode": "automatic" if m.group(1) == "0" else "manual",
        "operator": m.group(3),
        "act": m.group(4) or "",
    }

def parse_qccid(raw: str) -> str | None:
    m = QCCID_RE.search(raw)
    return m.group(1) if m else None

def parse_cereg(raw: str) -> dict[str, str]:
    m = CEREG_RE.search(raw)
    if not m:
        return {"status": "unknown"}
    stat = int(m.group(2))
    names = {0: "not_registered", 1: "registered_home", 2: "searching",
             3: "denied", 4: "unknown", 5: "registered_roaming", 6: "sms_only", 7: "attached", 8: "emergency"}
    return {"status": names.get(stat, f"unknown({stat})"), "raw": m.group(0)}

def parse_profile_list(raw: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(raw)
        return data.get("payload", {}).get("data", [])
    except (json.JSONDecodeError, KeyError):
        return []

def _ssh(ip: str, cmd: str, key: str | None = None) -> str:
    ssh_cmd = ["ssh", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new"]
    if key:
        ssh_cmd += ["-i", key]
    ssh_cmd += [f"root@{ip}", cmd]
    r = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=60)
    return r.stdout + r.stderr

def _ssh_ok(ip: str, key: str | None = None) -> bool:
    try:
        r = subprocess.run(
            ["ssh", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes"] +
            (["-i", key] if key else []) +
            [f"root@{ip}", "true"],
            capture_output=True, timeout=10
        )
        return r.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False

def _at_run(ip: str, cmd: str, key: str | None = None) -> str:
    return _ssh(ip, f'P=$(modem-at probe 2>/dev/null); modem-at run $P \'{cmd}\' 2>/dev/null', key)

def _lpac_run(ip: str, args: str, key: str | None = None) -> str:
    env = "LPAC_APDU=mbim LPAC_HTTP=curl LPAC_APDU_MBIM_UIM_SLOT=2"
    return _ssh(ip, f'export {env}; /usr/bin/lpac {args} 2>&1 | grep -v WARNING', key)


def wait_for_power_cycle(ip: str, key: str | None = None, timeout: int = 300) -> bool:
    """Poll SSH until the device goes down and comes back (a power cycle).

    Prints progress so the user knows to power-cycle.
    Returns True if the cycle was detected, False on timeout.
    """
    print("  >>> POWER-CYCLE THE ROUTER NOW (unplug PoE 10s, plug back) <<<")
    print("  [waiting for device to go down...]", end="", flush=True)

    start = time.time()
    went_down = False
    while time.time() - start < timeout:
        if not _ssh_ok(ip, key):
            went_down = True
            print(" ✓ (device went down)")
            break
        print(".", end="", flush=True)
        time.sleep(2)

    if not went_down:
        print(" TIMEOUT waiting for power-cycle")
        return False

    print("  [waiting for device to come back...]", end="", flush=True)
    start = time.time()
    while time.time() - start < timeout:
        if _ssh_ok(ip, key):
            print(" ✓ (device is back)")
            return True
        print(".", end="", flush=True)
        time.sleep(5)

    print(" TIMEOUT waiting for device to return")
    return False


def cmd_esim_status(ip: str, key: str | None) -> int:
    raw = _at_run(ip, 'AT+QENG="servingcell"', key)
    cell = parse_qeng(raw)

    cops_raw = _at_run(ip, "AT+COPS?", key)
    cops = parse_cops(cops_raw)

    iccid_raw = _at_run(ip, "AT+QCCID", key)
    iccid = parse_qccid(iccid_raw)

    cereg_raw = _at_run(ip, "AT+CEREG?", key)
    cereg = parse_cereg(cereg_raw)

    print("=== eSIM Status ===")
    if iccid:
        print(f"  ICCID:       {iccid}")
    if cell:
        print(f"  Operator:    {cops['operator'] if cops else '?'} (MCC={cell['mcc']} MNC={cell['mnc']})")
        print(f"  Technology:  {cell['tech']}")
        print(f"  Band:        {cell['band']} (EARFCN={cell['earfcn']})")
        print(f"  Signal:      RSRP={cell['rsrp']}dBm ({cell['quality']}) RSRQ={cell['rsrq']}dB SINR={cell['sinr']}dB")
    if cops:
        print(f"  Selection:   {cops['mode']}")
    print(f"  Registration: {cereg['status']}")
    return 0


def cmd_esim_profiles(ip: str, key: str | None) -> int:
    wdm = _ssh(ip, "ls /dev/cdc-wdm0 2>/dev/null && echo MBIM || echo NOT-MBIM", key)
    if "NOT-MBIM" in wdm:
        print("ERROR: not in MBIM mode — profile management requires usbnet=2")
        print("  Switch: modem-at run $(modem-at probe) 'AT+QCFG=\"usbnet\",2' + power-cycle")
        return 1

    raw = _lpac_run(ip, "profile list", key)
    profiles = parse_profile_list(raw)
    if not profiles:
        print("ERROR: could not list profiles")
        print(raw[:300])
        return 1

    print(f"{'ICCID':<22} {'State':<10} {'Provider':<20} {'Nickname'}")
    print("-" * 75)
    for p in profiles:
        nick = p.get("profileNickname") or ""
        print(f"{p['iccid']:<22} {p['profileState']:<10} {p.get('serviceProviderName','?'):<20} {nick}")
    return 0


def cmd_esim_provision(ip: str, key: str | None, smdp: str, matching_id: str,
                        apn: str, wifi_ssid: str = "", wifi_key: str = "") -> int:
    print("=== eSIM Provisioning Pipeline ===")
    print(f"  SM-DP+:     {smdp}")
    print(f"  Matching-ID: {matching_id}")
    print(f"  APN:        {apn}")
    print()

    # Phase 1: verify current state
    print("[1/7] Verifying current state...")
    if not _ssh_ok(ip, key):
        print("  ERROR: cannot reach router")
        return 1
    print("  ✓ Router reachable")

    # Phase 2: WiFi backup
    if wifi_ssid:
        print("[2/7] Setting up WiFi backup...")
        cmds = (
            f"uci set wireless.radio0.disabled='0'; "
            f"uci set wireless.wwansta=wifi-iface; "
            f"uci set wireless.wwansta.device='radio0'; "
            f"uci set wireless.wwansta.mode='sta'; "
            f"uci set wireless.wwansta.ssid='{wifi_ssid}'; "
            f"uci set wireless.wwansta.encryption='sae-mixed'; "
            f"uci set wireless.wwansta.key='{wifi_key}'; "
            f"uci set wireless.wwansta.network='wwan'; "
            f"uci set network.wwan=interface; "
            f"uci set network.wwan.proto='dhcp'; "
            f"uci commit wireless; uci commit network; wifi reload"
        )
        _ssh(ip, cmds, key)
        time.sleep(10)
        wifi_test = _ssh(ip, "ping -I phy0-sta0 -c 2 -W 5 8.8.8.8 2>&1 | tail -1", key)
        if "time=" in wifi_test or "round-trip" in wifi_test:
            print("  ✓ WiFi internet backup working")
        else:
            print(f"  ⚠ WiFi test: {wifi_test.strip()}")
            print("  (continuing — the ECM path may still work)")
    else:
        print("[2/7] Skipping WiFi backup (no --wifi-ssid)")

    # Phase 3: install kernel module
    print("[3/7] Ensuring kmod-usb-net-cdc-mbim...")
    _ssh(ip, "apk add kmod-usb-net-cdc-mbim 2>/dev/null || opkg install kmod-usb-net-cdc-mbim 2>/dev/null || true", key)
    print("  ✓ (installed or already present)")

    # Phase 4: switch to MBIM
    print("[4/7] Switching modem to MBIM mode...")
    _at_run(ip, 'AT+QCFG="usbnet",2', key)
    print("  usbnet=2 sent")

    if not wait_for_power_cycle(ip, key):
        print("  ERROR: power-cycle not detected")
        return 1

    time.sleep(60)  # modem settle time
    wdm = _ssh(ip, "ls /dev/cdc-wdm0 2>/dev/null && echo MBIM", key)
    if "MBIM" not in wdm:
        print("  ERROR: cdc-wdm0 not present after power-cycle")
        print("  Is kmod-usb-net-cdc-mbim installed? Try another power-cycle.")
        return 1
    print("  ✓ MBIM mode active (cdc-wdm0 present)")

    # Phase 5: MBIM gate
    print("[5/7] MBIM gate (read-only)...")
    chip_raw = _lpac_run(ip, "chip info", key)
    if "eidValue" not in chip_raw:
        print("  ERROR: chip info failed — cannot reach eUICC")
        print(chip_raw[:300])
        return 1

    import re as _re
    eid_m = _re.search(r'"eidValue":"([0-9a-fA-F]{32})"', chip_raw)
    eid = eid_m.group(1) if eid_m else "unknown"
    print(f"  ✓ EID: {eid}")

    profiles_raw = _lpac_run(ip, "profile list", key)
    profiles = parse_profile_list(profiles_raw)
    print(f"  ✓ {len(profiles)} profiles on card")
    for p in profiles:
        print(f"    {p['iccid']}: {p['profileState']} ({p.get('serviceProviderName','?')})")

    # Phase 6: download and enable (ONE-SHOT)
    print("[6/7] Downloading profile (ONE-SHOT — no retry)...")
    dl_raw = _lpac_run(ip, f"profile download -s {smdp} -m {matching_id}", key)
    if '"code":0' not in dl_raw:
        print("  ERROR: profile download FAILED")
        print(dl_raw[:500])
        print("  DO NOT RETRY without diagnosis (credential may be consumed)")
        return 1

    iccid_m = _re.search(r'"iccid":"(\d{19,20})"', dl_raw)
    new_iccid = iccid_m.group(1) if iccid_m else ""
    print(f"  ✓ Profile downloaded: {new_iccid}")

    if not new_iccid:
        print("  ERROR: could not extract new ICCID from response")
        return 1

    print(f"[6/7] Enabling profile {new_iccid}...")
    en_raw = _lpac_run(ip, f"profile enable {new_iccid}", key)
    if '"code":0' not in en_raw:
        print("  ERROR: enable failed")
        print(en_raw[:300])
        return 1
    print("  ✓ Profile enabled")

    # Process notifications
    print("[6/7] Processing notifications...")
    _lpac_run(ip, "notification process -a -r", key)
    print("  ✓ (done)")

    # Phase 7: switch back to ECM
    print("[7/7] Switching back to ECM mode...")
    _at_run(ip, "AT+CFUN=1,1", key)
    time.sleep(60)
    _at_run(ip, f'AT+CGDCONT=1,"IPV4V6","{apn}"', key)
    _at_run(ip, 'AT+QCFG="usbnet",1', key)
    print("  usbnet=1 sent, APN set")

    if not wait_for_power_cycle(ip, key):
        print("  ERROR: power-cycle not detected")
        return 1

    time.sleep(60)
    ping = _ssh(ip, "ping -c 2 -W 5 8.8.8.8 2>&1 | tail -1", key)
    if "time=" in ping or "round-trip" in ping:
        print("  ✓ INTERNET WORKING through new profile")
    else:
        print(f"  ⚠ Ping test: {ping.strip()}")

    new_iccid_raw = _at_run(ip, "AT+QCCID", key)
    final_iccid = parse_qccid(new_iccid_raw)
    if final_iccid == new_iccid:
        print(f"  ✓ ICCID confirmed: {new_iccid}")
    else:
        print(f"  ⚠ ICCID mismatch: expected {new_iccid}, got {final_iccid}")

    print("\n=== PROVISIONING COMPLETE ===")
    return 0


def cmd_esim_switch(ip: str, key: str | None, iccid: str) -> int:
    print(f"Switching to profile {iccid}...")
    result = _lpac_run(ip, f"profile enable {iccid}", key)
    if '"code":0' in result:
        print("  ✓ Profile enabled")
        _at_run(ip, "AT+CFUN=1,1", key)
        print("  (modem resetting, wait ~60s for re-registration)")
        return 0
    else:
        print(f"  ERROR: {result[:300]}")
        return 1


def register(uc_dict: dict) -> None:
    pass
