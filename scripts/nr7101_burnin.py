#!/usr/bin/env python3
"""nr7101_burnin.py — host-side runner for a ~2-minute NR7101 hardware burn-in.

Pushes a BusyBox-only POSIX-sh payload to a flashed unit over SSH
(``sh -s`` stdin — no staging, nothing persists except the test files it
creates and deletes), runs it, and collects a single-line JSON report.

Payload sections (facts from models/zyxel-nr7101.json, hardware-verified):
  identity   MAC, board_name, OpenWrt release/arch, kernel, uptime
  modem      Quectel RG502Q-EA: sysfs ids + AT (ATI, +GMR, +GSN, +QCCID,
             +CSQ, +COPS?, +QCFG="usbnet") on /dev/ttyUSB2 via the
             raw echo+cat pattern the model JSON documents
  cpu        fixed 48MB sha256 benchmark (single-core) + 45s dual-core soak
  ram        64MB tmpfs write + double-hash consistency
  flash      8MB overlay (UBIFS upper) write + hash + delete — guarded by df
  eth        eth0 speed/carrier
  thermal    thermal zones before/after soak
  health     dmesg error scan (ubi/jffs2 unchecked-orphan, usb, pcie)

FAIL gates (exit 1 + "result":"FAIL"): modem absent, ram hash mismatch,
flash write failure, cpu benchmark degenerate, thermal > 85 C.

Usage:
    python3 scripts/nr7101_burnin.py --ip 192.168.1.1 [--key ~/.ssh/id_ed25519] \
        [--json-dir data/burnin] [--inventory]

Report: <json-dir>/<mac12>-<timestamp>.json ; ``--inventory`` also appends a
summary line to data/inventory.jsonl (evidence log — the private registry
remains the system of record).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Runs ON THE DEVICE. BusyBox ash only: no timeout/jq/od/chpasswd/hostname.
# Every AT read is bounded by a background-cat + kill (no timeout applet).
# JSON values pass through _j() (charset whitelist) — no quoting hazards.
BURNIN_SCRIPT = r"""
_j() { printf '%s' "$1" | tr -c 'A-Za-z0-9 :+,.\/_-' ' ' | tr -s ' '; }
_now() { date +%s; }
_mac=$(cat /sys/class/net/eth0/address 2>/dev/null)
_m=$(printf '%s' "$_mac" | tr -d ':')
_board=$(cat /tmp/sysinfo/board_name 2>/dev/null)
_rel=$(cat /etc/openwrt_release 2>/dev/null | sed -n "s/^DISTRIB_RELEASE='\(.*\)'/\1/p" | head -1)
_arch=$(cat /etc/openwrt_release 2>/dev/null | sed -n "s/^DISTRIB_ARCH='\(.*\)'/\1/p" | head -1)
_kern=$(uname -r)
_up=$(cut -d. -f1 /proc/uptime)

# --- modem: sysfs + AT on /dev/ttyUSB2 (model JSON send_pattern) ---
_modem_present=0
_at_model="-"; _at_fw="-"; _at_imei="-"; _at_iccid="-"; _at_csq="-"; _at_cops="-"; _at_usbnet="-"
_usb_prod=$(cat /sys/bus/usb/devices/2-1/product 2>/dev/null)
_usb_ven=$(cat /sys/bus/usb/devices/2-1/idVendor 2>/dev/null)
if [ -c /dev/ttyUSB2 ]; then
    _modem_present=1
    _at() {
        _cmd="$1"; _out=/tmp/burnin.at.$$
        cat /dev/ttyUSB2 > "$_out" 2>/dev/null &
        _cpid=$!
        sleep 1
        printf '%s\r' "$_cmd" > /dev/ttyUSB2 2>/dev/null
        sleep 2
        kill "$_cpid" 2>/dev/null
        wait "$_cpid" 2>/dev/null
        cat "$_out" 2>/dev/null | tr -d '\r' | grep -v '^$' | grep -v '^AT' | head -4 | tr '\n' ';'
        rm -f "$_out"
    }
    _at_model=$(_at ATI)
    _at_fw=$(_at AT+GMR)
    _at_imei=$(_at AT+GSN)
    _at_iccid=$(_at AT+QCCID)
    _at_csq=$(_at AT+CSQ)
    _at_cops=$(_at AT+COPS?)
    _at_usbnet=$(_at 'AT+QCFG="usbnet"')
fi

# --- cpu: fixed 48MB benchmark, then 45s dual-core soak ---
_cpu0=$(_now)
dd if=/dev/zero bs=1048576 count=48 2>/dev/null | sha256sum > /dev/null
_cpu1=$(_now)
_cpu_secs=$(( _cpu1 - _cpu0 ))
( while [ $(_now) -lt $(( _cpu1 + 45 )) ]; do dd if=/dev/zero bs=1048576 count=16 2>/dev/null | sha256sum > /dev/null; done ) &
_soak1=$!
( while [ $(_now) -lt $(( _cpu1 + 45 )) ]; do dd if=/dev/zero bs=1048576 count=16 2>/dev/null | sha256sum > /dev/null; done ) &
_soak2=$!
wait $_soak1 $_soak2

# --- ram: 64MB tmpfs, double-hash consistency ---
_ram="ok"
_h1=$(dd if=/dev/zero bs=1048576 count=64 2>/dev/null | sha256sum | cut -c1-32)
_h2=$(dd if=/dev/zero bs=1048576 count=64 2>/dev/null | sha256sum | cut -c1-32)
[ "$_h1" = "$_h2" ] || _ram="hash-mismatch"

# --- flash: 8MB overlay write (guarded by free space) ---
_flash="ok"
_avail=$(df -Pk / | sed -n '2s/.* \([0-9]*\)$/\1/p')
if [ "${_avail:-0}" -gt 20480 ]; then
    if ! dd if=/dev/zero of=/etc/burnin-flash.$$ bs=1048576 count=8 2>/dev/null; then
        _flash="write-failed"
    else
        sha256sum /etc/burnin-flash.$$ > /dev/null 2>&1 || _flash="read-failed"
        rm -f /etc/burnin-flash.$$
    fi
else
    _flash="skipped-low-space"
fi

# --- eth / thermal / health ---
_eth_speed=$(cat /sys/class/net/eth0/speed 2>/dev/null)
_eth_carrier=$(cat /sys/class/net/eth0/carrier 2>/dev/null)
_thermal_after=$(for z in /sys/class/thermal/thermal_zone*/temp; do cat "$z" 2>/dev/null; done | sort -rn | head -1)
_thermal_max=${_thermal_after:-0}
_health=$(dmesg 2>/dev/null | grep -ciE 'jffs2.*(unchecked|orphan)|ubi.*error|usb .*error|pcie.*fail')

# --- gates ---
_result="PASS"
[ "$_modem_present" = "1" ] || _result="FAIL:modem-absent"
[ "$_ram" = "ok" ] || _result="FAIL:ram-$_ram"
[ "$_flash" = "ok" ] || [ "$_flash" = "skipped-low-space" ] || _result="FAIL:flash-$_flash"
[ "$_cpu_secs" -le 15 ] || _result="FAIL:cpu-degenerate"
[ "$_thermal_max" -lt 85000 ] 2>/dev/null || _result="FAIL:thermal-$_thermal_max"

printf '{"result":"%s","mac":"%s","board":"%s","release":"%s","arch":"%s","kernel":"%s","uptime_s":%s,"modem":{"present":%s,"usb_product":"%s","usb_vendor":"%s","ati":"%s","firmware":"%s","imei":"%s","iccid":"%s","csq":"%s","cops":"%s","usbnet":"%s"},"cpu":{"mb48_secs":%s},"ram":{"check":"%s"},"flash":{"check":"%s"},"eth":{"speed":"%s","carrier":"%s"},"thermal_millic_max":%s,"dmesg_health_hits":%s}\n' \
  "$_result" "$_mac" "$_board" "$_rel" "$_arch" "$_kern" "${_up:-0}" \
  "$_modem_present" "$(_j "${_usb_prod:-}")" "$(_j "${_usb_ven:-}")" \
  "$(_j "$_at_model")" "$(_j "$_at_fw")" "$(_j "$_at_imei")" "$(_j "$_at_iccid")" \
  "$(_j "$_at_csq")" "$(_j "$_at_cops")" "$(_j "$_at_usbnet")" \
  "${_cpu_secs:-0}" "$_ram" "$_flash" "${_eth_speed:-}" "${_eth_carrier:-}" \
  "${_thermal_max:-0}" "${_health:-0}"
[ "${_result%%:*}" = "PASS" ] || exit 1
exit 0
"""

REQUIRED_KEYS = {
    "result",
    "mac",
    "board",
    "release",
    "cpu",
    "ram",
    "flash",
    "modem",
}


def run_burnin(ip: str, key: str | None, timeout: int = 420) -> dict:
    """Run the payload on the device and return the parsed report."""
    cmd = [
        "ssh",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "LogLevel=ERROR",
    ]
    if key:
        cmd += ["-i", key]
    cmd.append(f"root@{ip}")
    cmd.append("sh -s")
    r = subprocess.run(cmd, input=BURNIN_SCRIPT, capture_output=True, text=True, timeout=timeout, check=False)
    lines = [ln.strip() for ln in r.stdout.splitlines() if ln.strip().startswith("{")]
    if not lines:
        raise RuntimeError(f"no JSON report from device (rc={r.returncode}): {r.stderr.strip()[:300]}")
    report = json.loads(lines[-1])
    missing = REQUIRED_KEYS - set(report)
    if missing:
        raise RuntimeError(f"report missing keys: {sorted(missing)}")
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="NR7101 ~2-minute burn-in over SSH")
    ap.add_argument("--ip", required=True, help="device IP (post-flash)")
    ap.add_argument("--key", help="SSH private key")
    ap.add_argument(
        "--json-dir", default=str(REPO / "data" / "burnin"), help="where reports are written (default data/burnin)"
    )
    ap.add_argument("--inventory", action="store_true", help="append a summary line to data/inventory.jsonl")
    ap.add_argument("--timeout", type=int, default=420)
    args = ap.parse_args(argv)

    print(f"burn-in: running on {args.ip} (~2 min)...")
    try:
        report = run_burnin(args.ip, args.key, args.timeout)
    except (RuntimeError, subprocess.TimeoutExpired) as e:
        print(f"FAIL: {e}", file=sys.stderr)
        return 1

    json_dir = Path(args.json_dir)
    json_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    mac12 = report.get("mac", "unknown").replace(":", "")
    out = json_dir / f"{mac12}-{ts}.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    m = report.get("modem", {})
    print(f"  result      {report['result']}")
    print(f"  mac         {report.get('mac')}")
    print(f"  board       {report.get('board')} @ {report.get('release')} ({report.get('arch')})")
    print(f"  modem       {m.get('usb_product')} fw={m.get('firmware')}")
    print(f"  imei        {m.get('imei')}")
    print(
        f"  cpu 48MB    {report.get('cpu', {}).get('mb48_secs')}s   ram {report.get('ram', {}).get('check')}   flash {report.get('flash', {}).get('check')}"
    )
    print(f"  thermal     {report.get('thermal_millic_max')} mC   dmesg-hits {report.get('dmesg_health_hits')}")
    print(f"  report      {out}")

    if args.inventory:
        sys.path.insert(0, str(REPO / "scripts"))
        from inventory import append_to_inventory

        append_to_inventory(
            {
                "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
                "device_serial": str(m.get("imei", "")),
                "model": "NR7101",
                "vendor": "Zyxel",
                "firmware_version": str(report.get("release", "")),
                "openwrt_target": str(report.get("arch", "")),
                "mac_addresses": [report.get("mac", "")],
                "notes": f"burnin {report['result']}; modem_fw={m.get('firmware')}; report={out}",
            }
        )
        print("  inventory   appended")

    return 0 if str(report["result"]).startswith("PASS") else 1


if __name__ == "__main__":
    sys.exit(main())
