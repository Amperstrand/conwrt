#!/usr/bin/env python3
"""sticker_creds -- extract factory WiFi SSID/password and MAC addresses
from D-Link COVR-X1860 config2 MTD partition dumps.

The config2 partition on D-Link COVR-X1860 NAND flash stores factory
configuration as ASCII key=value pairs embedded in a binary NAND image.
This module scans for those patterns, parses them, and extracts the
sticker credentials (WiFi SSID, password, MAC addresses).

Usage:
    # From a local binary dump
    python3 scripts/sticker_creds.py config2.bin

    # Dump via SSH from a running OpenWrt router
    python3 scripts/sticker_creds.py --ip 192.168.1.1
    python3 scripts/sticker_creds.py --ip 192.168.1.1 --key ~/.ssh/id_ed25519
"""

from __future__ import annotations

import argparse
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Path setup so we can import sibling modules when run directly
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))

from ssh_utils import run_ssh, ssh_cmd, scp_cmd  # noqa: E402
from model_loader import load_model  # noqa: E402

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_MODEL_ID = "dlink_covr-x1860-a1"
_CONFIG2_PARTITION_LABEL = "config2"

# Minimum printable ASCII range we consider valid for key=value content
_PRINTABLE_RANGE = set(range(0x20, 0x7F))
# NAND flash empty/erased byte
_NAND_EMPTY = 0xFF
# Key regex: alphanumeric/underscore key, = sign, then printable value
_KV_RE = re.compile(rb"([A-Za-z_][A-Za-z0-9_]{0,63})=([!-~]{1,256})")
# MAC address pattern
_MAC_RE = re.compile(
    rb"([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:"
    rb"[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2})"
)
# SSID pattern for D-Link default: dlink-XXXX or DLink-XXXX
_SSID_RE = re.compile(rb"[Dd][Ll]ink[-_]?([0-9A-Fa-f]{4,8})")


# ---------------------------------------------------------------------------
# Core parsing
# ---------------------------------------------------------------------------

def parse_config2(data: bytes) -> dict[str, str]:
    """Parse the binary config2 partition and return all key-value pairs.

    Scans the entire binary for ASCII ``key=value`` patterns, skipping over
    null bytes, 0xFF erasure markers, and other NAND flash artefacts.

    Args:
        data: Raw bytes of the config2 MTD partition dump.

    Returns:
        Dictionary of all key-value pairs found in the partition.
    """
    result: dict[str, str] = {}

    # Walk through the data looking for printable ASCII runs that contain
    # key=value patterns.  We use a sliding approach: scan for '=', then
    # backtrack for the key and forward for the value.
    pos = 0
    length = len(data)

    while pos < length:
        # Skip null bytes and 0xFF (erased NAND)
        if data[pos] == 0x00 or data[pos] == _NAND_EMPTY:
            pos += 1
            continue

        # Try to match a key=value pair starting at this position
        match = _KV_RE.match(data, pos)
        if match:
            key_bytes = match.group(1)
            val_bytes = match.group(2)

            # Validate: key must be fully printable ASCII
            key_str = key_bytes.decode("ascii", errors="replace")
            val_str = val_bytes.decode("ascii", errors="replace")

            # Filter out garbage: key should be clean alphanumeric/underscore
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key_str):
                # Value should not be all the same character (likely fill)
                if len(val_str) > 0 and not (len(set(val_str)) == 1):
                    result[key_str] = val_str

            pos = match.end()
        else:
            pos += 1

    return result


def extract_wifi_credentials(config: dict[str, str]) -> dict[str, str]:
    """Extract SSID and password for 2.4 GHz and 5 GHz radios.

    D-Link stock firmware stores WiFi credentials in config2 under keys
    like ``wlan_ssid``, ``wlan1_ssid``, ``wpa_key``, ``wlan1_wpa_key``,
    or variations.  This function searches for those patterns.

    Args:
        config: Key-value dict from :func:`parse_config2`.

    Returns:
        Dict with keys ``ssid_24g``, ``password_24g``, ``ssid_5g``,
        ``password_5g``.  Missing values are empty strings.
    """
    result: dict[str, str] = {
        "ssid_24g": "",
        "password_24g": "",
        "ssid_5g": "",
        "password_5g": "",
    }

    # Known key name patterns (D-Link stock firmware variations)
    # 2.4 GHz radio (radio0 / wlan0)
    ssid_24g_keys = [
        "wlan_ssid", "wlan0_ssid", "wifi_ssid", "ssid",
        "default_ssid", "ap_ssid", "w24g_ssid",
    ]
    password_24g_keys = [
        "wlan_wpa_key", "wlan0_wpa_key", "wpa_key", "wifi_key",
        "default_wpa_key", "ap_key", "w24g_key", "wlan_key",
        "wlan_password", "wifi_password", "w24g_password",
    ]

    # 5 GHz radio (radio1 / wlan1)
    ssid_5g_keys = [
        "wlan1_ssid", "wlan5g_ssid", "wifi5g_ssid", "ssid_5g",
        "default_ssid_5g", "ap_ssid_5g", "w5g_ssid",
    ]
    password_5g_keys = [
        "wlan1_wpa_key", "wlan5g_wpa_key", "wpa_key_5g", "wifi5g_key",
        "default_wpa_key_5g", "w5g_key", "wlan1_key",
        "wlan1_password", "wifi5g_password", "w5g_password",
    ]

    def _find_first(keys: list[str]) -> str:
        for k in keys:
            v = config.get(k, "")
            if v:
                return v
        return ""

    result["ssid_24g"] = _find_first(ssid_24g_keys)
    result["password_24g"] = _find_first(password_24g_keys)
    result["ssid_5g"] = _find_first(ssid_5g_keys)
    result["password_5g"] = _find_first(password_5g_keys)

    return result


def _mac_to_int(mac: str) -> int:
    """Convert a MAC address string ``xx:xx:xx:xx:xx:xx`` to an integer."""
    return int(mac.replace(":", ""), 16)


def _int_to_mac(val: int) -> str:
    """Convert an integer to a MAC address string ``xx:xx:xx:xx:xx:xx``."""
    return ":".join(f"{(val >> (40 - 8 * i)) & 0xFF:02x}" for i in range(6))


def _derive_mac(base_mac: str, offset: int) -> str:
    """Derive a MAC address by adding *offset* to *base_mac*."""
    return _int_to_mac(_mac_to_int(base_mac) + offset)


def extract_mac_addresses(
    config: dict[str, str],
    model: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Extract factory MAC and derive WAN/WiFi MAC addresses.

    The factory (LAN) MAC is stored directly in the config2 partition.
    Other interface MACs are derived by adding offsets to the factory MAC.
    Offsets are read from the model JSON when available, falling back to
    the D-Link COVR-X1860 defaults (WAN=+3, 2.4G=+1, 5G=+2).

    Args:
        config: Key-value dict from :func:`parse_config2`.
        model: Optional model definition dict (from model_loader).
               If ``None``, COVR-X1860 defaults are used.

    Returns:
        Dict with keys ``factory_mac``, ``wan_mac``, ``wifi_24g_mac``,
        ``wifi_5g_mac``.  Derived MACs are computed even when the
        partition stores them explicitly.
    """
    # Try to find the factory MAC from known key names
    factory_mac = ""
    mac_keys = [
        "factory_mac", "lan_mac", "mac", "base_mac",
        "ethaddr", "et0macaddr", "mac_addr",
    ]
    for k in mac_keys:
        v = config.get(k, "")
        if _is_valid_mac(v):
            factory_mac = v.lower()
            break

    # Also scan raw values for any MAC-looking string if not found yet
    if not factory_mac:
        for k, v in config.items():
            v_stripped = v.strip()
            if _is_valid_mac(v_stripped) and "mac" in k.lower():
                factory_mac = v_stripped.lower()
                break

    result: dict[str, str] = {
        "factory_mac": factory_mac,
        "wan_mac": "",
        "wifi_24g_mac": "",
        "wifi_5g_mac": "",
    }

    if not factory_mac:
        return result

    # Read derivation offsets from model JSON, fall back to defaults
    defaults = {"wan": 3, "wifi_24g": 1, "wifi_5g": 2}
    if model:
        sticker = model.get("sticker_credentials", {})
        derivation = sticker.get("mac_derivation", {})
        defaults.update(derivation)

    result["wan_mac"] = _derive_mac(factory_mac, defaults["wan"])
    result["wifi_24g_mac"] = _derive_mac(factory_mac, defaults["wifi_24g"])
    result["wifi_5g_mac"] = _derive_mac(factory_mac, defaults["wifi_5g"])

    return result


def _is_valid_mac(s: str) -> bool:
    """Check if *s* is a valid MAC address string."""
    return bool(re.match(
        r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$", s.strip()
    ))


# ---------------------------------------------------------------------------
# SSH integration -- dump config2 from a running OpenWrt router
# ---------------------------------------------------------------------------

def _find_config2_mtd_index(ip: str, key: str | None = None) -> str | None:
    """Find the MTD index for the config2 partition via /proc/mtd.

    Returns the device path (e.g. ``/dev/mtd7``) or ``None``.
    """
    result = run_ssh(ip, "cat /proc/mtd", key=key, timeout=15)
    if result.returncode != 0:
        return None

    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            label = parts[2].strip('"')
            if label == _CONFIG2_PARTITION_LABEL:
                dev_name = parts[0].rstrip(":")
                return f"/dev/{dev_name}"

    return None


def dump_and_extract_config2(
    ip: str,
    key: str | None = None,
    password: str | None = None,
) -> dict[str, Any]:
    """SSH to an OpenWrt router, dump config2 via nanddump, and parse it.

    This function:
    1. Finds the config2 MTD partition via ``/proc/mtd``
    2. Dumps it with ``nanddump -f /tmp/config2.bin /dev/mtdX``
    3. SCPs it to a local temp file
    4. Parses the binary with :func:`parse_config2`

    Args:
        ip: Router IP address.
        key: Path to SSH private key (key-based auth).
        password: Root password (not used for key-based auth, included
                  for API compatibility with password-based SSH).

    Returns:
        Dict with keys ``config`` (all key-value pairs),
        ``wifi`` (extracted WiFi credentials), ``macs`` (MAC addresses).

    Raises:
        RuntimeError: If SSH connection fails or partition is not found.
    """
    # Step 1: Find the config2 MTD device
    mtd_dev = _find_config2_mtd_index(ip, key=key)
    if not mtd_dev:
        raise RuntimeError(
            f"Could not find '{_CONFIG2_PARTITION_LABEL}' partition "
            f"on {ip}. Check /proc/mtd output."
        )

    # Step 2: Dump to temp file on the router
    remote_path = "/tmp/config2_dump.bin"
    dump_cmd = f"nanddump -f {remote_path} {mtd_dev}"
    result = run_ssh(ip, dump_cmd, key=key, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(
            f"nanddump failed (rc={result.returncode}): "
            f"{result.stderr.strip()[:300]}"
        )

    # Step 3: SCP to local temp file
    tmp_fd, tmp_path = tempfile.mkstemp(suffix="_config2.bin")
    os.close(tmp_fd)
    try:
        scp_result = subprocess.run(
            scp_cmd(ip, f"root@{ip}:{remote_path}", tmp_path, key=key),
            capture_output=True, text=True, timeout=120, check=False,
        )
        if scp_result.returncode != 0:
            raise RuntimeError(
                f"SCP failed (rc={scp_result.returncode}): "
                f"{scp_result.stderr.strip()[:300]}"
            )

        # Step 4: Read and parse
        data = Path(tmp_path).read_bytes()
    finally:
        # Cleanup local temp file
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        # Cleanup remote temp file
        run_ssh(ip, f"rm -f {remote_path}", key=key, timeout=10)

    config = parse_config2(data)

    # Load model for MAC derivation offsets
    try:
        model = load_model(_MODEL_ID)
    except FileNotFoundError:
        model = None

    wifi = extract_wifi_credentials(config)
    macs = extract_mac_addresses(config, model=model)

    return {
        "config": config,
        "wifi": wifi,
        "macs": macs,
    }


# ---------------------------------------------------------------------------
# Post-flash credential application
# ---------------------------------------------------------------------------

def apply_credentials_to_openwrt(
    ip: str,
    wifi: dict[str, str],
    key: str | None = None,
    model_id: str = _MODEL_ID,
) -> bool:
    """Apply extracted sticker WiFi credentials to a freshly flashed OpenWrt.

    Sets the SSID and password on both radios to match the original sticker
    values, so the device behaves identically to its factory configuration.

    Args:
        ip: Router IP address (after OpenWrt boot).
        wifi: WiFi credential dict from :func:`extract_wifi_credentials`.
        key: Path to SSH private key.
        model_id: Model ID for radio detection.

    Returns:
        ``True`` if both radios were configured successfully.
    """
    success = True

    for band, radio_suffix in [("24g", "radio0"), ("5g", "radio1")]:
        ssid = wifi.get(f"ssid_{band}", "")
        password = wifi.get(f"password_{band}", "")

        if not ssid:
            continue

        # Detect actual radio for this band
        detect_cmd = (
            "for _r in radio0 radio1 radio2 radio3; do "
            f'_band=$(uci -q get "wireless.$_r.band" 2>/dev/null); '
            'case "$_band" in '
        )
        if band == "24g":
            detect_cmd += (
                "'2g') echo \"$_r\"; exit 0 ;; "
            )
        else:
            detect_cmd += (
                "'5g') echo \"$_r\"; exit 0 ;; "
            )
        detect_cmd += "esac; done"

        r = subprocess.run(
            ssh_cmd(ip, detect_cmd, key=key, connect_timeout=10),
            capture_output=True, text=True, timeout=30, check=False,
        )
        radio = r.stdout.strip()
        if not radio:
            # Fall back to default
            radio = radio_suffix

        # Build uci commands
        uci_cmds = [
            f"uci set wireless.default_{radio}=wifi-iface",
            f"uci set wireless.default_{radio}.device='{radio}'",
            f"uci set wireless.{radio}.disabled='0'",
            f"uci set wireless.default_{radio}.mode='ap'",
            f"uci set wireless.default_{radio}.ssid='{ssid}'",
            f"uci set wireless.default_{radio}.encryption='psk2'",
            f"uci set wireless.default_{radio}.key='{password}'",
            "uci set wireless.default_{radio}.network='lan'",
            "uci commit wireless",
            "wifi reload",
        ]
        uci_chain = " && ".join(uci_cmds)

        r2 = subprocess.run(
            ssh_cmd(ip, uci_chain, key=key, connect_timeout=10),
            capture_output=True, text=True, timeout=60, check=False,
        )
        if r2.returncode != 0:
            print(
                f"WARNING: Failed to apply {band} credentials on {radio} "
                f"(rc={r2.returncode}): {r2.stderr.strip()[:200]}",
                file=sys.stderr,
            )
            success = False
        else:
            print(f"  Applied {band} WiFi credentials on {radio}: SSID={ssid}")

    return success


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _format_output(data: dict[str, Any]) -> str:
    """Format extracted credentials for human-readable output."""
    lines: list[str] = []

    macs = data.get("macs", {})
    wifi = data.get("wifi", {})
    config = data.get("config", {})

    lines.append("=" * 60)
    lines.append("Sticker Credentials (from config2 partition)")
    lines.append("=" * 60)

    if macs.get("factory_mac"):
        lines.append("")
        lines.append("MAC Addresses:")
        lines.append(f"  Factory (LAN): {macs['factory_mac']}")
        lines.append(f"  WAN:           {macs['wan_mac']}")
        lines.append(f"  WiFi 2.4GHz:   {macs['wifi_24g_mac']}")
        lines.append(f"  WiFi 5GHz:     {macs['wifi_5g_mac']}")

    if wifi.get("ssid_24g") or wifi.get("ssid_5g"):
        lines.append("")
        lines.append("WiFi Credentials:")
        if wifi.get("ssid_24g"):
            lines.append(f"  2.4 GHz SSID:    {wifi['ssid_24g']}")
            lines.append(f"  2.4 GHz Password: {wifi['password_24g']}")
        if wifi.get("ssid_5g"):
            lines.append(f"  5 GHz SSID:      {wifi['ssid_5g']}")
            lines.append(f"  5 GHz Password:   {wifi['password_5g']}")

    lines.append("")
    lines.append(f"All config2 keys ({len(config)} found):")
    for k in sorted(config.keys()):
        lines.append(f"  {k} = {config[k]}")

    lines.append("")
    return "\n".join(lines)


def main() -> int:
    """CLI entry point.

    Usage:
        python3 sticker_creds.py <config2.bin>
        python3 sticker_creds.py --ip 192.168.1.1 [--key ~/.ssh/id_ed25519]
    """
    parser = argparse.ArgumentParser(
        description=(
            "Extract factory WiFi SSID/password and MAC addresses "
            "from D-Link COVR-X1860 config2 MTD partition dumps."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s config2.bin\n"
            "  %(prog)s --ip 192.168.1.1\n"
            "  %(prog)s --ip 192.168.1.1 --key ~/.ssh/id_ed25519\n"
            "  %(prog)s --ip 192.168.1.1 --json\n"
        ),
    )
    parser.add_argument(
        "binfile",
        nargs="?",
        help="Path to a local config2 .bin dump file",
    )
    parser.add_argument(
        "--ip",
        help="Router IP address (dump config2 via SSH)",
    )
    parser.add_argument(
        "--key",
        help="Path to SSH private key for router connection",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output as JSON instead of human-readable text",
    )
    parser.add_argument(
        "--model-id",
        default=_MODEL_ID,
        help=f"Model ID (default: {_MODEL_ID})",
    )

    args = parser.parse_args()

    if not args.binfile and not args.ip:
        parser.error("Provide a .bin file path or --ip to dump from a router.")

    if args.binfile and args.ip:
        parser.error("Provide either a .bin file path OR --ip, not both.")

    # Load model for MAC derivation offsets
    try:
        model = load_model(args.model_id)
    except FileNotFoundError:
        print(
            f"WARNING: Model '{args.model_id}' not found, using defaults.",
            file=sys.stderr,
        )
        model = None

    if args.binfile:
        # Parse local file
        bin_path = Path(args.binfile)
        if not bin_path.is_file():
            print(f"ERROR: File not found: {bin_path}", file=sys.stderr)
            return 1

        data = bin_path.read_bytes()
        config = parse_config2(data)
        wifi = extract_wifi_credentials(config)
        macs = extract_mac_addresses(config, model=model)

        output_data = {
            "config": config,
            "wifi": wifi,
            "macs": macs,
        }
    else:
        # Dump via SSH
        try:
            output_data = dump_and_extract_config2(
                ip=args.ip,
                key=args.key,
            )
        except RuntimeError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1

    if args.json_output:
        print(json.dumps(output_data, indent=2))
    else:
        print(_format_output(output_data))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
