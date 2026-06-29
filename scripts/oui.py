#!/usr/bin/env python3
"""OUI (Organizationally Unique Identifier) vendor lookup.

Curated database of common networking vendors encountered in OpenWrt
router flashing. Each OUI prefix (first 3 octets of a MAC address) maps
to a vendor name. This is NOT the full IEEE database (~35,000 entries) --
just the ~40 vendors we actually see on routers, switches, and APs.

Usage as module:
    from oui import oui_lookup
    vendor = oui_lookup("d8:5d:84:11:22:33")  # -> "ZyXEL"

Usage as CLI:
    python3 scripts/oui.py d8:5d:84:11:22:33
    python3 scripts/oui.py d8-5d-84-11-22-33
    python3 scripts/oui.py d85d.8411.2233
"""

from __future__ import annotations

import re
import sys

# ---------------------------------------------------------------------------
# Curated OUI database
#
# Each key is a 3-octet MAC prefix in lowercase "xx:xx:xx" form.
# Sources: IEEE public OUI assignments + vendor documentation.
# Only vendors relevant to router/switch/AP flashing are included.
# ---------------------------------------------------------------------------

_OUI_DATABASE: dict[str, str] = {
    # --- Consumer / SMB router manufacturers ---

    "d8:5d:84": "ZyXEL",
    "c4:30:18": "ZyXEL",
    "e4:bd:4f": "ZyXEL",
    "00:19:cb": "ZyXEL",

    "00:13:46": "D-Link",
    "00:15:e9": "D-Link",
    "00:17:9a": "D-Link",
    "1c:7e:e5": "D-Link",
    "fc:75:16": "D-Link",

    "4c:11:bf": "TP-Link",
    "50:c7:bf": "TP-Link",
    "14:cc:20": "TP-Link",
    "60:32:b1": "TP-Link",
    "ac:84:c6": "TP-Link",
    "ec:08:6b": "TP-Link",

    "00:1b:2f": "Netgear",
    "c0:3f:0e": "Netgear",
    "9c:3d:cf": "Netgear",
    "44:a5:6e": "Netgear",
    "b0:7f:b9": "Netgear",

    "00:14:6c": "Linksys",
    "00:1a:70": "Linksys",
    "00:06:25": "Linksys",
    "30:23:03": "Linksys",
    "c0:c1:c0": "Linksys",

    "94:83:c4": "GL.iNet",
    "dc:e6:07": "GL.iNet",

    "00:1a:92": "ASUS",
    "04:d9:f5": "ASUS",
    "ac:9e:17": "ASUS",
    "f8:32:e4": "ASUS",

    "00:25:9e": "Huawei",
    "00:18:82": "Huawei",
    "48:46:fb": "Huawei",
    "cc:39:60": "Huawei",

    "00:0c:42": "MikroTik",
    "2c:c8:1b": "MikroTik",
    "d4:ca:6d": "MikroTik",
    "48:8f:5a": "MikroTik",

    "00:27:22": "Ubiquiti",
    "04:18:d6": "Ubiquiti",
    "68:72:51": "Ubiquiti",
    "fc:ec:da": "Ubiquiti",
    "78:8a:20": "Ubiquiti",

    "64:09:80": "Xiaomi",
    "28:6c:07": "Xiaomi",
    "34:ce:00": "Xiaomi",

    "c8:3a:35": "Tenda",
    "00:0d:0b": "Tenda",

    "00:0c:43": "COMFAST",

    # --- Enterprise networking ---

    "00:00:0c": "Cisco",
    "00:01:42": "Cisco",
    "00:01:63": "Cisco",
    "00:01:96": "Cisco",
    "00:1b:54": "Cisco",
    "00:24:14": "Cisco",
    "00:26:0b": "Cisco",
    "00:50:50": "Cisco",

    "00:0b:86": "Aruba",
    "00:24:6c": "Aruba",
    "20:4c:03": "Aruba",
    "d8:c7:c8": "Aruba",

    "00:01:30": "Extreme Networks",
    "00:04:96": "Extreme Networks",
    "00:90:0d": "Extreme Networks",

    "00:05:85": "Juniper",
    "00:12:1e": "Juniper",
    "2c:6b:f5": "Juniper",

    "00:1c:73": "Arista",

    "00:1f:41": "Ruckus",
    "00:25:c4": "Ruckus",
    "8c:1b:63": "Ruckus",

    "00:14:22": "Dell",
    "f8:db:88": "Dell",

    "00:1f:29": "HP",
    "00:23:7d": "HP",
    "00:0e:7e": "HP",

    "00:09:0f": "Fortinet",
    "00:0f:e2": "Fortinet",

    # --- Silicon / chip vendors (appear on dev boards / reference designs) ---

    "00:e0:4c": "Realtek",
    "00:03:7f": "Qualcomm Atheros",
    "00:50:43": "Marvell",
    "00:10:18": "Broadcom",

    # --- Consumer electronics / other networking ---

    "00:03:93": "Apple",
    "a4:5e:60": "Apple",
    "d0:81:7a": "Apple",

    "00:24:fe": "AVM",
    "00:0b:57": "AVM",

    "00:11:50": "Belkin",
    "00:17:3f": "Belkin",

    "00:14:d1": "TRENDnet",

    "00:15:6d": "Engenius",

    "00:1c:7e": "DrayTek",

    "00:50:fc": "Edimax",

    "00:1e:c2": "Sophos",

    "00:30:88": "WatchGuard",

    "00:11:32": "Synology",
    "00:08:9b": "QNAP",

    "00:02:c9": "Mellanox",
    "00:07:43": "Chelsio",

    "00:25:90": "Super Micro",

    "00:01:d7": "F5 Networks",

    "00:1e:42": "Teltonika",

    # --- ODM (Original Design Manufacturers) ---
    # These appear on white-label devices rebadged by many router brands.

    "00:11:4c": "SerComm",
    "00:30:1a": "Wistron",
    "00:22:b0": "Wistron",
}


# ---------------------------------------------------------------------------
# MAC normalization
# ---------------------------------------------------------------------------

_SEP_RE = re.compile(r"[:.\-\s]")
_HEX_RE = re.compile(r"[0-9a-f]+")


def _normalize_oui(mac: str) -> str | None:
    """Extract a 3-octet OUI prefix from any MAC address format.

    Handles all common formats:
        AA:BB:CC:DD:EE:FF   (colon-separated, POSIX)
        AA-BB-CC-DD-EE-FF   (hyphen-separated, Windows)
        AABB.CCDD.EEFF      (dot-separated, Cisco IOS)
        AABBCCDDEEFF        (no separators, compact)
        aa:bb:cc:dd:ee:ff   (lowercase)

    Returns the OUI in lowercase "xx:xx:xx" form, or None if the input
    is too short, empty, or contains non-hex characters.
    """
    if not mac:
        return None
    cleaned = _SEP_RE.sub("", mac).lower()
    if len(cleaned) < 6 or not _HEX_RE.fullmatch(cleaned):
        return None
    return f"{cleaned[0:2]}:{cleaned[2:4]}:{cleaned[4:6]}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def oui_lookup(mac: str) -> str | None:
    """Look up the vendor name for a MAC address.

    Args:
        mac: MAC address in any common format (colon, hyphen, dot,
             or no separator; upper or lower case).

    Returns:
        Vendor name (e.g., "ZyXEL") if the OUI is in the curated
        database, or None if not found or the MAC is invalid.
    """
    oui = _normalize_oui(mac)
    if oui is None:
        return None
    return _OUI_DATABASE.get(oui)


def oui_vendor_count() -> int:
    """Return the number of unique vendors in the OUI database."""
    return len(set(_OUI_DATABASE.values()))


def oui_prefix_count() -> int:
    """Return the total number of OUI prefixes in the database."""
    return len(_OUI_DATABASE)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <MAC-address>", file=sys.stderr)
        print(f"  e.g. {sys.argv[0]} d8:5d:84:11:22:33", file=sys.stderr)
        sys.exit(1)
    mac = sys.argv[1]
    vendor = oui_lookup(mac)
    if vendor:
        print(f"{mac} -> {vendor}")
    else:
        print(f"{mac} -> unknown (OUI not in curated database)")
        sys.exit(1)


if __name__ == "__main__":
    main()
