"""Deterministic IP and hostname derivation from MAC addresses.

Used by the profile system to generate unique, deterministic LAN IPs
and hostnames for each device based on its MAC address. The same device
always gets the same IP/hostname regardless of how many times it's flashed.
"""
from __future__ import annotations

import hashlib


def mac_to_host_byte(mac: str) -> int:
    """Derive a deterministic host byte (2-201) from a MAC address.

    Uses sha256 hash of the cleaned MAC string, takes first 4 bytes as
    uint32, modulo 200 + 2 to avoid .0, .1, and .255.
    """
    mac_clean = mac.lower().replace(':', '').replace('-', '').replace('.', '')
    h = hashlib.sha256(mac_clean.encode()).digest()
    val = int.from_bytes(h[:4], 'big')
    return (val % 200) + 2


def mac_to_lan_ip(mac: str, subnet_prefix: str) -> str:
    """Derive full LAN IP from MAC and subnet prefix.

    Args:
        mac: MAC address in any common format (aa:bb:cc:dd:ee:ff)
        subnet_prefix: First three octets, e.g. "10.231.9"

    Returns:
        Full IP like "10.231.9.42"
    """
    return f"{subnet_prefix}.{mac_to_host_byte(mac)}"


def mac_to_hostname_suffix(mac: str) -> str:
    """Get last 3 bytes of MAC as 6-char hex string.

    "aa:bb:cc:dd:ee:ff" → "ddeeff"
    """
    mac_clean = mac.lower().replace(':', '').replace('-', '').replace('.', '')
    return mac_clean[-6:]
