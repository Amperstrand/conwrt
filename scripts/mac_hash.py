#!/usr/bin/env python3
"""Deterministic IP and hostname derivation from MAC addresses.

Used by the profile system to generate unique, deterministic LAN IPs
and hostnames for each device based on its MAC address. The same device
always gets the same IP/hostname regardless of how many times it's flashed.

Uses SHA-256 for derivation — universally available on OpenWrt (BusyBox
sha256sum is required by base-files since 2018).

LAN IP scheme: ``10.<h2>.<h3>.1``
- h2, h3 derived from SHA-256 hash of the MAC (matching BusyBox sha256sum)
- Last octet always 1 (gateway address)
- Each device gets its own /24 subnet
- 62,500 possible subnets (250 × 250)

The on-device shell equivalent::

    _hash=$(printf '%s' "$_mac_clean" | sha256sum)
    _o2=$(printf '%d' 0x$(printf '%s' "$_hash" | cut -c1-8))
    _o2=$((_o2 % 250 + 1))
    _o3=$(printf '%d' 0x$(printf '%s' "$_hash" | cut -c9-16))
    _o3=$((_o3 % 250 + 1))
"""
from __future__ import annotations

import hashlib


HASH_ALGORITHM = "sha256"
HASH_BYTES = 32  # SHA-256 produces 32 bytes (64 hex chars)


def _hash_mac_hex(mac: str) -> str:
    """Clean and SHA-256 hash a MAC address, returning hex digest.

    Strips colons, dashes, and dots, lowercases, then SHA-256 hashes.
    Matches the BusyBox ``sha256sum`` output on-device.
    """
    mac_clean = mac.lower().replace(":", "").replace("-", "").replace(".", "")
    return hashlib.sha256(mac_clean.encode()).hexdigest()


def mac_to_subnet_octets(mac: str) -> tuple[int, int]:
    """Derive two subnet octets (1-250) from a MAC address.

    Uses SHA-256 hash of the cleaned MAC string (matching the BusyBox
    sha256sum used in the on-device shell script). First 8 hex chars
    → octet 2, next 8 hex chars → octet 3. Each mapped to 1-250 to
    avoid 0 and 255 (broadcast).
    """
    h = _hash_mac_hex(mac)
    o2 = (int(h[:8], 16) % 250) + 1
    o3 = (int(h[8:16], 16) % 250) + 1
    return (o2, o3)


def mac_to_lan_ip(mac: str) -> str:
    """Derive full LAN IP from MAC: ``10.<h2>.<h3>.1``.

    Args:
        mac: MAC address in any common format (aa:bb:cc:dd:ee:ff)

    Returns:
        Full IP like ``"10.42.137.1"``
    """
    o2, o3 = mac_to_subnet_octets(mac)
    return f"10.{o2}.{o3}.1"


def mac_to_lan_prefix(mac: str) -> str:
    """Derive LAN subnet prefix from MAC: ``10.<h2>.<h3>``.

    Args:
        mac: MAC address in any common format

    Returns:
        Subnet prefix like ``"10.42.137"``
    """
    o2, o3 = mac_to_subnet_octets(mac)
    return f"10.{o2}.{o3}"


def mac_to_hostname_suffix(mac: str) -> str:
    """Get last 3 bytes of MAC as 6-char hex string.

    ``"aa:bb:cc:dd:ee:ff"`` → ``"ddeeff"``
    """
    mac_clean = mac.lower().replace(":", "").replace("-", "").replace(".", "")
    return mac_clean[-6:]
