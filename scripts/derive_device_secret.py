#!/usr/bin/env python3
"""Derive per-device secrets from a fleet mnemonic + MAC address.

Replaces generate_nostr_keypair.py for fleet deployments. Given one
fleet-wide BIP39 mnemonic and a device's MAC address, deterministically
derives every secret the device needs:

  - Nostr private key (via HKDF from fleet seed + MAC salt)
  - Nostr npub (via secp256k1)
  - LAN IPv4 (CGNAT 100.64/10, matching identity.DeriveIPv4)
  - Per-interface MACs (matching identity.DeriveMAC)
  - Root password (NATO word format)
  - WiFi password (NATO word format)

No per-device database needed — re-running with the same mnemonic + MAC
always produces identical output. The fleet mnemonic (12 words) is the
single backup for the entire fleet.

Security properties (RFC 5869 HKDF):
  - Salt (MAC) is public — RFC 5869 explicitly allows this
  - One device's secret reveals nothing about others (HKDF key separation)
  - Fleet mnemonic compromise = all devices compromised (keep it offline)

Usage:
    python3 scripts/derive_device_secret.py \\
        --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" \\
        --mac aa:bb:cc:dd:ee:ff

    python3 scripts/derive_device_secret.py --mnemonic-file fleet.txt --mac 4c:c5:3e:12:34:56 --json
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys

# Reuse conwrt's existing secp256k1 + bech32 implementation
sys.path.insert(0, "scripts")
from generate_nostr_keypair import (
    derive_pubkey_compressed,
    bech32_encode,
    convertbits,
)

NATO_WORDS = [
    "Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot", "Golf",
    "Hotel", "India", "Juliet", "Kilo", "Lima", "Mike", "November",
    "Oscar", "Papa", "Quebec", "Romeo", "Sierra", "Tango", "Uniform",
    "Victor", "Whiskey", "Xray", "Yankee", "Zulu",
]

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _mnemonic_to_seed(mnemonic: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), b"mnemonic", 2048, dklen=64)


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    okm, t, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def derive_device_secret(mnemonic: str, mac: str) -> bytes:
    mac_clean = mac.lower().replace(":", "").replace("-", "").replace(".", "")
    seed = _mnemonic_to_seed(mnemonic)
    salt = bytes.fromhex(mac_clean)
    prk = _hkdf_extract(salt, seed)
    secret = _hkdf_expand(prk, b"tollgate-device-v1", 32)
    d = int.from_bytes(secret, "big")
    if d == 0 or d >= SECP256K1_N:
        raise ValueError("derived secret is not a valid secp256k1 scalar")
    return secret


def _derive_hash(domain_sep: str, pub_key_hex: str) -> bytes:
    h = hashlib.sha256()
    h.update(domain_sep.encode())
    h.update(pub_key_hex.encode())
    return h.digest()


def derive_ipv4(pub_key_hex: str) -> str:
    h = _derive_hash("tollgate-ipv4-v1:", pub_key_hex)
    return f"100.{64 + h[0] % 64}.{h[1]}.1"


def derive_mac_addr(pub_key_hex: str, iface: str) -> str:
    h = _derive_hash(f"tollgate-mac-v1:{iface}:", pub_key_hex)
    m = bytearray(h[:6])
    m[0] = (m[0] & 0xFC) | 0x02
    return ":".join(f"{b:02x}" for b in m)


def derive_root_password(pub_key_hex: str) -> str:
    h = _derive_hash("tollgate-root-pw-v1:", pub_key_hex)
    return f"{NATO_WORDS[h[0] % len(NATO_WORDS)]}-{NATO_WORDS[h[1] % len(NATO_WORDS)]}-{NATO_WORDS[h[2] % len(NATO_WORDS)]}-{h[3] % 100:02d}"


def derive_wifi_password(pub_key_hex: str, network: str = "private") -> str:
    h = _derive_hash(f"tollgate-wifi-pw-v1:{network}:", pub_key_hex)
    return f"{NATO_WORDS[h[0] % len(NATO_WORDS)]}-{NATO_WORDS[h[1] % len(NATO_WORDS)]}-{((h[2] << 8) | h[3]) % 10000:04d}"


def derive_all(mnemonic: str, mac: str) -> dict:
    secret = derive_device_secret(mnemonic, mac)
    priv_hex = secret.hex()
    pub_bytes = derive_pubkey_compressed(secret)
    pub_x_hex = pub_bytes[1:33].hex()
    npub = bech32_encode("npub", convertbits(bytes.fromhex(pub_x_hex), 8, 5))
    return {
        "mac": mac,
        "private_key": priv_hex,
        "npub": npub,
        "pubkey_hex": pub_x_hex,
        "ipv4": derive_ipv4(pub_x_hex),
        "mac_br_lan": derive_mac_addr(pub_x_hex, "br-lan"),
        "mac_wlan0": derive_mac_addr(pub_x_hex, "wlan0"),
        "mac_wlan1": derive_mac_addr(pub_x_hex, "wlan1"),
        "root_password": derive_root_password(pub_x_hex),
        "wifi_password": derive_wifi_password(pub_x_hex, "private"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--mnemonic", help="12-word BIP39 fleet mnemonic (quoted)")
    g.add_argument("--mnemonic-file", help="File containing the fleet mnemonic (first line)")
    parser.add_argument("--mac", required=True, help="Device MAC address")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    args = parser.parse_args()

    if args.mnemonic_file:
        with open(args.mnemonic_file) as f:
            mnemonic = f.readline().strip()
    else:
        mnemonic = args.mnemonic

    result = derive_all(mnemonic, args.mac)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        for k, v in result.items():
            print(f"{k:20s} {v}")


if __name__ == "__main__":
    main()
