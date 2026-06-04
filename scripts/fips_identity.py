"""Deterministic FIPS identity derivation from MAC addresses.

Derivation chain:
    MAC address → sha256 → secp256k1 private key → public key → bech32 (nsec/npub)

Uses pure-Python secp256k1 point arithmetic and BIP173 bech32 encoding.
No external dependencies beyond the standard library.

Usage:
    python3 scripts/fips_identity.py AA:BB:CC:DD:EE:FF
"""
from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# secp256k1 curve parameters
# ---------------------------------------------------------------------------
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_A = 0
_B = 7
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _modinv(a: int, m: int) -> int:
    """Modular inverse via extended Euclidean algorithm."""
    if a < 0:
        a = a % m
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m


def _extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def _point_add(p1: tuple[int, int] | None, p2: tuple[int, int] | None) -> tuple[int, int] | None:
    """Add two points on the secp256k1 curve. None represents the point at infinity."""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if y1 != y2:
            return None  # P + (-P) = O
        # Point doubling
        lam = (3 * x1 * x1 + _A) * _modinv(2 * y1, _P) % _P
    else:
        lam = (y2 - y1) * _modinv(x2 - x1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return x3, y3


def _point_mul(k: int, point: tuple[int, int] | None) -> tuple[int, int] | None:
    """Scalar multiplication using double-and-add."""
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _private_to_public(privkey: bytes) -> bytes:
    """Derive x-only public key (32 bytes) from private key using secp256k1."""
    k = int.from_bytes(privkey, "big")
    k = k % _N  # ensure within curve order
    pubkey_point = _point_mul(k, (_GX, _GY))
    if pubkey_point is None:
        raise ValueError("Invalid private key")
    # x-only public key: just the x-coordinate as 32 bytes
    return pubkey_point[0].to_bytes(32, "big")


# ---------------------------------------------------------------------------
# Bech32 encoding (BIP173)
# ---------------------------------------------------------------------------
_BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> list[int]:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            raise ValueError(f"Invalid value: {value}")
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("Non-zero padding")
    return ret


def bech32_encode(hrp: str, data: bytes) -> str:
    """Encode bytes as a bech32 string with the given human-readable prefix."""
    five_bit = _convertbits(data, 8, 5, pad=True)
    checksum = _bech32_create_checksum(hrp, five_bit)
    return hrp + "1" + "".join(_BECH32_CHARSET[d] for d in five_bit + checksum)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
@dataclass
class FIPSIdentity:
    """Deterministic FIPS identity derived from a MAC address."""
    private_key: bytes  # 32 bytes (sha256 of MAC)
    public_key: bytes   # 32 bytes (x-only secp256k1)
    nsec: str           # bech32-encoded private key (nsec1...)
    npub: str           # bech32-encoded public key (npub1...)


def derive_identity(mac: str) -> FIPSIdentity:
    """Derive a deterministic FIPS identity from a MAC address.

    Chain: MAC → sha256 → secp256k1 private key → x-only public key → bech32
    """
    mac_clean = mac.lower().replace(":", "").replace("-", "").replace(".", "")
    private_key = hashlib.sha256(mac_clean.encode()).digest()
    public_key = _private_to_public(private_key)
    nsec = bech32_encode("nsec", private_key)
    npub = bech32_encode("npub", public_key)
    return FIPSIdentity(
        private_key=private_key,
        public_key=public_key,
        nsec=nsec,
        npub=npub,
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} AA:BB:CC:DD:EE:FF", file=sys.stderr)
        sys.exit(1)
    identity = derive_identity(sys.argv[1])
    print(f"npub: {identity.npub}")
    print(f"nsec: {identity.nsec}")
    print(f"pubkey (hex): {identity.public_key.hex()}")
