#!/usr/bin/env python3
"""Generate a random Nostr keypair.

Outputs two lines: nsec1... (private key) then npub1... (public key).

Uses coincurve or secp256k1 library if available, otherwise falls back
to a pure-Python secp256k1 implementation using Python's native big integers.
"""
from __future__ import annotations

import hashlib
import os
import sys

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def bech32_polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp: str, data: list[int]) -> str:
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join([BECH32_CHARSET[d] for d in combined])


def bech32_decode(s: str) -> tuple[str, list[int]]:
    pos = s.rfind("1")
    hrp = s[:pos]
    data = [BECH32_CHARSET.index(c) for c in s[pos + 1:]]
    return hrp, data[:-6]


def convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> list[int]:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return []
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return []
    return ret


def _point_add(P: tuple[int, int] | None, Q: tuple[int, int] | None) -> tuple[int, int] | None:
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 != y2:
        return None
    lam = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (lam * lam - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _point_double(P: tuple[int, int] | None) -> tuple[int, int] | None:
    if P is None:
        return None
    x, y = P
    lam = (3 * x * x) * pow(2 * y, -1, _P) % _P
    x3 = (lam * lam - 2 * x) % _P
    y3 = (lam * (x - x3) - y) % _P
    return (x3, y3)


def _scalar_mul(k: int, P: tuple[int, int]) -> tuple[int, int] | None:
    result: tuple[int, int] | None = None
    addend = P
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_double(addend)
        k >>= 1
    return result


def derive_pubkey_compressed(privkey_bytes: bytes) -> bytes:
    d = int.from_bytes(privkey_bytes, "big")
    if d == 0 or d >= _N:
        raise ValueError("invalid private key")
    point = _scalar_mul(d, (_GX, _GY))
    assert point is not None
    x, y = point
    prefix = b"\x02" if y % 2 == 0 else b"\x03"
    return prefix + x.to_bytes(32, "big")


def _generate_privkey() -> bytes:
    privkey = os.urandom(32)
    d = int.from_bytes(privkey, "big")
    while d == 0 or d >= _N:
        privkey = os.urandom(32)
        d = int.from_bytes(privkey, "big")
    return privkey


def _derive_pubkey(privkey: bytes) -> bytes:
    try:
        import coincurve
        return coincurve.PrivateKey(privkey).public_key.format(compressed=True)
    except ImportError:
        pass
    try:
        import secp256k1
        return secp256k1.PrivateKey(privkey).pubkey.serialize(compressed=True)
    except ImportError:
        pass
    return derive_pubkey_compressed(privkey)


def generate_keypair() -> tuple[str, str]:
    """Generate a Nostr keypair.

    Returns (nsec, npub) where nsec is the bech32-encoded private key
    and npub is the bech32-encoded compressed public key.
    """
    privkey = _generate_privkey()
    nsec = bech32_encode("nsec", convertbits(privkey, 8, 5))
    pubkey = _derive_pubkey(privkey)
    npub = bech32_encode("npub", convertbits(pubkey, 8, 5))
    return nsec, npub


def main() -> None:
    nsec, npub = generate_keypair()
    print(nsec)
    print(npub)


if __name__ == "__main__":
    main()
