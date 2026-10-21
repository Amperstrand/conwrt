"""conwrt#228 — trust-on-first-boot host-side tooling.

Companion to docs/adr/ADR-0013-trust-on-first-boot.md. The device side
(scripts/tofb-device.sh, shipped into images via the profile builder in a
follow-up) generates an ed25519 host key on first boot, derives a 6-digit
attestation code from it, shows the code on the status LED, and serves a
link-local enrollment endpoint. This module is the operator side:

- derive the same 6-digit code from a host key the client sees over the
  network (ssh-keyscan output), so the operator can compare it against the
  LED;
- POST an operator public key to the device endpoint once the codes match.

All cryptography is platform primitives (hashlib/ssl stdlib); the code is a
truncated SHA-256 of the decoded public key blob, exactly as the device
computes it with BusyBox sha256sum.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import urllib.request
from typing import Optional

CODE_DIGITS = 6
LED_COLORS = ("red", "orange", "white")
ENDPOINT_FAILURES_LIMIT = 3


def key_blob(pubkey_line: str) -> bytes:
    """Decode the base64 key body from an OpenWire-format public key line.

    Accepts the single-line format dropbear and OpenSSH both emit/print
    (``<type> <base64> [comment]``). Raises ValueError on malformed input —
    TOFB must fail closed on anything it cannot hash deterministically.
    """
    fields = pubkey_line.strip().split()
    if len(fields) < 2:
        raise ValueError(f"not a public key line: {pubkey_line[:40]!r}")
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except Exception as e:
        raise ValueError(f"bad base64 key body: {e}") from e
    if not blob:
        raise ValueError("empty key body")
    return blob


def tofb_code(pubkey_line: str) -> str:
    """Derive the 6-digit LED attestation code for a public key.

    digest = SHA-256(key blob); code = int.from_bytes(digest[:8], "big")
    % 10**CODE_DIGITS, zero-padded. Mirrors the device-side derivation
    (BusyBox: ``base64 -d | sha256sum``, first 8 hex chars as u64).
    """
    digest = hashlib.sha256(key_blob(pubkey_line)).digest()
    value = int.from_bytes(digest[:8], "big") % (10**CODE_DIGITS)
    return str(value).zfill(CODE_DIGITS)


def led_sequence(code: str) -> list[tuple[str, int]]:
    """Encode the code as the LED display plan (ADR-0013 §2).

    Group i uses color i mod 3 so positions are self-locating on the
    single 3-color indicator; the digit is the blink count (0 renders as
    one long blink).
    """
    if len(code) != CODE_DIGITS or not code.isdigit():
        raise ValueError(f"code must be {CODE_DIGITS} digits: {code!r}")
    return [(LED_COLORS[i % 3], int(d)) for i, d in enumerate(code)]


def enrollment_url(device: str, interface: Optional[str] = None) -> str:
    """Build the scoped link-local enrollment URL for the device."""
    if not device.startswith("fe80:"):
        raise ValueError(f"TOFB enrollment is link-local only, got {device!r}")
    host = f"[{device}%25{interface}]" if interface else f"[{device}]"
    return f"http://{host}/tofb-enroll"


def enroll(device: str, code: str, pubkey_line: str, interface: Optional[str] = None,
           timeout: float = 10.0) -> dict:
    """POST the operator key + code to the device enrollment endpoint.

    Returns the parsed JSON response. Raises on HTTP errors; the device
    kills the endpoint after ENDPOINT_FAILURES_LIMIT wrong codes.
    """
    url = enrollment_url(device, interface)
    payload = json.dumps({"code": code, "pubkey": pubkey_line.strip()}).encode()
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_code = sub.add_parser("code", help="derive the LED code for a public key")
    p_code.add_argument("pubkey_line", help="public key line, or - for stdin")

    p_seq = sub.add_parser("led", help="show the LED blink plan for a code")
    p_seq.add_argument("code", help="6-digit code")

    p_enroll = sub.add_parser("enroll", help="enroll an operator key on a device")
    p_enroll.add_argument("--device", required=True, help="link-local address (fe80::...)")
    p_enroll.add_argument("--interface", help="scope (zone) interface for the target")
    p_enroll.add_argument("--code", required=True, help="the 6-digit code shown on the LED")
    p_enroll.add_argument("--pubkey", default="~/.ssh/id_ed25519.pub",
                          help="operator public key file")

    args = parser.parse_args(argv)

    if args.cmd == "code":
        line = sys.stdin.readline() if args.pubkey_line == "-" else args.pubkey_line
        print(tofb_code(line))
        return 0
    if args.cmd == "led":
        for color, blinks in led_sequence(args.code):
            kind = "long blink" if blinks == 0 else f"{blinks} blinks"
            print(f"{color:6} {kind}")
        return 0
    if args.cmd == "enroll":
        import os
        path = os.path.expanduser(args.pubkey)
        with open(path) as fh:
            pubkey_line = fh.readline().strip()
        result = enroll(args.device, args.code, pubkey_line, args.interface)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
