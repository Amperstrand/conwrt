#!/usr/bin/env python3
"""Deterministic per-device fleet secrets derived from MAC + fleet salt.

Pattern follows tollgate-module-basic-go ``src/identity/identity.go``:
domain-separated, versioned derivations from a single per-device root, so
one scheme evolves without invalidating every device at once. Here the
root is ``<fleet salt>:<device MAC>`` — the salt is operator-private
(config.toml / env, never committed), the MAC is on the unit's label, so
an operator can compute a unit's credentials BEFORE it ever boots, and
the password is not derivable from public data alone.

Derived attributes (all from sha256, BusyBox-compatible):
  - root password   domain ``root``           -> first N hex chars (default 20 = 80 bits)
  - wifi password   domain ``wifi:<network>`` -> first N hex chars (applied on-device
                    as the management-AP PSK by the fleet_identity use case on
                    radio-equipped models like the NR7101)
  - hostname        ``<prefix>-<mac12>``      (e.g. nr7101-aabbccddeeff)
  - wifi SSID       ``<prefix>_<mac12>``      (e.g. nr7101_aabbccddeeff)
  - LAN IP          re-exported from mac_hash (10.<h2>.<h3>.1)

The on-device shell equivalent (BusyBox ash, no extra tools — the same
idiom mac_hash.py documents)::

    _mac=$(cat /sys/class/net/eth0/address)          # aa:bb:cc:dd:ee:ff
    _m=$(printf '%s' "$_mac" | tr -d ':')
    _pw=$(printf '%s' "conwrt-fleet-v1:root:$_salt:$_m" | sha256sum | cut -c1-20)

``scripts/use_cases/fleet_identity.py`` ships exactly that pipeline as a
first-boot/SSH-apply script; this module is the host-side twin used to
look credentials up for the operator and to cross-check the device.

CLI:
    python3 scripts/fleet_secrets.py --mac AA:BB:CC:DD:EE:FF --salt <salt> [--json]
    CONWRT_FLEET_SALT=<salt> python3 scripts/fleet_secrets.py --mac ...
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys

# Bumped when the derivation format changes; both sides (this module and
# the fleet_identity use case script) embed it in every hashed string, so
# a bump only affects freshly configured devices.
DOMAIN_VERSION = "conwrt-fleet-v1"

# Salt charset: keeps the salt safely embeddable in single-quoted shell.
SALT_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")

DEFAULT_PASSWORD_LENGTH = 20
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 32


def clean_mac(mac: str) -> str:
    """Lowercase MAC with :, - and . stripped -> 12 hex chars."""
    return mac.lower().replace(":", "").replace("-", "").replace(".", "")


def validate_salt(salt: str) -> str:
    if not SALT_RE.match(salt):
        raise ValueError(
            "fleet salt must be 8-128 chars of [A-Za-z0-9_-] "
            "(shell-safe in single quotes; generate one: openssl rand -hex 16)"
        )
    return salt


def derive(mac: str, salt: str, domain: str, length: int = DEFAULT_PASSWORD_LENGTH) -> str:
    """Domain-separated hex secret: sha256(version:domain:salt:mac)[:length]."""
    if not (MIN_PASSWORD_LENGTH <= length <= MAX_PASSWORD_LENGTH):
        raise ValueError(f"length must be {MIN_PASSWORD_LENGTH}..{MAX_PASSWORD_LENGTH}")
    validate_salt(salt)
    material = f"{DOMAIN_VERSION}:{domain}:{salt}:{clean_mac(mac)}"
    return hashlib.sha256(material.encode()).hexdigest()[:length]


def root_password(mac: str, salt: str, length: int = DEFAULT_PASSWORD_LENGTH) -> str:
    return derive(mac, salt, "root", length)


def wifi_password(mac: str, salt: str, network: str = "fleet", length: int = DEFAULT_PASSWORD_LENGTH) -> str:
    return derive(mac, salt, f"wifi:{network}", length)


def hostname(mac: str, prefix: str = "nr7101") -> str:
    return f"{prefix}-{clean_mac(mac)}"


def wifi_ssid(mac: str, prefix: str = "nr7101") -> str:
    return f"{prefix}_{clean_mac(mac)}"


def derive_all(
    mac: str,
    salt: str,
    hostname_prefix: str = "nr7101",
    ssid_prefix: str = "nr7101",
    length: int = DEFAULT_PASSWORD_LENGTH,
) -> dict[str, str]:
    """Everything the operator needs for one unit, as a plain dict."""
    from mac_hash import mac_to_lan_ip

    m = clean_mac(mac)
    return {
        "mac": m,
        "hostname": hostname(m, hostname_prefix),
        "wifi_ssid": wifi_ssid(m, ssid_prefix),
        "root_password": root_password(m, salt, length),
        "wifi_password": wifi_password(m, salt, length=length),
        "lan_ip": mac_to_lan_ip(m),
    }


def shell_parity_check(mac: str, salt: str, domain: str = "root", length: int = DEFAULT_PASSWORD_LENGTH) -> bool:
    """Prove the BusyBox pipeline and Python agree (host `sh` stands in
    for ash; both use the same sha256sum/cut semantics)."""
    expected = derive(mac, salt, domain, length)
    m = clean_mac(mac)
    # Single quotes are safe: validate_salt() rejects them.
    cmd = f"printf '%s' '{DOMAIN_VERSION}:{domain}:{salt}:{m}' | sha256sum | cut -c1-{length}"
    r = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True, timeout=10)
    return r.returncode == 0 and r.stdout.strip() == expected


def _load_salt_from_config(path: str) -> str | None:
    """Read [use_cases.fleet_identity].salt from a conwrt config.toml."""
    try:
        import tomllib
    except ImportError:  # py<3.11
        return None
    try:
        with open(path, "rb") as f:
            cfg = tomllib.load(f)
        salt = cfg.get("use_cases", {}).get("fleet_identity", {}).get("salt")
        return str(salt) if salt else None
    except (OSError, ValueError):
        return None


def main(argv: list[str] | None = None) -> int:
    import argparse
    from pathlib import Path

    repo = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description="Derive per-device fleet secrets (MAC + salt)")
    ap.add_argument("--mac", required=True, help="device MAC in any common format")
    ap.add_argument("--salt", help="fleet salt (else $CONWRT_FLEET_SALT or config.toml)")
    ap.add_argument(
        "--config", default=str(repo / "config.toml"), help="config.toml to read [use_cases.fleet_identity].salt from"
    )
    ap.add_argument("--hostname-prefix", default="nr7101")
    ap.add_argument("--ssid-prefix", default="nr7101")
    ap.add_argument("--length", type=int, default=DEFAULT_PASSWORD_LENGTH)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument(
        "--check-shell", action="store_true", help="also verify the BusyBox pipeline parity and exit non-zero on drift"
    )
    args = ap.parse_args(argv)

    salt = args.salt or os.environ.get("CONWRT_FLEET_SALT") or _load_salt_from_config(args.config)
    if not salt:
        print("error: no salt (use --salt, $CONWRT_FLEET_SALT, or config.toml)", file=sys.stderr)
        return 2

    try:
        validate_salt(salt)
        info = derive_all(args.mac, salt, args.hostname_prefix, args.ssid_prefix, args.length)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.check_shell and not shell_parity_check(args.mac, salt, length=args.length):
        print("error: shell/Python derivation drift", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(info, sort_keys=True))
    else:
        for k, v in info.items():
            print(f"{k:15} {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
