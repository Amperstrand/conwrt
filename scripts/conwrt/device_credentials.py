"""Random root-password issuance with a local-only recovery record.

Blank root passwords are the recovery primitive for never-adopted bench
units (rom-audit gate in bench_adopt.py) — but on any device that also
runs system-auth services (uhttpd/LuCI on :80/:443/:8080) a blank root
password is a remote-root hole. This module gives conwrt one policy:

- devices conwrt CONFIGURES get a blank-password audit; blanks are
  replaced with a random password (never removing an existing one)
- every issued password is appended to data/device-credentials.jsonl
  (gitignored via the data/* rule) keyed by MAC so it can be recovered
- flash/ASU builds with no --password get a random one baked in

Lockout safety: setting a password only ever ADDS an auth method —
installed SSH keys keep working, so a recorded password cannot lock
us out.
"""
from __future__ import annotations

import json
import os
import secrets
import string
from datetime import datetime, timezone
from pathlib import Path
from typing import IO

_CHARSET = string.ascii_letters + string.digits
_LENGTH = 16


def generate(length: int = _LENGTH) -> str:
    return "".join(secrets.choice(_CHARSET) for _ in range(length))


def credentials_path() -> Path:
    return Path(os.environ.get("CONWRT_CREDENTIALS_FILE", "data/device-credentials.jsonl"))


def record(
    password: str,
    mac: str = "",
    model: str = "",
    ip: str = "",
    source: str = "",
    path: Path | None = None,
) -> Path:
    target = path or credentials_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    new_file = not target.exists()
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "mac": mac,
        "model": model,
        "ip": ip,
        "source": source,
        "root_password": password,
    }
    handle: IO[str]
    with open(target, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")
    if new_file:
        target.chmod(0o600)
    else:
        mode = target.stat().st_mode & 0o777
        if mode & 0o077:
            target.chmod(0o600)
    return target


def blank_password_probe() -> str:
    """SSH command printing root's shadow field ('' means blank/no password)."""
    return "awk -F: '$1==\"root\" {print $2}' /etc/shadow"


def is_blank(shadow_field: str) -> bool:
    return shadow_field.strip() == ""


def set_password_cmd(password: str) -> str:
    return "printf '%s\\n%s\\n' '{pw}' '{pw}' | passwd root".format(pw=password)


def mac_probe() -> str:
    return ("for i in eth0 lan wan; do "
            "[ -e /sys/class/net/$i/address ] && cat /sys/class/net/$i/address && exit 0; "
            "done; true")
