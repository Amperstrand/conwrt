"""Shell quoting and validation helpers for generated OpenWrt commands."""
from __future__ import annotations

import re
from typing import Iterable


class ValidationError(ValueError):
    pass


_UCI_NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]+$")
_PACKAGE_RE = re.compile(r"^[A-Za-z0-9_.+-]+$")
_RADIO_RE = re.compile(r"^[A-Za-z0-9_.$-]+$")

WIFI_BANDS = {"2.4ghz", "5ghz", "5ghz-low", "5ghz-high", "6ghz"}
WIFI_ENCRYPTIONS = {"none", "psk", "psk2", "psk3", "sae", "sae-mixed", "owe", "mixed-psk", "psk-mixed"}


def sh_quote(value: object) -> str:
    text = str(value)
    if "\x00" in text or "\n" in text or "\r" in text:
        raise ValidationError("shell argument contains an unsafe control character")
    return "'" + text.replace("'", "'\\''") + "'"


def require_choice(value: str, choices: Iterable[str], field: str) -> str:
    allowed = set(choices)
    if value not in allowed:
        raise ValidationError(f"{field} must be one of: {', '.join(sorted(allowed))}")
    return value


def uci_name(value: str, field: str = "UCI name") -> str:
    if not value or not _UCI_NAME_RE.fullmatch(value):
        raise ValidationError(f"{field} must contain only letters, digits, and underscores")
    return value


def radio_ref(value: str) -> str:
    if not value or not _RADIO_RE.fullmatch(value):
        raise ValidationError("radio reference contains unsafe characters")
    return value


def interface_name(value: str, field: str = "interface") -> str:
    if not value or not _IFACE_RE.fullmatch(value):
        raise ValidationError(f"{field} contains unsafe characters")
    return value


def wifi_band(value: str) -> str:
    return require_choice(value, WIFI_BANDS, "WiFi band")


def wifi_encryption(value: str) -> str:
    return require_choice(value, WIFI_ENCRYPTIONS, "WiFi encryption")


def package_name(value: str) -> str:
    if not value or not _PACKAGE_RE.fullmatch(value):
        raise ValidationError("package name contains unsafe characters")
    return value


def int_range(value: object, field: str, min_value: int = 0, max_value: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{field} must be an integer")
    if value < min_value:
        raise ValidationError(f"{field} must be >= {min_value}")
    if max_value is not None and value > max_value:
        raise ValidationError(f"{field} must be <= {max_value}")
    return value
