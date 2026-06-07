"""Shell quoting and validation helpers for generated OpenWrt commands."""
from __future__ import annotations

import re
from typing import Iterable


class ValidationError(ValueError):
    pass


_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_SSID_MAX_LEN = 32


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


def validate_host(value: str, field: str = "host") -> str:
    """Validate a hostname or IPv4 address. Rejects empty strings and invalid formats."""
    if not value:
        raise ValidationError(f"{field} must not be empty")
    if _IPV4_RE.fullmatch(value):
        return value
    if _HOSTNAME_RE.fullmatch(value) and len(value) <= 253:
        return value
    raise ValidationError(f"{field} must be a valid hostname or IPv4 address, got: {value!r}")


def validate_port(value: int, field: str = "port") -> int:
    """Validate a network port number (1-65535)."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(f"{field} must be an integer, got {type(value).__name__}")
    if value < 1 or value > 65535:
        raise ValidationError(f"{field} must be 1-65535, got {value}")
    return value


def validate_ssid(value: str, field: str = "SSID") -> str:
    """Validate a WiFi SSID: max 32 bytes, no control characters."""
    if not value:
        raise ValidationError(f"{field} must not be empty")
    encoded = value.encode("utf-8")
    if len(encoded) > _SSID_MAX_LEN:
        raise ValidationError(f"{field} must be at most {_SSID_MAX_LEN} bytes, got {len(encoded)}")
    if any(ord(c) < 0x20 for c in value):
        raise ValidationError(f"{field} contains control characters")
    return value


def validate_cidr(value: str, field: str = "CIDR") -> str:
    """Validate an IP/prefix CIDR notation (e.g. '10.0.0.0/24')."""
    if "/" not in value:
        raise ValidationError(f"{field} must contain a / prefix, got: {value!r}")
    host, _, prefix_str = value.rpartition("/")
    try:
        prefix = int(prefix_str)
    except ValueError:
        raise ValidationError(f"{field} prefix must be numeric, got: {prefix_str!r}") from None
    if not _IPV4_RE.fullmatch(host):
        raise ValidationError(f"{field} host part is not a valid IPv4 address: {host!r}")
    if prefix < 0 or prefix > 32:
        raise ValidationError(f"{field} prefix must be 0-32, got {prefix}")
    return value


def int_range(value: object, field: str, min_value: int = 0, max_value: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f"{field} must be an integer")
    if value < min_value:
        raise ValidationError(f"{field} must be >= {min_value}")
    if max_value is not None and value > max_value:
        raise ValidationError(f"{field} must be <= {max_value}")
    return value
