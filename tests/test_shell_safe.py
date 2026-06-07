from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from shell_safe import (
    ValidationError,
    sh_quote,
    validate_cidr,
    validate_host,
    validate_port,
    validate_ssid,
)


ROOT = Path(__file__).resolve().parents[1]


def load_firmware_manager():
    spec = importlib.util.spec_from_file_location("firmware_manager", ROOT / "scripts" / "firmware-manager.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sh_quote_keeps_shell_metacharacters_inside_single_argument() -> None:
    value = "name with spaces'; $(touch pwn); echo"
    quoted = sh_quote(value)
    assert quoted == "'name with spaces'\\''; $(touch pwn); echo'"


@pytest.mark.parametrize("bad", ["line\nbreak", "carriage\rreturn", "nul\x00byte"])
def test_sh_quote_rejects_control_characters(bad: str) -> None:
    with pytest.raises(ValidationError):
        sh_quote(bad)


def test_wifi_uci_lines_quote_injection_payloads() -> None:
    fm = load_firmware_manager()
    lines = fm.wifi_ap_uci_lines(
        "radio0",
        "Cafe'; reboot; echo '",
        "psk2",
        key="pass $(reboot) ; `reboot`",
        network="lan",
    )
    joined = "\n".join(lines)
    assert "Cafe'\\''; reboot; echo '\\'''" in joined
    assert "'pass $(reboot) ; `reboot`'" in joined
    assert "ssid='Cafe'; reboot" not in joined


def test_wifi_uci_lines_reject_newlines() -> None:
    fm = load_firmware_manager()
    with pytest.raises(ValidationError):
        fm.wifi_sta_uci_lines("radio0", "bad\nssid", "psk2")


# ── validate_host ──────────────────────────────────────────────────


class TestValidateHost:
    def test_ipv4(self) -> None:
        assert validate_host("192.168.1.1") == "192.168.1.1"

    def test_hostname(self) -> None:
        assert validate_host("vpn.example.com") == "vpn.example.com"

    def test_single_label(self) -> None:
        assert validate_host("myserver") == "myserver"

    def test_reject_empty(self) -> None:
        with pytest.raises(ValidationError, match="must not be empty"):
            validate_host("")

    def test_reject_special_chars(self) -> None:
        with pytest.raises(ValidationError):
            validate_host("host; rm -rf /")

    def test_reject_starts_with_dot(self) -> None:
        with pytest.raises(ValidationError):
            validate_host(".example.com")


# ── validate_port ──────────────────────────────────────────────────


class TestValidatePort:
    def test_valid(self) -> None:
        assert validate_port(443) == 443
        assert validate_port(1) == 1
        assert validate_port(65535) == 65535

    def test_reject_zero(self) -> None:
        with pytest.raises(ValidationError, match="1-65535"):
            validate_port(0)

    def test_reject_negative(self) -> None:
        with pytest.raises(ValidationError, match="1-65535"):
            validate_port(-1)

    def test_reject_too_large(self) -> None:
        with pytest.raises(ValidationError, match="1-65535"):
            validate_port(70000)

    def test_reject_bool(self) -> None:
        with pytest.raises(ValidationError, match="integer"):
            validate_port(True)  # type: ignore[arg-type]


# ── validate_ssid ──────────────────────────────────────────────────


class TestValidateSsid:
    def test_valid(self) -> None:
        assert validate_ssid("MyNetwork") == "MyNetwork"

    def test_max_length(self) -> None:
        assert validate_ssid("x" * 32) == "x" * 32

    def test_reject_empty(self) -> None:
        with pytest.raises(ValidationError, match="must not be empty"):
            validate_ssid("")

    def test_reject_too_long(self) -> None:
        with pytest.raises(ValidationError, match="32 bytes"):
            validate_ssid("x" * 33)

    def test_reject_control_chars(self) -> None:
        with pytest.raises(ValidationError, match="control"):
            validate_ssid("bad\x01ssid")

    def test_unicode_counts_bytes(self) -> None:
        # 32 bytes max — each emoji is 4 bytes in UTF-8
        with pytest.raises(ValidationError, match="32 bytes"):
            validate_ssid("🔥" * 9)  # 36 bytes


# ── validate_cidr ──────────────────────────────────────────────────


class TestValidateCidr:
    def test_valid(self) -> None:
        assert validate_cidr("10.0.0.0/24") == "10.0.0.0/24"

    def test_valid_host(self) -> None:
        assert validate_cidr("10.67.0.2/32") == "10.67.0.2/32"

    def test_reject_no_prefix(self) -> None:
        with pytest.raises(ValidationError, match="/ prefix"):
            validate_cidr("10.0.0.0")

    def test_reject_bad_host(self) -> None:
        with pytest.raises(ValidationError, match="not a valid IPv4"):
            validate_cidr("999.0.0.0/24")

    def test_reject_prefix_out_of_range(self) -> None:
        with pytest.raises(ValidationError, match="0-32"):
            validate_cidr("10.0.0.0/33")

    def test_reject_non_numeric_prefix(self) -> None:
        with pytest.raises(ValidationError, match="numeric"):
            validate_cidr("10.0.0.0/abc")
