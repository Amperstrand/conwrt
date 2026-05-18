from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from shell_safe import ValidationError, sh_quote


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
