"""pbr use-case tests: build smoke + the interface-name injection gate.

The gate is a 1.x security fix landed with the Rust pbr port (2026-10-23):
`wan_interface`/`lan_interface` interpolate UNQUOTED into the generated
uci lines — hostile values were a command-injection hole. The Rust twin
applies the same charset gate (`PbrProfile::validate`, plan.rs).
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

use_cases = importlib.import_module("use_cases")


def _pbr():
    return use_cases.registry()["pbr"]


def test_default_build_smoke():
    script = _pbr().build_configure({})
    assert "uci set pbr.config.enabled='1'" in script
    assert "netifd_interface_default=wan" in script
    assert "netifd_interface_local=lan" in script


@pytest.mark.parametrize(
    "field", ["wan_interface", "lan_interface"]
)
@pytest.mark.parametrize(
    "hostile",
    [
        "wan; reboot",
        "wan$(reboot)",
        "wan`id`",
        "wan && poweroff",
        "wan\nreboot",
        "",
    ],
)
def test_interface_injection_is_rejected(field, hostile):
    with pytest.raises(Exception, match="unsafe characters"):
        _pbr().build_configure({field: hostile})


@pytest.mark.parametrize(
    "field, safe", [("wan_interface", "wwan"), ("lan_interface", "br-guest.10")]
)
def test_valid_interface_names_pass(field, safe):
    script = _pbr().build_configure({field: safe})
    assert safe in script
