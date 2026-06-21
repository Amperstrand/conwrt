"""Guard tests for the use-case registry delivery metadata.

These lock the resolved (configure_via, packages_via) for every registered use
case. They make the requires_post_flash -> configure_via migration provably
behavior-preserving: the resolved values must be identical before and after.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import use_cases as uc  # noqa: E402

# Resolved (configure_via, packages_via) captured from the pre-migration registry.
EXPECTED: dict[str, tuple[str, str]] = {
    "adguard": ("ssh", "auto"),
    "ap-nostr-id": ("ssh", "auto"),
    "auto-sqm": ("both", "auto"),
    "configurationwizzard": ("ssh", "auto"),
    "doh": ("ssh", "auto"),
    "fips-bluetooth-rfcomm": ("ssh", "opkg"),
    "guest-wifi": ("ssh", "auto"),
    "mesh11sd": ("both", "auto"),
    "mwan3": ("both", "auto"),
    "openclash": ("ssh", "auto"),
    "sqm": ("both", "auto"),
    "ssh-hardening": ("both", "auto"),
    "ssl": ("ssh", "auto"),
    "tether": ("both", "auto"),
    "tether-android": ("both", "auto"),
    "tether-android-adb": ("both", "auto"),
    "tether-ios": ("both", "auto"),
    "tollgate": ("ssh", "auto"),
    "travelmate": ("both", "auto"),
    "wireguard-client": ("both", "auto"),
    "wireguard-server": ("ssh", "auto"),
}


def test_registry_contains_expected_use_cases() -> None:
    assert set(uc.registry()) == set(EXPECTED)


def test_resolved_delivery_metadata_is_stable() -> None:
    reg = uc.registry()
    actual = {name: (u.configure_via, u.packages_via) for name, u in reg.items()}
    assert actual == EXPECTED


def test_build_configure_is_deterministic_for_shell_only_cases() -> None:
    # These build pure UCI/shell from defaults (no host IO, no randomness).
    reg = uc.registry()
    for name in ("adguard", "wireguard-server", "wireguard-client"):
        out1 = reg[name].build_configure({})
        out2 = reg[name].build_configure({})
        assert isinstance(out1, str) and out1
        assert out1 == out2
