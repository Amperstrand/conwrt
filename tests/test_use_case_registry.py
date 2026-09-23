"""Guard tests for the use-case registry delivery metadata.

These lock the resolved (configure_via, packages_via) for every REQUIRED use
case. They make the requires_post_flash -> configure_via migration provably
behavior-preserving: the resolved values must be identical before and after.

The registry auto-discovers plugins from scripts/use_cases/, so in-flight WIP
plugins may register additional entries. Extra registrations are tolerated
(flagged informationally); a required use case going missing or changing its
resolved delivery metadata is a failure.
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
    "cashu-vpn-client": ("both", "auto"),
    "configurationwizzard": ("ssh", "auto"),
    "doh": ("ssh", "auto"),
    "fips-bluetooth-rfcomm": ("ssh", "opkg"),
    "guest-wifi": ("ssh", "auto"),
    "mesh11sd": ("both", "auto"),
    "mptcp-bonding": ("both", "auto"),
    "mwan3": ("both", "auto"),
    "nodns": ("ssh", "auto"),
    "openclash": ("ssh", "auto"),
    "pbr": ("both", "auto"),
    "sqm": ("both", "auto"),
    "ssh-hardening": ("both", "auto"),
    "ssl": ("ssh", "auto"),
    "tether": ("both", "auto"),
    "tether-android": ("both", "auto"),
    "tether-android-adb": ("both", "auto"),
    "tether-ios": ("both", "auto"),
    "tollgate": ("ssh", "auto"),
    "tollgate-security": ("both", "auto"),
    "travelmate": ("both", "auto"),
    "vpn-node": ("ssh", "auto"),
    "wireguard-client": ("both", "auto"),
    "wireguard-server": ("ssh", "auto"),
}


def test_registry_contains_expected_use_cases() -> None:
    registered = set(uc.registry())
    missing = set(EXPECTED) - registered
    assert not missing, f"required use cases missing from registry: {sorted(missing)}"
    extras = registered - set(EXPECTED)
    if extras:
        print(f"informational: additional plugins registered: {sorted(extras)}")


def test_resolved_delivery_metadata_is_stable() -> None:
    reg = uc.registry()
    for name, (configure_via, packages_via) in EXPECTED.items():
        resolved = (reg[name].configure_via, reg[name].packages_via)
        assert resolved == (configure_via, packages_via), (
            f"{name}: resolved delivery metadata changed: {resolved}"
        )


def test_build_configure_is_deterministic_for_shell_only_cases() -> None:
    # These build pure UCI/shell from defaults (no host IO, no randomness).
    reg = uc.registry()
    for name in ("adguard", "wireguard-server", "wireguard-client"):
        out1 = reg[name].build_configure({})
        out2 = reg[name].build_configure({})
        assert isinstance(out1, str) and out1
        assert out1 == out2
