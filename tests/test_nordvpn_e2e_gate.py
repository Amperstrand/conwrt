"""Regression: phone env must gate only the phone-dependent NordVPN stories."""
from __future__ import annotations

from e2e import test_nordvpn_e2e as mod


def test_router_stories_are_not_module_skipped():
    """A missing phone must not hide router-only VPN coverage."""
    assert not getattr(mod, "pytestmark", [])


def test_phone_gate_names_missing_values(monkeypatch):
    monkeypatch.setattr(mod, "ADB_HOST", "")
    monkeypatch.setattr(mod, "ANDROID_SERIAL", "")
    monkeypatch.setattr(mod, "VPN_AP_KEY", "")
    assert mod._phone_config_missing() == [
        "CONWRT_E2E_ADB_HOST",
        "CONWRT_E2E_ANDROID_SERIAL",
        "CONWRT_E2E_AP_KEY",
    ]


def test_phone_gate_accepts_complete_config(monkeypatch):
    monkeypatch.setattr(mod, "ADB_HOST", "bench-host")
    monkeypatch.setattr(mod, "ANDROID_SERIAL", "serial")
    monkeypatch.setattr(mod, "VPN_AP_KEY", "key")
    assert mod._phone_config_missing() == []
