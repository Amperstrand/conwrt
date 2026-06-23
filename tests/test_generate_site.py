"""Tests for the web bundle generator."""
from __future__ import annotations

import json

from generate_site import build_bundle


def test_bundle_has_models_flows_and_rendered():
    b = build_bundle()
    assert len(b["models"]) > 0
    assert any(f["name"] == "net4sats" for f in b["flows"])
    assert len(b["rendered"]) == len(b["models"])


def test_net4sats_flow_exposes_param_schema():
    b = build_bundle()
    flow = next(f for f in b["flows"] if f["name"] == "net4sats")
    assert flow["params"]["upstream_ssid"]["required"] is True
    assert flow["params"]["upstream_ssid"]["type"] == "string"
    assert flow["params"]["upstream_band"]["choices"] == ["2.4ghz", "5ghz"]


def test_rendered_templates_carry_placeholders_for_substitution():
    b = build_bundle()
    shell = b["rendered"]["dlink-covr-x1860-a1"]["net4sats"]["shell"]
    assert "{{upstream_ssid}}" in shell
    assert "{{upstream_key}}" in shell


def test_rendered_shell_uses_each_models_pinned_version_and_package_manager():
    b = build_bundle()
    assert "opkg install" in b["rendered"]["dlink-covr-x1860-a1"]["net4sats"]["shell"]
    assert "OpenWrt 24.10" in b["rendered"]["dlink-covr-x1860-a1"]["net4sats"]["shell"]
    assert "opkg install" in b["rendered"]["glinet-mt3000"]["net4sats"]["shell"]
    assert "OpenWrt 24.10" in b["rendered"]["glinet-mt3000"]["net4sats"]["shell"]


def test_bundle_is_json_serializable_roundtrip():
    b = build_bundle()
    s = json.dumps(b)
    assert json.loads(s) == b


def test_bundle_includes_password_snippet():
    b = build_bundle()
    assert "chpasswd" in b["password_snippet"]["shell"]
    assert "## Set a random root password" in b["password_snippet"]["markdown"]
