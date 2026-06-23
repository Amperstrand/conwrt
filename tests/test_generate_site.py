"""Tests for the web bundle generator."""
from __future__ import annotations

import json

from generate_site import build_bundle


def test_bundle_has_models_flows_versions_and_rendered():
    b = build_bundle()
    assert len(b["models"]) > 0
    assert any(f["name"] == "net4sats" for f in b["flows"])
    assert "24.10.7" in b["versions"] and "25.12.4" in b["versions"]
    assert len(b["rendered"]) == len(b["models"])


def test_net4sats_flow_exposes_param_schema():
    b = build_bundle()
    flow = next(f for f in b["flows"] if f["name"] == "net4sats")
    assert flow["params"]["upstream_ssid"]["required"] is True
    assert flow["params"]["upstream_ssid"]["type"] == "string"
    assert flow["params"]["upstream_band"]["choices"] == ["2.4ghz", "5ghz"]


def test_rendered_templates_carry_placeholders_for_substitution():
    b = build_bundle()
    shell = b["rendered"]["dlink-covr-x1860-a1"]["net4sats"]["24.10.7"]["shell"]
    assert "{{upstream_ssid}}" in shell
    assert "{{upstream_key}}" in shell


def test_version_dimension_switches_package_manager():
    b = build_bundle()
    mt3000 = b["rendered"]["glinet-mt3000"]["net4sats"]
    assert "opkg install" in mt3000["24.10.7"]["shell"]
    assert "OpenWrt 24.10.7" in mt3000["24.10.7"]["shell"]
    assert "apk add" in mt3000["25.12.4"]["shell"]
    assert "OpenWrt 25.12.4" in mt3000["25.12.4"]["shell"]
    assert "opkg install" not in mt3000["25.12.4"]["shell"]


def test_bundle_is_json_serializable_roundtrip():
    b = build_bundle()
    s = json.dumps(b)
    assert json.loads(s) == b


def test_bundle_includes_addons():
    b = build_bundle()
    names = [a["name"] for a in b["addons"]]
    assert "random-password" in names
    assert "hostname" in names
    rp = next(a for a in b["addons"] if a["name"] == "random-password")
    assert "chpasswd" in rp["shell"]
    hn = next(a for a in b["addons"] if a["name"] == "hostname")
    assert "{{hostname}}" in hn["shell"]
