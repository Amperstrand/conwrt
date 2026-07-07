"""Tests for the flows layer and the net4sats composite flow."""
from __future__ import annotations


from flows import get as get_flow
from flows.render import render_flow_markdown, render_flow_shell
from model_loader import load_model

_PARAMS = {"upstream_ssid": "home", "upstream_key": "secret", "upstream_band": "5ghz"}


def test_net4sats_flow_registered_with_eight_steps():
    flow = get_flow("net4sats")
    assert flow is not None
    assert [s.title for s in flow.steps] == [
        "Flash stock OpenWrt",
        "Connect the router to upstream WiFi",
        "Install the tollgate payment backend (v0.5.0-alpha3)",
        "Install umdns for .local mDNS resolution",
        "Install the net4sats portal (configurationwizzard)",
        "Set the router hostname to net4sats",
        "Brand the captive portal as net4sats",
        "Move the LAN off 192.168.1.1",
    ]


def test_net4sats_requires_upstream_params():
    flow = get_flow("net4sats")
    assert "upstream_ssid" in flow.params
    assert flow.params["upstream_ssid"].required
    assert flow.params["upstream_key"].required


def test_shell_x1860_uses_opkg_and_mipsel_artifact():
    flow = get_flow("net4sats")
    script = render_flow_shell(flow, load_model("dlink-covr-x1860-a1"), _PARAMS, version="24.10.7")
    assert "OpenWrt 24.10.7" in script
    assert "mipsel_24kc" in script
    assert "2fb588b10a445555923f1325d11c3cb28220cb32f078b283d71d4d3100e58286.ipk" in script
    assert "opkg install /tmp/2fb588" in script
    assert "apk add" not in script
    assert "ssh root@$IP sh <<'CONWRT_EOF'" in script


def test_shell_mt3000_uses_apk_and_aarch64_artifact():
    flow = get_flow("net4sats")
    script = render_flow_shell(flow, load_model("glinet-mt3000"), _PARAMS, version="25.12.0")
    assert "OpenWrt 25.12.0" in script
    assert "aarch64_cortex-a53" in script
    assert "1fcc1635a7d94a005ff270c4a44f49fb9c56b05a7fbfe01eabcba40e8d31571d.apk" in script
    assert "apk add --allow-untrusted /tmp/1fcc1635" in script
    assert "opkg install" not in script


def test_shell_wifi_sta_uses_provided_ssid_and_key():
    flow = get_flow("net4sats")
    script = render_flow_shell(flow, load_model("dlink-covr-x1860-a1"), _PARAMS, version="24.10.7")
    assert "ssid='home'" in script
    assert "key='secret'" in script
    assert "device='radio1'" in script


def test_markdown_has_section_headers_and_fenced_blocks():
    flow = get_flow("net4sats")
    md = render_flow_markdown(flow, load_model("glinet-mt6000"), _PARAMS, version="25.12.0")
    assert md.startswith("# net4sats on")
    for title in [s.title for s in flow.steps]:
        assert f"## {title}" in md
    assert "```sh" in md


def test_router_ops_in_shell_match_render_shell():
    flow = get_flow("net4sats")
    script = render_flow_shell(flow, load_model("dlink-covr-x1860-a1"), _PARAMS, version="24.10.7")
    assert "uci set wireless.sta1.ssid='home'" in script
    assert "uci commit wireless" in script
    assert "wifi reload" in script


def test_mt6000_model_supported_by_flow():
    script = render_flow_shell(get_flow("net4sats"), load_model("glinet-mt6000"), _PARAMS, version="25.12.0")
    assert "glinet-mt6000" in script
    assert "aarch64_cortex-a53" in script
