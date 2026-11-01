"""Regression tests for openperf_client + openperf_server gates.

The SSID charset gate and the port bound landed with the Rust port —
the SSID lands inside single-quoted uci values (surfshark #604 class).
"""
import pytest
from profile.ops import render_shell
from use_cases.openperf_client import _build_ops as _client_ops
from use_cases.openperf_server import _build_ops as _server_ops


class TestOpenPerfClient:
    def test_shape(self):
        rendered = render_shell(_client_ops({}))
        assert "cat > /etc/init.d/openperf-autostart" in rendered
        assert "sta_autostart.py" in rendered
        assert "uci set wireless.$iface.ssid='openperf'" in rendered
        assert "uci set wireless.$iface.ssid='openperf-halow'" in rendered
        assert "/etc/init.d/openperf-autostart enable" in rendered

    def test_custom_ssid(self):
        rendered = render_shell(_client_ops({"mgmt_ssid": "bench"}))
        assert "ssid='bench'" in rendered
        assert "ssid='bench-halow'" in rendered

    def test_hostile_ssid_rejected(self):
        for evil in ("x'; rm", 'a"b', "back\\slash", "a\nb"):
            with pytest.raises(ValueError, match="mgmt_ssid"):
                _client_ops({"mgmt_ssid": evil})


class TestOpenPerfServer:
    def test_shape(self):
        rendered = render_shell(_server_ops({}))
        assert "cat > /etc/init.d/openperf-server" in rendered
        assert "server.py" in rendered
        assert "PORT=7777" in rendered
        assert "uci set wireless.$iface.ssid='openperf'" in rendered
        assert "/etc/init.d/openperf-server enable" in rendered

    def test_custom_port(self):
        rendered = render_shell(_server_ops({"port": 8888}))
        assert "PORT=8888" in rendered

    def test_port_bounds(self):
        for bad in (0, 65536, -1):
            with pytest.raises(ValueError, match="port"):
                _server_ops({"port": bad})

    def test_hostile_ssid_rejected(self):
        with pytest.raises(ValueError, match="mgmt_ssid"):
            _server_ops({"mgmt_ssid": "x'; rm"})
