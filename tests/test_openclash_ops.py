"""Characterization tests for openclash.py ops pipeline.

render_shell(_build_openclash_ops(...)) is the authoritative output.
If ops change, these tests must be updated to match.
"""
from profile.ops import render_shell
from use_cases.openclash import _build_openclash_ops


DEFAULT_PARAMS = {}
CUSTOM_PARAMS = {"proxy_type": "vmess", "core_type": "Dev", "dns_mode": "fake-ip"}

EXPECTED_DEFAULT = (
    "# --- OpenClash transparent proxy ---\n"
    "mkdir -p /etc/openclash/config\n"
    "uci set openclash.config.enable='1'\n"
    "uci set openclash.config.config_path='/etc/openclash/config/config.yaml'\n"
    "uci set openclash.config.proxy_type='ss'\n"
    "uci set openclash.config.core_type='Meta'\n"
    "uci set openclash.config.dashboard_type='Official'\n"
    "uci set openclash.config.dns_mode='redir-host'\n"
    "uci set openclash.config.operation_mode='redir-host'\n"
    "uci commit openclash\n"
    "/etc/init.d/openclash enable\n"
    'echo "OpenClash configured: Meta core, ss proxy"\n'
    'echo "Post-flash: import your subscription config via the LuCI web UI"'
)

EXPECTED_CUSTOM = (
    "# --- OpenClash transparent proxy ---\n"
    "mkdir -p /etc/openclash/config\n"
    "uci set openclash.config.enable='1'\n"
    "uci set openclash.config.config_path='/etc/openclash/config/config.yaml'\n"
    "uci set openclash.config.proxy_type='vmess'\n"
    "uci set openclash.config.core_type='Dev'\n"
    "uci set openclash.config.dashboard_type='Official'\n"
    "uci set openclash.config.dns_mode='fake-ip'\n"
    "uci set openclash.config.operation_mode='fake-ip'\n"
    "uci commit openclash\n"
    "/etc/init.d/openclash enable\n"
    'echo "OpenClash configured: Dev core, vmess proxy"\n'
    'echo "Post-flash: import your subscription config via the LuCI web UI"'
)


class TestOpenclashOps:
    def test_default_params(self):
        assert render_shell(_build_openclash_ops(DEFAULT_PARAMS)) == EXPECTED_DEFAULT

    def test_custom_params(self):
        assert render_shell(_build_openclash_ops(CUSTOM_PARAMS)) == EXPECTED_CUSTOM

    def test_fake_ip_dns(self):
        rendered = render_shell(_build_openclash_ops({"dns_mode": "fake-ip"}))
        assert "dns_mode='fake-ip'" in rendered
        assert "operation_mode='fake-ip'" in rendered
        assert "vmess" not in rendered  # defaults to ss
