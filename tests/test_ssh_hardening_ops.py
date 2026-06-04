"""Characterization tests for ssh_hardening.py ops pipeline.

render_shell(_build_ssh_hardening_ops(...)) is the authoritative output.
If ops change, these tests must be updated to match.
"""
from profile.ops import render_shell
from use_cases.ssh_hardening import _build_ssh_hardening_ops


DEFAULT_PARAMS: dict = {}
CUSTOM_PARAMS = {
    "disable_password_auth": False,
    "idle_timeout": 600,
    "max_auth_tries": 5,
    "port": 2222,
    "disable_gateway_ports": False,
}

EXPECTED_DEFAULT = (
    "# --- SSH hardening ---\n"
    "uci set dropbear.@dropbear[0].PasswordAuth='off'\n"
    "uci set dropbear.@dropbear[0].RootPasswordAuth='off'\n"
    "uci set dropbear.@dropbear[0].Port='22'\n"
    "uci set dropbear.@dropbear[0].IdleTimeout='300'\n"
    "uci set dropbear.@dropbear[0].MaxAuthTries='3'\n"
    "uci set dropbear.@dropbear[0].GatewayPorts='no'\n"
    "uci commit dropbear\n"
    "/etc/init.d/dropbear restart 2>/dev/null || true\n"
    'echo "SSH hardened: password_auth=off idle=300s max_tries=3 port=22"'
)

EXPECTED_CUSTOM = (
    "# --- SSH hardening ---\n"
    "uci set dropbear.@dropbear[0].PasswordAuth='on'\n"
    "uci set dropbear.@dropbear[0].RootPasswordAuth='on'\n"
    "uci set dropbear.@dropbear[0].Port='2222'\n"
    "uci set dropbear.@dropbear[0].IdleTimeout='600'\n"
    "uci set dropbear.@dropbear[0].MaxAuthTries='5'\n"
    "uci set dropbear.@dropbear[0].GatewayPorts='yes'\n"
    "uci commit dropbear\n"
    "/etc/init.d/dropbear restart 2>/dev/null || true\n"
    'echo "SSH hardened: password_auth=on idle=600s max_tries=5 port=2222"'
)

EXPECTED_PW_ENABLED = (
    "# --- SSH hardening ---\n"
    "uci set dropbear.@dropbear[0].PasswordAuth='on'\n"
    "uci set dropbear.@dropbear[0].RootPasswordAuth='on'\n"
    "uci set dropbear.@dropbear[0].Port='22'\n"
    "uci set dropbear.@dropbear[0].IdleTimeout='300'\n"
    "uci set dropbear.@dropbear[0].MaxAuthTries='3'\n"
    "uci set dropbear.@dropbear[0].GatewayPorts='no'\n"
    "uci commit dropbear\n"
    "/etc/init.d/dropbear restart 2>/dev/null || true\n"
    'echo "SSH hardened: password_auth=on idle=300s max_tries=3 port=22"'
)

EXPECTED_PORT_TIMEOUT = (
    "# --- SSH hardening ---\n"
    "uci set dropbear.@dropbear[0].PasswordAuth='off'\n"
    "uci set dropbear.@dropbear[0].RootPasswordAuth='off'\n"
    "uci set dropbear.@dropbear[0].Port='2222'\n"
    "uci set dropbear.@dropbear[0].IdleTimeout='0'\n"
    "uci set dropbear.@dropbear[0].MaxAuthTries='3'\n"
    "uci set dropbear.@dropbear[0].GatewayPorts='no'\n"
    "uci commit dropbear\n"
    "/etc/init.d/dropbear restart 2>/dev/null || true\n"
    'echo "SSH hardened: password_auth=off idle=0s max_tries=3 port=2222"'
)

EXPECTED_GW_ENABLED = (
    "# --- SSH hardening ---\n"
    "uci set dropbear.@dropbear[0].PasswordAuth='off'\n"
    "uci set dropbear.@dropbear[0].RootPasswordAuth='off'\n"
    "uci set dropbear.@dropbear[0].Port='22'\n"
    "uci set dropbear.@dropbear[0].IdleTimeout='300'\n"
    "uci set dropbear.@dropbear[0].MaxAuthTries='3'\n"
    "uci set dropbear.@dropbear[0].GatewayPorts='yes'\n"
    "uci commit dropbear\n"
    "/etc/init.d/dropbear restart 2>/dev/null || true\n"
    'echo "SSH hardened: password_auth=off idle=300s max_tries=3 port=22"'
)

EXPECTED_ALL_CUSTOM = (
    "# --- SSH hardening ---\n"
    "uci set dropbear.@dropbear[0].PasswordAuth='off'\n"
    "uci set dropbear.@dropbear[0].RootPasswordAuth='off'\n"
    "uci set dropbear.@dropbear[0].Port='8022'\n"
    "uci set dropbear.@dropbear[0].IdleTimeout='120'\n"
    "uci set dropbear.@dropbear[0].MaxAuthTries='1'\n"
    "uci set dropbear.@dropbear[0].GatewayPorts='no'\n"
    "uci commit dropbear\n"
    "/etc/init.d/dropbear restart 2>/dev/null || true\n"
    'echo "SSH hardened: password_auth=off idle=120s max_tries=1 port=8022"'
)


class TestSshHardeningOps:
    def test_default_params(self):
        assert render_shell(_build_ssh_hardening_ops(DEFAULT_PARAMS)) == EXPECTED_DEFAULT

    def test_custom_params(self):
        assert render_shell(_build_ssh_hardening_ops(CUSTOM_PARAMS)) == EXPECTED_CUSTOM

    def test_password_auth_enabled(self):
        assert render_shell(_build_ssh_hardening_ops({"disable_password_auth": False})) == EXPECTED_PW_ENABLED

    def test_custom_port_and_timeout(self):
        assert render_shell(_build_ssh_hardening_ops({"port": 2222, "idle_timeout": 0})) == EXPECTED_PORT_TIMEOUT

    def test_gateway_ports_enabled(self):
        assert render_shell(_build_ssh_hardening_ops({"disable_gateway_ports": False})) == EXPECTED_GW_ENABLED

    def test_all_custom(self):
        params = {
            "disable_password_auth": True,
            "idle_timeout": 120,
            "max_auth_tries": 1,
            "port": 8022,
            "disable_gateway_ports": True,
        }
        assert render_shell(_build_ssh_hardening_ops(params)) == EXPECTED_ALL_CUSTOM
