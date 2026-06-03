"""Characterization and roundtrip tests for ssh_hardening.py UCI generators.

Characterization tests lock the current output of _build_ssh_hardening so
refactoring to ops can be verified.

Roundtrip tests verify that render_shell(_build_ssh_hardening_ops(...)) matches
the configuration lines from _build_ssh_hardening(...) (excluding comments/echo).
"""
from helpers import config_lines as _config_lines
from profile.ops import render_shell
from use_cases.ssh_hardening import _build_ssh_hardening, _build_ssh_hardening_ops


DEFAULT_PARAMS = {}
CUSTOM_PARAMS = {
    "disable_password_auth": False,
    "idle_timeout": 600,
    "max_auth_tries": 5,
    "port": 2222,
    "disable_gateway_ports": False,
}


class TestSshHardeningCharacterization:
    def test_default_params_output(self):
        script = _build_ssh_hardening(DEFAULT_PARAMS)
        assert "uci set dropbear.@dropbear[0].PasswordAuth='off'" in script
        assert "uci set dropbear.@dropbear[0].RootPasswordAuth='off'" in script
        assert "uci set dropbear.@dropbear[0].Port='22'" in script
        assert "uci set dropbear.@dropbear[0].IdleTimeout='300'" in script
        assert "uci set dropbear.@dropbear[0].MaxAuthTries='3'" in script
        assert "uci set dropbear.@dropbear[0].GatewayPorts='no'" in script
        assert "uci commit dropbear" in script

    def test_custom_params_output(self):
        script = _build_ssh_hardening(CUSTOM_PARAMS)
        assert "uci set dropbear.@dropbear[0].PasswordAuth='on'" in script
        assert "uci set dropbear.@dropbear[0].RootPasswordAuth='on'" in script
        assert "uci set dropbear.@dropbear[0].Port='2222'" in script
        assert "uci set dropbear.@dropbear[0].IdleTimeout='600'" in script
        assert "uci set dropbear.@dropbear[0].MaxAuthTries='5'" in script
        assert "uci set dropbear.@dropbear[0].GatewayPorts='yes'" in script


class TestSshHardeningOpsRoundtrip:
    def _assert_config_match(self, params: dict) -> None:
        script = _build_ssh_hardening(params)
        ops = _build_ssh_hardening_ops(params)
        rendered = render_shell(ops)
        expected = "\n".join(_config_lines(script))
        assert rendered == expected, f"\n--- rendered ---\n{rendered}\n--- expected ---\n{expected}\n"

    def test_default_params(self):
        self._assert_config_match(DEFAULT_PARAMS)

    def test_custom_params(self):
        self._assert_config_match(CUSTOM_PARAMS)

    def test_password_auth_enabled(self):
        self._assert_config_match({"disable_password_auth": False})

    def test_custom_port_and_timeout(self):
        self._assert_config_match({"port": 2222, "idle_timeout": 0})

    def test_gateway_ports_enabled(self):
        self._assert_config_match({"disable_gateway_ports": False})

    def test_all_custom(self):
        self._assert_config_match({
            "disable_password_auth": True,
            "idle_timeout": 120,
            "max_auth_tries": 1,
            "port": 8022,
            "disable_gateway_ports": True,
        })
