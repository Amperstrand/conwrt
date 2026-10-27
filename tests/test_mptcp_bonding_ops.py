"""Characterization + injection-gate tests for mptcp_bonding.py ops.

render_shell(_build_mptcp_ops(...)) is the authoritative output. The
param gates (validate_host / validate_port / uuid token charset) are
the Python half of the Rust port's MptcpBondingProfile::validate —
the three values interpolate UNQUOTED into a `curl | sh -s --` line.
"""
import pytest
from profile.ops import render_shell
from shell_safe import ValidationError
from use_cases.mptcp_bonding import _build_mptcp_ops


VALID_PARAMS: dict = {
    "server_ipv4": "203.0.113.7",
    "server_port": "16384",
    "uuid": "0f0e0d0c-0b0a-4909-8807-060504030201",
}

EXPECTED_VALID = (
    "# --- mptcp-bonding (BSBF) → 203.0.113.7:16384 ---\n"
    "apk add curl 2>/dev/null || opkg update && opkg install curl 2>/dev/null || true\n"
    "\n"
    "curl -fsSL owrt.bondingshouldbefree.org | sh -s -- "
    "--server-ipv4 203.0.113.7 --server-port 16384 "
    "--uuid 0f0e0d0c-0b0a-4909-8807-060504030201\n"
    "\n"
    'echo "BSBF installed. Verify: bsbf-bonding --status"\n'
    'echo "Monitor: bsbf-netspeed"\n'
    'echo "Uninstall: bsbf-bonding --uninstall"\n'
    "\n"
    "# REQUIRES: MPTCP-enabled kernel (CONFIG_MPTCP=y)\n"
    "# Firmware: https://firmware.bondingshouldbefree.org"
)


class TestMptcpBondingOps:
    def test_valid_params_render(self):
        assert render_shell(_build_mptcp_ops(VALID_PARAMS)) == EXPECTED_VALID

    def test_missing_required_params_raise(self):
        for key in ("server_ipv4", "server_port", "uuid"):
            params = {**VALID_PARAMS, key: ""}
            with pytest.raises(ValueError, match=key):
                _build_mptcp_ops(params)

    def test_hostile_server_ipv4_rejected(self):
        for evil in ("1.2.3.4; rm -rf /", "$(reboot)", "10.0.0.1 `id`", "-leadingdash"):
            with pytest.raises(ValidationError):
                _build_mptcp_ops({**VALID_PARAMS, "server_ipv4": evil})

    def test_hostile_server_port_rejected(self):
        for evil in ("16384; reboot", "$(id)", "0x4000", "-1"):
            with pytest.raises(ValueError):
                _build_mptcp_ops({**VALID_PARAMS, "server_port": evil})

    def test_out_of_range_port_rejected(self):
        for bad in ("0", "65536", "70000"):
            with pytest.raises(ValidationError):
                _build_mptcp_ops({**VALID_PARAMS, "server_port": bad})

    def test_hostile_uuid_rejected(self):
        for evil in ("$(reboot)", "abc; rm -rf /", "uuid `id`", "with space"):
            with pytest.raises(ValueError, match="unsafe characters"):
                _build_mptcp_ops({**VALID_PARAMS, "uuid": evil})

    def test_hostname_server_accepted(self):
        # validate_host accepts hostnames too — BSBF by DNS name must keep working
        ops = _build_mptcp_ops({**VALID_PARAMS, "server_ipv4": "vps.example.com"})
        assert "--server-ipv4 vps.example.com" in render_shell(ops)
