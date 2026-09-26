"""SSH-transport regression tests for vpn_providers.

Codex review of PR #81 (comment 4107888554, scripts/use_cases/vpn_providers/base.py):
``_run_step_script`` joins control-flow scripts line-by-line with `` && ``, so
the multiline ``JSON_HELPER_SH`` became ``if ...; then && apk ... && fi`` — an
ash syntax error that made SSH configuration mode unusable for every WireGuard
provider. These tests pin the fixed contract: the exact payload the executor
sends must be valid shell syntax with multiline control flow intact.
"""
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from profile.apply import _run_step_script
from profile.ops import render_shell
from use_cases.vpn_providers.base import transport_sh
from use_cases.vpn_providers.ivpn import _build_ivpn_ops
from use_cases.vpn_providers.mullvad import _build_mullvad_ops
from use_cases.vpn_providers.nordvpn import _build_nordvpn_ops
from use_cases.vpn_providers.openvpn import _build_openvpn_ops
from use_cases.vpn_providers.pia import _build_pia_ops
from use_cases.vpn_providers.surfshark import _build_surfshark_ops

from test_vpn_provider_ops import (
    IVPN_PARAMS,
    MULLVAD_PARAMS,
    NORDVPN_PARAMS,
    OVPN_PARAMS,
    PIA_PARAMS,
    SURFSHARK_PARAMS,
)


def _captured_payload(script: str) -> tuple[str, str]:
    """Run the real _run_step_script with a mocked subprocess; return (cmd, payload)."""
    captured: dict[str, str] = {}

    def fake_run(*args, **kwargs):
        captured["cmd"] = " ".join(args[0])
        captured["input"] = kwargs.get("input", "")
        m = MagicMock()
        m.returncode = 0
        m.stderr = ""
        return m

    with patch("profile.apply.subprocess.run", side_effect=fake_run):
        assert _run_step_script("1.2.3.4", script, "", MagicMock())
    return captured["cmd"], captured["input"]


PROVIDERS = [
    ("pia", _build_pia_ops, PIA_PARAMS),
    ("mullvad", _build_mullvad_ops, MULLVAD_PARAMS),
    ("nordvpn", _build_nordvpn_ops, NORDVPN_PARAMS),
    ("ivpn", _build_ivpn_ops, IVPN_PARAMS),
    ("surfshark", _build_surfshark_ops, SURFSHARK_PARAMS),
    ("openvpn", _build_openvpn_ops, OVPN_PARAMS),
]
PROVIDER_IDS = [name for name, _, _ in PROVIDERS]


class TestTransportSh:
    def test_wraps_body_in_quoted_heredoc_executed_via_sh(self):
        out = transport_sh("if true; then\n    echo hi\nfi")
        assert out.startswith("cat > /tmp/vpn_setup.sh << 'VPN_SETUP_EOF'\n")
        assert out.endswith("VPN_SETUP_EOF\nsh /tmp/vpn_setup.sh")

    def test_runtime_variables_survive_the_quoted_delimiter(self):
        # Single-quoted heredoc delimiter: ${VAR} stays literal at write time
        # and expands only when the inner script runs.
        out = transport_sh('uci set network.r.target="${SERVER_IP}"')
        assert 'target="${SERVER_IP}"' in out

    def test_wrapped_output_is_valid_shell_syntax(self):
        body = (
            "if ! command -v jq >/dev/null 2>&1; then\n"
            "    apk add jq >/dev/null 2>&1\n"
            "fi\n"
            "while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do\n"
            "    uci delete network.@wireguard_wg0[0]\n"
            "done\n"
        )
        r = subprocess.run(["sh", "-n"], input=transport_sh(body), capture_output=True, text=True)
        assert r.returncode == 0, r.stderr


class TestProviderStepTransport:
    """Every provider's step payload must parse under sh and keep multiline
    blocks intact — no ``then &&``/``do &&`` joins anywhere in the payload."""

    @pytest.mark.parametrize("name,builder,params", PROVIDERS, ids=PROVIDER_IDS)
    def test_step_payload_is_valid_shell_syntax(self, name, builder, params):
        script = render_shell(builder(dict(params)))
        cmd, payload = _captured_payload(script)
        assert "sh -s" in cmd, f"{name}: expected stdin transport"
        r = subprocess.run(["sh", "-n"], input=payload, capture_output=True, text=True)
        assert r.returncode == 0, f"{name}: executor payload is not valid shell: {r.stderr}"

    @pytest.mark.parametrize("name,builder,params", PROVIDERS, ids=PROVIDER_IDS)
    def test_multiline_control_flow_survives_transport(self, name, builder, params):
        script = render_shell(builder(dict(params)))
        _, payload = _captured_payload(script)
        assert payload.startswith("set -e\n"), f"{name}: expected newline-preserving stdin transport"
        assert "then &&" not in payload, f"{name}: if-block was &&-joined"
        assert "do &&" not in payload, f"{name}: loop body was &&-joined"
        assert "} && json_get" not in payload, f"{name}: function definition was &&-joined"

    @pytest.mark.parametrize("name,builder,params", PROVIDERS, ids=PROVIDER_IDS)
    def test_rendered_script_is_valid_shell_for_first_boot_path(self, name, builder, params):
        # The ASU first-boot path bakes the rendered script into uci-defaults,
        # where it runs as a plain sh file — it must parse without the wrapper.
        script = render_shell(builder(dict(params)))
        r = subprocess.run(["sh", "-n"], input=script, capture_output=True, text=True)
        assert r.returncode == 0, f"{name}: rendered script is not valid shell: {r.stderr}"
