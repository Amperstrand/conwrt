"""Transport-join sweep for EVERY use-case preset.

The ssl port of PR #486 (Codex round 9) showed the failure class this
file pins generically: ``profile/apply.py::_run_step_script`` routes any
line-start control-flow script through a `` && `` line-join, so a
multi-line ``if`` becomes ``then && uci ...`` — invalid shell that dies
at ``sh -n`` before any configuration runs. The VPN-provider family is
already pinned by ``test_vpn_provider_transport.py``; this sweep runs
the same real-transport check over the WHOLE registry so the next
preset author who writes a pretty multi-line conditional is caught in
CI, not on a device.

Presets needing required params get minimal valid ones; everything
else builds with defaults.
"""

from __future__ import annotations

import subprocess

import pytest

from test_vpn_provider_transport import _captured_payload
from use_cases import registry

# Minimal valid params for the presets whose builders raise on {}.
# Same stub values the provider op tests use (test_vpn_provider_ops.py)
# — the builds are offline; the network work happens on-device.
REQUIRED_PARAMS = {
    "maas-portable-lab": {
        "bench_gateway": "192.168.105.10",
        "maas_ip": "192.168.105.20",
        "uplink_ssid": "BenchUplink",
        "uplink_key": "benchpass",
        "uplink_password": "benchpass",
    },
    "mesh11sd": {"mesh_id": "testmesh"},
    "mptcp-bonding": {
        "server_ipv4": "192.0.2.10",
        "server_port": "4444",
        "uuid": "test-uuid-1234",
    },
    "vpn-ivpn": {"account_id": "ivpn-test123", "upstream_gateway": "192.168.1.1"},
    "vpn-mullvad": {
        "account_token": "1234567890",
        "country": "se",
        "upstream_gateway": "192.168.1.1",
    },
    "vpn-openvpn": {
        "ovpn_config": "client\ndev tun\nremote vpn.example.com 1194\nproto udp\n",
    },
    "vpn-pia": {
        "username": "testuser",
        "password": "testpass",
        "region": "czech",
        "upstream_gateway": "192.168.1.1",
    },
    "vpn-surfshark": {
        "username": "ssuser",
        "password": "sspass",
        "upstream_gateway": "192.168.1.1",
    },
}

PRESETS = sorted(registry())


def _script_for(name: str) -> str:
    params = dict(REQUIRED_PARAMS.get(name, {}))
    return registry()[name].build_configure(params)


@pytest.mark.parametrize("name", PRESETS)
def test_transport_payload_is_valid_shell(name):
    """The payload `_run_step_script` would actually send must parse
    under sh, whichever transport branch it takes."""
    script = _script_for(name)
    if not script.strip():
        pytest.skip("preset has no configure script")
    _, payload = _captured_payload(script)
    joined = subprocess.run(["sh", "-n"], input=payload, capture_output=True, text=True)
    assert joined.returncode == 0, (
        f"{name}: transport payload is not valid shell: {joined.stderr}\n"
        f"payload head: {payload[:300]!r}"
    )
    for fragment in ("then &&", "do &&", "} && json_get"):
        assert fragment not in payload, (
            f"{name}: control flow was &&-joined ({fragment!r} in payload)"
        )


@pytest.mark.parametrize("name", PRESETS)
def test_rendered_script_is_valid_shell_for_first_boot_path(name):
    """The ASU first-boot path bakes the rendered script into
    uci-defaults, where it runs as a plain sh file — it must parse
    without any transport wrapper."""
    script = _script_for(name)
    if not script.strip():
        pytest.skip("preset has no configure script")
    verbatim = subprocess.run(["sh", "-n"], input=script, capture_output=True, text=True)
    assert verbatim.returncode == 0, (
        f"{name}: rendered script is not valid shell: {verbatim.stderr}\n"
        f"script head: {script[:300]!r}"
    )


def test_sweep_actually_covers_the_registry():
    """A registry that grows must grow INTO the sweep, not past it:
    every preset needing params has them, and the count matches."""
    assert len(PRESETS) >= 40, "registry shrank — presets went missing"
    for name in REQUIRED_PARAMS:
        assert name in PRESETS, f"params supplied for a non-existent preset: {name}"


class TestMultiLineTransportBranch:
    """Pins the apply.py fix the sweep forced: multi-line control-flow
    blocks ride the transport verbatim; line-contained control flow
    keeps the historical && join."""

    def test_line_contained_control_flow_stays_joined(self):
        # the original join rationale (apply.py comment): `; if...fi`
        # fallbacks must keep the member-level fail-fast of the chain
        script = (
            'DEV=$(detection 2>/dev/null)\n'
            'if [ -z "$DEV" ]; then DEV=wan; fi\n'
            'uci set network.wan.device="$DEV"'
        )
        cmd, payload = _captured_payload(script)
        assert "sh -s" in cmd
        assert " && " in payload, "line-contained control flow must stay joined"
        joined = subprocess.run(["sh", "-n"], input=payload, capture_output=True, text=True)
        assert joined.returncode == 0, joined.stderr

    def test_multi_line_blocks_go_verbatim(self):
        # a block spanning lines could never survive the join — it must
        # arrive byte-for-byte as authored under a set -e prefix (heredoc
        # parity, #495): mid-script failures propagate instead of riding
        # a trailing echo to a fake success
        script = (
            "for _ in $(seq 1 3); do\n"
            "  ping -c1 bench >/dev/null 2>&1 || true\n"
            "done\n"
            "echo ok"
        )
        cmd, payload = _captured_payload(script)
        assert "sh -s" in cmd
        assert payload == "set -e\n" + script.strip() + "\n", (
            "multi-line block must ride verbatim under set -e"
        )
        assert " && " not in payload
        verbatim = subprocess.run(["sh", "-n"], input=payload, capture_output=True, text=True)
        assert verbatim.returncode == 0, verbatim.stderr

    def test_set_e_safe_fallback_idioms_survive(self):
        # the idioms these payloads rely on must NOT abort under the
        # transported set -e: POSIX exempts a failure before the last
        # command of an AND-OR list (verified in dash, pinned here)
        body = (
            "for cand in usb0 usb1; do\n"
            "    [ -e \"/sys/class/net/$cand\" ] && USB_DEV=\"$cand\" && break\n"
            "done\n"
            "[ -e /nonexistent ] && X=$(cat /nonexistent)\n"
            "echo survived"
        )
        r = subprocess.run(["sh", "-e", "-c", body], capture_output=True, text=True)
        assert r.returncode == 0, f"AND-list fallbacks must be set -e safe: {r.stderr}"
        assert "survived" in r.stdout
