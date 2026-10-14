"""End-to-end VPN tunnel test on the QEMU VM — one credential, everything real.

The ONLY secret is ``CONWRT_LIVE_NORDVPN_TOKEN`` (a NordVPN access token).
With it set, this test runs the whole chain a flashed router would:
credentials fetch and server selection host-side (conwrt build), op
application on a real OpenWrt VM (BusyBox/netifd), kernel WireGuard tunnel
establishment (live handshake against NordVPN), and real traffic THROUGH
the tunnel (exit IP via wg0 differs from the host's exit IP).

Without the token the test skips — no other setup, no bench hardware.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
import time
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from vm_port import port_from_env  # noqa: E402

pytestmark = [pytest.mark.hardware]

NORDVPN_TOKEN = os.environ.get("CONWRT_LIVE_NORDVPN_TOKEN", "")


def _host_exit_ip() -> str:
    with urllib.request.urlopen("https://api.ipify.org", timeout=15) as r:
        return r.read().decode().strip()


@pytest.mark.skipif(not NORDVPN_TOKEN, reason="CONWRT_LIVE_NORDVPN_TOKEN not set")
def test_nordvpn_token_tunnel_e2e(openwrt_vm, wireguard_installed):
    vm = wireguard_installed

    with tempfile.TemporaryDirectory() as tmp:
        config_toml = Path(tmp) / "config.toml"
        config_toml.write_text(textwrap.dedent("""\
            [password]
            mode = "none"
            [network]
            lan_ip_mode = "keep"
            [use_cases]
            enabled = ["vpn-nordvpn"]
            [use_cases.vpn-nordvpn]
            access_token = "{token}"
            server = "DE"
        """).format(token=NORDVPN_TOKEN))
        env = {**os.environ, "CONWRT_CONFIG": str(config_toml)}
        r = subprocess.run(
            ["python3", str(REPO_ROOT / "scripts" / "conwrt.py"), "configure",
             "--model-id", "virtual-x86-64", "--ip", "127.0.0.1"],
            capture_output=True, text=True, timeout=600, env=env,
        )
        assert r.returncode == 0, f"configure failed:\n{r.stdout[-800:]}\n{r.stderr[-400:]}"

    assert vm("uci -q get network.wg0.proto") == "wireguard"

    deadline = time.time() + 120
    handshake = 0
    while time.time() < deadline:
        out = vm("wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2}'")
        if out and out.isdigit() and int(out) > 0:
            handshake = int(out)
            break
        time.sleep(5)
    assert handshake > 0, (
        f"no WireGuard handshake within 120s — tunnel not established\n"
        f"wg show:\n{vm('wg show wg0')}")

    transfer = vm("wg show wg0 transfer")
    rx_bytes = sum(
        int(line.split()[2])
        for line in transfer.splitlines() if line and line[0] not in ("i",)
    )
    assert rx_bytes > 0, f"tunnel up but no received traffic: {transfer}"

    assert "curl" in vm("command -v curl || true"), \
        "curl must be preinstalled by the wireguard_installed fixture"
    vm_exit_ip = vm("curl -s --interface wg0 --max-time 30 https://api.ipify.org", timeout=45)
    host_exit_ip = _host_exit_ip()
    assert vm_exit_ip and vm_exit_ip != host_exit_ip, (
        f"traffic through wg0 did NOT exit via the VPN: "
        f"vm={vm_exit_ip!r} host={host_exit_ip!r}")
