"""VM tier for VPN providers: apply provider ops on a real OpenWrt VM.

The hermetic tier renders ops; this tier APPLIES them — the layer where
BusyBox quirks, uci syntax, op ordering, and netifd semantics actually
bite (the surfshark nslookup parse shipped broken in #150 and was only
caught by running it on a real VM).

Secret-free by design: uses vpn-nordvpn ``config_file`` mode (fully static
— no API, no account). The WireGuard keypair is well-formed random bytes,
so config application and kernel acceptance are verified while no tunnel
can (or should) come up.
"""
from __future__ import annotations

import base64
import os
import secrets
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from vm_port import port_from_env  # noqa: E402

pytestmark = [pytest.mark.hardware]

SESSION_PORT = port_from_env("CONWRT_VM_SESSION_PORT", 2222)
SSH_CMD = [
    "ssh", "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=5",
    "-o", "LogLevel=ERROR",
    "-i", str(REPO_ROOT / "tests" / "integration" / ".vm_ssh_key"),
    "-p", str(SESSION_PORT), "root@127.0.0.1",
]

ENDPOINT_HOST = "de1507.nordvpn.com"


def _vm(cmd: str, timeout: int = 60) -> str:
    r = subprocess.run(SSH_CMD + [cmd], capture_output=True, text=True, timeout=timeout)
    assert r.returncode == 0, f"vm command failed: {cmd}\n{r.stderr}"
    return r.stdout.strip()


def test_nordvpn_config_file_applies_and_kernel_accepts(openwrt_vm, wireguard_installed):
    vm = wireguard_installed
    privkey = base64.b64encode(secrets.token_bytes(32)).decode()
    peerkey = base64.b64encode(secrets.token_bytes(32)).decode()

    with tempfile.TemporaryDirectory() as tmp:
        conf = Path(tmp) / "nordvpn-test.conf"
        conf.write_text(textwrap.dedent(f"""\
            [Interface]
            PrivateKey = {privkey}
            Address = 10.5.0.2/32
            DNS = 103.86.96.100
            [Peer]
            PublicKey = {peerkey}
            AllowedIPs = 0.0.0.0/0
            Endpoint = {ENDPOINT_HOST}:51820
            PersistentKeepalive = 25
        """))
        config_toml = Path(tmp) / "config.toml"
        config_toml.write_text(textwrap.dedent(f"""\
            [password]
            mode = "none"
            [network]
            lan_ip_mode = "keep"
            [use_cases]
            enabled = ["vpn-nordvpn"]
            [use_cases.vpn-nordvpn]
            config_file = "{conf}"
        """))
        env = {**os.environ, "CONWRT_CONFIG": str(config_toml)}
        r = subprocess.run(
            ["python3", str(REPO_ROOT / "scripts" / "conwrt.py"), "configure",
             "--model-id", "virtual-x86-64", "--ip", "127.0.0.1"],
            capture_output=True, text=True, timeout=600, env=env,
        )
        assert r.returncode == 0, f"configure failed:\n{r.stdout[-800:]}\n{r.stderr[-400:]}"

    assert vm("uci -q get network.wg0.proto") == "wireguard"
    assert vm("uci -q get network.@wireguard_wg0[0].endpoint_host") == ENDPOINT_HOST
    assert vm("uci -q get network.@wireguard_wg0[0].public_key") == peerkey
    assert vm("uci -q get firewall.vpn_zone.name") == "vpn"
    wg_show = vm("wg show wg0", timeout=30)
    assert "interface: wg0" in wg_show, f"kernel did not accept the config: {wg_show}"
    assert peerkey in wg_show, f"peer missing from runtime state: {wg_show}"
    # wg displays the endpoint resolved to an IP, not the configured hostname
    assert "endpoint:" in wg_show and ":51820" in wg_show, wg_show
