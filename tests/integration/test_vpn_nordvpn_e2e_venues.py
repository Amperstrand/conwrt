"""The one-token NordVPN e2e, venue-parametrized (PRTA transition plan S3).

Supersedes the VM-only module (deleted, S3.5) — one secret
(``CONWRT_LIVE_NORDVPN_TOKEN``), full chain: credential fetch + server
selection host-side, ops applied via ``conwrt configure``, live WireGuard
handshake, traffic through the tunnel, exit IP differs from the host —
but the device comes from the canonical ``venue`` fixture:

    CONWRT_VM_SESSION_PORT=2322 pytest tests/integration/test_vpn_nordvpn_e2e_venues.py
    CONWRT_VENUES="labgrid:x1860-bench" CONWRT_LIVE_NORDVPN_TOKEN=... pytest ...

Venues without the direct-SSH capability (exporter-proxied bench places on
unrouted VLANs) skip with the reason: ``conwrt configure`` shells out to
plain ssh and needs host reachability.

S3.5 executed 2026-10-15: the VM-only predecessor was deleted after the
gate evidence in test-evidence/run-20261015-venues-s3-hardware-dry.md
(VM run green; hardware venues dry — every live DUT door owner-gated at
deletion time, deviation recorded there on explicit reviewer instruction).
"""
from __future__ import annotations

import base64
import os
import secrets
import subprocess
import sys
import tempfile
import textwrap
import time
import urllib.request
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration]

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

NORDVPN_TOKEN = os.environ.get("CONWRT_LIVE_NORDVPN_TOKEN", "")


def _host_exit_ip() -> str:
    with urllib.request.urlopen("https://api.ipify.org", timeout=15) as r:
        return r.read().decode().strip()


def _ensure_wireguard(venue) -> None:
    """Install wireguard + curl on whatever OpenWrt the venue runs.

    The opkg/apk era detection from tests/integration/conftest.py, driven
    through the venue channel instead of the session VM.
    """
    def run_checked(command: str, timeout: int = 180) -> str:
        r = venue.run(command, timeout=timeout)
        assert r.returncode == 0, f"{venue.name}: {command}\n{r.stderr}"
        return r.stdout.strip()

    has_opkg = "opkg" in (venue.run("command -v opkg || true").stdout or "")
    if has_opkg:
        if "wireguard-tools" not in (venue.run("opkg list-installed").stdout or ""):
            run_checked("opkg update >/dev/null 2>&1 && "
                        "opkg install wireguard-tools kmod-wireguard curl >/dev/null 2>&1")
    else:
        if "wireguard-tools" not in (venue.run("apk info 2>/dev/null").stdout or ""):
            run_checked("apk update >/dev/null 2>&1 && "
                        "apk add wireguard-tools kmod-wireguard curl >/dev/null 2>&1")
    assert "wg" in (venue.run("command -v wg || true").stdout or ""), \
        f"{venue.name}: wireguard-tools not installable"


def _vm_out(venue, command: str, timeout: int = 60) -> str:
    r = venue.run(command, timeout=timeout)
    assert r.returncode == 0, f"{venue.name}: {command}\n{r.stderr}"
    return r.stdout.strip()


@pytest.fixture()
def nordvpn_token():
    if not NORDVPN_TOKEN:
        pytest.skip("CONWRT_LIVE_NORDVPN_TOKEN not set")
    return NORDVPN_TOKEN


def test_nordvpn_token_tunnel_e2e(venue, nordvpn_token):
    if venue.ssh_target is None:
        pytest.skip(
            f"{venue.name}: no direct-SSH capability — `conwrt configure` needs "
            f"plain-ssh reachability (run from a host on the bench VLAN, or "
            f"expose the place via a routed path)")
    host, port, _key = venue.ssh_target

    _ensure_wireguard(venue)

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
        """).format(token=nordvpn_token))
        env = {**os.environ, "CONWRT_CONFIG": str(config_toml)}
        cmd = ["python3", str(REPO_ROOT / "scripts" / "conwrt.py"), "configure",
               "--ip", host, "--port", str(port)]
        if venue.model_id:
            cmd += ["--model-id", venue.model_id]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env)
        assert r.returncode == 0, (
            f"configure failed on {venue.name}:\n{r.stdout[-800:]}\n{r.stderr[-400:]}")

    assert _vm_out(venue, "uci -q get network.wg0.proto") == "wireguard"

    deadline = time.time() + 120
    handshake = 0
    while time.time() < deadline:
        out = _vm_out(venue, "wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2}'")
        if out and out.isdigit() and int(out) > 0:
            handshake = int(out)
            break
        time.sleep(5)
    assert handshake > 0, (
        f"{venue.name}: no WireGuard handshake within 120s\n"
        f"wg show:\n{_vm_out(venue, 'wg show wg0')}")

    transfer = _vm_out(venue, "wg show wg0 transfer")
    rx_bytes = sum(
        int(line.split()[2])
        for line in transfer.splitlines() if line and line[0] not in ("i",)
    )
    assert rx_bytes > 0, f"{venue.name}: tunnel up but no received traffic: {transfer}"

    assert "curl" in (_vm_out(venue, "command -v curl || true")), \
        f"{venue.name}: curl must be preinstalled before the tunnel claims the route"
    venue_exit_ip = _vm_out(
        venue, "curl -s --interface wg0 --max-time 30 https://api.ipify.org", timeout=45)
    host_exit_ip = _host_exit_ip()
    assert venue_exit_ip and venue_exit_ip != host_exit_ip, (
        f"{venue.name}: traffic through wg0 did NOT exit via the VPN: "
        f"venue={venue_exit_ip!r} host={host_exit_ip!r}")
