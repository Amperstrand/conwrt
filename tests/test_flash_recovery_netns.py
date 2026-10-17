"""flash-recovery.sh real-kernel ARP test (network namespace, no hardware).

Bridges the gap between the stubbed unit tests and the bench: runs the REAL
script from THIS checkout against the REAL dlink-covr-x1860-a1 model JSON,
with real ``ip``/``sudo``/``ping`` and a real Linux kernel ARP stack — the
"recovery server" is a veth peer in an isolated network namespace holding
192.168.0.1. Only ``curl`` is stubbed (to log and fail) so the test can
prove the one-request HTTP window is never touched.

This exercises everything the bench session (#240) will, except the physical
D-Link unit: neighbor flush, ARP solicitation, state-machine verdict,
temporary IP/route lifecycle, cleanup trap.

Not part of the unit tier (marked ``integration``). Run directly:

    pytest tests/test_flash_recovery_netns.py -v

Requires: Linux, root-capable passwordless sudo (``sudo -n true``).
Everything lives inside a throwaway netns/veth pair — the host's network
is untouched, and teardown removes the namespace.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "flash-recovery.sh"
MODEL = "dlink-covr-x1860-a1"
RECOVERY_IP = "192.168.0.1"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not sys.platform.startswith("linux")
        or not shutil.which("bash")
        or not shutil.which("ip")
        or subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0,
        reason="needs Linux, iproute2, and passwordless sudo (isolated netns)",
    ),
]


def _sh(*cmd: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)


@pytest.fixture()
def netns(tmp_path: Path):
    """Yield (iface, peer_mac, curl_log) with a live 192.168.0.1 in a netns."""
    tag = f"cwr{os.getpid() % 100000}"
    iface, peer, ns = f"{tag}h", f"{tag}p", f"{tag}ns"

    # curl is the ONLY stub: real binaries everywhere else.
    curl_log = tmp_path / "curl.attempts"
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    stub = stub_dir / "curl"
    stub.write_text(f'#!/bin/sh\nprintf \'curl %s\\n\' "$*" >> {curl_log}\nexit 1\n')
    stub.chmod(0o755)

    setup = [
        ["sudo", "ip", "netns", "add", ns],
        ["sudo", "ip", "link", "add", iface, "type", "veth", "peer", "name", peer],
        ["sudo", "ip", "link", "set", peer, "netns", ns],
        ["sudo", "ip", "netns", "exec", ns, "ip", "addr", "add", f"{RECOVERY_IP}/24", "dev", peer],
        ["sudo", "ip", "netns", "exec", ns, "ip", "link", "set", peer, "up"],
    ]
    try:
        for cmd in setup:
            r = _sh(*cmd)
            assert r.returncode == 0, f"setup failed: {' '.join(cmd)}\n{r.stderr}"
        peer_mac_r = _sh("sudo", "ip", "netns", "exec", ns, "ip", "-o", "link", "show", peer)
        peer_mac = next(
            word for word in peer_mac_r.stdout.replace("\\", " ").split() if word.count(":") == 5
        )
        yield iface, peer_mac, curl_log
    finally:
        _sh("sudo", "ip", "netns", "del", ns)
        _sh("sudo", "ip", "link", "del", iface)


def test_real_kernel_arp_arming_never_gets(netns):
    """Real kernel, real model: ARP arming verdict, zero HTTP requests."""
    iface, peer_mac, curl_log = netns
    stub_dir = curl_log.parent / "bin"  # the only stubbed binary is curl
    env = {
        "PATH": f"{stub_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "DRY_RUN": "1",
        "ASSUME_YES": "1",
    }
    out = subprocess.run(
        ["bash", str(SCRIPT), MODEL, iface],
        capture_output=True,
        text=True,
        env=env,
        input="",
        timeout=120,
        check=False,
    )
    assert out.returncode == 0, out.stdout + out.stderr
    assert f"Recovery server armed (ARP " in out.stdout
    assert peer_mac in out.stdout  # the verdict MAC is the REAL veth peer's MAC
    assert "DRY_RUN=1 — probe done; not flashing." in out.stdout
    attempts = curl_log.read_text() if curl_log.exists() else ""
    assert attempts == ""  # the one-request window was never touched
    # The script must have cleaned up its temporary address AND route (trap intact).
    leftover_addr = _sh("ip", "addr", "show", "dev", iface)
    assert "192.168.0.10" not in leftover_addr.stdout
    leftover_route = _sh("ip", "route", "show", "dev", iface)
    assert RECOVERY_IP not in leftover_route.stdout
