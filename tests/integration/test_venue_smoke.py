"""Venue-parametrized smoke test — the PRTA-pattern fixture seam proof.

One test body (SSH reachable + board identity) parametrized over venues:

  qemu-session      the existing session VM (``openwrt_vm`` fixture in this
                    directory's conftest — QEMU boots it, claims the host
                    port via CONWRT_VM_SESSION_PORT, tears down by pidfile)
  labgrid:<place>   a labgrid place on the shared coordinator, acquired for
                    exclusivity, driven through ``labgrid-client ssh``
                    (exporter-proxied), released at teardown

Unreachable venues SKIP (never fail): on a multi-agent host the coordinator
may be down, the place held by a sibling session, or the device itself dark
(bench DUTs were SSH-dark on 2026-10-14 while acquire/release still worked —
the skip path is load-bearing, not decorative).

Plan context: docs/plans/prta-transition-plan.md (migration step 0).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration]

REPO_ROOT = Path(__file__).resolve().parents[2]

COORDINATOR = os.environ.get("CONWRT_LABGRID_COORDINATOR", "ai-legion:20408")
PLACE = os.environ.get("CONWRT_VENUE_PLACE", "ap-lan2")
LABGRID_CLIENT = os.environ.get("CONWRT_LABGRID_CLIENT", "labgrid-client")

VENUES = ["qemu-session", f"labgrid:{PLACE}"]


class VenueHandle:
    """The whole venue contract a venue-agnostic test sees: a name + run()."""

    def __init__(self, name: str, run):
        self.name = name
        self._run = run

    def run(self, command: str, timeout: int = 30) -> subprocess.CompletedProcess:
        return self._run(command, timeout=timeout)


def _vm_runner(vm: dict):
    def _run(command: str, timeout: int) -> subprocess.CompletedProcess:
        return subprocess.run(
            [
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "LogLevel=ERROR",
                "-i",
                vm["key"],
                "-p",
                str(vm["port"]),
                f"root@{vm['host']}",
                command,
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )

    return _run


# labgrid-client reports infra failures (SSHDriver timeouts, missing driver)
# as rc=2 + traceback; a failing remote command propagates ITS exit status.
# Infra failure => venue unreachable (skip); remote failure => test failure.
_VENUE_UNREACHABLE_MARKERS = (
    "Timeout while waiting for ssh connection",
    "NoDriverFoundError",
    "Connection timed out",
    "Connection refused",
    "No route to host",
    "Traceback (most recent call last)",
)


def _venue_unreachable(stderr: str) -> bool:
    return any(marker in stderr for marker in _VENUE_UNREACHABLE_MARKERS)


def _labgrid(args: list[str], timeout: int = 40) -> subprocess.CompletedProcess:
    cmd = [LABGRID_CLIENT, "-x", COORDINATOR, "-p", PLACE, *args]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


@pytest.fixture(scope="module", params=VENUES, ids=VENUES)
def venue(request):
    if request.param == "qemu-session":
        vm = request.getfixturevalue("openwrt_vm")
        yield VenueHandle(
            name=f"virtual-x86-64@qemu(127.0.0.1:{vm['port']})",
            run=_vm_runner(vm),
        )
        return

    place = request.param.split(":", 1)[1]
    acquired = _labgrid(["acquire"], timeout=25)
    if acquired.returncode != 0:
        pytest.skip(
            f"labgrid place {place!r} not acquirable on {COORDINATOR} "
            f"(held by a sibling session or coordinator down): "
            f"{acquired.stderr.strip()[-200:]}"
        )

    def _run(command: str, timeout: int) -> subprocess.CompletedProcess:
        # Exporter-proxied SSH: this host has no route to the bench VLANs;
        # the labgrid client tunnels through the exporter host.
        r = _labgrid(["ssh", "--", command], timeout=timeout)
        if _venue_unreachable(r.stderr):
            pytest.skip(f"{place}: venue unreachable via labgrid (rc={r.returncode}): {r.stderr.strip()[-300:]}")
        return r

    try:
        yield VenueHandle(name=f"labgrid:{place}", run=_run)
    finally:
        _labgrid(["release"], timeout=25)


def test_ssh_reachable_and_board_identity(venue):
    """The one venue-agnostic story: the device answers SSH and knows who
    it is (board_name + openwrt_release non-empty)."""
    try:
        r = venue.run(
            "cat /tmp/sysinfo/board_name; . /etc/openwrt_release; echo $DISTRIB_RELEASE",
            timeout=60,
        )
    except subprocess.TimeoutExpired as exc:
        pytest.skip(f"{venue.name}: SSH timed out ({exc}) — venue dark, not a test failure")

    assert r.returncode == 0, f"{venue.name}: SSH failed rc={r.returncode}\n{r.stderr.strip()[-400:]}"
    lines = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
    assert len(lines) >= 2, f"{venue.name}: incomplete identity output: {r.stdout!r}"
    board, release = lines[0], lines[1]
    assert board and release, f"{venue.name}: empty identity fields: {lines}"
    print(f"[venue] {venue.name}: board={board} release={release}")
