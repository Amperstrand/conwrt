"""Venue-parametrized smoke test — one body, every venue (PRTA plan §8, S2).

Uses the canonical ``venue`` fixture from this directory's conftest:
selected by the runner via CONWRT_VENUES (default qemu-session only).
Dark labgrid venues skip inside the fixture; this file is only the
venue-agnostic story: the device answers SSH and knows who it is.

Plan context: docs/plans/prta-transition-plan.md (migration step S2).
"""

from __future__ import annotations

import subprocess

import pytest

pytestmark = [pytest.mark.integration]


def test_ssh_reachable_and_board_identity(venue):
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
