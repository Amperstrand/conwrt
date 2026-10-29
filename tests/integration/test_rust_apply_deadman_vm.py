"""Ring-2 runner for the #555 deadman/recovery-window tests.

``providers/conwrt-local-std/tests/qemu_apply.rs`` tests are env-gated
(``CONWRT_QEMU_VM=1`` + a reachable VM). This wrapper boots the standard
integration fixture and runs the two deadman tests through cargo with the
gate env set — the same shape as ``test_rust_apply_ports4_vm.py``. Skips
cleanly on hosts without qemu/KVM (CI keeps them gated-skip; the local
KVM host is where the ring-2 evidence is produced).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_qemu_apply_deadman_window_on_fixture_vm(openwrt_vm):
    env = {
        **os.environ,
        "CONWRT_QEMU_VM": "1",
        "CONWRT_VM_SESSION_PORT": str(openwrt_vm["port"]),
    }
    result = subprocess.run(
        [
            "cargo",
            "test",
            "-p",
            "conwrt-local-std",
            "--test",
            "qemu_apply",
            "--",
            "--nocapture",
            "deadman_cancelled_on_verified_apply_survives_window",
            "deadman_reverts_unverified_apply_at_window_expiry",
            "deadman_rearm_supersedes_stale_window",
        ],
        capture_output=True,
        text=True,
        timeout=600,
        cwd=str(REPO_ROOT),
        env=env,
    )

    assert result.returncode == 0, (
        f"qemu_apply deadman window tests failed (exit {result.returncode}):\n"
        f"stdout: {result.stdout[-4000:]}\nstderr: {result.stderr[-2000:]}"
    )
    # both tests must have RUN, not silently skipped (a skip here means
    # the env gate or VM wiring broke — the wrapper exists to prove them)
    for needle in (
        "deadman_cancelled_on_verified_apply_survives_window",
        "deadman_reverts_unverified_apply_at_window_expiry",
        "deadman_rearm_supersedes_stale_window",
    ):
        assert f"test {needle} ... ok" in result.stdout, (
            f"{needle} did not run green; stdout tail: {result.stdout[-2000:]}"
        )
