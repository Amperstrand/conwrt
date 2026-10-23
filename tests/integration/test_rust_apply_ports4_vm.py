"""Ring-2 runner for the §4 openclash/ssl port tests (PR #486 follow-up).

``providers/conwrt-local-std/tests/qemu_apply.rs`` tests are env-gated
(``CONWRT_QEMU_VM=1`` + a reachable VM). This wrapper boots the standard
integration fixture and runs the two new tests through cargo with the
gate env set — the same shape as ``test_rust_apply_sqm.py``. Skips
cleanly on hosts without qemu/KVM (CI keeps them gated-skip; the local
KVM host is where the ring-2 evidence is produced).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_qemu_apply_openclash_and_ssl_on_fixture_vm(openwrt_vm):
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
            "openclash",
            "ssl",
            "nodns",
            "pbr",
        ],
        capture_output=True,
        text=True,
        timeout=600,
        cwd=str(REPO_ROOT),
        env=env,
    )

    assert result.returncode == 0, (
        f"qemu_apply openclash+ssl+nodns+pbr failed (exit {result.returncode}):\n"
        f"stdout: {result.stdout[-4000:]}\nstderr: {result.stderr[-2000:]}"
    )
    # both tests must have RUN, not silently skipped (a skip here means
    # the env gate or VM wiring broke — the wrapper exists to prove them)
    for needle in (
        "openclash_config_surface_applies_on_real_openwrt",
        "ssl_certless_negative_and_cert_present_positive_on_real_openwrt",
        "nodns_full_plan_applies_and_verifies_on_real_openwrt",
        "pbr_config_surface_applies_on_real_openwrt",
    ):
        assert f"test {needle} ... ok" in result.stdout, (
            f"{needle} did not run green; stdout tail: {result.stdout[-2000:]}"
        )
