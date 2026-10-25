"""Shared pytest configuration.

Disables the soft-deprecation delay for every test run so migrated Python
commands stay fast under test; the notice itself still prints (and its
behavior is covered by tests/test_rust_migration.py).
"""

from __future__ import annotations

import os

os.environ.setdefault("CONWRT_RUST_MIGRATION_DELAY", "0")

# ---------------------------------------------------------------------------
# Network-egress guard for the hardware-safe tier (conwrt #563 root cause:
# 2026-10-25). Some configure-dispatch tests leave run_ssh-calling helpers
# unmocked, so a REAL `ssh root@192.168.1.1` executes. On a bench host
# where something answers 192.168.1.1:22 the call fails in ~0s and nobody
# notices; on CI runners the private-IP SYN is blackholed and every escaped
# call burns ConnectTimeout (measured: 51 tests = 640s vs 0.33s, ~2000x).
# Fix: unless a test tier explicitly wants the real network
# (CONWRT_REAL_NETWORK=1, set by the live/bench tiers), EVERY ssh/scp
# exec resolves to a stub that logs the invocation and fails instantly —
# escaped network egress becomes deterministic and visible instead of a
# probabilistic CI hang.
# ---------------------------------------------------------------------------

import shutil
import stat
import tempfile
from pathlib import Path

import pytest


@pytest.fixture(scope="session", autouse=True)
def _ssh_egress_stub():
    if os.environ.get("CONWRT_REAL_NETWORK") == "1":
        yield
        return
    stub_dir = Path(tempfile.mkdtemp(prefix="conwrt-ssh-stub-"))
    log_path = stub_dir / "calls.log"
    for tool in ("ssh", "scp", "sftp"):
        stub = stub_dir / tool
        stub.write_text(
            "#!/bin/sh\n"
            f'echo "{tool} $*" >> "{log_path}"\n'
            'echo "conwrt-test-stub: network egress blocked '
            f'({tool})" >&2\n'
            "exit 255\n"
        )
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    os.environ["CONWRT_SSH_STUB_LOG"] = str(log_path)
    old_path = os.environ["PATH"]
    os.environ["PATH"] = f"{stub_dir}:{old_path}"
    try:
        yield
    finally:
        os.environ["PATH"] = old_path
        if log_path.exists():
            n = sum(1 for _ in log_path.open())
            if n:
                print(f"\n[conwrt] ssh stub intercepted {n} escaped network call(s); see {log_path}")
        shutil.rmtree(stub_dir, ignore_errors=True)
