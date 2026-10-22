"""Rust apply path in the QEMU oracle suite — retirement-queue #4 gate.

`tests/integration/test_sqm.py` proves the PYTHON configure path applies
SQM on the VM. This file proves the RUST successor end-to-end in the
same oracle suite: `conwrt apply --profile sqm --execute` — TOFU
connect, fingerprint-confirmed identity, board/model gate, plan, apply,
verification — against the same fixture, asserting the same UCI
outcomes. When this is green in CI, the Python subprocess-ssh transport
in `profile/apply.py` is deprecated for the sqm flow (parity-matrix §6,
retirement queue #4).
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_conwrt_apply_execute_applies_sqm_like_the_python_path(openwrt_vm, ssh_cmd, tmp_path):
    known_hosts = tmp_path / "known-hosts"
    env = {**os.environ, "CONWRT_KNOWN_HOSTS": str(known_hosts)}
    result = subprocess.run(
        ["cargo", "run", "--quiet", "-p", "conwrt-cli", "--",
         "apply",
         "--profile", "sqm",
         "--model-id", "virtual-x86-64",
         "--download-kbps", "10000",
         "--upload-kbps", "5000",
         "--ip", "127.0.0.1",
         "--port", str(openwrt_vm["port"]),
         "--key", str(openwrt_vm["key"]),
         "--execute"],
        capture_output=True, text=True, timeout=300,
        cwd=str(REPO_ROOT), env=env,
    )

    assert result.returncode == 0, (
        f"conwrt apply --execute failed (exit {result.returncode}):\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "refused" not in result.stderr
    assert "applied:   script exit 0" in result.stdout
    assert result.stdout.count("verified:  ✓") >= 3

    # the same oracle assertions as the Python path (test_sqm.py)
    uci_output = ssh_cmd("uci show sqm")
    assert "sqm" in uci_output
    assert "enabled='1'" in uci_output
    assert "qdisc='cake'" in uci_output
    assert "script='piece_of_cake.qos'" in uci_output
    assert "download='10000'" in uci_output
    assert "upload='5000'" in uci_output

    out = ssh_cmd("/etc/init.d/sqm enabled && echo ENABLED || echo DISABLED")
    assert "ENABLED" in out

    # rollback so repeated runs (and the python twin) stay deterministic
    ssh_cmd(
        "for _s in $(uci -q show sqm 2>/dev/null | grep '=queue' "
        "| cut -d. -f2 | cut -d= -f1); do uci -q delete sqm.$_s; done; "
        "uci commit sqm; /etc/init.d/sqm stop 2>/dev/null; true"
    )
