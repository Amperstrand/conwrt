"""VM-level idempotency: running `conwrt configure` twice with the same
config must converge to identical UCI state.

Non-idempotent ops (uci add_list duplicates, append-style scripts, counters)
are invisible to unit tests with mocked SSH — they only surface on a real
UCI implementation, i.e. on the VM.
"""
from __future__ import annotations

import subprocess
import os
import tempfile
import textwrap
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
pytestmark = [pytest.mark.hardware]

VM_SSH = [
    "ssh", "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=5",
    "-i", str(REPO_ROOT / "tests" / "integration" / ".vm_ssh_key"),
    "-p", "2222", "root@127.0.0.1",
]

CONFIG = """\
    [password]
    mode = "none"
    [network]
    lan_ip_mode = "keep"
    [use_cases]
    enabled = ["sqm", "doh", "ssh-hardening"]
    [use_cases.sqm]
    download_kbps = 10000
    upload_kbps = 5000
    [use_cases.doh]
    provider = "cloudflare"
"""

SNAPSHOT_SECTIONS = "sqm https-dns-proxy dropbear firewall dhcp"


def _vm(cmd: str, timeout: int = 30) -> str:
    r = subprocess.run(VM_SSH + [cmd], capture_output=True, text=True, timeout=timeout)
    return r.stdout


def _snapshot() -> str:
    return _vm(f"uci show {SNAPSHOT_SECTIONS} 2>/dev/null | sort")


def _run_configure() -> subprocess.CompletedProcess:
    tmpdir = Path(tempfile.mkdtemp())
    (tmpdir / "config.toml").write_text(textwrap.dedent(CONFIG))
    env = {**os.environ, "CONWRT_CONFIG": str(tmpdir / "config.toml")}
    return subprocess.run(
        ["python3", str(REPO_ROOT / "scripts" / "conwrt.py"), "configure",
         "--model-id", "virtual-x86-64", "--ip", "127.0.0.1"],
        capture_output=True, text=True, timeout=600, cwd=str(REPO_ROOT), env=env,
    )


def test_configure_twice_converges_identical_uci(openwrt_vm):
    r1 = _run_configure()
    assert r1.returncode == 0, f"first configure failed: {r1.stderr[-500:]}"
    snap1 = _snapshot()

    r2 = _run_configure()
    assert r2.returncode == 0, f"second configure failed: {r2.stderr[-500:]}"
    snap2 = _snapshot()

    if snap1 != snap2:
        lines1 = snap1.splitlines()
        lines2 = snap2.splitlines()
        added = [ln for ln in lines2 if ln not in lines1]
        removed = [ln for ln in lines1 if ln not in lines2]
        detail = f"\n+added on re-run: {added}\n-removed on re-run: {removed}"
    else:
        detail = ""
    assert snap1 == snap2, f"configure is not idempotent — UCI drifted on re-run:{detail}"
