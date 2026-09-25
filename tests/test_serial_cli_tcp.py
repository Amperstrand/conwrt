"""CLI threading tests: every serial tool accepts tcp://HOST:PORT cleanly.

Real-surface subprocess tests only (no mocks): --help must document the
tcp:// form, and a refused bridge endpoint must exit with the typed error
message — never a traceback. Localhost-only (CI rule).
"""
from __future__ import annotations

import socket
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"

TOOLS = [
    "serial-console.py",
    "serial-boot-capture.py",
    "serial-configure.py",
    "serial-flash.py",
    "serial-backup.py",
]


def _dead_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _run(tool: str, argv: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPTS / tool), *argv],
        capture_output=True, text=True, timeout=30, cwd=cwd,
    )


@pytest.mark.parametrize("tool", TOOLS)
def test_help_documents_tcp_form(tool):
    result = _run(tool, ["--help"], cwd=Path("/tmp"))
    assert result.returncode == 0, result.stderr
    assert "tcp://HOST:PORT" in result.stdout


@pytest.mark.parametrize("tool,args", [
    ("serial-console.py", ["--monitor"]),
    ("serial-boot-capture.py", ["115200", "--max-wait", "1"]),
    ("serial-configure.py", ["115200", "--show-firmware"]),
    ("serial-backup.py", ["115200", "--list"]),
])
def test_refused_bridge_exits_clean_without_traceback(tool, args, tmp_path):
    url = f"tcp://127.0.0.1:{_dead_port()}"
    result = _run(tool, [url, *args], cwd=tmp_path)
    assert result.returncode != 0
    assert "Traceback" not in result.stderr
    assert url in result.stderr
    assert "ssh -N -L" in result.stderr


def test_serial_flash_refused_bridge_exits_clean(tmp_path):
    image = tmp_path / "fw.bin"
    image.write_bytes(b"\x00" * 16)
    url = f"tcp://127.0.0.1:{_dead_port()}"
    result = _run("serial-flash.py", [url, "115200", "--base64", str(image)], cwd=tmp_path)
    assert result.returncode != 0
    assert "Traceback" not in result.stderr
    assert url in result.stderr
    assert "ssh -N -L" in result.stderr


def test_serial_console_rejects_local_only_diagnostics_on_tcp(tmp_path):
    url = f"tcp://127.0.0.1:{_dead_port()}"
    result = _run("serial-console.py", [url, "--loopback"], cwd=tmp_path)
    assert result.returncode != 0
    assert "local /dev" in result.stderr
    assert "Traceback" not in result.stderr
