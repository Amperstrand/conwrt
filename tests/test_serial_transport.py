"""Characterization tests for serial_transport.SerialConsole on local /dev.

Written BEFORE the TCP transport existed: these pin the local /dev behavior
(open/write/read, line-chunked script delivery, RC markers, FT232R break
recovery) and must keep passing byte-for-byte after tcp:// support lands.
TCP tests live in test_serial_tcp.py.
"""
from __future__ import annotations

import os
import pty
import select
import threading
import time
import tty
from collections.abc import Iterator

import pytest
import serial as pyserial

from serial_transport import (
    MAX_LINE,
    SerialConsole,
    SerialLinterError,
    lint_script,
)

# ─── pty helpers ─────────────────────────────────────────────────────────────


@pytest.fixture()
def pty_slave() -> Iterator[tuple[int, str]]:
    """A raw-mode pty pair: (master_fd, slave_device_path).

    The slave line discipline is set raw (no echo, no CR/LF translation), so
    the pair is a deterministic byte pipe: what the test writes to master,
    SerialConsole reads on the slave, and vice versa.
    """
    master_fd, slave_fd = pty.openpty()
    tty.setraw(slave_fd)
    yield master_fd, os.ttyname(slave_fd)
    os.close(master_fd)
    os.close(slave_fd)


def master_read_until(master_fd: int, needle: bytes, timeout: float = 3.0) -> bytes:
    """Read from the pty master until `needle` appears (bounded by timeout)."""
    buf = b""
    end = time.time() + timeout
    while time.time() < end and needle not in buf:
        r, _, _ = select.select([master_fd], [], [], 0.2)
        if r:
            buf += os.read(master_fd, 4096)
    assert needle in buf, f"expected {needle!r} from console, got {buf!r}"
    return buf


def _run_with_peer(console: SerialConsole, master: int, cmd: str,
                   reply: bytes) -> tuple[int, str]:
    """Run a console command while a peer thread answers with `reply`."""

    def responder() -> None:
        master_read_until(master, f"{cmd} && echo".encode())
        os.write(master, reply)

    t = threading.Thread(target=responder)
    t.start()
    rc, out = console.run(cmd, timeout=5.0)
    t.join(timeout=3)
    return rc, out


# ─── local /dev characterization (baseline — must stay green) ───────────────


class TestSerialConsoleLocalCharacterization:
    def test_open_routes_local_dev_through_pyserial(self, pty_slave):
        _master, slave = pty_slave
        console = SerialConsole(slave, baud=115200, timeout=0.2)
        try:
            assert console.port == slave
            assert console.baud == 115200
            assert console.timeout == 0.2
            assert isinstance(console._s, pyserial.Serial)
        finally:
            console.close()

    def test_activate_sends_newline_and_reads_peer_bytes(self, pty_slave):
        master, slave = pty_slave
        console = SerialConsole(slave)
        try:
            # NB: bytes queued before the console opens are flushed by the
            # port open itself (macOS pty) — write the peer banner AFTER.
            os.write(master, b"BusyBox v1.36 built-in shell (ash)\r\n")
            out = console.activate()
            assert "BusyBox v1.36" in out
            # activate() must have sent exactly one newline to the device
            assert master_read_until(master, b"\n") == b"\n"
        finally:
            console.close()

    def test_run_delivers_single_command_and_collects_rc_ok(self, pty_slave):
        master, slave = pty_slave
        console = SerialConsole(slave)
        try:
            rc, out = _run_with_peer(console, master, "true", b"__RC0__\r\n")
            assert rc == 0
            assert "__RC0__" in out
        finally:
            console.close()

    def test_run_collects_rc_fail(self, pty_slave):
        master, slave = pty_slave
        console = SerialConsole(slave)
        try:
            rc, out = _run_with_peer(console, master, "false", b"__RC1__\r\n")
            assert rc == 1
            assert "__RC1__" in out
        finally:
            console.close()

    def test_run_times_out_with_rc_2_when_device_silent(self, pty_slave):
        _master, slave = pty_slave
        console = SerialConsole(slave)
        try:
            start = time.time()
            rc, out = console.run("true", timeout=1.0)
            assert rc == 2
            assert out == ""
            assert time.time() - start >= 1.0
        finally:
            console.close()

    def test_send_script_delivers_line_chunks_via_echo_append(self, pty_slave):
        master, slave = pty_slave
        console = SerialConsole(slave)
        try:
            def responder() -> None:
                # consume every delivered line, answer the final sh line OK
                master_read_until(master, b"echo 'touch /tmp/x' >> /tmp/conwrt-deploy.sh\n")
                master_read_until(master, b"sh /tmp/conwrt-deploy.sh && echo __RC0__ || echo __RC1__\n")
                os.write(master, b"__RC0__\r\n")

            t = threading.Thread(target=responder)
            t.start()
            rc, out = console.send_script(["# a comment", "touch /tmp/x"], timeout=5.0)
            t.join(timeout=3)
            assert rc == 0
            assert "__RC0__" in out
        finally:
            console.close()

    def test_break_byte_triggers_close_wait_reopen_recovery(self, pty_slave):
        master, slave = pty_slave
        console = SerialConsole(slave)
        try:
            def breaker() -> None:
                master_read_until(master, b"true && echo __RC0__")
                os.write(master, b"\x00")  # UART break (device power-off)
                time.sleep(3.5)            # past the 3s reopen + input flush
                os.write(master, b"__RC0__\r\n")

            t = threading.Thread(target=breaker)
            t.start()
            start = time.time()
            rc, out = console.run("true", timeout=8.0)
            t.join(timeout=3)
            assert rc == 0, f"console did not recover after break: rc={rc} out={out!r}"
            assert "__RC0__" in out
            # the FT232R recovery wait exists: >= 3s between break and recovery
            assert time.time() - start >= 3.0
        finally:
            console.close()

    def test_lint_rejects_runtime_vars_in_single_quotes(self):
        with pytest.raises(SerialLinterError):
            lint_script(["echo '$HOME'"])

    def test_lint_rejects_overlong_lines(self):
        with pytest.raises(SerialLinterError):
            lint_script(["x" * (MAX_LINE + 1)])
