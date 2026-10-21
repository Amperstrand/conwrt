"""TCP transport tests: SerialTCP / open_serial / SerialConsole over tcp://.

All tests run against a localhost echo-server thread only (CI rule: no
hardware, no network beyond localhost).
"""
from __future__ import annotations

import socket
import threading
import time

import pytest
import serial as pyserial

from serial_transport import (
    SerialConnectionError,
    SerialConsole,
    SerialTCP,
    open_serial,
    parse_tcp_endpoint,
)

# ─── TCP transport (localhost echo server only — CI rule) ───────────────────


class EchoServer:
    """Local TCP echo server thread: echoes bytes back on every connection.

    close_after_first=True models a bridge that drops its first client after
    one exchange (e.g. its SSH stream reconnected); later connections get a
    persistent echo.
    """

    def __init__(self, close_after_first: bool = False) -> None:
        self._srv = socket.create_server(("127.0.0.1", 0))
        self._srv.settimeout(0.2)
        self.port = self._srv.getsockname()[1]
        self.close_after_first = close_after_first
        self.accepted = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)

    @property
    def url(self) -> str:
        return f"tcp://127.0.0.1:{self.port}"

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self._srv.close()

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.accepted += 1
            first = self.accepted == 1
            persistent = not (first and self.close_after_first)
            threading.Thread(target=self._serve, args=(conn, persistent),
                             daemon=True).start()

    @staticmethod
    def _serve(conn: socket.socket, persistent: bool) -> None:
        try:
            if not persistent:
                data = conn.recv(4096)
                if data:
                    conn.sendall(data)
                return
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()


@pytest.fixture()
def echo_server():
    srv = EchoServer()
    srv.start()
    yield srv
    srv.stop()


def _dead_port() -> int:
    """An ephemeral localhost port with no listener (connection refused)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def tcp_read_until(transport: SerialTCP, needle: bytes, timeout: float = 3.0) -> bytes:
    buf = b""
    end = time.time() + timeout
    while time.time() < end and needle not in buf:
        chunk = transport.read(4096)
        if chunk:
            buf += chunk
    assert needle in buf, f"expected {needle!r} over tcp, got {buf!r}"
    return buf


class TestOpenSerialTCP:
    def test_connects_and_roundtrips_a_line(self, echo_server):
        t = open_serial(echo_server.url)
        try:
            assert isinstance(t, SerialTCP)
            t.write(b"ping\r\n")
            assert tcp_read_until(t, b"ping\r\n") == b"ping\r\n"
        finally:
            t.close()

    def test_in_waiting_then_reset_input_buffer(self, echo_server):
        t = open_serial(echo_server.url)
        try:
            assert t.in_waiting == 0
            t.write(b"hello\n")
            deadline = time.time() + 3
            while time.time() < deadline and t.in_waiting == 0:
                time.sleep(0.02)
            assert t.in_waiting > 0
            t.reset_input_buffer()
            assert t.in_waiting == 0
        finally:
            t.close()

    def test_read_times_out_bounded_when_silent(self, echo_server):
        t = open_serial(echo_server.url, timeout=0.3)
        try:
            start = time.time()
            assert t.read(4096) == b""
            elapsed = time.time() - start
            assert 0.25 <= elapsed < 2.0
        finally:
            t.close()

    def test_refused_connection_raises_typed_error_fast(self):
        port = _dead_port()
        start = time.time()
        with pytest.raises(SerialConnectionError) as excinfo:
            open_serial(f"tcp://127.0.0.1:{port}")
        assert time.time() - start < 5.0  # bounded: no hang on a dead endpoint
        msg = str(excinfo.value)
        assert f"127.0.0.1:{port}" in msg
        assert "ssh -N -L" in msg

    def test_connect_timeout_maps_to_typed_error(self, monkeypatch):
        def _timeout(*_a, **_k):
            raise TimeoutError("timed out")

        monkeypatch.setattr(socket, "create_connection", _timeout)
        with pytest.raises(SerialConnectionError, match="timed out"):
            open_serial("tcp://127.0.0.1:4002")

    @pytest.mark.parametrize("bad", [
        "tcp://host-only",        # no port
        "tcp://host:notaport",    # non-numeric port
        "tcp://host:0",           # port 0
        "tcp://host:70000",       # out of range
    ])
    def test_invalid_endpoints_raise_typed_error(self, bad):
        with pytest.raises(SerialConnectionError):
            open_serial(bad)

    def test_parse_tcp_endpoint_accepts_ipv6_brackets(self):
        assert parse_tcp_endpoint("tcp://[::1]:4002") == ("::1", 4002)


class TestSerialConsoleOverTCP:
    def test_run_roundtrips_through_line_chunked_delivery(self, echo_server):
        console = SerialConsole(echo_server.url)
        try:
            rc, out = console.run("echo hello", timeout=5.0)
            # the echo server mirrors the command line, whose tail already
            # carries the RC marker — pins that full round-trip works
            assert rc == 0
            assert "echo hello" in out
        finally:
            console.close()

    def test_bridge_drop_surfaces_as_serial_exception_then_fresh_invocation(self):
        srv = EchoServer(close_after_first=True)
        srv.start()
        try:
            t = open_serial(srv.url)
            t.write(b"first\n")
            tcp_read_until(t, b"first\n")
            with pytest.raises(pyserial.SerialException):
                deadline = time.time() + 3
                while time.time() < deadline:
                    t.read(4096)
            t.close()

            # stale-state rule: a NEW invocation opens a NEW connection and works
            console = SerialConsole(srv.url)
            try:
                deadline = time.time() + 3
                while time.time() < deadline and srv.accepted < 2:
                    time.sleep(0.02)
                assert srv.accepted == 2
                rc, out = console.run("echo again", timeout=5.0)
                assert rc == 0
                assert "echo again" in out
            finally:
                console.close()
        finally:
            srv.stop()
