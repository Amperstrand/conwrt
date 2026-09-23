#!/usr/bin/env python3
"""serial_transport — reliable command execution over OpenWrt serial consoles.

Encodes the lessons from the 2026-09-22 switch recovery (AGENTS.md):

  * OpenWrt consoles use askfirst: send Enter to activate, then interact.
  * Long single lines exceed the tty line buffer — deliver scripts
    line-by-line, assembled via `echo '...' >> file`, then `sh file`.
  * Never carry shell variables through the serial channel: single-quoted
    payload lines turn `$N` into a literal. The linter below REFUSES
    scripts containing runtime variable references (generate literals
    on the controlling host instead).
  * FT232R adapters wedge on the UART break when a device power-cycles:
    on reading 0x00, close, wait for the device to boot, reopen fresh.

Transports: a local /dev port via pyserial, or `tcp://HOST:PORT` via a
stdlib socket to a remote serial-console bridge (scripts/conwrt_serial_bridge.py
on the bench exporter). From a Mac without direct reachability, forward the
bridge port first, then use the forwarded address as the port:

    ssh -N -L 4002:127.0.0.1:4002 ai-legion
    ... --port tcp://127.0.0.1:4002

TCP semantics: baud is a property of the remote line and is ignored; every
SerialConsole/CLI invocation opens a fresh connection (no session reuse); a
relayed 0x00 break byte or a dropped bridge connection triggers the same
close → 3s wait → reopen recovery as a local FT232R (reopen = reconnect). All
socket operations are bounded by timeouts; connection setup failures raise
SerialConnectionError with a human-readable message instead of a traceback.

Runs anywhere with pyserial (macOS /dev/cu.*, Linux /dev/ttyUSB* or
/dev/serial/by-id/*). SSH transports should be preferred whenever the
device is reachable — this module is for bootstrap and recovery.
"""

from __future__ import annotations

import re
import select
import socket
import time
from pathlib import Path
from typing import TypeAlias

import serial

RC_OK = "__RC0__"
RC_FAIL = "__RC1__"
MAX_LINE = 200
TCP_PREFIX = "tcp://"


class SerialLinterError(ValueError):
    pass


class SerialConnectionError(RuntimeError):
    """A console transport could not be opened (refused/timeout/bad endpoint).

    The message is safe to print directly to an operator; it never carries a
    raw traceback.
    """


class SerialTCP:
    """pyserial-compatible facade over a raw TCP console stream (stdlib socket).

    Speaks the byte protocol of the conwrt serial bridge (and labgrid's
    NetworkSerialPort): raw bidirectional relay, no negotiation. Implements
    the pyserial surface the console tools use — read/write/in_waiting/
    reset_input_buffer/flush/close plus no-op RTS/DTR (no control lines on
    TCP). Reads block at most `timeout`; connection setup is bounded by
    `connect_timeout`. EOF and socket errors are translated to
    serial.SerialException so SerialConsole's break-recovery path treats a
    dropped bridge like a wedged local adapter.
    """

    def __init__(self, host: str, port: int, timeout: float = 0.2,
                 connect_timeout: float = 5.0) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: socket.socket | None = None
        try:
            self._sock = socket.create_connection((host, port), timeout=connect_timeout)
        except OSError as e:
            raise SerialConnectionError(
                f"cannot connect to tcp://{host}:{port}: {e} — is the serial bridge "
                f"running and forwarded? (Mac access: ssh -N -L {port}:127.0.0.1:{port} ai-legion)"
            ) from e
        self._sock.settimeout(None)

    def _require_sock(self) -> socket.socket:
        if self._sock is None:
            raise serial.SerialException(f"tcp://{self.host}:{self.port} is closed")
        return self._sock

    def read(self, size: int = 1) -> bytes:
        sock = self._require_sock()
        try:
            ready, _, _ = select.select([sock], [], [], self.timeout)
            if not ready:
                return b""
            data = sock.recv(size)
            if not data:
                raise serial.SerialException(
                    f"tcp://{self.host}:{self.port}: connection closed by remote bridge")
            return data
        except OSError as e:
            raise serial.SerialException(
                f"tcp://{self.host}:{self.port} read failed: {e}") from e

    def write(self, data: bytes | bytearray | memoryview) -> int:
        sock = self._require_sock()
        try:
            sock.sendall(data)
            return len(data)
        except OSError as e:
            raise serial.SerialException(
                f"tcp://{self.host}:{self.port} write failed: {e}") from e

    def flush(self) -> None:
        pass  # sendall is synchronous

    @property
    def in_waiting(self) -> int:
        """1 when data is pending, else 0 (TCP cannot report an exact count)."""
        sock = self._sock
        if sock is None:
            return 0
        ready, _, _ = select.select([sock], [], [], 0)
        return 1 if ready else 0

    def reset_input_buffer(self) -> None:
        sock = self._sock
        if sock is None:
            return
        sock.setblocking(False)
        try:
            while True:
                try:
                    if not sock.recv(4096):
                        break
                except BlockingIOError:
                    break
        except OSError:
            pass  # best-effort drain; read() reports real connection failures
        finally:
            sock.setblocking(True)

    def setRTS(self, value: bool) -> None:
        pass  # no control lines over TCP

    def setDTR(self, value: bool) -> None:
        pass  # no control lines over TCP

    def close(self) -> None:
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()


SerialLike: TypeAlias = serial.Serial | SerialTCP


def parse_tcp_endpoint(port: str) -> tuple[str, int]:
    """Split tcp://HOST:PORT into (host, port); typed error when malformed."""
    endpoint = port.removeprefix(TCP_PREFIX)
    host, sep, port_str = endpoint.rpartition(":")
    if not sep or not host:
        raise SerialConnectionError(
            f"invalid endpoint {port!r} — expected tcp://HOST:PORT")
    try:
        tcp_port = int(port_str)
    except ValueError:
        raise SerialConnectionError(
            f"invalid port {port_str!r} in {port!r} — expected tcp://HOST:PORT") from None
    if not 0 < tcp_port < 65536:
        raise SerialConnectionError(f"port {tcp_port} out of range in {port!r}")
    return host.strip("[]"), tcp_port


def open_serial(port: str, baud: int = 115200, timeout: float = 0.2) -> SerialLike:
    """Open a console transport by port spec.

    Local /dev paths open via pyserial (8N1). tcp://HOST:PORT connects to a
    remote serial-console bridge with a stdlib socket; baud is a property of
    the remote line and is ignored there. Raises SerialConnectionError (clean
    message, no traceback) when a tcp:// endpoint is malformed or unreachable.
    """
    if port.startswith(TCP_PREFIX):
        host, tcp_port = parse_tcp_endpoint(port)
        return SerialTCP(host, tcp_port, timeout=timeout)
    return serial.Serial(port=port, baudrate=baud, bytesize=8,
                         parity="N", stopbits=1, timeout=timeout)


def lint_script(lines: list[str]) -> None:
    for n, line in enumerate(lines, 1):
        if len(line) > MAX_LINE:
            raise SerialLinterError(f"line {n} exceeds {MAX_LINE} chars: {line[:60]!r}")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        single_quoted = re.findall(r"'([^']*)'", line)
        for payload in single_quoted:
            if "$" in payload:
                raise SerialLinterError(
                    f"line {n}: runtime variable inside single quotes "
                    f"(will not expand over serial): {line[:60]!r}"
                )


class SerialConsole:
    def __init__(self, port: str, baud: int = 115200, timeout: float = 0.2) -> None:
        self.port = port
        self.baud = baud
        self.timeout = timeout
        self._s: SerialLike = open_serial(port, baud, timeout)

    def close(self) -> None:
        self._s.close()

    def _reopen_after_break(self) -> None:
        self._s.close()
        time.sleep(3)
        self._s = open_serial(self.port, self.baud, self.timeout)
        self._s.reset_input_buffer()

    def activate(self, wait: float = 0.8) -> str:
        self._s.write(b"\n")
        time.sleep(wait)
        out = self._s.read(4096)
        return out.decode(errors="replace")

    def run(self, cmd: str, timeout: float = 20.0) -> tuple[int, str]:
        assert "\n" not in cmd, "run() takes a single command"
        self._s.reset_input_buffer()
        self._s.write(b"\n")
        time.sleep(0.3)
        self._s.reset_input_buffer()
        self._s.write(cmd.encode() + b" && echo " + RC_OK.encode() +
                      b" || echo " + RC_FAIL.encode() + b"\n")
        return self._collect(timeout)

    def _collect(self, timeout: float) -> tuple[int, str]:
        buf = b""
        end = time.time() + timeout
        while time.time() < end:
            try:
                chunk = self._s.read(4096)
            except serial.SerialException:
                self._reopen_after_break()
                continue
            if chunk and chunk[:1] == b"\x00":
                self._reopen_after_break()
                end = time.time() + timeout
                continue
            if chunk:
                buf += chunk
            if RC_OK.encode() in buf:
                time.sleep(0.3)
                buf += self._s.read(4096)
                return 0, buf.decode(errors="replace").replace("\r", "")
            if RC_FAIL.encode() in buf:
                time.sleep(0.3)
                buf += self._s.read(4096)
                return 1, buf.decode(errors="replace").replace("\r", "")
        return 2, buf.decode(errors="replace").replace("\r", "")

    def send_script(self, lines: list[str], timeout: float = 90.0) -> tuple[int, str]:
        lint_script(lines)
        self._s.reset_input_buffer()
        self._s.write(b"\n")
        time.sleep(0.3)
        self._s.reset_input_buffer()
        self._s.write(b"rm -f /tmp/conwrt-deploy.sh\n")
        time.sleep(0.2)
        for line in lines:
            if not line.strip() or line.strip().startswith("#"):
                continue
            escaped = line.replace("'", "'\\''")
            self._s.write(b"echo '" + escaped.encode() + b"' >> /tmp/conwrt-deploy.sh\n")
            time.sleep(0.12)
        self._s.write(b"sh /tmp/conwrt-deploy.sh && echo " + RC_OK.encode() +
                      b" || echo " + RC_FAIL.encode() + b"\n")
        return self._collect(timeout)

    def send_script_file(self, path: str | Path, timeout: float = 90.0) -> tuple[int, str]:
        return self.send_script(Path(path).read_text().splitlines(), timeout)
