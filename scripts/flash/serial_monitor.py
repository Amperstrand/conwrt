#!/usr/bin/env python3
"""Optional serial boot-milestone monitor for `conwrt flash --serial`.

When the flag is present, a background thread reads a serial stream —
`tcp://HOST:PORT` through the conwrt serial bridge (scripts/
conwrt_serial_bridge.py, reached from a Mac via `ssh -N -L PORT:127.0.0.1:PORT
ai-legion`) or a local /dev adapter — and emits `(Event, ts, detail)` tuples
into the same event queue the pcap monitor feeds. Milestones cover the boot
vocabulary observed on the AP3915i bench capture
(data/bench/ap-lan2/20260923-serial-via-lan4/lan2-boot.log):

    U-Boot 2012.07.22 (Jul 19 2022 - 10:26:07) (primary)   -> SERIAL_UBOOT_BANNER
    Starting kernel ...                                    -> SERIAL_KERNEL_START
    [    3.873775] init: - preinit -                       -> SERIAL_PROCD_PREINIT
       13.054844] procd: - init -                          -> SERIAL_PROCD_INIT
    root@OpenWrt:~#                                         -> SERIAL_LOGIN_PROMPT

Each milestone latches once per monitor lifetime: a single boot signal per
flash is what the timeline records, and re-matches of the same pattern (e.g.
the kernel cmdline echoing `BOOT_BOOTROM="U-Boot 2012..."`) are ignored.

Failure semantics (AGENTS.md): a stream that dies mid-flash — bridge drop,
adapter unplug — logs ONE warning and the flash continues pcap-only; the
monitor never aborts the flow. A relayed/local UART break byte (0x00 run,
device power-cycling) instead triggers the FT232R close→wait→reopen
recovery so the monitor is still alive when power returns.

This module is imported lazily (conwrt.monitors._setup_serial_monitor):
without `--serial`, flash never touches pyserial.
"""
from __future__ import annotations

import queue
import re
import threading
import time
from typing import Optional

import serial as pyserial

from flash.context import Event, log, ts
from serial_transport import (
    SerialConnectionError,
    SerialLike,
    TCP_PREFIX,
    open_serial,
    parse_tcp_endpoint,
)

BREAK_RECOVERY_WAIT = 3.0
_READ_TIMEOUT = 0.2
_READ_SIZE = 4096
_MAX_BUFFER = 65536
_KEEP_TAIL = 32768

_MILESTONE_PATTERNS: tuple[tuple[re.Pattern[str], Event], ...] = (
    (re.compile(r"U-Boot \d"), Event.SERIAL_UBOOT_BANNER),
    (re.compile(r"Starting kernel"), Event.SERIAL_KERNEL_START),
    (re.compile(r"init: - preinit -"), Event.SERIAL_PROCD_PREINIT),
    (re.compile(r"(?:init|procd): - init -"), Event.SERIAL_PROCD_INIT),
    (re.compile(r"root@"), Event.SERIAL_LOGIN_PROMPT),
)


def parse_serial_spec(spec: str) -> tuple[str, Optional[int]]:
    """Split a --serial spec into (port, baud-or-None).

    Forms: tcp://HOST:PORT[,baud] or /dev/path[,baud]. Baud applies to local
    adapters only (a tcp:// line's baud is a property of the remote side);
    it is still accepted there and simply ignored. Raises
    SerialConnectionError on a malformed endpoint or baud suffix.
    """
    port, sep, baud_str = spec.partition(",")
    baud: Optional[int] = None
    if sep:
        try:
            baud = int(baud_str)
        except ValueError:
            raise SerialConnectionError(
                f"invalid baud {baud_str!r} in --serial {spec!r} — expected "
                f"tcp://HOST:PORT[,baud] or /dev/path[,baud]") from None
    if port.startswith(TCP_PREFIX):
        parse_tcp_endpoint(port)
    elif not port.startswith("/"):
        raise SerialConnectionError(
            f"invalid --serial spec {spec!r} — expected tcp://HOST:PORT[,baud] "
            f"or /dev/path[,baud]")
    return port, baud


def _line_at(text: str, match: re.Match[str]) -> str:
    start = text.rfind("\n", 0, match.start()) + 1
    end = text.find("\n", match.end())
    if end == -1:
        end = len(text)
    return text[start:end].strip()[:120]


class SerialBootMonitor:
    """Background thread parsing a serial stream for boot milestones.

    Emits into the shared event queue with the pcap monitor's tuple shape
    (Event, ts, detail); serial observations are ground truth and win
    conflicts in flash.context.apply_serial_milestone.
    """

    def __init__(self, port: str, baud: int, event_queue: queue.Queue) -> None:
        self.port = port
        self.baud = baud
        self.event_queue = event_queue
        self._stop = threading.Event()
        self._transport: Optional[SerialLike] = None
        self._seen: set[Event] = set()
        self._buf = ""
        self._break_logged = False

    def stop(self) -> None:
        self._stop.set()

    def _emit(self, event: Event, detail: str) -> None:
        log(f"[serial] {event.name}: {detail}")
        self.event_queue.put((event, ts(), detail))

    def _feed(self, data: bytes) -> None:
        self._buf += data.decode(errors="replace")
        for pattern, event in _MILESTONE_PATTERNS:
            if event in self._seen:
                continue
            match = pattern.search(self._buf)
            if match:
                self._seen.add(event)
                self._emit(event, _line_at(self._buf, match))
        if len(self._buf) > _MAX_BUFFER:
            self._buf = self._buf[-_KEEP_TAIL:]

    def _close_transport(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None

    def _open_transport(self) -> None:
        self._transport = open_serial(self.port, self.baud, timeout=_READ_TIMEOUT)

    def _reopen_after_break(self) -> bool:
        """FT232R/bridge recovery for a UART break (device power cycle).

        Returns False when the line cannot be reopened — treated as a
        disconnect (warn once, pcap-only), never an abort.
        """
        if not self._break_logged:
            log("serial break byte (device power cycle) — recovering monitor")
            self._break_logged = True
        self._close_transport()
        time.sleep(BREAK_RECOVERY_WAIT)
        try:
            self._open_transport()
        except (SerialConnectionError, pyserial.SerialException) as e:
            log(f"WARNING: serial line lost after break ({e}) — continuing pcap-only")
            return False
        self._transport.reset_input_buffer()
        return True

    def run(self) -> None:
        is_tcp = self.port.startswith(TCP_PREFIX)
        baud_note = "" if is_tcp else f" @ {self.baud} baud"
        log(f"Serial monitor starting: {self.port}{baud_note}")
        try:
            self._open_transport()
        except (SerialConnectionError, pyserial.SerialException) as e:
            log(f"WARNING: serial monitor could not open {self.port} ({e}) — "
                f"continuing without serial monitoring")
            return
        try:
            while not self._stop.is_set():
                try:
                    chunk = self._transport.read(_READ_SIZE)
                except pyserial.SerialException as e:
                    log(f"WARNING: serial stream lost mid-flash ({e}) — "
                        f"continuing pcap-only")
                    return
                if not chunk:
                    continue
                if chunk[0:1] == b"\x00":
                    if not self._reopen_after_break():
                        return
                    chunk = chunk.lstrip(b"\x00")
                    if not chunk:
                        continue
                self._feed(chunk)
        finally:
            self._close_transport()
            log("Serial monitor stopped")
