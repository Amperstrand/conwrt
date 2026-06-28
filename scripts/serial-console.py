#!/usr/bin/env python3
"""Serial console monitor for conwrt — logs everything, supports command injection.

Based on pyserial's miniterm pattern (3-thread model) adapted for conwrt's
router flashing workflow. Designed to run inside tmux for programmatic control.

Features:
  - Dual logging: raw bytes (.raw.log) + human-readable with timestamps (.log)
  - Direction markers: [RX] for received, [TX] for sent
  - Boot stage detection: U-Boot, Z-Loader, OpenWrt kernel, userspace
  - Command injection via FIFO: write bytes to send them over serial
  - Session management: each session gets its own timestamped log directory
  - Hex+ASCII dual output for non-printable data

Usage:
  # Start monitoring (interactive mode — reads stdin for keystrokes)
  python3 scripts/serial-console.py /dev/cu.usbserial-BG02QAPG

  # Monitoring only (no stdin reading — for background/tmux use)
  python3 scripts/serial-console.py /dev/cu.usbserial-BG02QAPG --monitor

  # Custom baud rate
  python3 scripts/serial-console.py /dev/cu.usbserial-BG02QAPG --baud 57600

  # Specify session name (for log directory)
  python3 scripts/serial-console.py /dev/cu.usbserial-BG02QAPG --session nr7101-flash

Command injection (send keystrokes to a running session):
  printf '\\x1b' > /tmp/conwrt-serial-cmd          # ESC byte
  printf 'help\\r' > /tmp/conwrt-serial-cmd          # type "help" + CR
  printf 'ESCAPE' > /tmp/conwrt-serial-cmd           # special token → ESC
  printf 'ENTER' > /tmp/conwrt-serial-cmd            # special token → CR
  printf 'CTRLC' > /tmp/conwrt-serial-cmd            # special token → Ctrl-C

Log files are written to: serial/<session-name>/
  - console.log    — human-readable with timestamps and direction markers
  - console.raw    — exact raw bytes received (for replay/analysis)
  - session.json   — session metadata (port, baud, start time, stats)
"""
from __future__ import annotations

import argparse
import json
import select
import signal
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

try:
    import serial
except ImportError:
    print("ERROR: pyserial not installed. Run: pip install pyserial", file=sys.stderr)
    sys.exit(1)

from serial_baud import (
    COMMON_BAUDS,
    detect_boot_stage,
    score_baud_data,
)


# ─── Serial Session ─────────────────────────────────────────────────────────

class SerialSession:
    """Manages a serial port session with dual logging and command injection."""

    def __init__(self, port: str, baud: int = 115200, session_name: str = "",
                 log_dir: Path | None = None, interactive: bool = True):
        self.port = port
        self.baud = baud
        self.session_name = session_name or f"session-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        self.interactive = interactive

        # Log directory
        if log_dir:
            self.log_dir = log_dir / self.session_name
        else:
            self.log_dir = Path("serial") / self.session_name
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.console_log = self.log_dir / "console.log"
        self.raw_log = self.log_dir / "console.raw"
        self.session_meta = self.log_dir / "session.json"

        self.cmd_fifo = Path("/tmp/conwrt-serial-cmd")

        self.alive = False
        self.ser: serial.Serial | None = None
        self.reader_thread: threading.Thread | None = None

        self.total_rx = 0
        self.total_tx = 0
        self.boot_stage = "unknown"
        self.boot_stage_history: list[dict] = []
        self.start_time = time.time()

    def open(self) -> bool:
        """Open the serial port. Returns True on success."""
        try:
            self.ser = serial.Serial(
                self.port, self.baud,
                timeout=0.05,
                rtscts=False, dsrdtr=False,
            )
            self.ser.setRTS(False)
            self.ser.setDTR(False)
            return True
        except Exception as e:
            self._stderr(f"ERROR opening {self.port}: {e}")
            return False

    def close(self):
        """Close serial port and finalize logs."""
        self.alive = False
        if self.reader_thread and self.reader_thread.is_alive():
            self.reader_thread.join(timeout=2)
        if self.ser:
            self.ser.close()
        self._write_session_meta()

    def _stderr(self, msg: str):
        sys.stderr.write(f"[{self._ts()}] {msg}\n")
        sys.stderr.flush()

    @staticmethod
    def _ts() -> str:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    @staticmethod
    def _ts_ms() -> str:
        return datetime.now().strftime("%H:%M:%S.") + f"{int((time.time() % 1) * 1000):03d}"

    def _format_bytes(self, data: bytes, direction: str = "RX") -> str:
        """Format bytes for human-readable log: printable chars + escape sequences."""
        parts = []
        for byte in data:
            if byte == 0x0a:
                parts.append("\\n\n")  # actual newline in log
            elif byte == 0x0d:
                parts.append("\\r")
            elif byte == 0x08:
                parts.append("\\b")
            elif byte == 0x1b:
                parts.append("\\e")
            elif byte == 0x09:
                parts.append("\\t")
            elif 0x20 <= byte < 0x7f:
                parts.append(chr(byte))
            elif byte == 0x00:
                parts.append("\\0")
            else:
                parts.append(f"\\x{byte:02x}")
        return "".join(parts)

    def _log_rx(self, data: bytes):
        """Log received data."""
        self.total_rx += len(data)

        # Raw log — exact bytes
        with open(self.raw_log, "ab") as f:
            f.write(data)

        # Console log — human-readable with timestamps
        formatted = self._format_bytes(data, "RX")
        with open(self.console_log, "a", encoding="utf-8") as f:
            f.write(f"[RX {self._ts_ms()}] {formatted}")

        # Also write to stdout for tmux visibility
        try:
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
        except (BrokenPipeError, OSError):
            pass

        # Boot stage detection
        new_stage = detect_boot_stage(data, self.boot_stage)
        if new_stage != self.boot_stage:
            old = self.boot_stage
            self.boot_stage = new_stage
            self.boot_stage_history.append({
                "timestamp": self._ts(),
                "from": old,
                "to": new_stage,
                "elapsed_s": round(time.time() - self.start_time, 2),
            })
            self._stderr(f"BOOT STAGE: {old} → {new_stage}")

    def _log_tx(self, data: bytes, label: str = ""):
        """Log transmitted data."""
        self.total_tx += len(data)
        with open(self.console_log, "a", encoding="utf-8") as f:
            formatted = self._format_bytes(data, "TX")
            desc = f" ({label})" if label else ""
            f.write(f"\n[TX {self._ts_ms()}] {formatted}{desc}\n")
        self._stderr(f">>> SENT: {label or repr(data)} ({len(data)} bytes)")

    def _read_commands(self):
        """Check command FIFO for keystrokes to send."""
        if not self.cmd_fifo.exists():
            return

        try:
            with open(self.cmd_fifo, "rb") as f:
                cmd = f.read()
            self.cmd_fifo.unlink()
        except (OSError, IOError):
            return

        if not cmd:
            return

        # Handle special tokens
        tokens = {
            b"ESCAPE": (b"\x1b", "ESC"),
            b"ESC": (b"\x1b", "ESC"),
            b"ENTER": (b"\r", "CR"),
            b"RETURN": (b"\r", "CR"),
            b"CTRLC": (b"\x03", "Ctrl-C"),
            b"CTRL-D": (b"\x04", "Ctrl-D"),
            b"CTRL-Z": (b"\x1a", "Ctrl-Z"),
            b"TAB": (b"\x09", "Tab"),
        }

        if cmd in tokens:
            data, label = tokens[cmd]
        else:
            data = cmd
            label = cmd.decode("ascii", errors="replace")

        assert self.ser is not None
        self.ser.write(data)
        self.ser.flush()
        self._log_tx(data, label)

    def _reader_loop(self):
        """Reader thread: serial → log + stdout."""
        assert self.ser is not None
        try:
            while self.alive:
                n = self.ser.in_waiting
                if n:
                    data = self.ser.read(n)
                    if data:
                        self._log_rx(data)
                else:
                    time.sleep(0.01)
        except (serial.SerialException, OSError) as e:
            self._stderr(f"Serial read error: {e}")
            self.alive = False

    def _interactive_loop(self):
        """Interactive mode: read stdin (for console keystrokes)."""
        # On POSIX, set terminal to raw mode for single-char reading
        import termios

        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            new = termios.tcgetattr(fd)
            new[3] = new[3] & ~termios.ICANON & ~termios.ECHO
            new[6][termios.VMIN] = 1
            new[6][termios.VTIME] = 0
            termios.tcsetattr(fd, termios.TCSANOW, new)

            while self.alive:
                rlist, _, _ = select.select([sys.stdin], [], [], 0.1)
                if rlist:
                    ch = sys.stdin.buffer.read(1)
                    if ch and self.ser:
                        self.ser.write(ch)
                        self.ser.flush()
                        self._log_tx(ch, f"key:{ch.hex()}")
        finally:
            termios.tcsetattr(fd, termios.TCSAFLUSH, old)

    def run(self):
        """Start the session."""
        self.alive = True

        # Write session header
        with open(self.console_log, "a", encoding="utf-8") as f:
            f.write(f"\n{'='*70}\n")
            f.write(f"Serial session: {self.session_name}\n")
            f.write(f"Port: {self.port} @ {self.baud} 8N1\n")
            f.write(f"Started: {self._ts()}\n")
            f.write(f"Interactive: {self.interactive}\n")
            f.write(f"{'='*70}\n\n")

        self._stderr(f"Serial session: {self.session_name}")
        self._stderr(f"Port: {self.port} @ {self.baud} 8N1")
        self._stderr(f"Logs: {self.log_dir}/")
        self._stderr("  console.log  — human-readable with timestamps")
        self._stderr("  console.raw  — exact raw bytes")
        self._stderr(f"Cmd FIFO: {self.cmd_fifo}")
        if not self.interactive:
            self._stderr(">>> REBOOT THE DEVICE NOW <<<")
        self._stderr("")

        # Start reader thread
        self.reader_thread = threading.Thread(target=self._reader_loop, name="rx", daemon=True)
        self.reader_thread.start()

        # Main loop: command injection + interactive
        try:
            if self.interactive:
                # Run interactive in main thread (needs terminal control)
                # Command checking happens in a separate thread
                cmd_thread = threading.Thread(target=self._cmd_check_loop, daemon=True)
                cmd_thread.start()
                self._interactive_loop()
            else:
                # Monitor mode: just check commands in main loop
                self._cmd_check_loop()
        except KeyboardInterrupt:
            self._stderr("Interrupted by user")
        finally:
            self.close()

    def _cmd_check_loop(self):
        """Continuously check for commands from FIFO."""
        while self.alive:
            self._read_commands()
            time.sleep(0.01)

    def _write_session_meta(self):
        """Write session metadata JSON."""
        elapsed = round(time.time() - self.start_time, 2)
        meta = {
            "session_name": self.session_name,
            "port": self.port,
            "baud": self.baud,
            "start_time": datetime.fromtimestamp(self.start_time).isoformat(),
            "elapsed_s": elapsed,
            "total_rx_bytes": self.total_rx,
            "total_tx_bytes": self.total_tx,
            "final_boot_stage": self.boot_stage,
            "boot_stage_transitions": self.boot_stage_history,
        }
        with open(self.session_meta, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        self._stderr(f"Session saved: {self.session_meta}")
        self._stderr(f"  RX: {self.total_rx} bytes, TX: {self.total_tx} bytes, {elapsed}s")
        self._stderr(f"  Final boot stage: {self.boot_stage}")


# ─── Port Listing ───────────────────────────────────────────────────────────

def list_ports():
    """List available serial ports."""
    from serial.tools.list_ports import comports
    ports = sorted(comports())
    if not ports:
        print("No serial ports found.", file=sys.stderr)
        return []
    print("Available serial ports:", file=sys.stderr)
    for i, (port, desc, _hwid) in enumerate(ports, 1):
        print(f"  {i}. {port:30s} {desc}", file=sys.stderr)
    return [p[0] for p in ports]


# ─── Auto-Baud Detection ────────────────────────────────────────────────────


def _open_serial(port: str, baud: int = 115200, timeout: float = 0.1,
                  reset: bool = False) -> serial.Serial:
    s = serial.Serial(port, baud, timeout=timeout)
    s.setRTS(False)
    s.setDTR(False)
    if reset:
        s.reset_input_buffer()
    return s


def auto_detect_baud(port: str, sample_seconds: float = 2.0,
                     bauds: list[int] | None = None) -> tuple[int, dict]:
    """Try common baud rates and return the one with best signal quality.

    Returns (best_baud, results_dict).
    """
    bauds = bauds or COMMON_BAUDS
    results = {}

    print(f"Auto-detecting baud rate on {port}...", file=sys.stderr)
    print(f"  Testing {len(bauds)} rates, {sample_seconds}s each...", file=sys.stderr)

    for baud in bauds:
        try:
            s = _open_serial(port, baud, timeout=0.1, reset=True)

            # Sample for the specified duration
            data = bytearray()
            start = time.time()
            while time.time() - start < sample_seconds:
                if s.in_waiting:
                    data.extend(s.read(s.in_waiting))

            s.close()

            score, reason = score_baud_data(bytes(data))
            results[baud] = {
                "score": score,
                "bytes": len(data),
                "reason": reason,
                "sample_hex": data[:32].hex() if data else "",
            }

            marker = " ★" if score > 0 else ""
            print(f"  {baud:>7} baud: {len(data):>5}B, score={score:>3}{marker}  ({reason})",
                  file=sys.stderr)

        except Exception as e:
            results[baud] = {"score": -1, "error": str(e)}
            print(f"  {baud:>7} baud: ERROR: {e}", file=sys.stderr)

    # Pick best
    best_baud = max(results, key=lambda b: results[b].get("score", -1))
    best_score = results[best_baud].get("score", -1)

    if best_score > 0:
        print(f"\n  → Best: {best_baud} baud (score={best_score})", file=sys.stderr)
    else:
        print("\n  → No valid data at any baud rate. Device may not be transmitting.", file=sys.stderr)
        print("  → Check: RX/TX wiring, GND connection, device power.", file=sys.stderr)

    return (best_baud, results)


ADAPTER_CHIPS = {
    ("0403", "6001"): "FTDI FT232R (classic, 3.3V/5V via jumper)",
    ("0403", "6015"): "FTDI FT231X (3.3V native)",
    ("0403", "6010"): "FTDI FT2232H (dual channel)",
    ("10C4", "EA60"): "Silicon Labs CP210x (3.3V native)",
    ("1A86", "7523"): "CH340 (3.3V/5V via jumper)",
    ("1A86", "5523"): "CH341 (3.3V/5V via jumper)",
    ("067B", "2303"): "Prolific PL2303 (legacy)",
}

ADAPTER_VENDORS = {
    "0403": "FTDI",
    "10C4": "Silicon Labs",
    "1A86": "WCH",
    "067B": "Prolific",
}


def identify_adapter(vid: str, pid: str) -> str:
    if (vid, pid) in ADAPTER_CHIPS:
        return ADAPTER_CHIPS[(vid, pid)]
    if vid in ADAPTER_VENDORS:
        return f"{ADAPTER_VENDORS[vid]} (PID {pid})"
    return ""


# ─── Adapter Diagnostics ────────────────────────────────────────────────────

def diagnose_adapter(port: str | None = None):
    """Run adapter health checks without connecting to a device."""
    from serial.tools.list_ports import comports

    print("=== Serial Adapter Diagnostics ===\n", file=sys.stderr)

    # 1. List all ports
    ports = sorted(comports())
    usb_serial_ports = [(p, d, h) for p, d, h in ports
                        if "usbserial" in p or "USB" in d.upper() or "UART" in d.upper()
                        or "FTDI" in d.upper() or "CP210" in d.upper() or "CH340" in d.upper()]

    if not usb_serial_ports:
        print("❌ No USB-serial adapters detected.", file=sys.stderr)
        print("   Check: adapter plugged in? USB cable working? Driver loaded?", file=sys.stderr)
        return False

    print(f"Found {len(usb_serial_ports)} USB-serial adapter(s):\n", file=sys.stderr)
    for i, (p, desc, hwid) in enumerate(usb_serial_ports, 1):
        print(f"  {i}. {p}", file=sys.stderr)
        print(f"     Description: {desc}", file=sys.stderr)
        print(f"     Hardware ID: {hwid}", file=sys.stderr)

        # Parse VID/PID from hardware ID
        vid = pid = ""
        if "VID:PID=" in hwid:
            vppart = hwid.split("VID:PID=")[1].split(" ")[0]
            if ":" in vppart:
                vid, pid = vppart.split(":")

        adapter_info = identify_adapter(vid, pid)

        if adapter_info:
            print(f"     Chip: {adapter_info}", file=sys.stderr)
        print(file=sys.stderr)

    # 2. Check for duplicate device nodes (same adapter, multiple /dev entries)
    print("Checking for device node aliases...", file=sys.stderr)
    port_paths = {}
    for p, d, _h in usb_serial_ports:
        # Group by description (same chip = same adapter)
        port_paths.setdefault(d, []).append(p)
    for _desc, p_list in port_paths.items():
        if len(p_list) > 1:
            print(f"  ⚠️  Multiple device nodes for same adapter: {p_list}", file=sys.stderr)
            print("     These share one physical port — opening one locks the others.", file=sys.stderr)

    # 3. Try opening each port and check signal lines
    target_ports = [port] if port else [p for p, _, _ in usb_serial_ports]

    print(f"\nProbing signal lines on {len(target_ports)} port(s)...\n", file=sys.stderr)
    for p in target_ports:
        print(f"  {p}:", file=sys.stderr)
        try:
            s = serial.Serial(p, 115200, timeout=0.1)
            print("    ✓ Port opens successfully", file=sys.stderr)

            # Signal line states
            try:
                print(f"    CTS: {'HIGH' if s.cts else 'low'}", file=sys.stderr)
                print(f"    DSR: {'HIGH' if s.dsr else 'low'}", file=sys.stderr)
                print(f"    CD:  {'HIGH' if s.cd else 'low'}", file=sys.stderr)
                print(f"    RI:  {'HIGH' if s.ri else 'low'}", file=sys.stderr)
            except Exception:
                print("    (signal lines not readable on this adapter)", file=sys.stderr)

            # Quick RX check — any noise on the line?
            s.reset_input_buffer()
            time.sleep(0.5)
            rx_bytes = s.in_waiting
            if rx_bytes > 0:
                data = s.read(rx_bytes)
                print(f"    ⚠️  {rx_bytes} bytes already in RX buffer (noise?): {data[:16].hex()}", file=sys.stderr)
            else:
                print("    RX buffer: empty (good — no floating-pin noise)", file=sys.stderr)

            s.close()
        except Exception as e:
            print(f"    ❌ Cannot open: {e}", file=sys.stderr)
        print(file=sys.stderr)

    # 4. Summary
    print("=== Diagnostic Summary ===", file=sys.stderr)
    print(f"  Adapters found: {len(usb_serial_ports)}", file=sys.stderr)
    print("  To test TX/RX health: bridge TX→RX with jumper, run:", file=sys.stderr)
    print(f"    python3 scripts/serial-console.py {' '.join(target_ports[:1])} --loopback", file=sys.stderr)
    print("  To auto-detect baud rate: connect to device, run:", file=sys.stderr)
    print("    python3 scripts/serial-console.py <port> --auto-baud", file=sys.stderr)
    return True


# ─── Loopback Test ──────────────────────────────────────────────────────────

def loopback_test(port: str, baud: int = 115200) -> bool:
    """Test TX→RX path by sending known data and checking for echo.

    REQUIRES physical jumper wire between TX and RX pins on the adapter.
    """
    print(f"=== Loopback Test: {port} @ {baud} ===\n", file=sys.stderr)
    print("⚠️  This requires a physical jumper wire between TX and RX pins.\n", file=sys.stderr)

    test_patterns = [
        b"Hello, Serial!",
        b"\x55\x55\x55\x55",  # 0x55 = alternating bits (clock pattern)
        bytes(range(256)),     # All byte values
        b"conwrt-loopback-test\r\n",
    ]

    try:
        s = _open_serial(port, baud, timeout=0.5)
    except Exception as e:
        print(f"❌ Cannot open {port}: {e}", file=sys.stderr)
        return False

    all_pass = True
    for i, pattern in enumerate(test_patterns):
        s.reset_input_buffer()
        s.write(pattern)
        s.flush()
        time.sleep(0.1)  # Allow time for echo

        received = bytearray()
        while s.in_waiting:
            received.extend(s.read(s.in_waiting))

        if received == pattern:
            print(f"  Test {i+1}: ✓ PASS ({len(pattern)} bytes echoed correctly)", file=sys.stderr)
        elif len(received) == 0:
            print(f"  Test {i+1}: ✗ FAIL — no echo (TX→RX jumper missing or adapter TX dead)", file=sys.stderr)
            all_pass = False
        elif received != pattern:
            print(f"  Test {i+1}: ✗ FAIL — data mismatch", file=sys.stderr)
            print(f"    Sent:     {pattern[:32].hex()}", file=sys.stderr)
            print(f"    Received: {bytes(received)[:32].hex()}", file=sys.stderr)
            all_pass = False

    s.close()

    if all_pass:
        print("\n✓ ALL TESTS PASSED — adapter TX/RX is working correctly.", file=sys.stderr)
        print("  If device still shows no data, problem is in wiring to device or device itself.", file=sys.stderr)
    else:
        print("\n✗ TESTS FAILED — adapter may be broken or jumper not connected.", file=sys.stderr)
        print("  Check: Is TX physically bridged to RX? Try a different jumper wire.", file=sys.stderr)

    return all_pass


# ─── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Serial console monitor for conwrt router flashing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("port", nargs="?", default=None,
                        help="serial port (e.g. /dev/cu.usbserial-BG02QAPG)")
    parser.add_argument("--baud", type=int, default=115200,
                        help="baud rate (default: 115200)")
    parser.add_argument("--session", default="",
                        help="session name for log directory (default: timestamp)")
    parser.add_argument("--monitor", action="store_true",
                        help="monitor mode (no interactive stdin — for tmux/background)")
    parser.add_argument("--log-dir", default=None,
                        help="base directory for session logs (default: serial/)")
    parser.add_argument("-l", "--list", action="store_true",
                        help="list available serial ports and exit")

    diag_group = parser.add_argument_group("diagnostics")
    diag_group.add_argument("--auto-baud", action="store_true",
                            help="sweep common baud rates, auto-detect best one, then monitor")
    diag_group.add_argument("--auto-baud-only", action="store_true",
                            help="run baud detection only, print result and exit")
    diag_group.add_argument("--sample-time", type=float, default=2.0,
                            help="seconds to sample at each baud rate during auto-detect (default: 2.0)")
    diag_group.add_argument("--diagnose", action="store_true",
                            help="run adapter health check (no device needed) and exit")
    diag_group.add_argument("--loopback", action="store_true",
                            help="run TX/RX loopback test (requires jumper wire) and exit")
    args = parser.parse_args()

    if args.list:
        list_ports()
        sys.exit(0)

    if args.diagnose:
        diagnose_adapter(args.port)
        sys.exit(0)

    if args.port is None:
        list_ports()
        sys.exit(1)

    if args.loopback:
        loopback_test(args.port, args.baud)
        sys.exit(0)

    if args.auto_baud_only:
        best, results = auto_detect_baud(args.port, args.sample_time)
        if results[best].get("score", -1) > 0:
            print(best)
        else:
            sys.exit(1)
        sys.exit(0)

    if args.auto_baud:
        best, results = auto_detect_baud(args.port, args.sample_time)
        if results[best].get("score", -1) > 0:
            args.baud = best
        else:
            print("No valid baud detected — using default 115200", file=sys.stderr)

    log_base = Path(args.log_dir) if args.log_dir else None
    session = SerialSession(
        port=args.port,
        baud=args.baud,
        session_name=args.session,
        log_dir=log_base,
        interactive=not args.monitor,
    )

    # Clean shutdown on signals
    def signal_handler(sig, frame):
        session._stderr(f"Signal {sig} received — stopping")
        session.alive = False
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if not session.open():
        sys.exit(1)
    session.run()


if __name__ == "__main__":
    main()
