import argparse
import os
import queue
import re
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Optional

from flash.context import Event, OemState, RecoveryContext, State, Timeline, log, say, ts
from platform_utils import detect_platform


def _auto_detect_serial_port() -> str:
    import glob as globmod
    candidates = sorted(globmod.glob("/dev/cu.usbserial*") + globmod.glob("/dev/cu.SLAB_USBtoUART*"))
    if candidates:
        return candidates[0]
    raise FileNotFoundError(
        "No serial adapter found. Checked /dev/cu.usbserial* and /dev/cu.SLAB_USBtoUART*. "
        "Use --serial-port to specify manually."
    )


class TFTPServerManager:
    def __init__(self, tftp_root: str, bind_ip: str = "0.0.0.0"):
        self.tftp_root = tftp_root
        self.bind_ip = bind_ip or "0.0.0.0"
        self._proc: Optional[subprocess.Popen] = None

    def start(self) -> bool:
        if not os.path.isdir(self.tftp_root):
            log(f"ERROR: TFTP root directory not found: {self.tftp_root}")
            return False

        tftp_script = os.path.join(os.path.dirname(__file__), "..", "..", "jtag", "tftp-server.py")
        if not os.path.isfile(tftp_script):
            tftp_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tftp-server.py")

        tftp_cmd = None
        if os.path.isfile(tftp_script):
            tftp_cmd = [sys.executable, tftp_script, self.tftp_root, self.bind_ip]
        else:
            if detect_platform() != "openwrt":
                import shutil
                dnsmasq = shutil.which("dnsmasq")
                if dnsmasq:
                    tftp_cmd = [
                        dnsmasq,
                        f"--tftp-root={self.tftp_root}",
                        "--no-daemon",
                        "--port=0",
                        f"--listen-address={self.bind_ip}",
                    ]
            else:
                log("On OpenWrt: skipping dnsmasq (conflicts with existing DNS/DHCP)")
                log("  Place tftp-server.py in scripts/ directory for TFTP support")

        if not tftp_cmd:
            log("WARNING: No TFTP server script found. U-Boot TFTP commands may fail.")
            log("  Expected: jtag/tftp-server.py or scripts/tftp-server.py")
            return False

        log(f"Starting TFTP server: {' '.join(tftp_cmd)}")
        try:
            self._proc = subprocess.Popen(
                tftp_cmd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            time.sleep(1)
            if self._proc.poll() is not None:
                err = self._proc.stderr.read().decode(errors="replace")
                log(f"TFTP server failed to start: {err.strip()}")
                self._proc = None
                return False
            log(f"TFTP server serving {self.tftp_root} on {self.bind_ip}:69 (PID {self._proc.pid})")
            return True
        except Exception as e:
            log(f"TFTP server error: {e}")
            self._proc = None
            return False

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            log("TFTP server stopped")

    @property
    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None


class SerialUBootDriver:
    ERROR_STRINGS = ["ERROR:", "not found", "Bad CRC", "usage:", "Unknown command"]

    def __init__(self, port: str, baud: int = 115200, timeout: float = 0.1):
        try:
            import serial as _serial
        except ImportError:
            print("ERROR: pyserial is required for serial-tftp flash method.", file=sys.stderr)
            print("  Install with: pip install pyserial", file=sys.stderr)
            sys.exit(1)
        self._serial_mod = _serial
        self.ser = _serial.Serial(port, baud, timeout=timeout)
        self.port = port
        self.baud = baud

    def _drain(self, timeout: float = 0.5) -> bytes:
        time.sleep(timeout)
        data = b""
        while True:
            chunk = self.ser.read(4096)
            if not chunk:
                break
            data += chunk
        return data

    def wait_for_bootmenu(self, timeout: float = 60, interrupt: str = "ctrl-c",
                          console_option: str = "0", say_fn=None) -> bool:
        buf = b""
        start = time.time()
        while time.time() - start < timeout:
            chunk = self.ser.read(4096)
            if chunk:
                buf += chunk
                text = chunk.decode("ascii", errors="replace")
                for line in text.split("\n"):
                    clean = line.strip()
                    if clean:
                        log(f"  [serial] {clean}")

                full_text = buf.decode("ascii", errors="replace")

                if "Hit any key" in full_text or "stop autoboot" in full_text.lower():
                    log("Bootmenu countdown detected — entering U-Boot console")
                    if say_fn:
                        say_fn("Bootmenu detected. Entering U-Boot console.")
                    time.sleep(0.5)
                    self.ser.write(b"\x03")
                    time.sleep(0.3)
                    self.ser.write((console_option + "\r\n").encode())
                    time.sleep(2)
                    remaining = self._drain(2)
                    full_text += remaining.decode("ascii", errors="replace")

                if "=>" in full_text:
                    log("Got U-Boot prompt")
                    self._drain(0.5)
                    return True

                if "login:" in full_text or "init:" in full_text:
                    log("ERROR: Linux already booting — too late to interrupt")
                    return False

        log("ERROR: Timed out waiting for U-Boot bootmenu")
        return False

    def send_command(self, cmd: str, wait: float = 3) -> tuple[bool, str]:
        self._drain(0.2)
        self.ser.write((cmd + "\r\n").encode())
        time.sleep(wait)
        data = self._drain(0.5)
        text = data.decode("ascii", errors="replace")

        output_lines = []
        for line in text.strip().split("\n"):
            clean = line.strip()
            if clean and clean != cmd:
                output_lines.append(clean)

        has_error = any(err in text for err in self.ERROR_STRINGS)

        if "tftpboot" in cmd and "Bytes transferred" not in text and "LOAD ERROR" not in text.upper():
            if "ERROR" in text.upper() or "Retry count exceeded" in text:
                has_error = True

        return has_error, "\n".join(output_lines)

    def run_commands(self, commands: list[str], event_queue: queue.Queue,
                     say_fn=None, flash_time_seconds: int = 120) -> bool:
        total = len(commands)
        for i, cmd in enumerate(commands):
            progress = f"[{i+1}/{total}]"
            log(f"{progress} U-Boot: {cmd}")

            cmd_lower = cmd.lower()

            if "tftpboot" in cmd_lower:
                wait = 15
                if ".bin" in cmd_lower:
                    fn_match = re.search(r'tftpboot\s+\S+\s+(\S+)', cmd)
                    if fn_match:
                        fn = fn_match.group(1)
                        if "chunk" in fn:
                            wait = 300
                say_msg = f"Transferring file {i+1} of {total}"
            elif "nand erase" in cmd_lower or "mtd erase" in cmd_lower:
                wait = 30
                say_msg = f"Erasing flash partition {i+1} of {total}"
            elif "nand write" in cmd_lower or "mtd write" in cmd_lower:
                wait = 30
                say_msg = f"Writing flash partition {i+1} of {total}"
            elif "ubi create" in cmd_lower:
                wait = 5
                say_msg = f"Creating UBI volume {i+1} of {total}"
            elif "reset" in cmd_lower:
                wait = 2
                say_msg = "Rebooting router"
            else:
                wait = 3
                say_msg = ""

            if say_fn and say_msg:
                say_fn(say_msg)

            has_error, output = self.send_command(cmd, wait)

            if output:
                for line in output.split("\n")[:10]:
                    log(f"  {line}")

            if has_error and "reset" not in cmd_lower:
                log(f"ERROR: Command failed: {cmd}")
                log(f"  Output: {output[:300]}")
                event_queue.put((Event.SERIAL_COMMAND_DONE, ts(), f"ERROR: {cmd}"))
                return False

            event_queue.put((Event.SERIAL_COMMAND_DONE, ts(), cmd))

        event_queue.put((Event.SERIAL_ALL_DONE, ts(), ""))
        return True

    def close(self):
        if self.ser and self.ser.is_open:
            self.ser.close()
            log(f"Serial port {self.port} closed")


def _generate_random_password() -> str:
    password = secrets.token_urlsafe(16)
    print()
    print("=" * 60)
    print(f"  Generated random password: {password}")
    print("=" * 60)
    print()
    return password


def _validate_args(args: argparse.Namespace) -> Optional[str]:
    if not args.image and not args.request_image:
        return "One of --image or --request-image is required."

    if args.image and args.request_image:
        return "--image and --request-image are mutually exclusive."

    if args.image:
        image_only_flags = []
        if args.ssh_key:
            image_only_flags.append("--ssh-key")
        if args.password:
            image_only_flags.append("--password")
        if args.no_password:
            image_only_flags.append("--no-password")
        if args.wan_ssh:
            image_only_flags.append("--wan-ssh")
        if image_only_flags:
            return (
                f"{', '.join(image_only_flags)} only valid with --request-image, "
                f"not with --image."
            )

    return None
