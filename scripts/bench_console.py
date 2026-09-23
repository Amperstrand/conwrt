#!/usr/bin/env python3
"""bench_console — persistent serial console through the reference unit.

Opens ONE SSH session to the bench switch, then to the reference unit,
and tunnels the serial port (/dev/ttyMSM0) through it. Provides pexpect-
style sendline/expect/run methods for clean interaction with whatever
device is on the other end of the serial bridge.

Solves the nested quoting problem:
  Mac → SSH → switch → dbclient → reference unit → serial
by reducing it to:
  Mac → pexpect → SSH → (serial tunnel)

Usage:
    from bench_console import BenchConsole
    console = BenchConsole()
    console.login_stock()                    # admin/new2day
    output = console.run("ifconfig eth0")   # marker-based
    console.close()
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import pexpect

SWITCH_HOST = "192.168.13.2"
REF_UNIT_HOST = "192.168.104.51"
SSH_OPTS = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10"]

STOCK_USER = "admin"
STOCK_PASS = "new2day"
STOCK_PROMPT = r"->|#|\$"


class BenchConsole:
    """Persistent serial console via SSH tunnel to the reference unit."""

    def __init__(self, ref_host: str = REF_UNIT_HOST,
                 switch_host: str = SWITCH_HOST,
                 serial_dev: str = "/dev/ttyMSM0",
                 baud: int = 115200) -> None:
        self.ref_host = ref_host
        self.switch_host = switch_host
        self.serial_dev = serial_dev
        self.baud = baud
        self.child: pexpect.spawn | None = None
        self._marker_counter = 0

    def _ssh_cmd(self) -> str:
        """Build the SSH command chain: Mac → switch → ref unit → serial tunnel."""
        # The serial tunnel: read serial in background, write to serial from stdin
        inner = f"cat {self.serial_dev} & cat > {self.serial_dev}"
        dbclient = f"dbclient -y -y -i /root/.ssh/id_ed25519 root@{self.ref_host} '{inner}'"
        return f"ssh {' '.join(SSH_OPTS)} root@{self.switch_host} '{dbclient}'"

    def connect(self, timeout: int = 15) -> None:
        """Open the SSH+serial tunnel."""
        if self.child:
            self.close()
        cmd = self._ssh_cmd()
        self.child = pexpect.spawn(cmd, encoding="utf-8",
                                   codec_errors="replace", timeout=timeout)
        self.child.delaybeforesend = 0.3

    def close(self) -> None:
        if self.child:
            self.child.close(force=True)
            self.child = None

    def sendline(self, line: str) -> None:
        assert self.child, "not connected — call connect() first"
        self.child.sendline(line)

    def send(self, data: str) -> None:
        assert self.child, "not connected"
        self.child.send(data)

    def expect(self, pattern: str, timeout: int = 30) -> str:
        """Wait for pattern, return the output before the match."""
        assert self.child, "not connected"
        self.child.expect(pattern, timeout=timeout)
        return self.child.before or ""

    def _next_marker(self) -> str:
        self._marker_counter += 1
        return f"LG{uuid.uuid4().hex[:8]}"

    def run(self, cmd: str, timeout: int = 30) -> tuple[str, int]:
        """Run a command and return (output, exit_code) using marker wrapping."""
        assert self.child, "not connected"
        marker = self._next_marker()
        wrapped = f"echo {marker}S; {cmd}; echo {marker}E $?"
        self.child.sendline(wrapped)
        self.child.expect(f"{marker}E (\\d+)", timeout=timeout)
        exit_code = int(self.child.match.group(1))
        # Extract output between markers
        before = self.child.before or ""
        start = before.find(f"{marker}S")
        if start >= 0:
            output = before[start + len(marker) + 1:].strip()
        else:
            output = before.strip()
        return output, exit_code

    def login_stock(self, username: str = STOCK_USER,
                    password: str = STOCK_PASS,
                    timeout: int = 60) -> bool:
        """Login to the stock Extreme firmware on the serial console."""
        assert self.child, "not connected"
        # Send newline to wake up the console / get a fresh prompt
        self.child.sendline("")
        time.sleep(2)

        # Wait for either login prompt or existing shell prompt
        idx = self.child.expect(
            ["login:", STOCK_PROMPT, pexpect.TIMEOUT],
            timeout=timeout
        )
        if idx == 0:
            self.child.sendline(username)
            self.child.expect(r"[Pp]assword:", timeout=10)
            self.child.sendline(password)
            time.sleep(2)
            idx2 = self.child.expect(
                [STOCK_PROMPT, "Login incorrect", pexpect.TIMEOUT],
                timeout=15
            )
            if idx2 == 0:
                return True
            return False
        elif idx == 1:
            return True  # already logged in
        return False

    def login_uboot(self, interrupt_key: str = "s",
                    autoboot_pattern: str = "stop autoboot",
                    timeout: int = 60) -> bool:
        """Interrupt U-Boot autoboot and get to the prompt."""
        assert self.child, "not connected"
        idx = self.child.expect(
            [autoboot_pattern, r"Boot.*->", pexpect.TIMEOUT],
            timeout=timeout
        )
        if idx == 0:
            self.child.send(interrupt_key)
            time.sleep(1)
            self.child.expect(r"Boot.*->| #", timeout=10)
            return True
        elif idx == 1:
            return True  # already at prompt
        return False


def main() -> int:
    """Quick smoke: connect, send newline, show what comes back."""
    console = BenchConsole()
    print(f"connecting to {console.ref_host} via {console.switch_host}...")
    console.connect()
    print("connected — sending newline to probe...")
    console.sendline("")
    try:
        output = console.expect(r"login:|#|->|\$", timeout=10)
        print(f"got response: {output[-200:] if output else '(empty)'}")
    except pexpect.TIMEOUT:
        print("timeout — no response in 10s")
    console.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
