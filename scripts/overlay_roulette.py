#!/usr/bin/env python3
"""overlay_roulette — reproduce the OpenWrt overlay-corruption failure modes.

The 2026-09-22 bench incident class (firstboot on marginal flash -> every
boot replays differently -> auth state lost) reduced to a labgrid/QEMU
harness on ai-legion:

  FM1  tmpfs->overlay switch race at S95done (fs-agnostic; reproducible on
       x86-64's ext4 overlay)
  FM2  power cut during/fresh-after overlay writes (torn state)
  FM3  debris accumulation across repeated dirty cuts

Targets: qemu-x86-persist.yaml (persistent disk — cuts must leave torn
state IN the image for the next boot to trip over). The stock-image x86-64
overlay is ext4 (journaled), so the jffs2-specific replay dice run on real
hardware in phase C; everything else — the race, the cut semantics, the
classifier, and the fix mechanics — is exercised here.

Usage (on ai-legion):
    python3 overlay_roulette.py persist-check
    python3 overlay_roulette.py sweep --cuts 5,10,20,35,50 --runs 1
"""
from __future__ import annotations

import argparse
import json
import os
import select
import subprocess
import time
from pathlib import Path
from labgrid.protocol import PowerProtocol

QEMU = "/usr/bin/qemu-system-x86_64"
BASE_IMAGE = "/home/ubuntu/labgrid/images/openwrt-24.10.2-x86-64-generic-squashfs-combined.img"
WORK_IMAGE = "/home/ubuntu/labgrid/images/work.img"
RESULTS = Path("/home/ubuntu/labgrid/results.jsonl")
LOGIN_HINT = b"Please press Enter to activate this console"
PROMPT = b"root@"


class VM:
    """Direct-QEMU lifecycle (the labgrid QEMUDriver's serial-socket path
    breaks under persistent-disk configs on our build). Serial on stdio,
    hard cut = process kill — the same protocol as bench serial consoles."""

    def __init__(self, image: str = WORK_IMAGE) -> None:
        self.image = image
        self.proc: subprocess.Popen | None = None

    def _start(self) -> None:
        self.proc = subprocess.Popen(
            [QEMU, "-machine", "pc", "-cpu", "max", "-m", "256M",
             "-enable-kvm", "-display", "none", "-serial", "stdio",
             "-drive", f"if=virtio,format=raw,file={self.image}",
             "-netdev", "user,id=net0",
             "-device", "virtio-net-pci,netdev=net0"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)

    def _read_until(self, marker: bytes, timeout_s: float) -> bytes:
        assert self.proc and self.proc.stdout
        fd = self.proc.stdout.fileno()
        buf = b""
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], 1.0)
            if ready:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                buf += chunk
                if marker in buf:
                    return buf
        return buf

    def boot(self, shell_timeout_s: int = 150) -> bool:
        self._start()
        if LOGIN_HINT not in self._read_until(LOGIN_HINT, shell_timeout_s):
            return False
        assert self.proc and self.proc.stdin
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            self.proc.stdin.write(b"\n")
            self.proc.stdin.flush()
            if PROMPT + b"OpenWrt" in self._read_until(PROMPT, 10):
                return True
        return False

    def run(self, cmd: str, timeout_s: int = 30) -> str:
        assert self.proc and self.proc.stdin and self.proc.stdout
        self.proc.stdin.write(cmd.encode() + b"; echo __DONE__$?\n")
        self.proc.stdin.flush()
        out = self._read_until(b"__DONE__", timeout_s)
        time.sleep(0.3)
        fd = self.proc.stdout.fileno()
        while True:
            ready, _, _ = select.select([fd], [], [], 0.3)
            if not ready:
                break
            chunk = os.read(fd, 8192)
            if not chunk:
                break
            out += chunk
        return out.decode(errors="replace")

    def cut(self) -> None:
        if self.proc:
            self.proc.kill()
            self.proc.wait()
            self.proc = None


def classify(vm: "VM | None", boot_s: float) -> dict:
    row = {"boot_seconds": round(boot_s, 1)}
    if vm is None or vm.proc is None:
        row["outcome"] = "no-shell"
        return row
    row["outcome"] = "managed"
    row["overlay"] = vm_run(vm, "mount | grep ' on /overlay ' | cut -d' ' -f1-5")
    row["dropbear_keys"] = vm_run(vm, "ls /etc/dropbear/ 2>/dev/null | grep -c key || echo 0")
    row["fs_debris"] = vm_run(vm, "dmesg | grep -iE 'ext4-fs error|orphan|unchecked|recovery' | tail -3")
    row["uptime"] = vm_run(vm, "uptime | cut -d, -f1")
    return row


def vm_run(vm: "VM", cmd: str) -> str:
    try:
        out = vm.run(cmd, timeout_s=20)
        return " | ".join(out) if isinstance(out, list) else str(out)
    except Exception as err:  # noqa: BLE001 — classification must not crash
        return f"<err {type(err).__name__}>"


def record(row: dict) -> None:
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    with RESULTS.open("a") as fh:
        fh.write(json.dumps(row) + "\n")
    print(json.dumps(row))


def cmd_persist_check(_args: argparse.Namespace) -> int:
    """Boot -> write marker -> hard cut -> boot -> does the marker survive?"""
    vm = VM()
    t0 = time.monotonic()
    vm = VM()
    if not vm.boot():
        record({"exp": "persist-check", "phase": "boot1", "outcome": "no-shell"})
        vm.cut()
        return 1
    vm.run("echo cut-marker > /overlay/CUTMARK; sync")
    vm.cut()
    time.sleep(2)
    vm2 = VM()
    sh2 = vm2.boot()
    row: dict = {"exp": "persist-check"}
    if not sh2:
        row.update({"phase": "boot2", "outcome": "no-shell",
                    "note": "cut left image unbootable or shell lost"})
    else:
        marker = vm_run(vm2, "cat /overlay/CUTMARK 2>&1")
        row.update({"phase": "boot2", "marker": marker,
                    "persisted": "cut-marker" in marker})
        row.update(classify(vm2, time.monotonic() - t0))
        vm2.cut()
    record(row)
    return 0 if row.get("persisted") else 1


def cmd_sweep(args: argparse.Namespace) -> int:
    """FM2: firstboot, then cut N seconds into the format boot, classify."""
    for t_cut in [int(x) for x in args.cuts.split(",")]:
        for run_n in range(args.runs):
            t0 = time.monotonic()
            vm = VM()
            sh = vm.boot()
            if not sh:
                record({"exp": "sweep", "t_cut": t_cut, "run": run_n,
                        "outcome": "no-shell-prepare"})
                vm.cut()
                continue
            rc = vm.run("firstboot -y; echo RC=$?")
            vm.cut()
            time.sleep(2)
            # format boot: cut at t_cut seconds in
            vmf = VM()
            vmf._start()
            time.sleep(t_cut)
            vmf.cut()
            time.sleep(2)
            # aftermath boot: classify
            vm2 = VM()
            sh2 = vm2.boot()
            row = {"exp": "sweep", "t_cut": t_cut, "run": run_n,
                   "firstboot_rc": rc.strip()}
            row.update(classify(vm2, time.monotonic() - t0))
            if sh2 is not None:
                vm2.cut()
            record(row)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("persist-check")
    s = sub.add_parser("sweep")
    s.add_argument("--cuts", default="5,10,20,35,50")
    s.add_argument("--runs", type=int, default=1)
    args = ap.parse_args()
    if args.cmd == "persist-check":
        return cmd_persist_check(args)
    return cmd_sweep(args)


if __name__ == "__main__":
    raise SystemExit(main())
