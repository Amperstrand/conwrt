#!/usr/bin/env python3
"""bench_tollgate — tollgate bench lifecycle on labgrid places.

Maps the conwrt QEMU tollgate E2E (tests/integration, PR #50) onto the
physical bench (GS1900 pattern, docs/BENCH-SWITCH-PATTERN.md):

  cloud (QEMU)                    bench (this tool)
  --------------------------      ----------------------------------------
  pristine qcow2 overlay   ->     sysupgrade -n to a verified baseline FIT
  localhost SSH           ->     SSH to the DUT's per-place VLAN address
  baked tollgate image    ->     baked image + scp -O / opkg runtime upgrade
  veth+netns client       ->     WiFi client on the DUT AP (phone later)
  CLN xpay payer (signet) ->     same payer, run from the bench host
  junit + nostr evidence  ->     local evidence dir + same publishing flow

Loop discipline (matches PRTA / physical-router-test-automation):
  inner loop = bench_adopt.py reset+adopt (firstboot keeps the flashed
  version; assertion-gated, v6 link-local channel) then install-ipk here
  (opkg refresh touches only tollgate),
  outer loop = flash-baseline (sysupgrade -n; image QA; ALWAYS behind an
  armed TFTP lifeline — the DUT's bootcmd falls back to boot_net).

Destructive stages refuse to run without --i-know. sysupgrade -F is
forbidden (AGENTS.md); this tool never emits it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

SWITCH_HOST_DEFAULT = os.environ.get("BENCH_SWITCH_HOST", "")
COORDINATOR_DEFAULT = os.environ.get("LG_COORDINATOR", "")
RECOVERY_WAIT_S = 150


@dataclass(frozen=True)
class Place:
    name: str          # labgrid place, e.g. "ap-lan4"
    dut_ip: str        # DUT address on its VLAN (e.g. 192.168.104.51)

    @property
    def port(self) -> str:
        return self.name.removeprefix("ap-")       # lan4

    @property
    def index(self) -> int:
        return int(self.port.removeprefix("lan"))  # 4

    @property
    def vlan(self) -> int:
        return 1000 + self.index                   # 1004


@dataclass(frozen=True)
class Config:
    coordinator: str
    switch_host: str


def _labgrid(cfg: Config, place: str, *args: str) -> list[str]:
    return ["labgrid-client", "-x", cfg.coordinator, "-p", place, *args]


def _dut_ssh(place: Place, cmd: str) -> list[str]:
    opts = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
    return ["ssh", *opts, f"root@{place.dut_ip}", cmd]


def _dut_scp(place: Place, local: str, remote: str) -> list[str]:
    opts = ["-O", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
    return ["scp", *opts, local, f"root@{place.dut_ip}:{remote}"]


def lifeline_command(place: Place, cfg: Config, tftproot: Path) -> list[str]:
    """dnsmasq TFTP lifeline on the switch for this place's VLAN.

    Serves the baseline FIT + env images so `run boot_net` (the bootcmd
    fallback tail) can recover the DUT if the flash write goes wrong.

    The daemon must OUTLIVE the SSH session that arms it: `nohup ... &`
    dies with the session on BusyBox (AGENTS detached-daemon rule), so
    dnsmasq self-daemonizes instead (no --no-daemon) and the arming
    command only echoes LIFELINE-ARMED after pgrep proves the server is
    actually alive."""
    return _switch_ssh(cfg, (
        f"ifname=switch.{place.vlan}; ip link show $ifname >/dev/null 2>&1 || ip link add $ifname link switch type vlan id {place.vlan}; "
        f"kill $(pgrep -f 'dnsmasq.*{tftproot}') 2>/dev/null; sleep 1; "
        f"dnsmasq --log-facility=/tmp/tftp-{place.vlan}.log --port=0 --enable-tftp "
        f"--tftp-root={tftproot} --interface=$ifname --bind-dynamic; "
        f"sleep 1; pgrep -f 'dnsmasq.*{tftproot}' >/dev/null && echo LIFELINE-ARMED "
        "|| echo LIFELINE-BROKEN"))


def arm_lifeline(place: Place, cfg: Config, tftproot: Path) -> bool:
    """Arm AND verify the lifeline; the marker is content-gated, not just
    exit-code gated (a plain `echo LIFELINE-ARMED` proves nothing)."""
    proc = subprocess.run(lifeline_command(place, cfg, tftproot),
                          capture_output=True, text=True, timeout=30)
    return "LIFELINE-ARMED" in (proc.stdout + proc.stderr)


def _switch_ssh(cfg: Config, cmd: str) -> list[str]:
    opts = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]
    return ["ssh", *opts, f"root@{cfg.switch_host}", cmd]


def flash_sequence(place: Place, image: Path) -> list[list[str]]:
    """Command sequence for flash-baseline. sysupgrade -n only, never -F."""
    remote = f"/tmp/{image.name}"
    return [
        _dut_scp(place, str(image), remote),
        _dut_ssh(place, f"sha256sum {remote}"),
        _dut_ssh(place, f"sysupgrade -n {remote}"),
    ]


def install_sequence(place: Place, ipk: Path) -> list[list[str]]:
    remote = f"/tmp/{ipk.name}"
    return [
        _dut_scp(place, str(ipk), remote),
        _dut_ssh(place, f"opkg install {remote}"),
        _dut_ssh(place, f"rm -f {remote}"),
    ]


LOG_SOURCES = ("logread", "dmesg", "ndsctl status 2>/dev/null || true",
               "opkg list-installed 2>/dev/null | grep -iE 'tollgate|nodogsplash' || true",
               "ubus call network.interface dump 2>/dev/null || true",
               "wifi status 2>/dev/null || true")


def collect_sequence(place: Place) -> list[list[str]]:
    blob = " && echo --- && ".join(LOG_SOURCES)
    return [_dut_ssh(place, f"( {blob} ) 2>&1")]


def run_cmds(cmds: list[list[str]], timeout: int = 120) -> int:
    for cmd in cmds:
        print("+", " ".join(cmd))
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            print(proc.stdout[-500:], proc.stderr[-500:], sep="\n")
            return proc.returncode
        if proc.stdout.strip():
            print(proc.stdout[-800:])
    return 0


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def wait_for_dut(place: Place, cfg: Config, timeout_s: int) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            proc = subprocess.run(_dut_ssh(place, "echo up"), capture_output=True,
                                  text=True, timeout=15)
            if proc.returncode == 0:
                return True
        except subprocess.TimeoutExpired:
            pass
        time.sleep(10)
    return False


def evidence_dir(place: Place) -> Path:
    out = REPO_ROOT / "data" / "bench" / place.name / time.strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--place", default="ap-lan4")
    ap.add_argument("--dut-ip", required=True,
                    help="DUT address on its bench VLAN (e.g. 192.168.104.51)")
    ap.add_argument("--coordinator", default=COORDINATOR_DEFAULT,
                    help="labgrid coordinator host:port (or set LG_COORDINATOR; "
                         "real coords live in local bench records)")
    ap.add_argument("--switch", default=SWITCH_HOST_DEFAULT,
                    help="bench switch mgmt IP (or set BENCH_SWITCH_HOST)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("plan")
    f = sub.add_parser("flash-baseline")
    f.add_argument("--image", type=Path, required=True)
    f.add_argument("--sha256", help="expected image sha256; upload refuses on mismatch")
    f.add_argument("--tftproot", type=Path, help="dir to serve via the TFTP lifeline")
    f.add_argument("--i-know", action="store_true")
    i = sub.add_parser("install-ipk")
    i.add_argument("--ipk", type=Path, required=True)
    i.add_argument("--i-know", action="store_true")
    sub.add_parser("logs")
    p = sub.add_parser("power")
    p.add_argument("state", choices=["on", "off", "cycle"])

    args = ap.parse_args(argv)
    place = Place(args.place, args.dut_ip)
    if not args.coordinator:
        ap.error("--coordinator required (or set LG_COORDINATOR in the environment)")
    if not args.switch:
        ap.error("--switch required (or set BENCH_SWITCH_HOST in the environment)")
    cfg = Config(args.coordinator, args.switch)

    if args.cmd == "plan":
        image = Path("openwrt-baseline-sysupgrade.fit")
        ipk = Path("tollgate.ipk")
        print(json.dumps({
            "power_cycle": _labgrid(cfg, place.name, "power", "cycle"),
            "lifeline": lifeline_command(place, cfg, Path("/tmp/tftproot")),
            "flash": [" ".join(c) for c in flash_sequence(place, image)],
            "wait": f"SSH poll root@{place.dut_ip} up to {RECOVERY_WAIT_S}s",
            "install": [" ".join(c) for c in install_sequence(place, ipk)],
            "logs": [" ".join(c) for c in collect_sequence(place)],
        }, indent=1))
        return 0

    if args.cmd == "power":
        return run_cmds([_labgrid(cfg, place.name, "power", args.state)], timeout=60)

    if args.cmd == "logs":
        out = evidence_dir(place)
        for n, cmd in enumerate(collect_sequence(place)):
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            (out / f"{n:02d}-capture.txt").write_text(proc.stdout + proc.stderr)
        (out / "meta.json").write_text(json.dumps(
            {"place": place.name, "dut_ip": place.dut_ip, "vlan": place.vlan}, indent=1))
        print(f"evidence -> {out}")
        return 0

    if args.cmd == "install-ipk":
        if not args.i_know:
            print("refusing device mutation without --i-know"); return 2
        if not args.ipk.exists():
            print(f"FAIL: {args.ipk} missing"); return 1
        rc = run_cmds(install_sequence(place, args.ipk))
        return rc

    if args.cmd == "flash-baseline":
        if not args.i_know:
            print("refusing sysupgrade without --i-know"); return 2
        if not args.tftproot:
            # The AP3915i's only flash-failure recovery door is the bootcmd
            # `run boot_net` tail — flashing without an armed, verified
            # lifeline removes that door (AGENTS escape-hatch rule 1).
            print("FAIL: flash-baseline requires --tftproot (TFTP lifeline) — "
                  "refusing to flash without a verified recovery path")
            return 2
        if not args.image.exists():
            print(f"FAIL: {args.image} missing"); return 1
        digest = sha256_of(args.image)
        if args.sha256 and digest != args.sha256:
            print(f"FAIL: sha256 mismatch {digest} != {args.sha256}"); return 1
        print(f"image sha256 {digest}")
        if not arm_lifeline(place, cfg, args.tftproot):
            print("FAIL: could not arm TFTP lifeline — aborting flash")
            return 1
        print("power-cycling to a clean pre-flash state")
        run_cmds([_labgrid(cfg, place.name, "power", "off")], timeout=60)
        time.sleep(5)
        run_cmds([_labgrid(cfg, place.name, "power", "on")], timeout=60)
        if not wait_for_dut(place, cfg, RECOVERY_WAIT_S):
            print("FAIL: DUT did not come back after power cycle"); return 1
        for cmd in flash_sequence(place, args.image):
            if "sysupgrade" in " ".join(cmd):
                continue  # run last, connection dies mid-command
            if run_cmds([cmd]) != 0:
                return 1
        try:
            proc = subprocess.run(flash_sequence(place, args.image)[-1], capture_output=True,
                                  text=True, timeout=30)
        except subprocess.TimeoutExpired:
            proc = None  # expected: sysupgrade drops the connection mid-upgrade
        if proc is not None and wait_for_dut(place, cfg, 15):
            # A synchronous sysupgrade failure (image validation rejected,
            # bad metadata) leaves the DUT SSH-reachable — reporting success
            # here would hide the authoritative stop signal.
            print(f"FAIL: sysupgrade exited rc={proc.returncode} but the DUT is "
                  f"still reachable — upgrade never started:\n"
                  f"{(proc.stdout + proc.stderr)[-300:]}")
            return 1
        print(f"flash started; polling SSH up to {RECOVERY_WAIT_S}s")
        if not wait_for_dut(place, cfg, RECOVERY_WAIT_S):
            print("FAIL: DUT did not return after sysupgrade — check lifeline log")
            return 1
        print("DUT back — run `logs` to capture evidence")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
