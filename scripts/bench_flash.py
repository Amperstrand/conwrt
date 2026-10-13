#!/usr/bin/env python3
"""bench_flash — the sysupgrade -n deployment path for bench DUTs.

The flash half of the deploy strategy (labgrid Strategy pattern, adapted):
gated image -> lifeline-first -> verified upload -> detached sysupgrade -n ->
tolerant post-poll -> converge on bench_adopt's adopt stage.

Brick-safety gates, in order, ALL mandatory (AGENTS.md + operator rule
2026-09-22: stock OpenWrt 24.x/25.x only):
  1. image registry entry (data/bench/images.json): sha256+version+profile
  2. version matches ^(24|25)\\. — stock releases only
  3. profile matches the bench model (extreme-networks_ws-ap3915i)
  4. on-disk file sha256 equals the registry sha256
  5. TFTP lifeline armed AND verified on the switch BEFORE any upload —
     the bootcmd fallback tail (run boot_net) is the only recovery door
  6. on-device sha256 readback equals before sysupgrade runs
  7. sysupgrade -n only; -F / --force are never generated
  8. recovery policy: ONE session power-cycle mid-poll, then stop with
     serial/recovery guidance — never re-flash a silent unit
     (labgrid @never_retry pattern)

fw4 drops unsolicited inbound UDP on runtime VLAN interfaces, so the
lifeline script re-inserts the runtime accept rule (iifname "switch.10*")
that vanishes on every switch reboot — AGENTS.md AP3915i rule 6.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_adopt import AdoptError, Place, Runner  # noqa: E402

if TYPE_CHECKING:
    # annotation-only: bench_session imports bench_flash at module level
    from bench_session import BenchSession

EXPECTED_PROFILE = "extreme-networks_ws-ap3915i"
STOCK_VERSION_RE = re.compile(r"^(24|25)\.")
FLASH_POLL_S = 360
POWER_CYCLE_AT_S = 180


def load_images(path: Path) -> dict[str, dict[str, str]]:
    return json.loads(path.read_text())["images"]


def check_image(entry: dict[str, str], image_path: Path) -> str:
    for field in ("sha256", "version", "profile"):
        if field not in entry:
            raise AdoptError(f"image registry entry missing {field!r}")
    if not STOCK_VERSION_RE.match(entry["version"]):
        raise AdoptError(f"image version {entry['version']!r} is not stock 24.x/25.x — refusing")
    if entry["profile"] != EXPECTED_PROFILE:
        raise AdoptError(f"image profile {entry['profile']!r} != {EXPECTED_PROFILE} — refusing")
    if not image_path.exists():
        raise AdoptError(f"image file missing: {image_path}")
    digest = hashlib.sha256(image_path.read_bytes()).hexdigest()
    if digest != entry["sha256"]:
        raise AdoptError(f"image sha256 mismatch: {digest} != {entry['sha256']} — refusing")
    return digest


def lifeline_lines(place: Place, image_name: str, tftproot: str) -> list[str]:
    """dnsmasq self-daemonizes (no nohup; --no-daemon never worked on this
    BusyBox — 2026-09-22 live lesson) and logs to a file we can read for
    RRQ evidence. Service stays disabled; we invoke the binary explicitly."""
    vlan = place.vlan
    return [
        f"mkdir -p {tftproot}",
        f"nft insert rule inet fw4 input iifname \"switch.{vlan}\" accept 2>/dev/null",
        f"ifname=switch.{vlan}",
        f"ip link show $ifname >/dev/null 2>&1 || ip link add $ifname link switch type vlan id {vlan}",
        f"kill $(pgrep -f 'dnsmasq.*{tftproot}') 2>/dev/null; sleep 1",
        f"dnsmasq --log-facility=/tmp/tftp-{vlan}.log --port=0 --enable-tftp "
        f"--tftp-root={tftproot} --interface=$ifname --bind-dynamic",
        "sleep 1",
        f"pgrep -f 'dnsmasq.*{tftproot}' >/dev/null && [ -f {tftproot}/{image_name} ] "
        "&& echo LIFELINE-OK || echo LIFELINE-BROKEN",
    ]


def stage_flash(r: Runner, entry: dict[str, str], image_path: Path, tftproot: str,
                session: BenchSession) -> None:
    p = r.place
    if not p.reset_allowed:
        raise AdoptError(f"flash refused: {p.name} is reset_allowed=false")
    digest = check_image(entry, image_path)
    print(f"[PASS] image gates: sha256 {digest[:16]}… version {entry['version']}")

    target = r.sh("flash-target", [
        f"dbclient -y -y -i /root/.ssh/id_ed25519 root@{p.dut_ip} "
        "'echo FLASH-TARGET-OK; cat /tmp/sysinfo/board_name' </dev/null || echo TARGET-FAIL"])
    for required in ("FLASH-TARGET-OK", EXPECTED_PROFILE.split(",")[-1]):
        if required not in target:
            raise AdoptError(f"flash target not reachable/verified at {p.dut_ip}:\n{target[:300]}")

    remote_img = f"/tmp/{image_path.name}"
    session.switch_put(image_path, f"{tftproot}/{image_path.name}")
    out = r.sh("flash-lifeline", lifeline_lines(p, image_path.name, tftproot))
    if "LIFELINE-OK" not in out:
        raise AdoptError(f"lifeline not verifiably serving — refusing to flash:\n{out[:300]}")
    print(f"[PASS] lifeline armed: {tftproot} serving on switch.{p.vlan}")

    out = r.sh("flash-push", [
        f"sha256sum {tftproot}/{image_path.name} | grep -q {digest} || echo SWITCH-SHA-FAIL",
        f"dbclient -y -y -i /root/.ssh/id_ed25519 root@{p.dut_ip} "
        f"'cat > {remote_img}' < {tftproot}/{image_path.name} </dev/null",
        f"dbclient -y -y -i /root/.ssh/id_ed25519 root@{p.dut_ip} "
        f"'sha256sum {remote_img}' </dev/null"])
    if digest not in out or "SWITCH-SHA-FAIL" in out:
        raise AdoptError(f"image push/readback failed:\n{out[:300]}")
    print("[PASS] image staged on DUT, sha256 verified end-to-end")

    r.sh("flash-go", [
        f"dbclient -y -y -i /root/.ssh/id_ed25519 root@{p.dut_ip} "
        f"'nohup sh -c \"sysupgrade -n {remote_img}\" >/dev/null 2>&1 &' </dev/null"])
    print(f"[ARMED] sysupgrade -n fired on {p.name}; polling v6 for factory boot")

    deadline = time.monotonic() + FLASH_POLL_S
    cycled = False
    last = ""
    while time.monotonic() < deadline:
        if not cycled and time.monotonic() > deadline - FLASH_POLL_S + POWER_CYCLE_AT_S:
            print("[RECOVER] no factory boot at 180s — ONE power cycle (boot_net fallback)")
            session.power(p, "cycle")
            cycled = True
        time.sleep(20)
        try:
            out = r.dut("flash-check",
                        "ls /etc/dropbear/authorized_keys 2>&1; "
                        "grep DISTRIB_RELEASE /etc/openwrt_release; "
                        f"grep -q {entry['version']} /etc/openwrt_release && echo VERSION-MATCH",
                        auth="password")
        except AdoptError:
            continue
        last = out
        if "VERSION-MATCH" in out and "No such file" in out:
            print(f"[PASS] flash {p.name}: {entry['version']} factory state on new image")
            return
    raise AdoptError(
        f"flash: {p.name} did not return after sysupgrade (last: {last[:200]}). "
        "STOP — do not re-flash. Recovery: TFTP lifeline is armed on "
        f"switch.{p.vlan} ({tftproot}); power-cycle once; if still silent, "
        "the unit is serial-gated (AGENTS #62 class).")
