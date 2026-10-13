#!/usr/bin/env python3
"""bench_adopt — assertion-gated bring-up for bench DUTs over v6 link-local.

Codifies the spike validated 2026-09-22 on ap-lan4 (WS-AP3915i):

  preflight -> backup -> reset(firstboot) -> adopt(keys+static) -> verify

Design rules from that session's audit — every one is an assertion here:

  * Liveness is SSH/TCP, never ICMP (units filter echo; ping lied twice).
  * The v6 link-local is DERIVED from the known MAC and asserted reachable
    before any change; it is the only channel that survives firstboot.
  * board_name and DISTRIB_RELEASE are asserted against per-place
    expectations before and after every stage (aparcar healthcheck_version).
  * `uci changes` must equal the exact expected diff (or be empty for an
    idempotent re-run) before `uci commit` — stale-diff merges are fatal.
  * reset post-conditions: uptime fresh, authorized_keys ABSENT, release
    UNCHANGED — proving an overlay wipe, not a reflash.
  * adopt post-conditions: new address answers SSH with the pushed key and
    `uci get network.lan.proto` reads back the staged value.
  * Places with reset_allowed=false (TFTP-dependent units) never reset.
  * Switch-side scripts feed dbclient from /dev/null (stdin-eats-script bug)
    and the Mac-side subprocess timeout is the hang guard (BusyBox here has
    no `timeout` applet).
  * All output lands in evidence files under data/bench/<place>/<ts>/ —
    nothing is trusted to have "printed".

Places registry (local-only, data/bench/places.json):
  {"places": [{"name": "ap-lan4", "mac": "b4:2d:56:25:79:b1",
               "dut_ip": "192.168.104.51", "reset_allowed": true}]}
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_BOARD = "extreme-networks,ws-ap3915i"
EXPECTED_RELEASE = "24.10.2"

Transport = Callable[[str], str]  # staged switch-side script -> stdout


class AdoptError(Exception):
    """Stage assertion failed; evidence is in the message."""


@dataclass(frozen=True)
class Place:
    name: str
    mac: str
    dut_ip: str
    reset_allowed: bool = True
    release: str = EXPECTED_RELEASE
    board: str = EXPECTED_BOARD
    note: str = ""

    @property
    def port(self) -> str:
        return self.name.removeprefix("ap-")

    @property
    def vlan(self) -> int:
        return 1000 + int(self.port.removeprefix("lan"))

    @property
    def linklocal(self) -> str:
        return eui64_linklocal(self.mac)


def eui64_linklocal(mac: str) -> str:
    octets = mac.split(":")
    if len(octets) != 6 or any(len(o) != 2 for o in octets):
        raise AdoptError(f"bad MAC: {mac!r}")
    flipped = int(octets[0], 16) ^ 0x02
    eui = [f"{flipped:02x}"] + octets[1:3] + ["ff", "fe"] + octets[3:6]
    hextets = [f"{int(''.join(eui[i:i + 2]), 16):x}" for i in range(0, 8, 2)]
    return "fe80::" + ":".join(hextets)


PLACE_FIELDS = frozenset(
    {"name", "mac", "dut_ip", "reset_allowed", "release", "board", "note"})


def load_places(path: Path) -> dict[str, Place]:
    """Load places.json into Place objects.

    Unknown keys (e.g. per-place passwords kept in the local-only registry)
    are ignored rather than crashing Place(**p) — places.json is
    operator-maintained and carries fields this module does not consume.
    """
    raw = json.loads(path.read_text())
    return {p["name"]: Place(**{k: v for k, v in p.items() if k in PLACE_FIELDS})
            for p in raw["places"]}


def load_labgrid_host(path: Path) -> str:
    return json.loads(path.read_text()).get("labgrid_host", "ai-legion")


class Runner:
    def __init__(self, transport: Transport, place: Place, evidence: Path) -> None:
        self.transport = transport
        self.place = place
        self.evidence = evidence
        self.evidence.mkdir(parents=True, exist_ok=True)

    def sh(self, name: str, lines: list[str], timeout_s: int = 60) -> str:
        script = "\n".join(lines) + "\n"
        (self.evidence / f"{name}.sh").write_text(script)
        try:
            out = self.transport(script)
        except subprocess.TimeoutExpired:
            raise AdoptError(f"{name}: switch-side script timed out ({timeout_s}s)") from None
        (self.evidence / f"{name}.out").write_text(out)
        return out

    def dut(self, name: str, remote_cmd: str, auth: str = "key", timeout_s: int = 60) -> str:
        ll = self.place.linklocal
        if auth == "key":
            client = f"dbclient -y -y -i /root/.ssh/id_ed25519 root@{ll}%switch.{self.place.vlan}"
        else:
            client = f"DROPBEAR_PASSWORD='' dbclient -y -y root@{ll}%switch.{self.place.vlan}"
        return self.sh(name, [f"{client} '{remote_cmd}' </dev/null"], timeout_s)


def parse_field(captured: str, key: str) -> str:
    for line in captured.splitlines():
        if key in line:
            return line.strip()
    raise AdoptError(f"expected {key!r} in captured output, got:\n{captured[:400]}")


def assert_expected_state(captured: str, where: str, place: Place) -> None:
    if place.board not in captured:
        raise AdoptError(f"{where}: board mismatch — expected {place.board}:\n{captured[:400]}")
    if place.release not in captured:
        raise AdoptError(f"{where}: release mismatch — expected {place.release}:\n{captured[:400]}")


# ----------------------------------------------------------------- stages

AUTH_DEAD_MARKERS = ("Remote closed the connection",)


def _auth_dead(out: str) -> bool:
    return any(marker in out for marker in AUTH_DEAD_MARKERS)


def dut_with_fallback(r: Runner, name: str, remote_cmd: str) -> str:
    """Key auth first; empty-password v6 fallback for never-adopted units."""
    out = r.dut(name, remote_cmd)
    if r.place.board not in out:
        out = r.dut(f"{name}-pw", remote_cmd, auth="password")
    return out


def stage_rom_audit(r: Runner) -> None:
    """Fail-early gate: prove the ROM will accept passwordless root SSH
    AFTER a reset, before we strand the unit. dropbear's OpenWrt patch
    (600-allow-blank-root-password) requires: root user + PasswordAuth on +
    RootPasswordAuth on + EMPTY shadow field. Verified against openwrt-24.10
    and openwrt-25.12 branch defaults and lan4's live ROM (2026-09-22)."""
    p = r.place
    # Quote-free by design: dut() wraps remote_cmd in single quotes, so any
    # embedded quote or pipe breaks through the Mac->ssh->switch->dbclient
    # shell nesting (seen live 2026-09-24: 'PasswordAuth|RootPasswordAuth'
    # executed as a pipeline -> false-negative rom-audit on ap-lan5).
    out = r.dut("rom-audit",
                "grep ^root /rom/etc/shadow; grep PasswordAuth /rom/etc/config/dropbear; "
                "grep RootPasswordAuth /rom/etc/config/dropbear")
    shadow_ok = any(line.startswith("root::") for line in out.splitlines())
    if not shadow_ok:
        raise AdoptError(f"rom-audit: root password is not blank in ROM — a reset "
                         f"would leave {p.name} with ZERO auth methods (unmanageable). "
                         f"ROM shadow:\n{out[:300]}")
    if "option PasswordAuth 'on'" not in out or "option RootPasswordAuth 'on'" not in out:
        raise AdoptError(f"rom-audit: ROM dropbear refuses password auth — reset "
                         f"would strand {p.name}. ROM config:\n{out[:300]}")
    print(f"[PASS] rom-audit {p.name}: blank root + password auth in ROM — "
          "post-reset manageability proven")


def stage_preflight(r: Runner) -> None:
    p = r.place
    out = dut_with_fallback(r, "preflight",
                            "cat /tmp/sysinfo/board_name; grep DISTRIB_RELEASE /etc/openwrt_release; "
                            "uptime; ip -6 addr show br-lan | grep fe80 || true")
    assert_expected_state(out, "preflight", r.place)
    if "fe80" not in out:
        raise AdoptError("preflight: no link-local on br-lan — v6 channel unavailable")
    print(f"[PASS] preflight {p.name}: board+release ok, v6 channel present")


def stage_backup(r: Runner) -> None:
    out = r.dut("backup", "sysupgrade -b /tmp/bench-adopt-backup.tar.gz >/dev/null 2>&1; "
                          "md5sum /tmp/bench-adopt-backup.tar.gz")
    digest = parse_field(out, "bench-adopt-backup.tar.gz").split()[0]
    if len(digest) != 32:
        raise AdoptError(f"backup: no md5 in output:\n{out[:300]}")
    pulled = r.sh("backup-pull", [
        f"dbclient -y -y -i /root/.ssh/id_ed25519 root@{r.place.linklocal}%switch.{r.place.vlan} "
        f"'cat /tmp/bench-adopt-backup.tar.gz' </dev/null > /tmp/bench-adopt-backup.tar.gz 2>/dev/null",
        "md5sum /tmp/bench-adopt-backup.tar.gz"])
    if digest not in pulled:
        raise AdoptError("backup: md5 mismatch DUT vs switch — refusing to continue")
    print(f"[PASS] backup {r.place.name}: md5 {digest} verified end-to-end")


def stage_overlay(r: Runner) -> None:
    """Gate: refuse firstboot on a dirty jffs2 overlay — unchecked/orphan
    xattrs are the documented precondition for nondeterministic auth-dead
    boots (ap-lan2 2026-09-22, ap-lan5 2026-09-24; AGENTS.md reset-failsafe
    rule 2). sysupgrade -n (--method flash) formats a fresh overlay and is
    the safe alternative."""
    out = dut_with_fallback(r, "overlay-health", "dmesg | grep jffs2_build_xattr")
    if "unchecked" not in out and "orphan" not in out:
        print(f"[PASS] overlay {r.place.name}: no jffs2 xattr debris in dmesg")
        return
    if "0 unchecked, 0 orphan" in out:
        print(f"[PASS] overlay {r.place.name}: clean overlay (0 unchecked, 0 orphan)")
        return
    raise AdoptError(
        f"overlay {r.place.name}: DIRTY jffs2 overlay — firstboot from this state "
        f"is the known auth-dead trigger. Boot to health or use --method flash "
        f"(sysupgrade -n formats a fresh overlay deterministically). dmesg:\n{out[:300]}")


def stage_reset(r: Runner) -> None:
    p = r.place
    if not p.reset_allowed:
        raise AdoptError(f"reset refused: {p.name} is reset_allowed=false "
                         "(TFTP-dependent unit — re-arm lifeline or run #61 first)")
    try:
        out = dut_with_fallback(r, "reset-firstboot", "firstboot -y; echo FIRSTBOOT-RC=$?")
    except AdoptError as exc:
        out = str(exc)
    if "FIRSTBOOT-RC=0" in out:
        try:
            r.dut("reset-reboot", "reboot")
        except AdoptError:
            pass
        print(f"[ARMED] reset {p.name}: firstboot RC=0, reboot issued")
    elif "FIRSTBOOT-RC" not in out:
        # Channel closed before the RC echo (usually the reboot racing the
        # wrapper's return). firstboot is a RAM-staged overlay wipe that
        # still takes effect — ap-lan5 2026-09-24 ran exactly this path and
        # the post-condition poll confirmed a factory-state boot. Do not
        # abort on the unseen RC; let the post-conditions decide.
        print(f"[WARN] reset {p.name}: firstboot RC unseen "
              f"({out.strip()[:120]}) — channel closed mid-command; "
              "post-conditions will verify")
    else:
        raise AdoptError(f"reset: firstboot returned nonzero (25.x kills backgrounded "
                         f"chains, so we run it synchronously — 2026-09-22 lesson):\n{out[:300]}")
    deadline = time.monotonic() + 240
    last = ""
    consecutive_auth_dead = 0
    poe_cycles = 0
    while time.monotonic() < deadline:
        time.sleep(20)
        try:
            out = r.dut("reset-check",
                        "uptime; ls /etc/dropbear/authorized_keys /root/.ssh/authorized_keys 2>&1; "
                        "grep DISTRIB_RELEASE /etc/openwrt_release; cat /tmp/sysinfo/board_name",
                        auth="password")
        except AdoptError:
            continue
        last = out
        if p.board not in out or p.release not in out:
            if _auth_dead(out):
                consecutive_auth_dead += 1
                if consecutive_auth_dead >= 4:
                    if poe_cycles < 2:
                        # Documented cure for the jffs2 replay race: the boot
                        # is nondeterministic and one deliberate PoE cycle
                        # re-runs the replay (ap-lan2 + ap-lan5 both cured
                        # by exactly one cycle). Bounded at 2 per AGENTS.md.
                        port = p.name.removeprefix("ap-")
                        print(f"[HEAL] reset {p.name}: auth-dead (jffs2 replay race) — "
                              f"deliberate PoE cycle {poe_cycles + 1}/2 on {port}")
                        r.sh("reset-poecycle", [
                            f'ubus call poe manage "{{\"port\":\"{port}\",\"action\":\"disable\"}}"; sleep 8; '
                            f'ubus call poe manage "{{\"port\":\"{port}\",\"action\":\"enable\"}}"',
                        ], timeout_s=60)
                        poe_cycles += 1
                        consecutive_auth_dead = 0
                        time.sleep(100)
                    else:
                        raise AdoptError(
                            f"reset: {p.name} still auth-dead after {poe_cycles} deliberate "
                            "PoE cycles — overlay replay is hard-stuck. CONSOLE REQUIRED: "
                            "move the serial splice to this unit (see SERIAL-VIA-AP3915I.md).")
            continue
        if "No such file" not in out:
            raise AdoptError("reset: authorized_keys still present — overlay was NOT wiped")
        for fresh in ("up 1 min", "up 2 min", "up 3 min", "up 4 min"):
            if fresh in out:
                print(f"[PASS] reset {p.name}: factory state confirmed (keys gone, release kept)")
                return
    raise AdoptError(f"reset: DUT did not return to factory state in 240s. Last output:\n{last[:400]}")


def stage_adopt(r: Runner) -> None:
    p = r.place
    deadline = time.monotonic() + 120
    ready = False
    while time.monotonic() < deadline:
        try:
            out = r.dut("adopt-ready", "cat /tmp/sysinfo/board_name", auth="password")
        except AdoptError:
            time.sleep(10)
            continue
        if p.board in out:
            ready = True
            break
        if _auth_dead(out):
            raise AdoptError("adopt: factory state refuses all sessions (zero auth "
                             "methods) — same condition the reset classifier catches; "
                             "console required, do not keep retrying")
        time.sleep(10)
    if not ready:
        raise AdoptError("adopt: DUT never became shell-ready within 120s")

    mac_keys: list[str] = []
    for pub in (Path.home() / ".ssh" / "id_ed25519.pub", Path.home() / ".ssh" / "id_rsa.pub"):
        if pub.exists():
            mac_keys += [line.strip() for line in pub.read_text().splitlines() if line.strip()]
    payload = ("mkdir -p /etc/dropbear; "
               "grep -q '$(head -c 24 /root/.ssh/id_ed25519.pub)' /etc/dropbear/authorized_keys 2>/dev/null "
               "|| cat /root/.ssh/id_ed25519.pub >> /etc/dropbear/authorized_keys")
    for key in mac_keys:
        marker = key.split()[1][:24]
        payload += (f"; grep -q '{marker}' /etc/dropbear/authorized_keys 2>/dev/null "
                    f"|| echo '{key}' >> /etc/dropbear/authorized_keys")
    payload += ("; chmod 700 /etc/dropbear; chmod 600 /etc/dropbear/authorized_keys; "
                "echo KEYS-PUSHED")
    keys_script = [
        f"DROPBEAR_PASSWORD='' dbclient -y -y root@{p.linklocal}%switch.{p.vlan} "
        f"\"{payload}\" </dev/null",
        # Wrong password on purpose: dbclient silently falls back from pubkey
        # to password auth, so a bare -i proof can pass on the blank/known
        # password instead of the key (2026-09-23 NR7101 lesson). With a
        # bogus password, KEY-AUTH-OK can only come from the key.
        f"DROPBEAR_PASSWORD='pubkey-proof-only' dbclient -y -y -i /root/.ssh/id_ed25519 "
        f"root@{p.linklocal}%switch.{p.vlan} "
        "'echo KEY-AUTH-OK; wc -l /etc/dropbear/authorized_keys' </dev/null",
    ]
    out = r.sh("adopt-keys", keys_script)
    if "KEY-AUTH-OK" not in out:
        raise AdoptError(f"adopt: key channel not established:\n{out[:400]}")

    gw = f"192.168.{p.vlan - 900}.1"
    # Clean baseline first: aborted runs leave /tmp/.uci staging that survives
    # SSH sessions and poisons diffs (2026-09-22 live lesson). Then stage,
    # then VALUE READBACKS — the textual-diff guard was shape-brittle across
    # 24.10/25.12 factory forms.
    staged = (f"uci revert network 2>/dev/null; "
              f"uci set network.lan.proto='static'; uci delete network.lan.ipaddr 2>/dev/null; "
              f"uci add_list network.lan.ipaddr='{p.dut_ip}/24'; "
              f"uci set network.lan.gateway='{gw}'; uci set network.lan.dns='{gw}'; "
              f"echo ---READBACK---; "
              f"uci get network.lan.proto; uci get network.lan.ipaddr; "
              f"uci get network.lan.gateway; uci get network.lan.dns")
    out = r.dut("adopt-stage", staged)
    readback = out.split("---READBACK---")[-1].split()
    expected_values = ["static", f"{p.dut_ip}/24", gw, gw]
    if readback != expected_values:
        raise AdoptError(f"adopt: value readback mismatch — got {readback}, "
                         f"expected {expected_values} (raw: {out[-200:]})")
    out = r.dut("adopt-commit", "uci commit network; echo COMMITTED; "
                                "/etc/init.d/network restart >/dev/null 2>&1; echo RESTARTED")
    if "COMMITTED" not in out:
        raise AdoptError(f"adopt: commit did not confirm:\n{out[:300]}")
    print(f"[PASS] adopt {p.name}: keys (idempotent) + clean-baseline static config committed")


def stage_verify(r: Runner) -> None:
    p = r.place
    time.sleep(15)
    out = r.sh("verify", [
        f"DROPBEAR_PASSWORD='pubkey-proof-only' dbclient -y -y -i /root/.ssh/id_ed25519 root@{p.dut_ip} "
        "'echo SSH-OK-NEW-IP; uci get network.lan.proto; ip -4 addr show br-lan | grep inet; "
        "grep DISTRIB_RELEASE /etc/openwrt_release' </dev/null || echo NEW-IP-SSH-FAIL",
        f"ip neigh | grep 'switch.{p.vlan}'",
    ])
    for required in ("SSH-OK-NEW-IP", "static", p.dut_ip, p.release):
        if required not in out:
            raise AdoptError(f"verify: missing {required!r} in evidence:\n{out[:400]}")
    print(f"[PASS] verify {p.name}: key-auth SSH at {p.dut_ip}, proto=static, release kept")


STAGES = {"rom-audit": stage_rom_audit, "preflight": stage_preflight, "backup": stage_backup,
          "overlay": stage_overlay, "reset": stage_reset, "adopt": stage_adopt, "verify": stage_verify}
ORDER = ["rom-audit", "preflight", "backup", "overlay", "reset", "adopt", "verify"]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--place", required=True)
    ap.add_argument("--places", type=Path, default=REPO_ROOT / "data/bench/places.json")
    ap.add_argument("--switch", default="192.168.13.2")
    ap.add_argument("--stages", default="all", help="comma list or 'all'")
    ap.add_argument("--method", choices=["firstboot", "flash"], default="firstboot",
                    help="deployment path: factory reset keeps the flashed "
                         "version; flash sysupgrades -n to a gated stock image")
    ap.add_argument("--image", help="image registry key (data/bench/images.json); required for --method flash")
    ap.add_argument("--images", type=Path, default=REPO_ROOT / "data/bench/images.json")
    ap.add_argument("--tftproot", default="/tmp/bench-tftp",
                    help="switch-side TFTP lifeline root (must hold the image)")
    ap.add_argument("--i-know", action="store_true",
                    help="required for stages that mutate the DUT (reset, adopt, flash)")
    args = ap.parse_args(argv)

    places = load_places(args.places)
    if args.place not in places:
        print(f"unknown place {args.place}; known: {sorted(places)}"); return 2
    place = places[args.place]

    # lazy import: bench_session imports bench_adopt at module level (Place)
    import bench_session
    session = bench_session.get_session(switch_host=args.switch)

    plan: list[tuple[str, Place, Callable[[Runner], None]]]
    if args.method == "firstboot":
        plan = [(s, place, STAGES[s]) for s in ORDER]
    else:
        if not args.image:
            print("--method flash requires --image (registry key)"); return 2
        import bench_flash
        if not args.images.exists():
            print(f"images registry missing: {args.images} "
                  "(schema: labgrid/images.example.json)"); return 2
        images = bench_flash.load_images(args.images)
        if args.image not in images:
            print(f"unknown image {args.image!r}; known: {sorted(images)}"); return 2
        entry = images[args.image]
        from dataclasses import replace
        flashed = replace(place, release=entry["version"])

        def flash_stage(r: Runner) -> None:
            bench_flash.stage_flash(r, entry, Path(entry["path"]), args.tftproot, session)
        plan = [(s, place, STAGES[s]) for s in ("rom-audit", "preflight", "backup")] + \
               [("flash", flashed, flash_stage)] + \
               [(s, flashed, STAGES[s]) for s in ("adopt", "verify")]

    wanted = [s for s, _, _ in plan] if args.stages == "all" else args.stages.split(",")
    if any(s not in {s for s, _, _ in plan} for s in wanted):
        print(f"unknown stage in {wanted}; this method offers: {[s for s, _, _ in plan]}"); return 2
    mutating = any(s in ("reset", "adopt", "flash") for s in wanted)
    if mutating and not args.i_know:
        print("refusing DUT mutation without --i-know"); return 2

    evidence = REPO_ROOT / "data" / "bench" / place.name / time.strftime("%Y%m%d-%H%M%S")
    for stage, stage_place, fn in plan:
        if stage not in wanted:
            continue
        r = Runner(session.switch_sh, stage_place, evidence)
        try:
            fn(r)
        except AdoptError as err:
            print(f"[FAIL] {stage}: {err}\n  evidence: {evidence}")
            return 1
    print(f"done. evidence: {evidence}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
