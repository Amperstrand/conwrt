#!/usr/bin/env python3
"""bench_adopt — assertion-gated bring-up for bench DUTs over v6 link-local.

Codifies the spike validated 2026-09-22 on ap-lan4 (WS-AP3915i):

  preflight -> backup -> envelope(lifeline + recorder + blank-pw proof)
            -> reset(firstboot) -> adopt(keys+static) -> verify

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
  * firstboot NEVER runs unless the recovery envelope was armed AND
    verified in the same session (#289; AGENTS.md reset-failsafe rule 1:
    "The envelope must exist BEFORE the reset, not after"): per-VLAN TFTP
    lifeline (reuses bench_flash.lifeline_lines), a detached (setsid)
    aliveness recorder on the switch, and the blank-password v6 channel
    proven. stage_reset refuses without a receipt — fail-closed.
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
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    # annotation-only: bench_session imports this module's Place
    from bench_session import BenchSession

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


# Remote-side completion marker: a probe command that appends
# `; echo PROBE-DONE` proves the DUT channel executed it. Output bearing
# this marker is authoritative evidence even when the board name is absent
# (#288: overlay-health output never contains the board name).
PROBE_DONE = "PROBE-DONE"


def dut_with_fallback(r: Runner, name: str, remote_cmd: str) -> str:
    """Key auth first; empty-password v6 fallback for never-adopted units.

    The key-auth result is only discarded when it shows no evidence the
    remote command actually ran (neither the board name nor the
    PROBE-DONE marker): discarding marker-bearing key-auth output and
    retrying over the empty-password channel made the retry's auth error
    read as a clean result — the #288 false-PASS right before firstboot.
    """
    out = r.dut(name, remote_cmd)
    if r.place.board in out or PROBE_DONE in out:
        return out
    retry = r.dut(f"{name}-pw", remote_cmd, auth="password")
    # Prefer whichever attempt actually reached the DUT shell.
    if r.place.board in retry or PROBE_DONE in retry:
        return retry
    return out + "\n" + retry


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
    # PROBE-DONE brackets the evidence: a healthy grep prints NOTHING, so
    # without a completion marker a successful probe is indistinguishable
    # from a dead channel (#288).
    out = dut_with_fallback(r, "overlay-health",
                            "echo OVERLAY-BEGIN; dmesg | grep jffs2_build_xattr; "
                            f"echo {PROBE_DONE}")
    if PROBE_DONE not in out:
        raise AdoptError(
            f"overlay {r.place.name}: health probe never completed on either auth "
            f"channel — dirty-overlay state UNKNOWN, refusing to gate firstboot "
            f"on unproven evidence (both outputs follow):\n{out[:400]}")
    debris = out.split("OVERLAY-BEGIN", 1)[-1]
    if "unchecked" not in debris and "orphan" not in debris:
        print(f"[PASS] overlay {r.place.name}: no jffs2 xattr debris in dmesg")
        return
    if "0 unchecked, 0 orphan" in debris:
        print(f"[PASS] overlay {r.place.name}: clean overlay (0 unchecked, 0 orphan)")
        return
    raise AdoptError(
        f"overlay {r.place.name}: DIRTY jffs2 overlay — firstboot from this state "
        f"is the known auth-dead trigger. Boot to health or use --method flash "
        f"(sysupgrade -n formats a fresh overlay deterministically). dmesg:\n{debris[:300]}")


# --------------------------------------------- recovery envelope (#289)

RECORDER_OK = "RECORDER-OK"
BLANK_CHANNEL_OK = "BLANK-CHANNEL-OK"
V6_CHANNEL_OK = "V6-CHANNEL-OK"


@dataclass(frozen=True)
class EnvelopeReceipt:
    """Proof that stage_envelope armed AND verified this place's recovery
    envelope in the current session. stage_reset refuses to run without a
    matching one — the capability-token shape of the pilot's RESET_ENVELOPE
    assertion (cf8260b)."""

    place: str
    vlan: int
    tftproot: str
    lifeline_log: str
    recorder_log: str


def recorder_log_path(place: Place) -> str:
    return f"/tmp/bench-aliveness-{place.name}.log"


def recorder_loop_body(place: Place, log: str) -> str:
    """One probe iteration of the aliveness recorder (runs on the switch).

    Probes the config-independent v6 channel (AGENTS.md reset-failsafe
    rule 6) with the same empty-password dbclient the post-reset recovery
    ladder uses, and classifies into the incident taxonomy: up /
    auth-dead (TCP:22 answers but no shell — the jffs2 replay-race
    signature, AGENTS.md rule 3) / down. Liveness is SSH/TCP, never ICMP.
    Kept free of single quotes so it can ride inside `setsid sh -c '...'`.
    """
    return (
        f"out=$(DROPBEAR_PASSWORD= dbclient -y -y root@{place.linklocal}%switch.{place.vlan} "
        f"\"echo REC-ALIVE\" </dev/null 2>&1); "
        f"case \"$out\" in *REC-ALIVE*) st=up;; "
        f"*closed*|*auth*|*Auth*) st=auth-dead;; *) st=down;; esac; "
        f"echo $(date +%s) $st >> {log}"
    )


def recorder_lines(place: Place) -> list[str]:
    """Arm the detached switch-side aliveness recorder (#289).

    BusyBox rule (AGENTS.md reset-failsafe rule 8): `nohup cmd &` over ssh
    DIES when the session closes — `setsid cmd &` survives. The recorder
    must outlive BOTH the adopting SSH session and the DUT's own sshd
    dying mid-reset, so a failed reset leaves a timestamped
    up/auth-dead/down timeline instead of silence. Its output must be
    redirected off the ssh pipe or switch_sh blocks on pipe EOF forever.
    Runtime-only state: dies on switch reboot — re-arm per session.
    """
    log = recorder_log_path(place)
    return [
        # idempotent re-arm: stop any previous recorder for this place
        f"kill $(pgrep -f 'bench-aliveness-{place.name}') 2>/dev/null; sleep 1",
        f": > {log}",
        # the 'armed' line proves the loop is executing even while the
        # first probe is still in flight (a down DUT answers slowly)
        f"setsid sh -c 'echo $(date +%s) armed >> {log}; "
        f"while true; do {recorder_loop_body(place, log)}; sleep 10; done' "
        ">/dev/null 2>&1 &",
        "sleep 2",
        f"pgrep -f 'bench-aliveness-{place.name}' >/dev/null && [ -s {log} ] "
        f"&& echo {RECORDER_OK} || echo RECORDER-BROKEN",
    ]


def resolve_lifeline_image(place: Place, images_path: Path,
                           explicit: str | None) -> tuple[str, Path | None, str]:
    """Recovery image the TFTP lifeline will serve: an operator-staged
    --lifeline-image NAME (assumed already present in the tftproot), else
    the images.json entry whose version matches the place release (gated
    by bench_flash.check_image). Returns (image_name, local_path, sha256);
    path/digest are set only when this code pushes the file itself."""
    import bench_flash  # lazy: bench_flash imports this module at load time

    if explicit:
        return explicit, None, ""
    if not images_path.exists():
        raise AdoptError(
            f"envelope: no recovery image for {place.name} — {images_path} is "
            f"missing. Stage an image in the tftproot and pass --lifeline-image, "
            f"or add an images.json entry matching release {place.release}.")
    for entry in bench_flash.load_images(images_path).values():
        if entry.get("version") == place.release:
            path = Path(entry["path"])
            return path.name, path, bench_flash.check_image(entry, path)
    raise AdoptError(
        f"envelope: no images.json entry with version {place.release} for "
        f"{place.name} — stage a recovery image and pass --lifeline-image.")


def stage_envelope(r: Runner, tftproot: str, image_name: str,
                   image_path: Path | None, digest: str,
                   session: BenchSession) -> EnvelopeReceipt:
    """Arm + verify the pre-reset recovery envelope (#289; AGENTS.md
    reset-failsafe rule 1: the envelope must exist BEFORE the reset, not
    after):

      (a) per-VLAN TFTP lifeline — REUSES bench_flash.lifeline_lines (the
          bootcmd `run boot_net` fallback tail is the only flash-level
          recovery door);
      (b) detached aliveness recorder on the switch (setsid — survives
          the SSH session dying mid-reset);
      (c) blank-password channel proof — the exact auth path that exists
          after firstboot wipes authorized_keys (ROM-blank root, gated
          earlier by stage_rom_audit).

    Any unverified part refuses firstboot — the bench_tollgate --tftproot
    refusal pattern. A reset you cannot recover from is a reset you do
    not run.
    """
    import bench_flash  # lazy: circular with bench_flash's bench_adopt import

    p = r.place
    if image_path is not None:
        session.switch_put(image_path, f"{tftproot}/{image_name}")
    lifeline = bench_flash.lifeline_lines(p, image_name, tftproot)
    if digest:
        lifeline.append(f"sha256sum {tftproot}/{image_name} | grep -q {digest} "
                        "&& echo IMAGE-SHA-OK || echo IMAGE-SHA-FAIL")
    out = r.sh("envelope-lifeline", lifeline)
    required = ["LIFELINE-OK"] + (["IMAGE-SHA-OK"] if digest else [])
    missing = [m for m in required if m not in out]
    if missing:
        raise AdoptError(
            f"envelope: TFTP lifeline not verifiably armed on switch.{p.vlan} "
            f"(missing {missing}) — refusing firstboot, the boot_net fallback "
            f"would have nothing to serve:\n{out[:300]}")
    print(f"[PASS] envelope {p.name}: TFTP lifeline serving {image_name} "
          f"from {tftproot} on switch.{p.vlan}")

    out = r.sh("envelope-recorder", recorder_lines(p))
    if RECORDER_OK not in out:
        raise AdoptError(
            f"envelope: detached aliveness recorder not verified on the switch "
            f"— refusing firstboot (an SSH death mid-reset would leave no "
            f"aliveness timeline for the recovery ladder):\n{out[:300]}")
    print(f"[PASS] envelope {p.name}: detached recorder -> {recorder_log_path(p)}")

    blank = r.dut("envelope-blankpw",
                  f"echo {BLANK_CHANNEL_OK}; cat /tmp/sysinfo/board_name",
                  auth="password")
    if BLANK_CHANNEL_OK not in blank:
        # The live unit has a root password set (blank auth rejected). The
        # channel MECHANISM is still proven if key auth reaches a shell over
        # the same v6 link-local; the post-reset blank password is
        # stage_rom_audit's ROM guarantee, not live state.
        v6key = r.dut("envelope-v6key",
                      f"echo {V6_CHANNEL_OK}; cat /tmp/sysinfo/board_name")
        if V6_CHANNEL_OK not in v6key:
            raise AdoptError(
                f"envelope: neither the blank-password nor the key channel "
                f"gives a shell over v6 on {p.name} — firstboot would strand "
                f"the unit. If both outputs show `Remote closed the "
                f"connection` the unit is ALREADY auth-dead (jffs2 replay "
                f"race): heal with one PoE cycle and re-run the overlay gate "
                f"before resetting. Blank-channel output:\n{blank[:300]}\n"
                f"Key-channel output:\n{v6key[:300]}")
        print(f"[PASS] envelope {p.name}: v6 channel proven via key auth (live "
              f"root password is set; the post-reset blank channel is "
              f"rom-audit's ROM guarantee)")
    else:
        print(f"[PASS] envelope {p.name}: blank-password channel proven over v6 "
              f"— the exact post-reset recovery path")
    return EnvelopeReceipt(place=p.name, vlan=p.vlan, tftproot=tftproot,
                           lifeline_log=f"/tmp/tftp-{p.vlan}.log",
                           recorder_log=recorder_log_path(p))


def stage_reset(r: Runner, envelope: EnvelopeReceipt | None = None) -> None:
    p = r.place
    if not p.reset_allowed:
        raise AdoptError(f"reset refused: {p.name} is reset_allowed=false "
                         "(TFTP-dependent unit — re-arm lifeline or run #61 first)")
    if envelope is None:
        raise AdoptError(
            f"reset refused: no recovery envelope verified for {p.name} this "
            f"session — run the envelope stage first (AGENTS.md: the envelope "
            f"must exist BEFORE the reset, not after)")
    if (envelope.place, envelope.vlan) != (p.name, p.vlan):
        raise AdoptError(
            f"reset refused: envelope receipt is for {envelope.place}/"
            f"switch.{envelope.vlan}, not {p.name}/switch.{p.vlan} — re-arm "
            f"this place's envelope")
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
    # The switch's pubkey must be read SWITCH-side and embedded in the
    # payload: the payload executes on a factory-fresh DUT where
    # /root/.ssh/id_ed25519.pub does not exist, so the old
    # `cat /root/.ssh/id_ed25519.pub >> authorized_keys` fallback appended
    # nothing and the switch key was never installed by this stage (#291).
    key_out = r.sh("adopt-switchkey", ["cat /root/.ssh/id_ed25519.pub"])
    switch_keys = [line.strip() for line in key_out.splitlines() if line.strip()]
    if not switch_keys or not switch_keys[0].startswith("ssh-"):
        raise AdoptError(f"adopt: cannot read the switch pubkey at "
                         f"/root/.ssh/id_ed25519.pub (switch-side) — the KEY-AUTH-OK "
                         f"gate below could never pass:\n{key_out[:300]}")
    switch_key = switch_keys[0]
    payload = "mkdir -p /etc/dropbear"
    for key in (switch_key, *mac_keys):
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
# envelope is deliberately NOT in STAGES: it needs arming arguments, so main
# injects a per-run closure. ORDER still schedules it before reset.
ORDER = ["rom-audit", "preflight", "backup", "overlay", "envelope", "reset", "adopt", "verify"]


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
    ap.add_argument("--lifeline-image",
                    help="recovery image filename already staged in --tftproot "
                         "(default: images.json entry matching the place release)")
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
    envelope_receipt: EnvelopeReceipt | None = None

    def envelope_stage(r: Runner) -> None:
        nonlocal envelope_receipt
        name, path, digest = resolve_lifeline_image(place, args.images,
                                                    args.lifeline_image)
        envelope_receipt = stage_envelope(r, args.tftproot, name, path, digest,
                                          session)

    def gated_reset(r: Runner) -> None:
        # fail-closed: refuses unless stage_envelope ran in THIS invocation
        stage_reset(r, envelope=envelope_receipt)

    if args.method == "firstboot":
        stages = {**STAGES, "envelope": envelope_stage, "reset": gated_reset}
        plan = [(s, place, stages[s]) for s in ORDER]
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
    if "reset" in wanted and not {"rom-audit", "envelope"} <= set(wanted):
        # tollgate-style refusal: firstboot is a brick-class operation and
        # must not run without the recovery envelope verified in the same
        # invocation (AGENTS.md reset-failsafe rule 1)
        print("refusing reset without the recovery envelope: the rom-audit and "
              "envelope stages must run in the same invocation (AGENTS.md: the "
              "envelope must exist BEFORE the reset, not after)"); return 2

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
