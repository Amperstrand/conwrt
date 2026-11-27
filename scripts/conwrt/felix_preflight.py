#!/usr/bin/env python3
"""felix-preflight — the stage-gated checklist driver for the NR7101
flash → configure → eSIM chain (#835: 'idiotproof for felixfelix-bot
-class users ... with preflight checklists').

One command per stage; every gate is machine-checkable with evidence;
the verdict is a printed table + JSON. The connectivity expectation
is IPv6-door-first (the E11 lesson: a multi-VLAN host carries several
192.168.1.0/24 routes — the v6 link-local is the canonical door that
survives every v4 failure mode, including the routing table).

Stages and their gates:

  flash      image sha pinned + `zycast --validate` passes, specimen
             MAC read LIVE and matching the record, sender mutex
             clear, PoE method known + evidence-verified transitions.
             Expectation: unit dark until stream + final cycle; boot
             evidence is NEW-image-only (fresh host key / uptime
             reset / bare-initramfs config).

  configure  unit alive through the v6 door, board_name matches the
             model, key auth works (adopted) or the adoption gates
             are next, preset renders + its verify commands known.

  esim       GATE 0 FIRST (the paid-for lesson): card-state diff
             before/after, modem just-proven-stable, transport
             (lpac/pcscd/ifd) reachable, activation code present —
             per docs/NR7101-ESIM-PLAYBOOK.md.

Exit 0 = all gates green; 1 = any gate red (the detail carries the
evidence). --json emits the machine form for agent drivers.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

V6_DOOR_NOTE = (
    "IPv6 link-local is the canonical door (fe80::<EUI-64> zone-scoped "
    "to the staging VLAN): it survives every v4 failure mode AND the "
    "multi-route hazard a multi-VLAN host carries for 192.168.1.0/24."
)


@dataclass
class Gate:
    name: str
    ok: bool | None = None
    detail: str = ""
    expectation: str = ""


@dataclass
class StageReport:
    stage: str
    gates: list[Gate] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """Full attestation: every gate explicitly ok."""
        return all(g.ok for g in self.gates)

    @property
    def blocked(self) -> bool:
        """A hard red gate exists (ok is False). INFO gates (ok=None,
        not-yet-attested) do NOT block — a stage whose only misses are
        INFO gates is PENDING, not BLOCKED."""
        return any(g.ok is False for g in self.gates)


def _run(cmd: list[str], timeout: int = 20) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except (subprocess.SubprocessError, OSError) as e:
        return 127, str(e)[:120]


def derive_v6(mac: str) -> str:
    """EUI-64 link-local from a MAC (the v6door derivation)."""
    m = mac.lower().replace(":", "").replace("-", "")
    if len(m) != 12:
        return ""
    h = f"{int(m[0:2], 16) ^ 0x02:02x}" + m[2:6] + "fffe" + m[6:]
    h = ":".join(h[i:i + 4] for i in range(0, 16, 4))
    return f"fe80::{h}"


def stage_flash(args: argparse.Namespace) -> StageReport:
    rep = StageReport(stage="flash")
    image = Path(args.image) if args.image else None

    g = Gate("image present + sha pinned",
             expectation="the exact artifact that will be multicast")
    if image and image.exists():
        rc, out = _run(["sha256sum", str(image)])
        g.ok = rc == 0
        g.detail = out.split()[0][:24] + "…" if rc == 0 else out
    else:
        g.ok = False
        g.detail = "no --image given or file missing"
    rep.gates.append(g)

    g = Gate("zycast --validate passes (magic/model/pacing)",
             expectation="every payload gate green BEFORE any unit "
                         "spends its listen window (#847/#852)")
    if image and image.exists():
        binpath = REPO_ROOT / "target" / "debug" / "conwrt"
        rc, out = _run(["sh", "-c",
                        f"cd {REPO_ROOT} && cargo run -q -p conwrt-cli -- "
                        f"zycast -i lo '{image}' --validate "
                        f"--expect-model {args.expect_model or '7101'}"],
                       timeout=300)
        g.ok = rc == 0 and "all gates passed" in out
        g.detail = out.splitlines()[-1][:120] if out else "no output"
    else:
        g.ok = False
        g.detail = "image missing (gate 1 red)"
    rep.gates.append(g)

    g = Gate("specimen MAC read LIVE matches the record",
             expectation="AGENTS 'Verify the SPECIMEN': the multicast hits "
                         "EVERY ZyXEL bootloader in the window")
    mac = (args.specimen_mac or "").lower()
    if mac:
        # ARP read through the staging interface (any address works to
        # populate the table; the evidence is the neighbor entry)
        iface = args.staging_iface or "enp2s0.999"
        _run(["ping", "-c1", "-W1", "-I", iface, "192.168.1.1"], timeout=5)
        rc, out = _run(["ip", "neigh", "show", "dev", iface])
        g.ok = mac in out.lower()
        g.detail = ("neighbor entry present" if g.ok
                    else f"{mac} NOT seen on {iface} — unit dark or wrong seat")
    else:
        g.ok = False
        g.detail = "no --specimen-mac given"
    rep.gates.append(g)

    g = Gate("sender mutex clear (no live zycast)",
             expectation="interleaved streams flash-loop the target "
                         "(the 2026-11-10 incident)")
    rc, out = _run(["pgrep", "-af", "conwrt zycast"])
    g.ok = rc != 0
    g.detail = "clear" if g.ok else out[:120]
    rep.gates.append(g)

    g = Gate("PoE control method + evidence discipline known",
             expectation="this switch exposes `ubus call poe manage`; "
                         "manage() can silently no-op — every transition "
                         "needs liveness-evidence verification")
    rep.gates.append(g)
    if args.poe_verified:
        g.ok = True
        g.detail = "operator attested transitions verified by evidence"
    else:
        g.ok = None
        g.detail = ("INFO: pass --poe-verified after checking the "
                    "power-drop by ping-stop/draw evidence")
    return rep


def stage_configure(args: argparse.Namespace) -> StageReport:
    rep = StageReport(stage="configure")
    door = args.unit or ""
    if not door and args.specimen_mac:
        door = derive_v6(args.specimen_mac)
        if args.staging_iface:
            door += f"%{args.staging_iface}"
    g = Gate("unit alive through the v6 door",
             expectation=V6_DOOR_NOTE)
    if door:
        rc, out = _run(["ping", "-c2", "-W2", "-I",
                        (args.staging_iface or "enp2s0.999"), door.split("%")[0]])
        g.ok = rc == 0
        g.detail = f"door {door}: {'alive' if rc == 0 else 'silent'}"
    else:
        g.ok = False
        g.detail = "no --unit or --specimen-mac to derive the door"
    rep.gates.append(g)

    g = Gate("board identity matches the model",
             expectation="board_name + MAC: the identity gate before config")
    if door:
        rc, out = _run(["ssh", "-o", "BatchMode=yes",
                        "-o", "StrictHostKeyChecking=no",
                        "-o", "UserKnownHostsFile=/dev/null",
                        "-o", "ConnectTimeout=8", f"root@{door}",
                        "cat /tmp/sysinfo/board_name; "
                        "cat /sys/class/net/eth0/address"])
        m = re.search(r"zyxel,nr7101", out)
        g.ok = rc == 0 and m is not None
        g.detail = out.replace("\n", " ")[:100]
    else:
        g.ok = False
        g.detail = "no door"
    rep.gates.append(g)

    g = Gate("preset renders + verify commands known",
             expectation="conwrt profile --profile <name> renders; each "
                         "preset's verify command comes from its PR body")
    if args.preset:
        rc, out = _run(["sh", "-c",
                        f"cd {REPO_ROOT} && PYTHONPATH=scripts python3 -m "
                        f"conwrt profile --profile {args.preset} 2>&1 | head -3"],
                       timeout=60)
        g.ok = rc == 0 and out.strip() != ""
        g.detail = out[:120]
    else:
        g.ok = None
        g.detail = "INFO: pass --preset <name> to render-check it"
    rep.gates.append(g)
    return rep


def stage_esim(args: argparse.Namespace) -> StageReport:
    rep = StageReport(stage="esim")
    g = Gate("GATE 0: card-state diff armed (before/after every session)",
             expectation="the paid-for lesson: a dying modem can execute "
                         "destructive profile ops on the way down; the "
                         "diff is the ONLY detector (playbook Gate 0)")
    g.ok = None if not args.card_diff_path else True
    g.detail = ("profile map recorded at " + args.card_diff_path
                if args.card_diff_path else
                "INFO: record `lpac profile list` output to a file and "
                "pass --card-diff-path before ANY card session")
    rep.gates.append(g)

    g = Gate("modem just-proven-stable",
             expectation="never seat/work an eUICC through a modem that "
                         "has not just proven stable (playbook Gate 0)")
    g.ok = None if not args.modem_stable else True
    g.detail = ("attested" if args.modem_stable else
                "INFO: pass --modem-stable after a clean "
                "wwandctl/modem session")
    rep.gates.append(g)

    g = Gate("transport reachable (lpac → pcscd → ifd-modemifd → AT)",
             expectation="the SSH-exec transport is the proven path "
                         "(playbook 'Transport decision')")
    rc, out = _run(["sh", "-c", "command -v lpac && pgrep -x pcscd"])
    g.ok = rc == 0 and "pcscd" in out
    g.detail = out[:100] if out else "lpac/pcscd not found on this host"
    rep.gates.append(g)

    g = Gate("activation code present (SMDP+matching ID)",
             expectation="single-use: consumed even on a failed session")
    g.ok = None if not args.activation_code else True
    g.detail = ("present" if args.activation_code else
                "INFO: pass --activation-code (or confirm the profile "
                "already seated)")
    rep.gates.append(g)
    return rep


STAGES = {"flash": stage_flash, "configure": stage_configure,
          "esim": stage_esim}


def cmd_felix_preflight(args: argparse.Namespace) -> int:
    rep = STAGES[args.stage](args)
    if args.json:
        print(json.dumps({
            "stage": rep.stage, "passed": rep.passed,
            "blocked": rep.blocked,
            "verdict": ("READY" if rep.passed else
                        "BLOCKED" if rep.blocked else "PENDING"),
            "gates": [{"name": g.name, "ok": g.ok, "detail": g.detail}
                      for g in rep.gates]}, indent=2))
    else:
        print(f"== felix-preflight: {rep.stage} ==")
        for g in rep.gates:
            mark = {"PASS": "✔", "FAIL": "✘", "INFO": "·"}[
                "PASS" if g.ok else ("FAIL" if g.ok is False else "INFO")]
            print(f"  [{mark}] {g.name}")
            print(f"        {g.detail}")
            if g.expectation:
                print(f"        expect: {g.expectation}")
        verdict = ("READY" if rep.passed else
                   "BLOCKED" if rep.blocked else "PENDING")
        print(f"== {verdict} ==")
    # Exit codes: 0 READY, 1 BLOCKED (a red gate), 2 PENDING (only INFO
    # gates outstanding — not a failure, but not attested complete).
    return 0 if rep.passed else (1 if rep.blocked else 2)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="conwrt felix-preflight",
        description="the stage-gated checklist driver for the NR7101 "
                    "flash → configure → eSIM chain (#835)")
    p.add_argument("--stage", required=True,
                   choices=["flash", "configure", "esim"])
    p.add_argument("--image", default=None, help="flash: image path")
    p.add_argument("--expect-model", default="7101")
    p.add_argument("--specimen-mac", default=None)
    p.add_argument("--staging-iface", default="enp2s0.999")
    p.add_argument("--poe-verified", action="store_true")
    p.add_argument("--unit", default=None,
                   help="configure: v6 door or address")
    p.add_argument("--preset", default=None)
    p.add_argument("--card-diff-path", default=None)
    p.add_argument("--modem-stable", action="store_true")
    p.add_argument("--activation-code", default=None)
    p.add_argument("--json", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    return cmd_felix_preflight(build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
