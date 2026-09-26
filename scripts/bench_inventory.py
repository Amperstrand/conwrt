#!/usr/bin/env python3
"""bench_inventory — reconcile bench ports with the places registry.

Answers "what is currently connected to which switch port" for a bench
built on the BENCH-SWITCH-PATTERN (GS1900 class: DUT port lanN isolated
in VLAN 100N with SVI switch.100N on the switch). Routers get moved
between ports; this script detects that and re-syncs the registries.

Strictly READ-ONLY on device state: one SSH batch of ubus/bridge/ip reads,
bounded liveness probes (ICMP, TCP:22/TCP:80 connect attempts, ICMPv6 —
never a login, never a config write) and optional dbclient identity probes.
It NEVER power-toggles a port to "discover" it (owner directive 2026-09-22)
and never writes to a DUT.

Data sources (one SSH round-trip to the switch through BenchSession —
get_session(); CONWRT_BENCH / config.toml select the backend, direct by
default):
  1. ubus call poe info            -> per-port PoE status
  2. bridge fdb show               -> learned MACs per port (dynamic only;
                                        static/local/permanent self-entries
                                        are filtered)
  3. ip neigh show dev switch.10N  -> L3 neighbors per DUT VLAN (v4 + v6)
  4. dbclient to fe80::EUI-64      -> board/model/hostname/release (--probe,
                                        key auth via the switch, non-fatal)
  5. liveness probes per delivering
     registered port              -> ping dut_ip, TCP connect :22/:80,
                                        ping6 the EUI-64 link-local of the
                                        registered MAC, then a fresh neigh
                                        read. Cache tables say who SPOKE,
                                        not who is alive: entries age out
                                        (false dark — lan4, 2026-09-23) and
                                        linger after death (false ok). Some
                                        units filter ICMP, so liveness is
                                        SSH/TCP-first, never ICMP-only.

Reconciliation against data/bench/places.json (place -> MAC expectation)
and data/inventory.jsonl (specimen records by MAC). Drift classes:

  ok          expected MAC seen on its port with fresh liveness
  moved       expected MAC seen on a DIFFERENT port (the router was
              re-homed; registries + exporter.yaml need updating)
  swapped     different unit on the port, expected MAC nowhere on the bench
  multi_mac   several MACs learned on one port (dumb switch daisy-chain?)
  alive       liveness probes answered but no L2 MAC learned (registry gap)
  dark        PoE delivering and NO fresh liveness. Probes run BEFORE the
              verdict; `dark` detail distinguishes "never seen" (no
              entries, no probe answers) from stale-entries-with-failed-
              probes (cached MACs that no longer answer). Do not verdict
              dead — run scripts/bench_discover.py (AGENTS dark-device
              class)
  empty       no PoE draw, no L2/L3 entries
  unregistered unit detected on a port with no places.json entry

Opt-in actions:
  --emit-exporter F   regenerate labgrid exporter.yaml stanzas from current
                      reality. Ports marked "power_export": false in
                      places.json get NO NetworkPowerPort (one-way-trip
                      rule — ap-lan5 class) and a loud warning if a unit
                      is sitting on one.
  --update-places     rewrite mac/dut_ip in places.json to match
                      observations. Never deletes fields; unknown keys
                      (passwords, notes) are preserved verbatim; vacated
                      places keep their fields with a dated note.
  --record            append one bench_scan event per observed unit to
                      data/inventory.jsonl (specimen-level, append-only).

Exit codes: 0 = clean, 1 = drift detected, 2 = tool error.

Usage:
  LG_COORDINATOR/bench coords are local-only; this tool needs the switch:
    python3 scripts/bench_inventory.py scan --host <switch-ip>
    python3 scripts/bench_inventory.py scan --host <switch> --emit-exporter -
    python3 scripts/bench_inventory.py scan --host <switch> --update-places --record
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from bench_adopt import eui64_linklocal  # noqa: E402
from bench_session import BenchError, get_session  # noqa: E402
from inventory import append_to_inventory, read_inventory  # noqa: E402

DEFAULT_PLACES = REPO_ROOT / "data" / "bench" / "places.json"
DEFAULT_INVENTORY = str(REPO_ROOT / "data" / "inventory.jsonl")
BENCH_PORTS = tuple(f"lan{i}" for i in range(2, 9))  # lan1 = uplink, never a DUT
FDB_SKIP_TOKENS = ("static", "local", "permanent", "added_by_user")


class ScanError(Exception):
    """Switch unreachable or returned unusable data."""


def _session(switch_host: str):
    """Bench transport for this scan (BenchSession via get_session —
    CONWRT_BENCH / config.toml select the backend; direct by default)."""
    return get_session(switch_host=switch_host)


# ----------------------------------------------------------------- parsing


def parse_poe_info(raw: str) -> dict[str, str]:
    """ubus poe info -> {port: status}. Tolerates entry-as-dict or -as-str."""
    info = json.loads(raw)
    ports = info.get("ports", {})
    out: dict[str, str] = {}
    for port, entry in ports.items():
        out[port] = entry["status"] if isinstance(entry, dict) else str(entry)
    return out


def parse_fdb(raw: str) -> dict[str, set[str]]:
    """bridge fdb show -> {port: {mac}} for dynamic learned entries only.

    The switch's own MAC shows up as static/local/permanent on every port;
    those flags are filtered so only devices that actually spoke on a DUT
    VLAN remain.
    """
    out: dict[str, set[str]] = {}
    for line in raw.splitlines():
        low = line.lower()
        if any(tok in low for tok in FDB_SKIP_TOKENS):
            continue
        tokens = line.split()
        if len(tokens) < 4 or tokens[1] != "dev" or not tokens[2].startswith("lan"):
            continue
        if "vlan" not in tokens[3:5]:
            continue
        out.setdefault(tokens[2], set()).add(tokens[0].lower())
    return out


def parse_neigh(raw: str, vlan_by_svi: dict[int, int] | None = None) -> dict[int, list[tuple[str, str]]]:
    """Batched `ip neigh` for all switch.10N SVIs -> {vlan: [(ip, mac)]}.

    Input is the marked block this tool's collection script emits:
      --vlan 1002
      192.168.102.51 dev switch.1002 lladdr dc:b8:08:6c:ea:7f  REACHABLE
    Entries are scoped by the --vlan marker: BusyBox `ip neigh show dev X`
    omits the `dev X` token (it is implied by the filter), so the `dev`
    field must not be required:
      192.168.102.51 lladdr dc:b8:08:6c:ea:7f used 0/0/0 probes 1 STALE
    Entries without lladdr (FAILED/INCOMPLETE probes) are skipped.
    """
    del vlan_by_svi  # SVI number IS the VLAN on this pattern (switch.10N)
    out: dict[int, list[tuple[str, str]]] = {}
    vlan = 0
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("--vlan "):
            vlan = int(stripped.split()[1])
            continue
        if not vlan or " lladdr " not in stripped:
            continue
        parts = stripped.split()
        try:
            llidx = parts.index("lladdr")
            ip, mac = parts[0], parts[llidx + 1].lower()
        except (ValueError, IndexError):
            continue
        out.setdefault(vlan, []).append((ip, mac))
    return out


def parse_identity(raw: str) -> dict[str, str]:
    """dbclient probe output (board, model, hostname, release — one per line)."""
    fields = ("board", "model", "hostname", "release")
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    if len(lines) < 4:
        return {}
    return dict(zip(fields, lines[:4], strict=False))


# ------------------------------------------------------------------ model


@dataclass
class Liveness:
    """Outcome of the active probe batch for one port.

    An observation with ``liveness is None`` was never probed (port not
    delivering / unregistered / probe transport failed) and is classified
    from cached evidence alone, like the pre-refresh tool did.
    ``controls_ok=False`` marks a batch whose positive controls failed:
    every probe negative in it is UNTRUSTWORTHY (missing applet, broken
    path) and must not be verdicted dark.
    """

    ping4: bool = False
    tcp22: bool = False
    tcp80: bool = False
    ping6: bool = False
    arp: bool = False       # neighbor entry materialized during probing
    controls_ok: bool = True

    @property
    def ok(self) -> bool:
        return self.ping4 or self.tcp22 or self.tcp80 or self.ping6 or self.arp

    @property
    def channels(self) -> str:
        names = (("ping4", self.ping4), ("tcp:22", self.tcp22),
                 ("tcp:80", self.tcp80), ("ping6", self.ping6),
                 ("arp", self.arp))
        return ",".join(n for n, on in names if on) or "none"


@dataclass
class PortObservation:
    port: str
    vlan: int
    poe: str = ""
    macs: set[str] = field(default_factory=set)
    ips: dict[str, list[str]] = field(default_factory=dict)
    identity: dict[str, str] = field(default_factory=dict)
    liveness: Liveness | None = None

    @property
    def poe_delivering(self) -> bool:
        return "deliver" in self.poe.lower()

    @property
    def has_evidence(self) -> bool:
        return bool(self.macs)


@dataclass
class Finding:
    place: str            # registry place name, or "" for unregistered ports
    port: str
    status: str           # ok | moved | swapped | multi_mac | alive | dark | unprobed | empty | unregistered
    expected_mac: str
    seen_mac: str
    detail: str

    def line(self) -> str:
        head = f"[{self.status}]".ljust(14)
        who = self.place or f"port:{self.port}"
        return f"{head} {who}  mac={self.seen_mac or '-'}  {self.detail}"


@dataclass
class Registry:
    """places.json, tolerant loader that preserves unknown keys for rewrite."""
    path: Path
    raw: dict
    entries: list[dict]

    @classmethod
    def load(cls, path: Path) -> "Registry":
        raw = json.loads(path.read_text())
        return cls(path=path, raw=raw, entries=list(raw.get("places", [])))

    def place_at(self, port: str) -> dict | None:
        name = f"ap-{port}"
        return next((e for e in self.entries if e.get("name") == name), None)

    def port_of_mac(self, mac: str) -> tuple[str, dict] | None:
        mac = mac.lower()
        for e in self.entries:
            if str(e.get("mac", "")).lower() == mac:
                return str(e.get("name", "")).removeprefix("ap-"), e
        return None

    def power_export_ok(self, entry: dict) -> bool:
        return bool(entry.get("power_export", True))


def classify(registry: Registry, obs: dict[str, PortObservation]) -> list[Finding]:
    findings: list[Finding] = []
    registered_ports = {str(e.get("name", "")).removeprefix("ap-") for e in registry.entries}
    for port in sorted(set(obs) | registered_ports):
        o = obs.get(port)
        entry = registry.place_at(port)
        name = str(entry.get("name", "")) if entry else ""
        expected = str(entry.get("mac", "")).lower() if entry else ""

        if o is None:
            findings.append(Finding(name, port, "empty", expected, "",
                                    "no observation (port not scanned)"))
            continue
        on_port = o.macs
        where = None
        if expected:
            for p, other in obs.items():
                if expected in other.macs:
                    where = p
                    break

        probed_dead = o.poe_delivering and o.liveness is not None and not o.liveness.ok

        if probed_dead and not o.liveness.controls_ok:
            status, seen = "unprobed", ""
            detail = ("PoE delivering; liveness probes ran but their positive "
                      "controls FAILED (ping/ping6/nc against the switch's own "
                      "SVI) — the probe path is broken, fix it before verdicting "
                      "this port dark")
        elif expected and expected in on_port and not probed_dead:
            status, seen = "ok", expected
            extra = on_port - {expected}
            detail = f"poe={o.poe or '?'}"
            if o.liveness is not None and o.liveness.ok:
                detail += f"  liveness ok ({o.liveness.channels})"
            if extra:
                detail += f"  extra MACs on port: {','.join(sorted(extra))}"
        elif expected and where and where != port:
            status, seen = "moved", expected
            detail = f"expected here but seen on {where} — update registries"
        elif probed_dead:
            status, seen = "dark", ""
            if on_port:
                detail = (f"PoE delivering; stale L2/L3 entries "
                          f"({','.join(sorted(on_port))}) but all liveness probes "
                          "failed — dark-device class (bench_discover.py)")
            else:
                detail = ("PoE delivering; never seen and all liveness probes "
                          "failed — dark-device class (bench_discover.py)")
        elif len(on_port) > 1:
            status, seen = "multi_mac", ",".join(sorted(on_port))
            detail = f"several MACs on {port} — daisy-chained switch?"
        elif len(on_port) == 1:
            seen = next(iter(on_port))
            if entry is None:
                status = "unregistered"
                detail = f"unit on {port} has no places.json entry (mac {seen})"
            else:
                status = "swapped"
                owner = registry.port_of_mac(seen)
                owner_note = f" (registry says this MAC belongs to ap-{owner[0]})" if owner else ""
                detail = f"different unit on {port}{owner_note} — expected {expected or 'nothing'}"
        elif o.poe_delivering:
            if o.liveness is not None and o.liveness.ok:
                status, seen = "alive", ""
                detail = (f"poe={o.poe or '?'}  liveness ok ({o.liveness.channels}) "
                          "but no L2 MAC learned — registry mac missing?")
            else:
                status, seen = "dark", ""
                detail = ("PoE delivering, zero L2/L3 and no probe candidates — "
                          "dark-device class (bench_discover.py)")
        else:
            status, seen = "empty", ""
            detail = f"poe={o.poe or '?'}"

        if entry is not None and not registry.power_export_ok(entry) and (on_port or o.poe_delivering):
            detail += "  HAZARD: unit on a power_export=false port"
        findings.append(Finding(name, port, status, expected, seen, detail))
    return findings


# ------------------------------------------------------------- collection


def collect_script(ports: tuple[str, ...]) -> str:
    vlans = " ".join(str(1000 + int(p.removeprefix("lan"))) for p in ports)
    return (
        "echo ===POE===; ubus call poe info; "
        "echo ===FDB===; bridge fdb show; "
        f"echo ===NEIGH===; for v in {vlans}; do echo --vlan $v; "
        "ip neigh show dev switch.$v; done"
    )


def collect(switch_host: str, ports: tuple[str, ...]) -> dict[str, PortObservation]:
    try:
        out = _session(switch_host).switch_exec(collect_script(ports))
    except BenchError as e:
        raise ScanError(f"switch ssh failed: {e}") from e
    try:
        poe = parse_poe_info(out.split("===POE===", 1)[1].split("===FDB===", 1)[0])
        fdb = parse_fdb(out.split("===FDB===", 1)[1].split("===NEIGH===", 1)[0])
        neigh = parse_neigh(out.split("===NEIGH===", 1)[1])
    except (IndexError, json.JSONDecodeError) as e:
        raise ScanError(f"unexpected switch output shape: {e}") from e

    obs: dict[str, PortObservation] = {}
    for port in ports:
        n = int(port.removeprefix("lan"))
        o = PortObservation(port=port, vlan=1000 + n, poe=poe.get(port, ""))
        for mac in fdb.get(port, set()):
            o.macs.add(mac)
        for ip, mac in neigh.get(o.vlan, []):
            o.macs.add(mac)
            o.ips.setdefault(mac, []).append(ip)
        obs[port] = o
    return obs


# ------------------------------------------------------- liveness refresh

PROBE_MARKERS = (("P4", "ping4"), ("T22", "tcp22"), ("T80", "tcp80"), ("P6", "ping6"))


def validated_candidates(dut_ip: str, mac: str) -> tuple[str, str]:
    """Registry candidates cross-checked before they reach a root shell:
    (dut_ip, EUI-64 link-local), "" where absent or malformed. Shared by the
    script builder and the marker accounting so the two cannot drift."""
    try:
        ipaddress.ip_address(dut_ip)
    except ValueError:
        dut_ip = ""
    try:
        ll = eui64_linklocal(mac)
    except Exception:  # noqa: BLE001 — malformed registry MAC must not kill the scan
        ll = ""
    return dut_ip, ll


CONTROL_MARKERS = ("C4", "CT", "C6")


def control_script(vlan: int) -> str:
    """Positive controls for the probe classes, run through the SAME VLAN
    interface against the switch itself (its own SVI answers ping, its
    dropbear answers :22, and it answers all-nodes multicast) — a probe
    negative is only evidence if the probe provably works (AGENTS rule).

    The switch's L3 on this VLAN is 192.168.10N.1 (bench-switch pattern),
    which exists because liveness probes only run on delivering ports
    whose SVI the collect step already touched."""
    svi = f"192.168.{vlan - 900}.1"
    return "; ".join([
        f"ping -c 1 -W 2 -I switch.{vlan} {svi} >/dev/null 2>&1; echo C4:$?",
        f"nc -w 3 {svi} 22 </dev/null >/dev/null 2>&1; echo CT:$?",
        f"ping6 -c 2 -W 2 -I switch.{vlan} ff02::1 >/dev/null 2>&1; echo C6:$?",
    ])


def probe_markers(dut_ip: str, mac: str) -> tuple[str, ...]:
    """Markers the batch for these candidates emits. parse_liveness requires
    every one of them in the output before trusting the verdict."""
    ip, ll = validated_candidates(dut_ip, mac)
    if not ip and not ll:
        return ()
    return CONTROL_MARKERS + (("P4", "T22", "T80") if ip else ()) + (("P6",) if ll else ())


def liveness_script(dut_ip: str, mac: str, vlan: int) -> str:
    """BusyBox probe batch for one registered candidate: controls first,
    then the candidate probes.

    ping/nc/ping6 only, each with its own bounded timeout (~16s worst case
    per port). ICMP alone is not liveness on this fleet (some units filter
    it — AGENTS bench_adopt rule), hence the TCP connects; :80 sends a real
    request so an idle-holding HTTP server still closes cleanly. ping6
    retries 3 times: a single echo can be lost to NDP re-resolution of a
    cold/STALE neighbor, and one lost packet must not fake a dead verdict.
    """
    ip, ll = validated_candidates(dut_ip, mac)
    if not ip and not ll:
        return ""
    parts: list[str] = [control_script(vlan)]
    if ip:
        parts += [
            f"ping -c 1 -W 2 {ip} >/dev/null 2>&1; echo P4:$?",
            f"nc -w 3 {ip} 22 </dev/null >/dev/null 2>&1; echo T22:$?",
            f"printf 'GET / HTTP/1.0\\r\\n\\r\\n' | nc -w 3 {ip} 80 "
            ">/dev/null 2>&1; echo T80:$?",
        ]
    if ll:
        parts.append(f"ping6 -c 3 -W 2 {ll}%switch.{vlan} "
                     ">/dev/null 2>&1; echo P6:$?")
    return "; ".join(parts)


def parse_liveness(raw: str, expected: tuple[str, ...]) -> Liveness | None:
    """Probe batch output -> Liveness, or None when the verdict is unusable:
    no markers expected, or any expected marker line missing from the
    output. A partial batch (lost output) must read unprobed — filling the
    gaps with False would fabricate a probed-dead verdict. A FAILED control
    returns a controls_ok=False Liveness: the negatives are untrusted and
    classification must say unprobed, not dark."""
    if not expected:
        return None
    lv = Liveness()
    got: set[str] = set()
    controls_failed = False
    for line in raw.splitlines():
        name, sep, code = line.partition(":")
        if not sep:
            continue
        for marker, attr in PROBE_MARKERS:
            if name == marker:
                setattr(lv, attr, code.strip() == "0")
                got.add(marker)
                break
        if name in CONTROL_MARKERS:
            got.add(name)
            if code.strip() != "0":
                controls_failed = True
    if set(expected) - got:
        return None
    if controls_failed:
        lv.controls_ok = False
    return lv


def refresh_liveness(switch_host: str, registry: Registry,
                     obs: dict[str, PortObservation]) -> None:
    """Probe every PoE-delivering registered port, then re-read its neighbors.

    A probe answer materializes as fresh MAC/IP evidence (merged into the
    observation); a neighbor entry appearing during an otherwise failed
    batch still counts as liveness (the probe traffic resolved it). Any
    transport failure leaves the port unprobed (liveness None) so
    classification falls back to cached evidence instead of faking a
    verdict either way.
    """
    for port, o in sorted(obs.items()):
        if not o.poe_delivering:
            continue
        entry = registry.place_at(port)
        if entry is None:
            continue
        dut_ip = str(entry.get("dut_ip", "") or "")
        mac = str(entry.get("mac", "") or "")
        script = liveness_script(dut_ip, mac, o.vlan)
        if not script:
            continue
        before = set(o.macs)
        try:
            out = _session(switch_host).switch_exec(script, timeout_s=40)
        except (BenchError, subprocess.TimeoutExpired):
            continue
        lv = parse_liveness(out, probe_markers(dut_ip, mac))
        if lv is None:
            continue
        try:
            neigh_out = _session(switch_host).switch_exec(
                f"ip neigh show dev switch.{o.vlan}", timeout_s=15)
        except (BenchError, subprocess.TimeoutExpired):
            neigh_out = None
        if neigh_out is not None:
            fresh = parse_neigh(f"--vlan {o.vlan}\n{neigh_out}").get(o.vlan, [])
            for ip, mac in fresh:
                o.macs.add(mac)
                o.ips.setdefault(mac, []).append(ip)
            lv.arp = any(mac not in before for _, mac in fresh)
        o.liveness = lv


def probe_identities(switch_host: str, obs: dict[str, PortObservation]) -> None:
    """Best-effort board/model probe over v6 link-local from the switch."""
    for o in obs.values():
        for mac in sorted(o.macs):
            try:
                ll = eui64_linklocal(mac)
            except Exception:  # noqa: BLE001 — bad MAC must not kill the scan
                continue
            cmd = (f"dbclient -y -y -i /root/.ssh/id_ed25519 "
                   f"root@{ll}%switch.{o.vlan} "
                   "'cat /tmp/sysinfo/board_name; "
                   "ubus call system board | jsonfilter -e \"@.model\" -e \"@.hostname\"; "
                   ". /etc/openwrt_release; echo $DISTRIB_RELEASE' </dev/null")
            try:
                out = _session(switch_host).switch_exec(cmd, timeout_s=25)
            except BenchError:
                continue
            ident = parse_identity(out)
            if ident:
                o.identity = ident
                break


# ---------------------------------------------------------------- actions


def emit_exporter(findings: list[Finding], registry: Registry,
                  switch_ip: str) -> str:
    lines = [
        "## Generated by scripts/bench_inventory.py scan --emit-exporter",
        f"## at {time.strftime('%Y-%m-%dT%H:%M:%S')} — review, then scp to the exporter host.",
        "## Comments must stay ## (Jinja). Never hand-add a NetworkPowerPort",
        "## for a power_export=false place (one-way-trip rule).",
        "",
    ]
    for f in findings:
        entry = registry.place_at(f.port)
        if entry is None:
            if f.status == "unregistered":
                lines.append(f"## {f.port}: unit present but UNREGISTERED — add a places.json entry first")
                lines.append("")
            continue
        if not registry.power_export_ok(entry):
            lines.append(f"## {entry.get('name')}: power_export=false — no NetworkPowerPort BY DESIGN")
            lines.append(f"##   ({f.detail})")
            lines.append("")
            continue
        n = int(f.port.removeprefix("lan"))
        lines.append(f"{entry.get('name')}:")
        lines.append("  NetworkPowerPort:")
        lines.append("    model: conwrt_poe")
        lines.append(f"    host: {switch_ip}")
        lines.append(f"    index: {n}")
        dut_ip = str(entry.get("dut_ip", "") or "")
        if dut_ip:
            lines.append("  NetworkService:")
            lines.append(f"    address: {dut_ip}")
            lines.append("    username: root")
        lines.append("")
    return "\n".join(lines)


def update_places(registry: Registry, findings: list[Finding],
                  obs: dict[str, PortObservation]) -> list[str]:
    """Rewrite mac/dut_ip in places.json to match the bench. Never deletes."""
    changes: list[str] = []
    stamp = time.strftime("%Y-%m-%d")
    for f in findings:
        entry = registry.place_at(f.port)
        if entry is None:
            continue
        o = obs.get(f.port)
        v4 = ""
        if o and f.seen_mac:
            v4 = next((ip for ip in o.ips.get(f.seen_mac, []) if "." in ip), "")
        if f.status == "ok" and f.seen_mac and str(entry.get("mac", "")).lower() != f.seen_mac:
            entry["mac"] = f.seen_mac
            entry["note"] = (str(entry.get("note", "")) +
                             f" [bench_inventory {stamp}: mac normalized]").strip()
            changes.append(f"{f.place}: mac -> {f.seen_mac}")
        elif f.status == "moved":
            went_to = f.detail.split("seen on ")[-1]
            entry["mac"] = ""
            entry["note"] = (str(entry.get("note", "")) +
                             f" [bench_inventory {stamp}: unit moved to {went_to}, "
                             "mac cleared here]").strip()
            changes.append(f"{f.place}: mac cleared (unit now on {went_to})")
        elif f.status == "swapped" and f.seen_mac:
            entry["mac"] = f.seen_mac
            if v4:
                entry["dut_ip"] = v4
            entry["note"] = (str(entry.get("note", "")) +
                             f" [bench_inventory {stamp}: unit swapped in, was "
                             f"{f.expected_mac or 'unknown'}]").strip()
            changes.append(f"{f.place}: mac -> {f.seen_mac}"
                           + (f", dut_ip -> {v4}" if v4 else ""))
    if changes:
        registry.raw["places"] = registry.entries
        registry.path.write_text(json.dumps(registry.raw, indent=2) + "\n")
    return changes


def record(findings: list[Finding], obs: dict[str, PortObservation],
           inventory_path: str) -> int:
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
    known = {m.lower(): e for e in read_inventory(inventory_path)
             for m in e.get("mac_addresses", [])}
    written = 0
    for f in findings:
        if not f.seen_mac or f.status in ("empty", "dark"):
            continue
        o = obs.get(f.port)
        ident = o.identity if o else {}
        entry = {
            "timestamp": stamp,
            "event": "bench_scan",
            "bench_place": f.place or f"port:{f.port}",
            "mac_addresses": [f.seen_mac] if "," not in f.seen_mac else
                             f.seen_mac.split(","),
            "model": ident.get("model") or known.get(f.seen_mac, {}).get("model", ""),
            "firmware_version": ident.get("release", ""),
            "notes": f"{f.status}: {f.detail}",
        }
        append_to_inventory(entry, inventory_path)
        written += 1
    return written


# -------------------------------------------------------------------- cli


def cmd_scan(args: argparse.Namespace) -> int:
    registry = Registry.load(Path(args.places))
    ports = tuple(sorted({p.removeprefix("ap-") for p in
                          (str(e.get("name", "")) for e in registry.entries) if p}
                         | (set() if args.registered_only else set(BENCH_PORTS))))
    try:
        obs = collect(args.host, ports)
    except ScanError as e:
        print(f"FAIL: {e}")
        return 2
    refresh_liveness(args.host, registry, obs)
    if args.probe:
        probe_identities(args.host, obs)

    findings = classify(registry, obs)
    for f in findings:
        print(f.line())
        o = obs.get(f.port)
        if o and o.identity:
            print(f"               board={o.identity.get('board')} "
                  f"model={o.identity.get('model')} "
                  f"fw={o.identity.get('release')}")

    drift = [f for f in findings if f.status not in ("ok",)]
    if args.emit_exporter:
        content = emit_exporter(findings, registry, args.host)
        if args.emit_exporter == "-":
            print(content)
        else:
            Path(args.emit_exporter).write_text(content)
            print(f"exporter stanzas written -> {args.emit_exporter} (review + scp + restart exporter)")
    if args.update_places:
        changes = update_places(registry, findings, obs)
        for c in changes:
            print(f"[updated] {c}")
        if not changes:
            print("[updated] places.json already in sync")
    if args.record:
        n = record(findings, obs, args.inventory)
        print(f"[record] {n} bench_scan events appended to {args.inventory}")
    print(f"SUMMARY: {len(findings)} ports, {len(drift)} with drift")
    return 1 if drift else 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="read-only port scan + reconciliation")
    s.add_argument("--host", required=True, help="bench switch management IP")
    s.add_argument("--places", default=str(DEFAULT_PLACES))
    s.add_argument("--inventory", default=DEFAULT_INVENTORY)
    s.add_argument("--probe", dest="probe", action="store_true", default=True,
                   help="dbclient identity probe per detected MAC (default)")
    s.add_argument("--no-probe", dest="probe", action="store_false")
    s.add_argument("--registered-only", action="store_true",
                   help="scan only ports named in places.json")
    s.add_argument("--emit-exporter", metavar="PATH",
                   help="write exporter.yaml stanzas ('-' = stdout)")
    s.add_argument("--update-places", action="store_true",
                   help="rewrite mac/dut_ip in places.json (preserves all other fields)")
    s.add_argument("--record", action="store_true",
                   help="append bench_scan events to inventory.jsonl")
    s.set_defaults(func=cmd_scan)
    args = ap.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
