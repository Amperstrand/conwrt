#!/usr/bin/env python3
"""bench-discover — hypothesis-driven discovery ladder for dark/unknown bench devices.

Generalizes the 2026-09-22 lan7/lan8 recovery into a repeatable methodology:

  Layer 0  positive controls  prove EACH probe class (v4 ping, v6 ping,
                              ip-neigh, nc) against something known-good
                              first; a class that fails its control emits
                              no trusted negatives (AGENTS.md rule 11)
  Layer 1  v6 link-local      derive fe80::<EUI-64> from any observed source MAC
                             (Linux/OpenWrt/network gear still default to EUI-64
                             link-locals) and ping6 it on the access VLAN
  Layer 2  v4 archaeology     sweep candidate subnets: the probe host's OWN
                             interface subnets, inventory history for this MAC,
                             RFC1918/common router defaults
  Layer 3  service identify   banner-grab open TCP ports (22/80/443/2222),
                             LFP-style benign probes (SYN->RST iTTL/IPID/window)
  Layer 4  credential ladder  defaults -> fleet-history passwords -> vendor
                             defaults. NEVER auto-executed; printed as ready
                             dbclient commands for the operator.

Usage:
    python3 scripts/bench_discover.py plan --mac b4:2d:56:25:47:a2 \
        --iface switch.1007 --probe-host my-switch --control-ip 192.168.13.1

    python3 scripts/bench_discover.py run   --mac ... --probe-host my-switch \
        --iface switch.1007 --control-ip 192.168.13.1 --json out.json

``plan`` only prints the ladder (default and always hardware-safe).
``run`` executes the passive/v6/v4/banner layers over SSH to --probe-host
(an on-link OpenWrt host, e.g. the bench switch) and records results.
Credential attempts are printed, never executed, in both modes.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INVENTORY = REPO_ROOT / "data" / "inventory.jsonl"

RFC1918_COMMON = (
    "192.168.1.0/24", "192.168.0.0/24", "10.0.0.0/24", "192.168.8.0/24",
    "172.16.0.0/24", "192.168.13.0/24", "192.168.10.0/24", "192.168.100.0/24",
)
SERVICE_PORTS = (22, 80, 443, 2222, 53)
IPv4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


# ---------------------------------------------------------------- pure logic

def mac_to_eui64_linklocal(mac: str) -> str:
    """Modified EUI-64 link-local from a 48-bit MAC: split, insert FFFE, XOR 0x02."""
    digits = re.sub(r"[^0-9a-fA-F]", "", mac.lower())
    if len(digits) != 12:
        raise ValueError(f"not a 48-bit MAC: {mac!r}")
    b = [int(digits[i:i + 2], 16) for i in range(0, 12, 2)]
    b[0] ^= 0x02
    b[3:3] = [0xFF, 0xFE]
    return "fe80::" + ":".join(f"{x:02x}{y:02x}" for x, y in zip(b[0::2], b[1::2], strict=True))


def initial_ttl_guess(received_ttl: int) -> int:
    """Smallest typical initial TTL (32/64/128/255) >= received (LFP method)."""
    for candidate in (32, 64, 128, 255):
        if received_ttl <= candidate:
            return candidate
    return 255


def dhcp55_fingerprint(options: list[int]) -> str:
    """Fingerbank-style DHCP option-55 fingerprint string."""
    return ",".join(str(o) for o in options)


def inventory_ip_history(mac: str, inventory_path: Path = DEFAULT_INVENTORY) -> list[str]:
    """Past IPv4s recorded for this MAC in specimen inventory notes (archaeology)."""
    mac_n = re.sub(r"[^0-9a-fA-F]", "", mac.lower())
    history: list[str] = []
    if not inventory_path.exists():
        return history
    for line in inventory_path.read_text().splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        blob = json.dumps(entry).lower()
        entry_macs = [re.sub(r"[^0-9a-f]", "", m) for m in entry.get("mac_addresses", [])]
        if mac_n not in entry_macs and mac_n not in blob:
            continue
        for addr in IPv4_RE.findall(entry.get("notes", "")):
            if addr not in history:
                history.append(addr)
    return history


def subnet_candidates(
    probe_host_subnets: list[str],
    inventory_history: list[int | str] | None = None,
    extra: list[str] | None = None,
) -> list[str]:
    """Ordered, de-duplicated v4 sweep list. Priority: inventory archaeology,
    probe host's own subnets (today's lesson: the switch KNEW about .13/24),
    operator extras, then RFC1918/common defaults."""
    ordered: list[str] = []
    hist = [str(h) for h in (inventory_history or [])]
    for group in (hist, probe_host_subnets, list(extra or []), list(RFC1918_COMMON)):
        for item in group:
            try:
                net = ipaddress.ip_network(item if "/" in item else f"{item}/24", strict=False)
            except ValueError:
                continue
            if str(net) not in ordered:
                ordered.append(str(net))
    return ordered


def credential_ladder(
    fleet_passwords: list[str] | None = None,
    usernames: tuple[str, ...] = ("root", "admin"),
) -> list[dict[str, str]]:
    """Ordered credential hypotheses. Fleet history first (highest prior),
    then empty/vendor defaults. Returned for operator review — never executed."""
    ladder: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(user: str, pw: str, why: str) -> None:
        if (user, pw) not in seen:
            seen.add((user, pw))
            ladder.append({"user": user, "password": pw, "rationale": why})

    for pw in fleet_passwords or []:
        for user in usernames:
            add(user, pw, "fleet-history")
    add("root", "", "OpenWrt default (empty)")
    add("root", "conwrt", "conwrt May-2026 flash lineage")
    add("root", None, "conwrt no-serial flow (password from local bench records)")
    add("admin", "new2day", "Extreme WiNG stock service shell")
    add("admin", "admin", "vendor default")
    add("root", "openwrt", "common community default")
    add("root", "password", "common default")
    return ladder


# ---------------------------------------------------------------- ladder

@dataclass
class Hypothesis:
    layer: str
    statement: str
    command: str
    positive_means: str
    negative_next: str
    status: str = "planned"  # planned | positive | negative | skipped | control-failed
    # Which probe methodology this step uses; a step only runs after its
    # class passed a layer-0 positive control (AGENTS rule 11: no trusted
    # negative without a proven probe).
    probe_class: str = "v4-ping"
    # True only for the ping of the TARGET's derived EUI-64 link-local.
    # Multicast all-nodes answers and NDP-cache hits prove on-link life,
    # never that THIS target answers v6 — only this flag may suppress the
    # IPv4 sweep ladder.
    target_specific: bool = False
    # "content": rc==0 alone proves nothing for banner grabs — `nc | head`
    # pipelines exit 0 on closed ports — so require non-empty output too.
    positive_gate: str = "rc"
    # False for documentation-only steps (credential ladder) that must
    # never be shipped to the probe host as a command.
    executable: bool = True
    # True for the primary control whose failure aborts the whole run.
    primary_control: bool = False

    def render(self) -> str:
        return (f"[{self.layer}] {self.statement}\n"
                f"    $ {self.command}\n"
                f"    + : {self.positive_means}\n"
                f"    - : {self.negative_next}")


@dataclass
class DiscoverContext:
    mac: str
    iface: str
    probe_host: str
    control_ip: str
    subnets: list[str] = field(default_factory=list)
    v6_linklocal: str = ""
    # IPv4 addresses harvested from layer-2 ARP sweeps; layer-3 service
    # probes run against every one of them (an IPv4-only target must still
    # get its banner/stack probes — not just the derived v6 address).
    v4_addrs: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.v6_linklocal = mac_to_eui64_linklocal(self.mac)


def sweep_hosts(net: str) -> list[str]:
    """Exact usable-host list for the sweep loop — never a /24 assumption.

    The CLI accepts any CIDR; reducing every network to its first three
    octets silently probed the wrong range (a /16 request swept only its
    first /24, a /25 swept outside it). Callers must reject inputs whose
    host count exceeds MAX_SWEEP_HOSTS.
    """
    return [str(h) for h in ipaddress.ip_network(net).hosts()]


MAX_SWEEP_HOSTS = 254


def build_ladder(ctx: DiscoverContext) -> list[Hypothesis]:
    """The ordered probe ladder. Layer 0 is ALWAYS the positive controls —
    one per probe class, so no methodology emits trusted negatives without
    first proving itself against something known-good."""
    steps: list[Hypothesis] = [
        Hypothesis(
            layer="0-control", probe_class="v4-ping", primary_control=True,
            statement=f"Probe methodology works: control host {ctx.control_ip} answers",
            command=f"ping -c2 -W2 -I {ctx.iface} {ctx.control_ip}",
            positive_means="methodology validated; trust negatives below",
            negative_next="ABORT: negatives below would be meaningless (AGENTS rule 11)",
        ),
        Hypothesis(
            layer="0-control", probe_class="v6-ping",
            statement="v6 probe path works: an on-link node answers all-nodes multicast",
            command=f"ping -c2 -W2 -I {ctx.iface} ff02::1",
            positive_means="ping6 negatives below are trustworthy",
            negative_next="v6 negatives untrusted — fix the v6 probe path first",
        ),
        Hypothesis(
            layer="0-control", probe_class="ndp",
            statement="Neighbor-table probe works on the probe host",
            command=f"ip neigh show dev {ctx.iface} >/dev/null && echo NDP-OK",
            positive_means="NDP-cache negatives below are trustworthy",
            negative_next="ndp negatives untrusted (applet missing or fails)",
        ),
        Hypothesis(
            layer="0-control", probe_class="nc",
            statement="nc is present on the probe host (banner/stack probes need it)",
            command="command -v nc >/dev/null && echo NC-OK",
            positive_means="service-probe negatives below are trustworthy",
            negative_next="banner/LFP probes untrusted (applet missing)",
        ),
        Hypothesis(
            layer="1-v6", probe_class="v6-ping", target_specific=True,
            statement=f"Device is IPv6-alive at derived EUI-64 link-local {ctx.v6_linklocal}",
            command=f"ping -c3 -W2 -I {ctx.iface} {ctx.v6_linklocal}",
            positive_means="kernel up; go straight to banner+SSH over v6",
            negative_next="v6 stack down or not EUI-64; continue to v4 sweep",
        ),
        Hypothesis(
            layer="1-v6", probe_class="v6-ping",
            statement="Anything on-segment answers all-nodes multicast",
            command=f"ping -c3 -W2 -I {ctx.iface} ff02::1",
            positive_means="compare responder MACs; on-link liveness independent of v4",
            negative_next="segment silent; passive re-listen during PoE cycle",
        ),
        Hypothesis(
            layer="1-v6", probe_class="ndp",
            statement="Neighbor entry exists for derived link-local (NDP cache)",
            command=f"ip neigh show dev {ctx.iface} | grep {ctx.v6_linklocal.split('::')[-1]}",
            positive_means="device previously communicated; STALE != dead",
            negative_next="no NDP history; rely on active probes",
        ),
    ]
    for net in ctx.subnets:
        hosts = sweep_hosts(net)
        steps.append(Hypothesis(
            layer="2-v4",
            statement=f"Device holds a static address inside {net} (ARP sweep of "
                      f"{len(hosts)} usable hosts)",
            command=(f"for ip in {' '.join(hosts)}; do ping -c1 -W1 -I {ctx.iface} "
                     "$ip & done; wait; "
                     f"ip neigh show dev {ctx.iface} | grep -v FAILED"),
            positive_means="REACHABLE/STALE entry reveals the address; banner-grab it",
            negative_next="next candidate subnet",
        ))
    steps.extend([
        Hypothesis(
            layer="3-service", probe_class="nc", positive_gate="content",
            statement="SSH banner on port 22 at any discovered address (v4 or v6)",
            command=f"for p in {' '.join(map(str, SERVICE_PORTS))}; do "
                    f"(sleep 2; echo '') | nc <ADDR> $p | head -c 60; done",
            positive_means="server string (dropbear/openssh/udhttpd) narrows OS+creds",
            negative_next="no listeners; try PoE-cycle boot-window banner race",
        ),
        Hypothesis(
            layer="3-service", probe_class="nc",
            statement="LFP-style stack probe: SYN to closed port elicits RST with iTTL/IPID",
            command="nc -w2 <ADDR> 33533 </dev/null; then compare response TTL",
            positive_means=f"iTTL guess + IPID pattern classify the stack family "
                           f"(received TTL t -> initial {initial_ttl_guess(64)}-style table)",
            negative_next="host filters closed ports; rely on open-port banners",
        ),
        Hypothesis(
            layer="4-creds", executable=False,
            statement="Credential ladder (PRINTED ONLY — never auto-executed)",
            command="see credential_ladder(); run via: "
                    "ssh <probe-host> 'DROPBEAR_PASSWORD=<pw> dbclient -y -y "
                    "root@<ADDR>%<IFACE> \"echo OK\"'",
            positive_means="shell; proceed to uci diagnose/fix",
            negative_next="serial console is the remaining path (see playbook)",
        ),
    ])
    return steps


# ---------------------------------------------------------------- runner

def ssh_probe_host(probe_host: str, command: str, timeout: int = 120) -> tuple[int, str]:
    proc = subprocess.run(
        ["ssh", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes", probe_host, command],
        capture_output=True, text=True, timeout=timeout,
    )
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def _harvest_ipv4(ctx: DiscoverContext, sweep_output: str) -> None:
    """Collect usable neighbor addresses out of an `ip neigh` sweep output."""
    for line in sweep_output.splitlines():
        if "FAILED" in line or " lladdr " not in line:
            continue
        for addr in IPv4_RE.findall(line):
            first, *rest = addr.split(".")
            is_multicast_or_broadcast = first in ("0", "224", "225", "239", "255") \
                or rest[-1] in ("0", "255")
            if not is_multicast_or_broadcast and addr not in ctx.v4_addrs:
                ctx.v4_addrs.append(addr)


def _run_service_step(ctx: DiscoverContext, step: Hypothesis) -> None:
    """Probe EVERY discovered address — v4 finds first, v6 fallback last.

    Replacing <ADDR> with only the derived link-local would skip the very
    IPv4 address a layer-2 sweep just discovered, breaking the
    wrong-subnet recovery flow for IPv4-only targets."""
    addrs = list(ctx.v4_addrs) + [ctx.v6_linklocal]
    evidence: list[tuple[str, int, str]] = []
    for addr in addrs:
        cmd = step.command.replace("<ADDR>", addr).replace("<IFACE>", ctx.iface)
        rc, out = ssh_probe_host(ctx.probe_host, cmd)
        positive = rc == 0 and (out.strip() != "" if step.positive_gate == "content" else True)
        if positive:
            step.status = "positive"
            print(step.render())
            print(f"    => POSITIVE at {addr}: {out[:200]}")
            return
        evidence.append((addr, rc, out[:120]))
    step.status = "negative"
    print(step.render())
    for addr, rc, out in evidence:
        print(f"    => negative at {addr} (rc={rc}): {out}")


def run_ladder(ctx: DiscoverContext, steps: list[Hypothesis]) -> list[Hypothesis]:
    controls = [s for s in steps if s.layer == "0-control"]
    probes = [s for s in steps if s.layer != "0-control"]

    passed_classes: set[str] = set()
    for control in controls:
        rc, out = ssh_probe_host(ctx.probe_host,
                                 control.command.replace("<IFACE>", ctx.iface))
        control.status = "positive" if rc == 0 else "control-failed"
        if control.status == "positive":
            passed_classes.add(control.probe_class)
        print(control.render())
        print(f"    => {control.status.upper()}: {out[:120]}")

    primary = next((c for c in controls if c.primary_control), None)
    if primary is not None and primary.status != "positive":
        print("\nREFUSING to run discovery probes: positive control failed.")
        print("Fix the probe path before trusting any negative result (AGENTS rule 11).")
        return steps

    v6_target_alive = False
    for step in probes:
        if not step.executable:
            print(step.render())
            print("    => OPERATOR-ONLY: printed, never executed")
            continue
        if step.probe_class not in passed_classes:
            step.status = "control-failed"
            print(step.render())
            print(f"    => CONTROL-FAILED: {step.probe_class} control did not pass — "
                  "a negative here would be meaningless")
            continue
        if step.layer == "2-v4" and v6_target_alive:
            step.status = "skipped"
            continue
        if step.layer == "3-service":
            _run_service_step(ctx, step)
            continue
        addr_cmd = step.command.replace("<ADDR>", ctx.v6_linklocal).replace("<IFACE>", ctx.iface)
        rc, out = ssh_probe_host(ctx.probe_host, addr_cmd)
        step.status = "positive" if rc == 0 else "negative"
        if step.layer == "1-v6" and step.target_specific and rc == 0:
            # ONLY the target's own EUI-64 answer may suppress the v4
            # ladder — multicast/NDP hits prove other hosts or stale state.
            v6_target_alive = True
        if step.layer == "2-v4" and rc == 0:
            _harvest_ipv4(ctx, out)
        print(step.render())
        print(f"    => {step.status.upper()}: {out[:200]}")
    return steps


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=("plan", "run"), nargs="?", default="plan")
    parser.add_argument("--mac", required=True, help="source MAC observed in any frame")
    parser.add_argument("--iface", required=True, help="on-link L3 iface on probe host (e.g. switch.1007)")
    parser.add_argument("--probe-host", help="SSH alias of on-link probe host (required for run)")
    parser.add_argument("--control-ip", required=True, help="known-good host for the positive control")
    parser.add_argument("--probe-subnets", default="", help="comma list of subnets the probe host itself lives in")
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--json", type=Path, help="write ladder+results as JSON")
    args = parser.parse_args(argv)

    history = inventory_ip_history(args.mac, args.inventory)
    subnets = subnet_candidates(
        [s.strip() for s in args.probe_subnets.split(",") if s.strip()],
        inventory_history=history,
    )
    for net in subnets:
        if len(sweep_hosts(net)) > MAX_SWEEP_HOSTS:
            parser.error(
                f"subnet {net} has more than {MAX_SWEEP_HOSTS} usable hosts — the ARP "
                "sweep runs one parallel ping per host; split it into /24 blocks")
    ctx = DiscoverContext(
        mac=args.mac, iface=args.iface,
        probe_host=args.probe_host or "", control_ip=args.control_ip, subnets=subnets,
    )
    print(f"# bench-discover ladder for {args.mac}")
    print(f"# derived link-local: {ctx.v6_linklocal} (EUI-64)")
    print(f"# v4 sweep order: {', '.join(ctx.subnets) or '(none)'}")
    print(f"# inventory archaeology: {history or '(no hits)'}\n")

    steps = build_ladder(ctx)
    if args.mode == "run":
        if not args.probe_host:
            parser.error("--probe-host is required for run mode")
        steps = run_ladder(ctx, steps)
    else:
        for step in steps:
            print(step.render())

    print("\n# credential ladder (operator-executed only):")
    for cred in credential_ladder():
        print(f"    {cred['user']!r:>8} / {cred['password']!r:<18} ({cred['rationale']})")

    if args.json:
        payload = {
            "mac": ctx.mac, "iface": ctx.iface, "linklocal": ctx.v6_linklocal,
            "subnets": ctx.subnets, "inventory_history": history,
            "steps": [s.__dict__ for s in steps],
            "credentials": credential_ladder(),
        }
        args.json.write_text(json.dumps(payload, indent=1))
        print(f"\n# wrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
