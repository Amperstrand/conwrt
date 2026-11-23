#!/usr/bin/env python3
"""bootlisten — boot-capture classifier for dark-unit recovery (#323 item 2).

Pure text-in → verdict-out: every capture source (live tcpdump, a saved
`tcpdump -ne` transcript, the bench netlog) feeds the SAME classifier,
so the classification logic is provable offline against fixture
captures — no hardware needed to test the brain (the FakeDoor pattern
that made `conwrt adopt` testable; the choice is documented in
docs/DETECTION-RECOVERY-TOOLING.md).

Classifies one PoE/boot window's worth of tcpdump -ne lines into the
detection-and-recovery playbook's decision ladder:

  kernel-up      IPv6 DAD (NS/NA for own tentative address), MLD
                 reports, Router Solicitations — the first frames a
                 booting Linux emits, before any v4
  dhcp-client    DHCPDISCOVER/REQUEST FROM the device (distinct from
                 offers TO it — a rogue-DHCP check on shared segments)
  static-ARP     who-has <gw> tell <src> leaks: the device holds a
   leak          static v4 config and is fishing for its gateway — the
                 leaked source IP names the subnet to alias-probe
  vendor         UDP beacons on vendor fallback ports (4919-class),
  fallback       vendor-default IP chatter

Verdict carries the SUGGESTED NEXT ACTION — the playbook's first move
per outcome — as machine-readable JSON so automation (bench netlog,
nightly sweeps) can act on it without parsing prose.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field

# Vendor fallback beacon ports to flag by default (the UDP 4919 class —
# model JSON `detection.beacon_ports` extends this per species).
DEFAULT_BEACON_PORTS: tuple[int, ...] = (4919,)

_MAC = r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}"


@dataclass
class Observation:
    kind: str            # mld|rs|dad_ns|dad_na|ns|icmp6|arp_who_has|dhcp_client|udp_beacon|other
    src_mac: str = ""
    src_ip: str = ""
    detail: str = ""


@dataclass
class BootVerdict:
    frames: int = 0
    kernel_up: bool = False
    kernel_evidence: list[str] = field(default_factory=list)
    dhcp_client: bool = False
    arp_leak_candidates: list[str] = field(default_factory=list)
    vendor_fallback_ports: list[int] = field(default_factory=list)
    source_macs: list[str] = field(default_factory=list)
    next_action: str = ""
    next_action_reason: str = ""

    def to_json(self) -> str:
        return json.dumps(self.__dict__, indent=2, sort_keys=True)


def parse_line(line: str, beacon_ports: tuple[int, ...] = DEFAULT_BEACON_PORTS,
               exclude_macs: tuple[str, ...] = ()) -> Observation | None:
    """Parse one `tcpdump -ne` line into an Observation (None for noise)."""
    low = line.lower()
    if not low.strip() or low.startswith(("tcpdump:", "listening on", "0 packets")):
        return None
    mac_m = re.search(_MAC, line)
    src_mac = mac_m.group(0).lower() if mac_m else ""
    if src_mac and src_mac in {m.lower() for m in exclude_macs}:
        return None  # our own fixture/probes (the boot-watch lesson)
    ip_m = re.search(r"IP(?:v6)? (\S+?)\.?\d+ >", line) or re.search(r"IP6 (\S+) >", line)
    src_ip = ip_m.group(1) if ip_m else ""

    if "multicast listener" in low or "mld" in low:
        return Observation("mld", src_mac, src_ip, line.strip())
    if "router solicitation" in low or "router-solicitation" in low or " rs," in low:
        return Observation("rs", src_mac, src_ip, line.strip())
    if "neighbor solicitation" in low:
        # DAD = NS for the sender's own tentative address (src == target,
        # both under ff02::1); generic NS otherwise
        kind = "dad_ns" if "ff02::1" in low else "ns"
        return Observation(kind, src_mac, src_ip, line.strip())
    if "neighbor advertisement" in low:
        return Observation("dad_na", src_mac, src_ip, line.strip())
    if "icmp6" in low:
        return Observation("icmp6", src_mac, src_ip, line.strip())
    if "who-has" in low:
        return Observation("arp_who_has", src_mac, src_ip, line.strip())
    if "dhcpdiscover" in low or "bootp" in low or "dhcp request" in low:
        return Observation("dhcp_client", src_mac, src_ip, line.strip())
    for port in beacon_ports:
        # udp beacon shape: ".<port> > ..." toward broadcast/vendor ports
        if re.search(rf"\.{port}\s*>", low):
            return Observation("udp_beacon", src_mac, src_ip, line.strip())
    return Observation("other", src_mac, src_ip, line.strip())


def classify(lines: list[str], *,
             beacon_ports: tuple[int, ...] = DEFAULT_BEACON_PORTS,
             exclude_macs: tuple[str, ...] = ()) -> BootVerdict:
    """Classify a capture window; verdict includes the next action."""
    v = BootVerdict()
    obs = [o for o in (parse_line(l, beacon_ports, exclude_macs) for l in lines) if o]
    v.frames = len(obs)
    for o in obs:
        if o.src_mac and o.src_mac not in v.source_macs:
            v.source_macs.append(o.src_mac)
        if o.kind in ("mld", "rs", "dad_ns", "dad_na"):
            v.kernel_up = True
            v.kernel_evidence.append(o.kind)
        elif o.kind == "dhcp_client":
            v.dhcp_client = True
        elif o.kind == "arp_who_has":
            # "who-has <gw> tell <src>": the leaked TELL address is the
            # device's static v4 — name it for the alias-probe ladder
            m = re.search(r"who-has (\S+) tell (\S+)", o.detail)
            if m and m.group(2) not in ("0.0.0.0",):
                cand = f"{m.group(2)} (gateway {m.group(1)})"
                if cand not in v.arp_leak_candidates:
                    v.arp_leak_candidates.append(cand)
        elif o.kind == "udp_beacon":
            m = re.search(r"\.(\d+)\s*>", o.detail)
            if m and int(m.group(1)) not in v.vendor_fallback_ports:
                v.vendor_fallback_ports.append(int(m.group(1)))

    # Next action: the playbook ladder, first match wins. Order matters
    # exactly as the manual runbook orders it (v6 door is cheaper than
    # v4 archaeology; a leak is better evidence than a beacon).
    mac = v.source_macs[0] if v.source_macs else "<src-mac>"
    if v.frames == 0:
        v.next_action = "no-frames"
        v.next_action_reason = (
            "nothing emitted in the window: check carrier/PHY and PoE "
            "draw first (dark-device playbook layer 0), then serial"
        )
    elif v.kernel_up:
        v.next_action = "v6door"
        v.next_action_reason = (
            f"kernel is up (v6 first-frames seen): dial the v6 door — "
            f"conwrt v6door --mac {mac} --via <on-link-host> --vlan <n> "
            f"--cmd 'uname -a' (link-local survives every v4 failure mode)"
        )
    elif v.arp_leak_candidates:
        v.next_action = "alias-probe"
        v.next_action_reason = (
            f"static-ARP leak: device holds a static v4 and is fishing "
            f"for its gateway — alias-probe the leaked subnet: "
            f"conwrt probe (bench_discover ladder layer 2) against "
            f"{v.arp_leak_candidates[0].split(' ')[0].rstrip(',')}/24"
        )
    elif v.dhcp_client:
        v.next_action = "dhcp-adopt"
        v.next_action_reason = (
            "DHCP client live: confirm exactly ONE DHCP authority on the "
            "segment (rogue-DHCP discipline), find the leased IP, then "
            "conwrt adopt"
        )
    elif v.vendor_fallback_ports:
        v.next_action = "vendor-fallback"
        v.next_action_reason = (
            f"vendor fallback beacon on UDP {v.vendor_fallback_ports}: "
            f"probe the model JSON detection.vendor_subnets"
        )
    else:
        v.next_action = "capture-longer"
        v.next_action_reason = (
            "frames present but no boot signature yet: capture another "
            "cycle (boot chatter is loudest in the first ~10s)"
        )
    return v


def _capture_live(iface: str, seconds: int) -> list[str]:
    import subprocess
    proc = subprocess.run(
        ["tcpdump", "-ne", "-i", iface, "-c", "500", "-G", str(seconds), "-W", "1"],
        capture_output=True, text=True, timeout=seconds + 30,
    )
    return proc.stdout.splitlines()


def cmd_listen(args: argparse.Namespace) -> int:
    beacons = tuple(args.beacon_port or ()) + DEFAULT_BEACON_PORTS
    excludes = tuple(args.exclude_mac or ())
    if args.pcap_text:
        lines = open(args.pcap_text, encoding="utf-8", errors="replace").read().splitlines()
    elif args.iface:
        print(f"listening on {args.iface} for {args.seconds}s...", file=sys.stderr)
        lines = _capture_live(args.iface, args.seconds)
    else:
        lines = sys.stdin.read().splitlines()
    verdict = classify(lines, beacon_ports=beacons, exclude_macs=excludes)
    print(verdict.to_json() if args.json else _render(verdict))
    return 0


def _render(v: BootVerdict) -> str:
    out = [f"boot verdict: frames={v.frames} kernel_up={v.kernel_up} "
           f"dhcp_client={v.dhcp_client}"]
    if v.kernel_evidence:
        out.append(f"  kernel evidence: {', '.join(v.kernel_evidence)}")
    if v.arp_leak_candidates:
        out.append(f"  arp leaks: {'; '.join(v.arp_leak_candidates)}")
    if v.vendor_fallback_ports:
        out.append(f"  vendor beacons: {v.vendor_fallback_ports}")
    if v.source_macs:
        out.append(f"  source MACs: {', '.join(v.source_macs)}")
    out.append(f"next: {v.next_action} — {v.next_action_reason}")
    return "\n".join(out)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="conwrt listen",
                                description="classify a boot capture into a recovery verdict (#323)")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--pcap-text", help="saved `tcpdump -ne` transcript to classify")
    src.add_argument("--iface", help="capture live on this interface")
    p.add_argument("--seconds", type=int, default=60, help="live capture window")
    p.add_argument("--beacon-port", type=int, action="append",
                   help="vendor fallback beacon port to flag (repeatable; 4919 always on)")
    p.add_argument("--exclude-mac", action="append", default=[],
                   help="ignore frames from this MAC (your own fixture/probes)")
    p.add_argument("--json", action="store_true", help="emit the machine-readable verdict")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return cmd_listen(args)


if __name__ == "__main__":
    raise SystemExit(main())
