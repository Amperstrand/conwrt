"""boot-watch — watch an interface for device boot signatures.

During the 2026-09-27 flash attempts the difference between "device is
flashing", "device rebooted", and "device is dead" had to be inferred by
hand from tcpdump one-liners and carrier reads, and two home-grown watchers
false-positived on the fixture's own ARP probes. This command watches:

  * packets on the interface, EXCLUDING any MACs you list (list your own
    fixture/router MACs or every probe you send will look like boot traffic)
  * carrier transitions on the interface (reboots show as link flaps)
  * optional target IPs (ping) for post-boot reachability

and classifies the first packets using boot signatures observed on real
devices (IPv6 MLD reports are typically the very first frame a booting
Linux emits, before DHCP or ARP).
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import threading
import time


def classify_packet_line(line: str) -> str | None:
    """Classify one tcpdump -ne line; return a signature tag or None."""
    low = line.lower()
    if not low.strip() or low.startswith(("tcpdump:", "listening on")):
        return None
    if "mld" in low or "multicast listener" in low:
        return "mld-report (booting Linux signature)"
    if "router solicitation" in low or "rs," in low:
        return "router-solicitation"
    if "dhcp" in low or "bootp" in low:
        return "dhcp"
    if "who-has" in low or "arp" in low:
        return "arp"
    if "icmp6" in low:
        return "icmp6"
    return "packet"


class _Carrier:
    def __init__(self, interface: str) -> None:
        self.interface = interface
        self.state = self._read()

    def _read(self) -> str:
        try:
            with open(f"/sys/class/net/{self.interface}/carrier", encoding="ascii") as fh:
                return fh.read().strip()
        except OSError:
            return "unknown"

    def poll(self) -> str | None:
        new = self._read()
        if new != self.state:
            old, self.state = self.state, new
            return f"{old}->{new}"
        return None


def cmd_boot_watch(args: argparse.Namespace) -> int:
    if not args.exclude_mac:
        print("note: no --exclude-mac given; your own probe traffic will be "
              "classified as boot traffic", file=sys.stderr)

    filters = [f"not ether host {m}" for m in args.exclude_mac]
    filt = " and ".join(filters) if filters else ""
    cmd = ["tcpdump", "-i", args.interface, "-ne", "-l", "-c", str(args.max_packets)]
    if filt:
        cmd.append(filt)

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True)
    seen_any = False
    lock = threading.Lock()
    events: list[tuple[float, str]] = []

    def reader() -> None:
        nonlocal seen_any
        assert proc.stdout is not None
        for line in proc.stdout:
            tag = classify_packet_line(line)
            if tag and tag != "packet":
                with lock:
                    events.append((time.monotonic(), tag))
                    seen_any = True
                print(f"[pkt ] {line.strip()[:150]}")
                print(f"       -> {tag}")
            elif tag:
                seen_any = True

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()

    carrier = _Carrier(args.interface)
    deadline = time.monotonic() + args.duration
    boot_detected = False

    while time.monotonic() < deadline:
        flap = carrier.poll()
        if flap:
            print(f"[link] carrier {flap} at t+{int(time.monotonic() - (deadline - args.duration))}s")
        for ip in args.watch_ip:
            r = subprocess.run(["ping", "-c", "1", "-W", "1", ip],
                               capture_output=True, text=True, check=False)
            if r.returncode == 0:
                print(f"[ping ] {ip} is UP")
                boot_detected = True
                deadline = min(deadline, time.monotonic() + 5)
        if seen_any:
            boot_detected = True
        time.sleep(args.poll_interval)

    proc.terminate()
    print(f"[done ] boot traffic seen: {'yes' if seen_any else 'no'}; "
          f"{len(events)} classified signatures")
    return 0 if boot_detected else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="boot-watch",
        description="Watch an interface for device boot signatures (packet + carrier + ping).")
    p.add_argument("--interface", required=True,
                   help="interface sharing L2 with the watched device")
    p.add_argument("--exclude-mac", action="append", default=[],
                   help="MAC to exclude from classification (repeatable); "
                        "list your fixture/router MACs here")
    p.add_argument("--watch-ip", action="append", default=[],
                   help="IP to ping-poll for post-boot reachability (repeatable)")
    p.add_argument("--duration", type=int, default=300,
                   help="watch window in seconds (default 300)")
    p.add_argument("--poll-interval", type=float, default=2.0,
                   help="carrier/ping poll interval seconds (default 2)")
    p.add_argument("--max-packets", type=int, default=2000,
                   help="tcpdump packet cap (default 2000)")
    return p


def main(argv: list[str] | None = None) -> int:
    return cmd_boot_watch(build_parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
