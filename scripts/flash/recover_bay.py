# pyright: reportAttributeAccessIssue=false
"""Bench-side recovery watcher for one-request U-Boot recovery servers.

The COVR recovery httpd serves a ~5-8 min window from power-on; a POST that
arrives late hits an idle-dead server that HANGS the connection (looks
identical to an accepted upload — see chromium_upload.classify_outcome).
Every miss so far was a timing miss between the operator's power-cycle and
the upload. This tool removes the timing: it watches the bay for a FRESH
arming (link drop -> link up -> live ARP answer) and fires the local-form
POST within seconds, then verifies consumption by watching the recovery
server vanish.

Bench specifics (switch address, bay port, SVI) come from CLI args — this
file stays species-level.

Sequence: watch (until fresh arming, --watch-timeout) -> fire (local-form
Chromium POST via an ssh -L tunnel) -> gate (recovery ARP must vanish within
--gate-timeout) -> optional door watch (--door-ip, e.g. 192.168.1.1 for
lan_ip_mode=keep images; prints the door MAC so bay<->unit identity resolves).
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from contextlib import nullcontext
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from flash.chromium_upload import upload  # noqa: E402

FRESH_STATES = ("REACHABLE", "DELAY", "PROBE")


class BayPcap:
    """Record the bay wire into a local pcap file.

    The #91 rule: never blame the client without a pcap. Five recovery POSTs
    on 2026-10-19 produced five no-boots and zero wire evidence — this makes
    the evidence automatic. One file per run holds every phase: the arming
    ARP polls, the multipart POST byte stream, the server vanish, and any
    boot traffic (DHCP discovers / RAs / ARP) during the door watch.

    Two transports: switch mode streams a remote tcpdump over ssh; direct
    mode (``direct_iface``) records a locally-attached interface — the
    historically clean path (every fast clean flash of this model ran from
    a host directly on the recovery link; every tunneled attempt since
    October no-booted).
    """

    def __init__(self, switch: str, key: str, svi: str, pcap_dir: str,
                 direct_iface: str | None = None):
        self.switch, self.key, self.svi = switch, key, svi
        self.direct_iface = direct_iface
        name = direct_iface or svi
        self.path = Path(pcap_dir) / f"recover-{name}-{time.strftime('%Y%m%d-%H%M%S')}.pcap"

    def __enter__(self) -> "BayPcap":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.fh = open(self.path, "wb")
        if self.direct_iface:
            cmd = ["tcpdump", "-i", self.direct_iface, "-U", "-n", "-s", "0", "-w", "-"]
        else:
            cmd = ["ssh", *ssh_opts(self.key), self.switch,
                   f"tcpdump -i {self.svi} -U -n -s 0 -w - 2>/dev/null"]
        self.proc = subprocess.Popen(cmd, stdout=self.fh, stderr=subprocess.DEVNULL)
        print(f"[pcap] recording bay wire to {self.path}")
        return self

    def __exit__(self, *exc: object) -> bool:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.fh.close()
        size = self.path.stat().st_size if self.path.exists() else 0
        print(f"[pcap] saved {self.path} ({size} bytes)")
        return False


def ssh_opts(key: str) -> list[str]:
    return ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=8", "-i", key]


def ssh_run(switch: str, key: str, cmd: str, timeout: int = 15) -> str:
    r = subprocess.run(["ssh", *ssh_opts(key), switch, cmd],
                       capture_output=True, text=True, timeout=timeout, check=False)
    return r.stdout.strip()


def ensure_tunnel(switch: str, key: str, local_port: int, recovery_ip: str) -> None:
    probe = subprocess.run(
        ["pgrep", "-f", f"[-]L {local_port}:{recovery_ip}:80"], capture_output=True)
    if probe.returncode == 0:
        return
    subprocess.run(["ssh", "-f", "-N", *ssh_opts(key),
                    "-L", f"{local_port}:{recovery_ip}:80", switch], check=True)


def arm_alias(switch: str, key: str, svi: str, client_ip: str, present: bool) -> None:
    verb = "add" if present else "del"
    ssh_run(switch, key, f"ip addr {verb} {client_ip}/24 dev {svi} 2>/dev/null; true")


def poller_cmd(svi: str, port: str, recovery_ip: str) -> str:
    return (
        f"while true; do "
        f"C=$(cat /sys/class/net/{port}/carrier 2>/dev/null || echo 0); "
        f"ping -c1 -W1 {recovery_ip} >/dev/null 2>&1; "
        f"N=$(ip neigh show {recovery_ip} dev {svi} 2>/dev/null | head -1); "
        f"echo \"POLL C=$C N=${{N:-none}}\"; "
        f"sleep 1; done"
    )


def parse_poll(line: str) -> tuple[int, str]:
    carrier, neigh = 0, "none"
    if "POLL C=" in line:
        rest = line.split("POLL C=", 1)[1]
        carrier = int(rest[0]) if rest[:1].isdigit() else 0
        if " N=" in rest:
            neigh = rest.split(" N=", 1)[1].strip()
    return carrier, neigh


def wait_fresh_arming(proc, deadline: float) -> bool:
    """True when the bay shows link drop -> link up -> live ARP answer."""
    saw_drop_at: float | None = None
    heartbeat = time.monotonic()
    for raw in proc.stdout:
        if time.monotonic() > deadline:
            return False
        carrier, neigh = parse_poll(raw)
        now = time.monotonic()
        if carrier == 0:
            saw_drop_at = now
        elif carrier == 1 and saw_drop_at and (now - saw_drop_at) < 240 \
                and any(s in neigh for s in FRESH_STATES):
            print(f"[watch] fresh arming detected: link cycle + live ARP ({neigh})")
            return True
        if now - heartbeat > 10:
            print(f"[watch] waiting for power-cycle (carrier={carrier}, "
                  f"neigh={neigh[:60] or 'none'})")
            heartbeat = now
    return False


def wait_consumption(proc, gate_timeout: float) -> bool:
    """True when the recovery server stops answering ARP (POST consumed)."""
    deadline = time.monotonic() + gate_timeout
    for raw in proc.stdout:
        if time.monotonic() > deadline:
            return False
        _, neigh = parse_poll(raw)
        if "FAILED" in neigh or "INCOMPLETE" in neigh or neigh == "none":
            print("[gate] recovery server vanished — POST consumed, flashing")
            return True
        if any(s in neigh for s in FRESH_STATES):
            print(f"[gate] server still answering ({neigh})")
    return False


def watch_door(switch: str, key: str, svi: str, door_ip: str, timeout: float,
               direct_iface: str | None = None) -> str | None:
    iface = direct_iface or svi
    print(f"[door] watching {door_ip} on {iface} for up to {int(timeout / 60)} min "
          f"(dual-image boot: expect two reboots)")
    if direct_iface:
        def ssh_or_local(cmd: str) -> str:
            return subprocess.run(["sh", "-c", cmd], capture_output=True,
                                  text=True, check=False).stdout.strip()
        ssh_or_local(f"ip addr add 192.168.1.2/24 dev {iface} 2>/dev/null; true")
    else:
        def ssh_or_local(cmd: str) -> str:
            return ssh_run(switch, key, cmd)
        ssh_or_local("ip addr del 192.168.1.254/24 dev switch.1 2>/dev/null; true")
        ssh_or_local(f"ip addr add 192.168.1.2/24 dev {svi} 2>/dev/null; true")
    deadline = time.monotonic() + timeout
    mac = None
    try:
        while time.monotonic() < deadline:
            out = ssh_or_local(
                f"ping -c1 -W1 {door_ip} >/dev/null 2>&1; "
                f"ip neigh show {door_ip} dev {iface} 2>/dev/null | head -1")
            if out and "FAILED" not in out and "INCOMPLETE" not in out:
                mac = out.split("lladdr")[1].split()[0] if "lladdr" in out else "?"
                print(f"[door] UP: {out}")
                break
            time.sleep(5)
    finally:
        if direct_iface:
            ssh_or_local(f"ip addr del 192.168.1.2/24 dev {iface} 2>/dev/null; true")
        else:
            ssh_or_local(f"ip addr del 192.168.1.2/24 dev {svi} 2>/dev/null; true")
            ssh_or_local("ip addr add 192.168.1.254/24 dev switch.1 2>/dev/null; true")
    return mac


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Watch one bay; auto-fire on fresh arming.")
    p.add_argument("--image", required=True)
    p.add_argument("--switch", default="root@192.168.104.1")
    p.add_argument("--key", default=str(Path.home() / ".ssh/id_ed25519"))
    p.add_argument("--svi", help="bay SVI on the switch, e.g. switch.1003 (switch mode)")
    p.add_argument("--port", help="bay switch port, e.g. lan3 (switch mode)")
    p.add_argument("--recovery-ip", default="192.168.0.1")
    p.add_argument("--client-ip", default="192.168.0.2")
    p.add_argument("--local-port", type=int, default=18080)
    p.add_argument("--watch-timeout", type=int, default=900)
    p.add_argument("--gate-timeout", type=int, default=150)
    p.add_argument("--door-ip", default="192.168.1.1")
    p.add_argument("--door-timeout", type=int, default=1500)
    p.add_argument("--pcap-dir", default="/tmp/conwrt-recovery-pcaps",
                   help="where bay-wire pcaps land (default-on; see BayPcap)")
    p.add_argument("--no-pcap", action="store_true", help="disable the wire recording")
    p.add_argument("--direct-iface", default=None,
                   help="direct mode: IFACE is locally attached to the unit "
                        "(recovery subnet pre-configured, e.g. 192.168.0.10/24). "
                        "No switch, no tunnel, no SVI aliases — the historically "
                        "clean path. Overrides --switch/--svi/--port transport.")
    args = p.parse_args(argv)
    direct = args.direct_iface

    if direct:
        have = subprocess.run(["sh", "-c", f"ip -4 addr show dev {direct} | grep -c 'inet '"],
                              capture_output=True, text=True).stdout.strip()
        print(f"[setup] direct mode on {direct} (IPv4 addrs: {have}); "
              f"endpoint http://{args.recovery_ip}/upload")
    else:
        ensure_tunnel(args.switch, args.key, args.local_port, args.recovery_ip)
        arm_alias(args.switch, args.key, args.svi, args.client_ip, present=True)
        print(f"[setup] tunnel :{args.local_port} + alias {args.client_ip} on {args.svi}")
    print("[watch] power-cycle the unit whenever ready (plain cycle; no button)")

    capture = nullcontext() if args.no_pcap else \
        BayPcap(args.switch, args.key, args.svi, args.pcap_dir, direct_iface=direct)
    with capture:
        poll_cmd = poller_cmd(direct or args.svi, direct or args.port, args.recovery_ip)
        if direct:
            proc = subprocess.Popen(["sh", "-c", poll_cmd],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    text=True, bufsize=1)
        else:
            proc = subprocess.Popen(
                ["ssh", *ssh_opts(args.key), args.switch, poll_cmd],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        try:
            if not wait_fresh_arming(proc, time.monotonic() + args.watch_timeout):
                print("[verdict] WINDOW TIMEOUT — no fresh arming seen; rerun after a power-cycle")
                return 2
            endpoint = (f"http://{args.recovery_ip}/upload" if direct
                        else f"http://127.0.0.1:{args.local_port}/upload")
            accepted, verdict = upload(args.image, endpoint, "firmware", 300)
            print(f"[fire] {verdict}")
            if not wait_consumption(proc, args.gate_timeout):
                print("[verdict] NOT CONSUMED — server never vanished (idle-dead or rejected); "
                      "power-cycle and rerun")
                return 3
        finally:
            proc.terminate()
            if not direct:
                arm_alias(args.switch, args.key, args.svi, args.client_ip, present=False)

        mac = watch_door(args.switch, args.key, args.svi, args.door_ip, args.door_timeout,
                         direct_iface=direct)
        if mac:
            print(f"[verdict] RECOVERED — door {args.door_ip} MAC {mac} "
                  f"(record it: this settles bay<->unit identity)")
            return 0
        print("[verdict] CONSUMED but no door — accepted-no-boot class; capture, do not blind-retry")
        return 4


if __name__ == "__main__":
    sys.exit(main())
