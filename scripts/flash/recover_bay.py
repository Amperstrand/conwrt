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
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from flash.chromium_upload import upload  # noqa: E402

FRESH_STATES = ("REACHABLE", "DELAY", "PROBE")


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


def watch_door(switch: str, key: str, svi: str, door_ip: str, timeout: float) -> str | None:
    print(f"[door] watching {door_ip} on {svi} for up to {int(timeout / 60)} min "
          f"(dual-image boot: expect two reboots)")
    ssh_run(switch, key, "ip addr del 192.168.1.254/24 dev switch.1 2>/dev/null; true")
    arm_alias(switch, key, svi, "192.168.1.2", present=True)
    deadline = time.monotonic() + timeout
    mac = None
    try:
        while time.monotonic() < deadline:
            out = ssh_run(switch, key,
                          f"ping -c1 -W1 {door_ip} >/dev/null 2>&1; "
                          f"ip neigh show {door_ip} dev {svi} 2>/dev/null | head -1")
            if out and "FAILED" not in out and "INCOMPLETE" not in out:
                mac = out.split("lladdr")[1].split()[0] if "lladdr" in out else "?"
                print(f"[door] UP: {out}")
                break
            time.sleep(5)
    finally:
        arm_alias(switch, key, svi, "192.168.1.2", present=False)
        ssh_run(switch, key, "ip addr add 192.168.1.254/24 dev switch.1 2>/dev/null; true")
    return mac


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Watch one bay; auto-fire on fresh arming.")
    p.add_argument("--image", required=True)
    p.add_argument("--switch", default="root@192.168.104.1")
    p.add_argument("--key", default=str(Path.home() / ".ssh/id_ed25519"))
    p.add_argument("--svi", required=True, help="bay SVI on the switch, e.g. switch.1003")
    p.add_argument("--port", required=True, help="bay switch port, e.g. lan3")
    p.add_argument("--recovery-ip", default="192.168.0.1")
    p.add_argument("--client-ip", default="192.168.0.2")
    p.add_argument("--local-port", type=int, default=18080)
    p.add_argument("--watch-timeout", type=int, default=900)
    p.add_argument("--gate-timeout", type=int, default=150)
    p.add_argument("--door-ip", default="192.168.1.1")
    p.add_argument("--door-timeout", type=int, default=1500)
    args = p.parse_args(argv)

    ensure_tunnel(args.switch, args.key, args.local_port, args.recovery_ip)
    arm_alias(args.switch, args.key, args.svi, args.client_ip, present=True)
    print(f"[setup] tunnel :{args.local_port} + alias {args.client_ip} on {args.svi}")
    print("[watch] power-cycle the unit whenever ready (plain cycle; no button)")

    proc = subprocess.Popen(
        ["ssh", *ssh_opts(args.key), args.switch, poller_cmd(args.svi, args.port, args.recovery_ip)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    try:
        if not wait_fresh_arming(proc, time.monotonic() + args.watch_timeout):
            print("[verdict] WINDOW TIMEOUT — no fresh arming seen; rerun after a power-cycle")
            return 2
        accepted, verdict = upload(args.image, f"http://127.0.0.1:{args.local_port}/upload",
                                   "firmware", 300)
        print(f"[fire] {verdict}")
        if not wait_consumption(proc, args.gate_timeout):
            print("[verdict] NOT CONSUMED — server never vanished (idle-dead or rejected); "
                  "power-cycle and rerun")
            return 3
    finally:
        proc.terminate()
        arm_alias(args.switch, args.key, args.svi, args.client_ip, present=False)

    mac = watch_door(args.switch, args.key, args.svi, args.door_ip, args.door_timeout)
    if mac:
        print(f"[verdict] RECOVERED — door {args.door_ip} MAC {mac} "
              f"(record it: this settles bay<->unit identity)")
        return 0
    print("[verdict] CONSUMED but no door — accepted-no-boot class; capture, do not blind-retry")
    return 4


if __name__ == "__main__":
    sys.exit(main())
