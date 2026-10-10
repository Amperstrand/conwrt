#!/usr/bin/env python3
"""Arm / disarm / inspect the Raspberry Pi netboot rescue server on an OpenWrt router.

When ARMED, the router's dnsmasq serves a rescue boot tree over TFTP to selected
Raspberry Pi MACs. Any Pi whose bootloader falls back to network boot (empty boot
order tail, missing boot media, or a deliberate network-first BOOT_ORDER) then
boots a RAM-only rescue environment instead of hanging in a DHCP DISCOVER loop.

When DISARMED, dnsmasq is back to stock and a network-first Pi falls through to
its next boot medium (USB disk, SD card). This arm/disarm pair is the "network
boot on/off switch" for lab Pis.

Safety design (learned the hard way — see recipes/raspberry-pi/netboot-rescue.md):

- OpenWrt runs dnsmasq inside a procd ujail. A tftp-root that does not exist, or
  that is outside the jail's mounted paths, makes dnsmasq crash-loop — and the
  router loses DHCP/DNS for the whole LAN.
- arm() therefore uploads the boot tree FIRST, reconfigures dnsmasq SECOND, and
  rollbacks the dnsmasq config automatically if dnsmasq is not healthy after the
  restart.
- The default TFTP root lives under the jail-mounted dnsmasq conf-dir
  (/tmp/dnsmasq.<section>.d), which is visible to the jailed dnsmasq.

Usage:
    pi_netboot.py arm    --router 192.168.13.1 --tree ~/pi-rescue-kit/tftp-tree \
                         --mac e4:5f:01:14:a4:66
    pi_netboot.py disarm --router 192.168.13.1 [--purge]
    pi_netboot.py status --router 192.168.13.1
    pi_netboot.py detect --router 192.168.13.1 [--min-discover 3]
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from oui import oui_lookup  # noqa: E402
from ssh_utils import run_ssh  # noqa: E402

MARKER_START = "# --- Pi netboot rescue (managed by conwrt pi_netboot) ---"
MARKER_END = "# --- end Pi netboot rescue ---"
DEFAULT_TFTP_ROOT = "/tmp/dnsmasq.cfg01411c.d/tftpboot"
DEFAULT_BOOTFILE = "config.txt"
DNSMASQ_CONF = "/etc/dnsmasq.conf"


# ---------------------------------------------------------------------------
# Pure helpers (unit-testable, no I/O)
# ---------------------------------------------------------------------------

def render_block(router_ip: str, macs: list[str], tftp_root: str,
                 bootfile: str = DEFAULT_BOOTFILE) -> str:
    """Render the dnsmasq config block for the rescue server."""
    host_lines = "\n".join(
        f"dhcp-host={mac.lower()},set:pinetboot" for mac in macs
    )
    return (
        f"{MARKER_START}\n"
        f"{host_lines}\n"
        f"dhcp-option=tag:pinetboot,66,{router_ip}\n"
        f"dhcp-option=tag:pinetboot,67,{bootfile}\n"
        f"enable-tftp\n"
        f"tftp-root={tftp_root}\n"
        f"log-dhcp\n"
        f"{MARKER_END}"
    )


def strip_block(config_text: str, marker: str = MARKER_START) -> tuple[str, bool]:
    """Remove the managed block. Returns (new_config, removed).

    Tolerates legacy variants of the block (older manual re-arm scripts used a
    different marker suffix and no end marker — their last line is log-dhcp).
    """
    lines = config_text.splitlines()
    start = None
    end = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if start is None:
            if stripped.startswith("# --- Pi netboot rescue"):
                start = i
            continue
        if stripped == MARKER_END:
            end = i
            break
        if stripped == "log-dhcp":
            end = i
            if i + 1 < len(lines) and lines[i + 1].strip() == MARKER_END:
                end = i + 1
            break
    if start is None:
        return config_text, False
    if end is None:
        end = len(lines) - 1
    remaining = lines[:start] + lines[end + 1:]
    return "\n".join(remaining).rstrip() + "\n", True


def is_armed(config_text: str, marker: str = MARKER_START) -> bool:
    # the per-host tag is the real functional marker; any variant of the block
    # carries it
    return "pinetboot" in config_text


def parse_dhcp_log(log_text: str) -> dict[str, dict[str, int]]:
    """Count DISCOVER/REQUEST/ACK per MAC from dnsmasq-dhcp log lines."""
    counts: dict[str, dict[str, int]] = {}
    for line in log_text.splitlines():
        if "dnsmasq-dhcp" not in line:
            continue
        mac = None
        verb = None
        for token in ("DHCPDISCOVER", "DHCPREQUEST", "DHCPACK", "DHCPOFFER"):
            if token in line:
                verb = token.lower().replace("dhcp", "")
                after = line.split(token, 1)[1]
                for part in after.split():
                    if part.count(":") == 5:
                        mac = part.lower().rstrip(",")
                        break
                break
        if mac and verb:
            entry = counts.setdefault(mac, {"discover": 0, "request": 0, "ack": 0})
            entry[verb] = entry.get(verb, 0) + 1
    return counts


def netboot_loop_candidates(counts: dict[str, dict[str, int]],
                            min_discover: int = 3) -> list[str]:
    """MACs that keep DISCOVERing but never REQUEST — classic netboot loop."""
    out = []
    for mac, c in counts.items():
        if c.get("discover", 0) >= min_discover and c.get("request", 0) == 0:
            out.append(mac)
    return sorted(out)


# ---------------------------------------------------------------------------
# Remote I/O
# ---------------------------------------------------------------------------

def _ssh(router: str, command: str, timeout: int = 30) -> tuple[int, str, str]:
    proc = run_ssh(router, command, timeout=timeout)
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def remote_detect_tftp_root(router: str) -> str:
    """Find the dnsmasq conf-dir on the router (jail-visible TFTP location)."""
    rc, out, _ = _ssh(router, "ls -d /tmp/dnsmasq*.d 2>/dev/null | head -n1")
    out = out.strip()
    if rc == 0 and out:
        return out.rstrip("/") + "/tftpboot"
    return DEFAULT_TFTP_ROOT


def read_remote_config(router: str) -> str:
    rc, out, err = _ssh(router, f"cat {DNSMASQ_CONF}")
    if rc != 0:
        raise RuntimeError(f"cannot read {DNSMASQ_CONF} on {router}: {err}")
    return out


def write_remote_config(router: str, config_text: str) -> None:
    proc = run_ssh(router, f"cat > {DNSMASQ_CONF}", timeout=30,
                   input=config_text)
    if proc.returncode != 0:
        raise RuntimeError(f"cannot write {DNSMASQ_CONF}: {proc.stderr}")


def restart_dnsmasq(router: str) -> None:
    _ssh(router, "/etc/init.d/dnsmasq restart", timeout=60)
    time.sleep(3)


def dnsmasq_healthy(router: str, tftp_root: str | None = None) -> bool:
    rc, out, _ = _ssh(router, "pgrep dnsmasq >/dev/null && echo alive")
    if "alive" not in out:
        return False
    if tftp_root is not None:
        rc, out, _ = _ssh(
            router, f"netstat -lnup 2>/dev/null | grep -q ':69 ' && echo tftp")
        if "tftp" not in out:
            return False
        _, out, _ = _ssh(router, f"test -f {tftp_root}/config.txt && echo tree")
        if "tree" not in out:
            return False
    return True


def upload_tree(router: str, tree_dir: Path, remote_root: str) -> None:
    if not (tree_dir / "config.txt").is_file():
        raise RuntimeError(f"{tree_dir} does not look like a rescue boot tree "
                           "(missing config.txt)")
    parent = remote_root.rsplit("/", 1)[0]
    rc, _, err = _ssh(router, f"mkdir -p {remote_root}")
    if rc != 0:
        raise RuntimeError(f"cannot create {remote_root}: {err}")
    proc = subprocess_scp_tree(tree_dir, router, remote_root)
    if proc.returncode != 0:
        raise RuntimeError(f"tree upload failed: {proc.stderr}")


def subprocess_scp_tree(tree_dir: Path, router: str, remote_root: str):
    import subprocess
    files = sorted(str(p) for p in tree_dir.iterdir() if p.is_file())
    cmd = ["scp", "-O", "-o", "BatchMode=yes"] + files + [
        f"root@{router}:{remote_root}/"]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=300)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_arm(args: argparse.Namespace) -> int:
    tree_dir = Path(args.tree).expanduser().resolve()
    macs = [m.lower() for m in args.mac]
    tftp_root = args.tftp_root or remote_detect_tftp_root(args.router)

    print(f"router      : {args.router}")
    print(f"tree        : {tree_dir} -> {tftp_root}")
    print(f"macs        : {', '.join(macs)}")

    upload_tree(args.router, tree_dir, tftp_root)

    old_conf = read_remote_config(args.router)
    was_armed = is_armed(old_conf)
    base = strip_block(old_conf)[0] if was_armed else old_conf
    new_conf = base.rstrip() + "\n\n" + render_block(
        args.router, macs, tftp_root, args.bootfile) + "\n"

    write_remote_config(args.router, new_conf)
    restart_dnsmasq(args.router)

    if not dnsmasq_healthy(args.router, tftp_root):
        print("dnsmasq unhealthy after reconfig — ROLLING BACK", file=sys.stderr)
        _, log, _ = _ssh(args.router, "logread | grep -i dnsmasq | tail -5")
        write_remote_config(args.router, old_conf)
        restart_dnsmasq(args.router)
        print(log, file=sys.stderr)
        print("rollback complete; dnsmasq restored", file=sys.stderr)
        return 1

    print(f"ARMED ({'updated' if was_armed else 'new block'}): "
          f"netboot rescue serving {tftp_root} to {len(macs)} MAC(s)")
    return 0


def cmd_disarm(args: argparse.Namespace) -> int:
    old_conf = read_remote_config(args.router)
    new_conf, removed = strip_block(old_conf)
    if not removed:
        print("not armed — nothing to do")
        return 0
    write_remote_config(args.router, new_conf)
    restart_dnsmasq(args.router)
    if not dnsmasq_healthy(args.router):
        print("WARNING: dnsmasq unhealthy after disarm — inspect the router",
              file=sys.stderr)
        return 1
    if args.purge:
        tftp_root = args.tftp_root or remote_detect_tftp_root(args.router)
        _ssh(args.router, f"rm -rf {tftp_root}")
        print(f"purged {tftp_root}")
    print("DISARMED: dnsmasq back to stock; network-first Pis fall through "
          "to their next boot medium")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    conf = read_remote_config(args.router)
    armed = is_armed(conf)
    tftp_root = args.tftp_root or remote_detect_tftp_root(args.router)
    _, out, _ = _ssh(args.router,
                     f"netstat -lnup 2>/dev/null | grep ':69 ' >/dev/null "
                     f"&& echo listening || echo not-listening")
    listening = out.strip()
    _, tree, _ = _ssh(args.router,
                      f"ls {tftp_root} 2>/dev/null | wc -l")
    print(f"router      : {args.router}")
    print(f"armed       : {armed}")
    print(f"tftp        : {listening} ({tftp_root}, {tree.strip()} files)")
    if args.mac:
        for mac in args.mac:
            _, out, _ = _ssh(
                args.router,
                f"logread | grep '{mac.lower()}' | grep dnsmasq-dhcp | tail -4")
            print(f"--- {mac} ({oui_lookup(mac)}) recent dhcp:")
            print(out.rstrip() or "  (no dhcp events)")
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    _, out, _ = _ssh(args.router, "logread | grep dnsmasq-dhcp | tail -400")
    counts = parse_dhcp_log(out)
    loops = netboot_loop_candidates(counts, args.min_discover)
    if not loops:
        print("no netboot-loop candidates found")
        return 0
    print("netboot-loop candidates (DISCOVERing but never REQUESTing):")
    for mac in loops:
        c = counts[mac]
        print(f"  {mac}  ({oui_lookup(mac)})  "
              f"discover={c['discover']} request={c['request']} ack={c['ack']}")
    print("\nTo rescue: arm the rescue server (pi_netboot.py arm) and "
          "power-cycle the Pi.")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp: argparse.ArgumentParser, macs: bool = False) -> None:
        sp.add_argument("--router", required=True,
                        help="OpenWrt router running dnsmasq (root SSH)")
        sp.add_argument("--tftp-root", default=None,
                        help="override TFTP root (default: auto-detect confdir)")
        if macs:
            sp.add_argument("--mac", required=True, nargs="+",
                            help="Pi MAC address(es) allowed to netboot")

    sp = sub.add_parser("arm", help="upload tree + configure dnsmasq + restart")
    add_common(sp, macs=True)
    sp.add_argument("--tree", required=True,
                    help="local rescue boot tree (must contain config.txt)")
    sp.add_argument("--bootfile", default=DEFAULT_BOOTFILE)
    sp.set_defaults(func=cmd_arm)

    sp = sub.add_parser("disarm", help="remove the managed dnsmasq block")
    add_common(sp)
    sp.add_argument("--purge", action="store_true",
                    help="also delete the remote TFTP tree")
    sp.set_defaults(func=cmd_disarm)

    sp = sub.add_parser("status", help="show armed state and recent Pi dhcp events")
    add_common(sp, macs=True)
    sp.set_defaults(func=cmd_status)

    sp = sub.add_parser("detect",
                        help="find MACs stuck in a netboot DISCOVER loop")
    add_common(sp)
    sp.add_argument("--min-discover", type=int, default=3)
    sp.set_defaults(func=cmd_detect)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
