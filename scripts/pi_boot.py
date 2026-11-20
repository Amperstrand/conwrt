#!/usr/bin/env python3
"""Probe and test Raspberry Pi boot media: SD card, USB mass storage, network.

The Pi 4 bootloader (EEPROM) decides which medium is booted, and which media it
*can* use depends on the firmware date. Two release boundaries are easy to
conflate, and both decide what a recovery plan may assume:

    2020-04-16  network boot promoted to the DEFAULT production bootloader
                (beta since 2019-09-23)
    2020-09-03  USB mass-storage boot promoted to default (2020-09-14;
                beta since 2020-05-15)

So "this Pi boots from USB" implies "it can also netboot", but NOT the reverse:
a Pi from the 2019 / early-2020 window netboots while still being unable to
boot from USB at all. Capability is only half the story — the stock
BOOT_ORDER is ``0xf41`` = SD -> USB -> restart. Network is NOT in that list, so
a fully capable Pi never attempts a netboot until someone sets
``BOOT_ORDER=0xf241`` (or 0xf142 for network-first).

Capability and configuration are therefore separate verdicts, and the only
place both can be read truthfully is on the Pi itself, once booted. This tool
never guesses them from the model.

Subcommands
-----------
    scan   [--sweep CIDR]              passive ARP scan (+ optional ICMP sweep)
                                       for Raspberry Pi MAC prefixes, with a
                                       reachability class per hit
    probe  --host IP [--user pi]       read model/serial/firmware/boot order
                                       and the medium this boot actually used
    detect --host IP [--user pi]       classify an address as OS-up /
                                       rescue-shell / silent (netboot-fallback)
    capability --firmware 2020-04-16 --boot-order 0xf41
                                       offline capability matrix (no hardware)
    matrix --host IP [--legs sd,usb,net]
                                       walk the media in turn, power-cycling in
                                       between, and record PASS/FAIL per leg

``matrix`` is deliberately semi-manual: inserting an SD card cannot be
automated, so each leg prints its precondition and waits. Supply ``--power-cmd``
to automate the power cycle (labgrid, a relay, `virsh`, a smart plug CLI) and
``--yes`` to skip the Enter prompt.

Examples
--------
    # is the board on this L2 at all?
    scripts/pi_boot.py scan --sweep 192.168.1.0/24

    # what is the stickless Pi doing?
    scripts/pi_boot.py detect --host 192.168.1.50

    # it booted — where from, and can it do the other two?
    scripts/pi_boot.py probe --host 192.168.1.50 --user pi

    # full three-way boot test, manual media swaps, automated power
    scripts/pi_boot.py matrix --host 192.168.1.50 --user pi \
        --power-cmd 'labgrid-client -p <labgrid-place> power cycle' --json out.json

The report is JSON with ``--json PATH``; a PASS/FAIL verdict table is always
printed. Exit status is 0 only when every leg requested is PASS.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import shlex
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pi_eeprom import BOOT_MODES, decode_boot_order  # noqa: E402
from ssh_utils import run_ssh  # noqa: E402

# ---------------------------------------------------------------------------
# Firmware facts (from raspberrypi/rpi-eeprom firmware-2711 release-notes.md)
# ---------------------------------------------------------------------------

FW_NETBOOT_BETA = (2019, 9, 23)
FW_NETBOOT_STABLE = (2020, 4, 16)
FW_USB_BETA = (2020, 5, 15)
FW_USB_STABLE = (2020, 9, 3)

#: (boot mode name as it appears in BOOT_ORDER, medium reported by probe,
#:  first firmware with the feature in a beta, first DEFAULT firmware)
CAPABILITY = (
    ("sd", "sd", None, None),
    ("usb", "usb", FW_USB_BETA, FW_USB_STABLE),
    ("network", "net", FW_NETBOOT_BETA, FW_NETBOOT_STABLE),
)

MONTHS = {name: i for i, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}

#: Each matrix leg: what the operator must arrange, and what proves the boot.
LEGS = {
    "sd": {
        "expect_medium": "sd",
        "evidence": "ssh",
        "precondition": ("microSD with a bootable OS inserted; USB boot devices "
                         "removed; netboot server disarmed"),
    },
    "usb": {
        "expect_medium": "usb",
        "evidence": "ssh",
        "precondition": ("USB boot device inserted; microSD removed; netboot "
                         "server disarmed"),
    },
    "net": {
        "expect_medium": "net",
        "evidence": "telnet",
        "precondition": ("no microSD and no USB boot device; rescue server "
                         "ARMED for this Pi's MAC with a pinned IP"),
    },
}

PROBE_SCRIPT = r"""
echo "@@model"; tr -d '\0' < /proc/device-tree/model 2>/dev/null; echo
echo "@@serial"; sed -n 's/^Serial[[:space:]]*:[[:space:]]*//p' /proc/cpuinfo | head -1
echo "@@cmdline"; cat /proc/cmdline 2>/dev/null
echo "@@lsblk"; lsblk -P -o NAME,TRAN,TYPE,PARTUUID,SIZE 2>/dev/null
echo "@@mount"; findmnt -no SOURCE,FSTYPE / 2>/dev/null
echo "@@os"; (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") || uname -sr
echo "@@fw"; vcgencmd bootloader_version 2>/dev/null || sudo -n vcgencmd bootloader_version 2>/dev/null
echo "@@conf"; vcgencmd bootloader_config 2>/dev/null || sudo -n vcgencmd bootloader_config 2>/dev/null
echo "@@section-end"
"""


# ---------------------------------------------------------------------------
# Pure helpers (unit-testable, no I/O)
# ---------------------------------------------------------------------------

def parse_fw_date(text: str) -> tuple[int, int, int] | None:
    """Extract the firmware date from ``vcgencmd bootloader_version`` output.

    That command's first line is locale-dependent: ``Apr 16 2020 12:00:00`` on
    stock Pi OS, but a 2023+ wrapper prints ISO ``2020-04-16 12:00:00``. Both
    are accepted; anything else returns None rather than guessing.
    """
    if not text:
        return None
    first = text.strip().splitlines()[0].strip()
    m = re.match(r"(\d{4})-(\d{1,2})-(\d{1,2})", first)
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    m = re.match(r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{4})", first)
    if m and m.group(1) in MONTHS:
        return (int(m.group(3)), MONTHS[m.group(1)], int(m.group(2)))
    return None


def parse_bootloader_config(text: str) -> dict[str, str]:
    """Parse ``vcgencmd bootloader_config`` / ``rpi-eeprom-config`` output."""
    settings: dict[str, str] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        settings[key.strip()] = value.strip()
    return settings


def parse_boot_order(value: str) -> tuple[list[str], str | None]:
    """Decode BOOT_ORDER to (modes, error). Never raises on bad input."""
    try:
        return decode_boot_order(value), None
    except (ValueError, TypeError) as exc:
        return [], str(exc)


def capability_rows(firmware: tuple[int, int, int] | None,
                    modes: list[str], order_known: bool = True) -> list[dict]:
    """Per-mode capability/configuration verdict.

    ``supported`` is one of ``yes`` (shipping default contains the feature),
    ``beta`` (feature exists only in a beta bootloader of that date), ``no``,
    or ``unknown`` when the firmware date could not be read.

    ``ordered`` is True/False, or **None when no BOOT_ORDER could be read**.
    An unread config is not an empty config: collapsing the two would report
    "the bootloader will never try network" for a Pi whose configuration was
    simply unavailable (no vcgencmd, no sudo, not a Pi). That is a false
    claim, not a conservative one.
    """
    rows = []
    for mode, medium, beta_floor, stable_floor in CAPABILITY:
        if stable_floor is None:
            supported = "yes"
        elif firmware is None:
            supported = "unknown"
        elif firmware >= stable_floor:
            supported = "yes"
        elif beta_floor is not None and firmware >= beta_floor:
            supported = "beta"
        else:
            supported = "no"
        rows.append({
            "mode": mode,
            "medium": medium,
            "supported": supported,
            "ordered": (mode in modes) if order_known else None,
            "stable_floor": _fmt_date(stable_floor),
            "beta_floor": _fmt_date(beta_floor),
        })
    return rows


def ordered_cell(row: dict) -> str:
    """Renderer cell for the tri-state ``ordered`` value."""
    if row["ordered"] is None:
        return "?"
    return "yes" if row["ordered"] else "NO"


def capability_notes(row: dict) -> str:
    """One-line explanation of what a capability row means in practice."""
    mode = row["mode"]
    if row["supported"] == "unknown":
        return "firmware date unknown — read it on the Pi (vcgencmd bootloader_version)"
    if row["supported"] == "no":
        return (f"firmware predates {mode} boot "
                f"(first default release {row['stable_floor']}) — boot an SD card "
                f"and run rpi-eeprom-update")
    if row["supported"] == "beta":
        return (f"only in a BETA bootloader dated >= {row['beta_floor']} "
                f"(default release {row['stable_floor']}) — update before relying on it")
    if row["ordered"] is None:
        return ("firmware supports it, but BOOT_ORDER could not be read — the "
                "Pi never told us whether it will try this medium")
    if not row["ordered"]:
        nibble = BOOT_MODES.get(mode)
        hint = f" Add {nibble:#x} to BOOT_ORDER (e.g. 0xf241 for SD -> USB -> network)." \
            if nibble is not None else ""
        return (f"capable but NOT in BOOT_ORDER — the bootloader will never try "
                f"'{mode}'.{hint}")
    return "capable and reachable — this medium will be tried"


def _fmt_date(value: tuple[int, int, int] | None) -> str | None:
    return None if value is None else "%04d-%02d-%02d" % value


_KV = re.compile(r'([A-Z0-9_]+)="([^"]*)"')


def parse_lsblk(text: str) -> list[dict[str, str]]:
    """Parse ``lsblk -P`` (key="value") output, skipping blank/garbage lines."""
    rows = []
    for line in (text or "").splitlines():
        row = dict(_KV.findall(line))
        if row:
            rows.append(row)
    return rows


def _medium_from_block(tran: str, name: str) -> str:
    tran = (tran or "").lower()
    name = name or ""
    if tran == "mmc" or name.startswith("mmcblk"):
        return "sd"
    if tran == "usb" or name.startswith("sd"):
        return "usb"
    if tran == "nvme":
        return "nvme"
    return "unknown"


def _root_value(cmdline: str) -> str:
    try:
        tokens = shlex.split(cmdline or "")
    except ValueError:
        tokens = (cmdline or "").split()
    for token in tokens:
        if token.startswith("root="):
            # Unbalanced quotes survive the shlex fallback; a stray quote must
            # not turn a readable root device into "unknown".
            return token[len("root="):].strip("\"'")
    return ""


def boot_medium(cmdline: str, rows: list[dict[str, str]],
                root_source: str = "") -> str:
    """Which medium did this boot come from: sd / usb / net / nvme / unknown.

    Resolution order: nfsroot -> root=PARTUUID -> root=/dev/... -> RAM root.
    A kernel on the network always carries nfsroot (or root=/dev/nfs); a RAM
    boot has no block root at all.
    """
    try:
        tokens = shlex.split(cmdline or "")
    except ValueError:
        tokens = (cmdline or "").split()
    if any(t.startswith("nfsroot=") for t in tokens):
        return "net"

    root = _root_value(cmdline)
    if root:
        if root.startswith("/dev/nfs") or root == "/dev/ram0":
            return "net"
        if root.upper().startswith("PARTUUID="):
            want = root.split("=", 1)[1].strip().lower()
            for row in rows:
                partuuid = (row.get("PARTUUID") or "").lower()
                if partuuid and partuuid == want:
                    return _medium_from_block(row.get("TRAN", ""), row.get("NAME", ""))
            # Some kernels report a PARTUUID without the "-NN" partition suffix.
            for row in rows:
                partuuid = (row.get("PARTUUID") or "").lower()
                if partuuid and want.startswith(partuuid + "-"):
                    return _medium_from_block(row.get("TRAN", ""), row.get("NAME", ""))
            return "unknown"
        if root.startswith("/dev/"):
            name = root.rsplit("/", 1)[-1]
            for row in rows:
                if row.get("NAME") == name:
                    return _medium_from_block(row.get("TRAN", ""), row.get("NAME", ""))
            return _medium_from_block("", name)

    source = (root_source or "").split(" ")[0].strip()
    if source in ("rootfs", "tmpfs", "ramfs") or source.startswith("/dev/ram"):
        return "net"
    return "unknown"


def split_sections(text: str) -> dict[str, str]:
    """Split the probe script's ``@@name`` marked output into sections."""
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in (text or "").splitlines():
        if line.startswith("@@") and len(line) > 2:
            current = line[2:].strip()
            sections.setdefault(current, [])
        elif current is not None:
            sections[current].append(line)
    return {name: "\n".join(lines).strip() for name, lines in sections.items()}


_TFTP_SENT = re.compile(r"sent\s+(\S+)\s+to\s+(\S+)")


def tftp_fetches(log_text: str) -> dict[str, int]:
    """Count TFTP file deliveries per filename from dnsmasq-tftp log lines.

    Sample line:
        dnsmasq-tftp[1234]: sent /tmp/dnsmasq.cfg01411c.d/tftpboot/config.txt to 192.168.1.50

    This separates the two net-leg failures that look identical from the
    client side: a board that never asked for TFTP (power, cable, boot order,
    or a still-present boot medium) versus one that fetched the kernel and
    then died (bad kernel/dtb, or the TFTP tree is incomplete).
    """
    counts: dict[str, int] = {}
    for line in (log_text or "").splitlines():
        match = _TFTP_SENT.search(line)
        if not match:
            continue
        name = match.group(1).rsplit("/", 1)[-1]
        counts[name] = counts.get(name, 0) + 1
    return counts


def classify(tcp22: bool, tcp23: bool) -> str:
    """Classify a reachable address. Mirrors the netboot-rescue playbook table."""
    if tcp22:
        return "os"
    if tcp23:
        return "rescue-shell"
    return "silent"


DEFAULT_MODEL = Path(__file__).resolve().parent.parent / "models" / "raspberrypi-4b.json"
MAX_SWEEP_HOSTS = 4096

# Trailing state may carry flags ("router REACHABLE", "extern_learn"), so the
# tail is captured wholesale rather than as a single token.
_NEIGH = re.compile(r"^(\S+)\s+dev\s+(\S+)(?:\s+lladdr\s+(\S+))?(?:\s+(.*))?$")


def parse_ip_neigh(text: str) -> list[dict[str, str]]:
    """Parse ``ip neigh show`` into rows, dropping entries with no lladdr.

    An incomplete neighbour (no MAC) is an address we tried and failed to
    resolve — reporting it as a candidate would be a false positive.
    """
    rows = []
    for line in (text or "").splitlines():
        match = _NEIGH.match(line.strip())
        if not match:
            continue
        ip, dev, mac, state = match.groups()
        if not mac:
            continue
        rows.append({"ip": ip, "dev": dev, "mac": mac.lower(),
                     "state": (state or "").strip()})
    return rows


def pi_prefixes(model_path: Path = DEFAULT_MODEL) -> tuple[str, ...]:
    """Raspberry Pi MAC prefixes, read from the model (the SSOT)."""
    data = json.loads(Path(model_path).read_text())
    return tuple(prefix.lower() for prefix in data.get("mac_oui", []))


def is_pi_mac(mac: str, prefixes: tuple[str, ...]) -> bool:
    if not mac or not prefixes:
        return False
    return mac.lower().startswith(prefixes)


def sweep(cidr: str, timeout: float = 1.0, workers: int = 64) -> int:
    """ICMP-sweep a CIDR so the ARP table learns its live hosts. Returns count."""
    hosts = list(ipaddress.ip_network(cidr, strict=False).hosts())
    if len(hosts) > MAX_SWEEP_HOSTS:
        raise ValueError(f"{cidr} has {len(hosts)} hosts (limit {MAX_SWEEP_HOSTS}); "
                         f"narrow the range")

    def probe(host) -> bool:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(max(int(timeout), 1)), "-n", "-q", str(host)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        return result.returncode == 0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return sum(pool.map(probe, hosts))


def render_scan(hits: list[dict]) -> str:
    if not hits:
        return ("no Raspberry Pi MAC prefixes on this L2.\n"
                "If the board should be here: check its link LED, try "
                "--sweep <cidr>, and remember a bootloader in netboot fallback "
                "only emits DHCP DISCOVERs (scripts/pi_netboot.py detect --router IP).")
    lines = [f"{'ip':<16}{'mac':<20}{'dev':<10}{'state':<12}listeners"]
    for hit in hits:
        listeners = ",".join(
            name for name, up in (("22", hit.get("ssh")), ("23", hit.get("telnet"))) if up
        ) or "-"
        lines.append(f"{hit['ip']:<16}{hit['mac']:<20}{hit['dev']:<10}"
                     f"{hit['state']:<12}{listeners}")
    return "\n".join(lines)


def evaluate_leg(leg: str, medium: str | None = None,
                 ssh_up: bool = False, telnet_up: bool = False) -> tuple[str, str]:
    """Turn observed evidence into a PASS/FAIL verdict for one matrix leg."""
    spec = LEGS[leg]
    if spec["evidence"] == "ssh":
        if not ssh_up:
            return "FAIL", "no SSH listener — the board did not reach an OS"
        if medium == spec["expect_medium"]:
            return "PASS", f"boot medium = {medium}"
        return ("FAIL", f"booted, but medium = {medium} "
                        f"(expected {spec['expect_medium']})")
    if ssh_up:
        return ("FAIL", "SSH is up: the board booted an installed OS, not the "
                        "rescue shell — a boot medium is still attached")
    if telnet_up:
        return "PASS", "rescue shell reachable on tcp/23 (RAM boot over TFTP)"
    return "FAIL", "no telnet listener — no netboot fallback observed"


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def tcp_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_for(predicate, timeout: float, interval: float = 2.0) -> bool:
    """Poll ``predicate`` until true or the timeout expires."""
    deadline = time.monotonic() + max(timeout, 0)
    while True:
        if predicate():
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(interval)


def parse_probe_output(text: str, host: str = "") -> dict:
    """Parse a probe dump — live SSH output, or a saved one via --from-file.

    Keeping the parser separate from the transport makes a field report
    replayable: an operator can paste ``cat`` of a probe dump and get the same
    verdict, and the test-suite can pin real output shapes without hardware.
    """
    sections = split_sections(text)

    firmware_text = sections.get("fw", "")
    firmware = parse_fw_date(firmware_text)
    config = parse_bootloader_config(sections.get("conf", ""))
    order_text = config.get("BOOT_ORDER", "")
    modes, order_error = parse_boot_order(order_text) if order_text else ([], None)

    cmdline = sections.get("cmdline", "")
    rows = parse_lsblk(sections.get("lsblk", ""))
    medium = boot_medium(cmdline, rows, sections.get("mount", ""))

    return {
        "host": host,
        "model": sections.get("model", ""),
        "serial": sections.get("serial", ""),
        "os": sections.get("os", ""),
        "cmdline": cmdline,
        "root": _root_value(cmdline),
        "boot_medium": medium,
        "boot_order": order_text,
        "boot_order_modes": modes,
        "boot_order_error": order_error,
        "firmware_date": _fmt_date(firmware),
        "firmware_version": _first_version_line(firmware_text),
        "bootloader_config": config,
        "capabilities": capability_rows(firmware, modes,
                                        order_known=bool(order_text)),
    }


def probe_host(host: str, user: str = "root", key: str | None = None,
               timeout: int = 30, dump: str | Path | None = None) -> dict:
    """Read boot facts from a booted Pi over SSH.

    ``dump`` saves the raw output so the report is replayable elsewhere with
    ``probe --from-file`` — a field report becomes evidence, not a paraphrase.
    """
    result = run_ssh(host, PROBE_SCRIPT, user=user, key=key, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"ssh to {user}@{host} failed: "
                           f"{(result.stderr or result.stdout).strip()[:200]}")
    if dump:
        Path(dump).write_text(result.stdout)
    return parse_probe_output(result.stdout, host)


def _first_version_line(text: str) -> str:
    for line in (text or "").splitlines():
        if line.strip().lower().startswith("version"):
            return line.strip()
    return ""


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_probe(report: dict) -> str:
    medium = report["boot_medium"]
    order = report["boot_order"] or "unknown"
    modes = " -> ".join(report["boot_order_modes"])
    order_line = f"  boot order      {order}" + (f"   {modes}" if modes else "")
    firmware = report["firmware_date"] or "unknown"
    version = report["firmware_version"]
    firmware_line = f"  bootloader      {firmware}" + (f"   {version}" if version else "")
    lines = [
        f"{report['model'] or 'unknown model'}  ({report['host']})",
        f"  serial          {report['serial'] or 'unknown'}",
        f"  os              {report['os'] or 'unknown'}",
        f"  boot medium     {medium}   (root={report['root'] or 'n/a'})",
        order_line,
        firmware_line,
        "",
        f"  {'mode':<8}{'firmware':<10}{'ordered':<9}verdict",
    ]
    for row in report["capabilities"]:
        lines.append(f"  {row['mode']:<8}{row['supported']:<10}"
                     f"{ordered_cell(row):<9}"
                     f"{capability_notes(row)}")
    if report["boot_order_error"]:
        lines.append(f"\n  ! BOOT_ORDER could not be decoded: {report['boot_order_error']}")
    return "\n".join(lines)


def render_matrix(results: list[dict]) -> str:
    lines = [f"{'leg':<6}{'verdict':<9}detail"]
    for item in results:
        lines.append(f"{item['leg']:<6}{item['verdict']:<9}{item['detail']}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_probe(args: argparse.Namespace) -> int:
    from_file = getattr(args, "from_file", None)
    if from_file:
        report = parse_probe_output(Path(from_file).read_text(),
                                    args.host or "fixture")
    else:
        if not args.host:
            print("probe needs --host (or --from-file to replay a saved dump)",
                  file=sys.stderr)
            return 2
        try:
            report = probe_host(args.host, user=args.user, key=args.key,
                                timeout=args.timeout,
                                dump=getattr(args, "dump", None))
        except RuntimeError as exc:
            print(f"probe failed: {exc}", file=sys.stderr)
            return 1
    print(render_probe(report))
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2) + "\n")
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    tcp22 = tcp_open(args.host, 22, timeout=args.timeout)
    tcp23 = tcp_open(args.host, 23, timeout=args.timeout)
    kind = classify(tcp22, tcp23)
    print(f"{args.host}: {kind}", flush=True)
    if kind == "os":
        return cmd_probe(args)
    if kind == "rescue-shell":
        print("\nThe Pi is in the RAM netboot rescue shell (telnet root@<ip>, no "
              "password). Nothing persists across reboot: this is a boot, not an OS.")
        return 0
    print("\nNo listener. This is the netboot-fallback / dead-medium signature.\n"
          "Confirm from the DHCP side — a bootloader DISCOVERs but never REQUESTs:\n"
          "    scripts/pi_netboot.py detect --router <router-ip>\n"
          "If it is netboot-fallbacking, arm the rescue tree (pi_netboot.py arm)\n"
          "and power-cycle. If it produces no DHCP at all, check power/cable first.")
    return 1


def cmd_scan(args: argparse.Namespace) -> int:
    prefixes = pi_prefixes()
    if args.sweep:
        try:
            seen = sweep(args.sweep, timeout=args.timeout)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        print(f"swept {args.sweep}: {seen} host(s) answered\n", flush=True)

    neigh = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True,
                           check=False)
    if neigh.returncode != 0:
        print(f"ip neigh failed: {neigh.stderr.strip()}", file=sys.stderr)
        return 1
    rows = parse_ip_neigh(neigh.stdout)
    if not rows:
        # An empty table is not "no Pi on this L2" — it is "nothing has been
        # learned yet". Reporting the former would be a count-zero false
        # negative on a host that has not talked to anything since boot.
        print("the neighbour table is empty: no L2 address has been learned, "
              "so this scan proves nothing about the Pi." +
              ("" if args.sweep else " Run with --sweep <cidr> first."),
              file=sys.stderr)
        return 2
    hits = [row for row in rows if is_pi_mac(row["mac"], prefixes)]
    print(f"inspected {len(rows)} neighbour entr"
          f"{'y' if len(rows) == 1 else 'ies'}; {len(hits)} match a "
          f"Raspberry Pi OUI\n", flush=True)
    for hit in hits:
        hit["ssh"] = tcp_open(hit["ip"], 22, timeout=args.timeout)
        hit["telnet"] = tcp_open(hit["ip"], 23, timeout=args.timeout)

    print(render_scan(hits))
    if hits:
        first = hits[0]["ip"]
        print(f"\nnext: scripts/pi_boot.py detect --host {first}")
    if args.json:
        Path(args.json).write_text(json.dumps(hits, indent=2) + "\n")
    return 0 if hits else 1


def cmd_capability(args: argparse.Namespace) -> int:
    firmware = parse_fw_date(args.firmware) if args.firmware else None
    if args.firmware and firmware is None:
        print(f"could not parse firmware date: {args.firmware!r}", file=sys.stderr)
        return 2
    modes, error = parse_boot_order(args.boot_order) if args.boot_order else ([], None)
    if error:
        print(f"could not decode BOOT_ORDER: {error}", file=sys.stderr)
        return 2
    print(f"firmware {args.firmware or 'unknown'}   "
          f"BOOT_ORDER {args.boot_order or 'unknown'}"
          f"   {' -> '.join(modes) or ''}\n")
    print(f"{'mode':<8}{'firmware':<10}{'ordered':<9}verdict")
    for row in capability_rows(firmware, modes, order_known=bool(args.boot_order)):
        print(f"{row['mode']:<8}{row['supported']:<10}"
              f"{ordered_cell(row):<9}{capability_notes(row)}")
    return 0


def _run_power(args: argparse.Namespace) -> tuple[bool, str]:
    """Run the power hook; return (trusted, error).

    A power command that fails or hangs must not be swallowed: if the board
    never actually cycled, the leg's evidence describes an unknown power
    state, and a PASS would be a false green. The caller records ERROR and
    skips the wait instead.
    """
    if not args.power_cmd:
        print("  power-cycle the board now.")
        return True, ""
    print(f"  power: {args.power_cmd}")
    timeout = getattr(args, "power_timeout", 120)
    try:
        proc = subprocess.run(args.power_cmd, shell=True, capture_output=True,
                              text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f"power command timed out after {timeout}s"
    if proc.returncode != 0:
        output = (proc.stderr or proc.stdout).strip().splitlines()
        tail = output[-1][:120] if output else "no output"
        return False, f"power command exited {proc.returncode}: {tail}"
    return True, ""


def _wait_for_leg(args: argparse.Namespace, leg: str) -> tuple[bool, bool]:
    """Return (ssh_up, telnet_up) once the leg's evidence appears."""
    if legs_evidence(leg) == "ssh":
        ok = wait_for(lambda: tcp_open(args.host, 22, timeout=2.0),
                      args.boot_timeout)
        return ok, False

    # Net leg: tcp/23 is the pass signal, but SSH appearing means the board
    # booted an installed OS instead (a medium was left in). Fail fast with
    # that diagnosis rather than waiting out boot_timeout and reporting "no
    # netboot", which would point the operator at TFTP when the real cause is
    # a card still in the slot.
    seen = {"kind": None}

    def poll() -> bool:
        if tcp_open(args.host, 23, timeout=2.0):
            seen["kind"] = "telnet"
            return True
        if tcp_open(args.host, 22, timeout=2.0):
            seen["kind"] = "ssh"
            return True
        return False

    wait_for(poll, args.boot_timeout)
    return seen["kind"] == "ssh", seen["kind"] == "telnet"


def legs_evidence(leg: str) -> str:
    return LEGS[leg]["evidence"]


def _net_tftp_summary(router: str) -> str:
    """Best-effort: what the router's dnsmasq saw being fetched over TFTP."""
    result = run_ssh(router, "logread | grep -i dnsmasq-tftp | tail -200",
                     timeout=20)
    if result.returncode != 0:
        return f"router log unavailable ({result.stderr.strip()[:80]})"
    counts = tftp_fetches(result.stdout)
    if not counts:
        return ("no TFTP fetches in the router log — the board never asked "
                "(power, cable, boot order, or a medium is still present)")
    summary = ", ".join(f"{name} x{count}" for name, count in sorted(counts.items()))
    return f"router saw {summary}"


def cmd_matrix(args: argparse.Namespace) -> int:
    legs = [leg.strip() for leg in args.legs.split(",") if leg.strip()]
    unknown = [leg for leg in legs if leg not in LEGS]
    if unknown:
        print(f"unknown leg(s): {', '.join(unknown)} (choose from "
              f"{', '.join(LEGS)})", file=sys.stderr)
        return 2

    results: list[dict] = []
    for leg in legs:
        spec = LEGS[leg]
        print(f"\n=== leg: {leg} ===")
        print(f"  precondition: {spec['precondition']}")
        if not args.yes:
            try:
                input("  press Enter when the board is in that state (Ctrl-C to abort) ")
            except (EOFError, KeyboardInterrupt):
                print("\naborted")
                return 130
        power_ok, power_error = _run_power(args)
        if not power_ok:
            # Without a confirmed power cycle the evidence below describes an
            # unknown boot, so neither PASS nor FAIL is honest.
            print(f"  ERROR: {power_error}")
            results.append({
                "leg": leg,
                "verdict": "ERROR",
                "detail": power_error,
                "tftp": "",
                "probe": None,
            })
            continue

        ssh_up, telnet_up = _wait_for_leg(args, leg)
        probe = None
        medium = None
        if ssh_up:
            # sshd can be up before cloud-init has created the login user;
            # retry the probe rather than reporting a false medium.
            last_error = ""
            for _ in range(3):
                try:
                    probe = probe_host(args.host, user=args.user, key=args.key,
                                       timeout=args.timeout)
                    medium = probe["boot_medium"]
                    break
                except RuntimeError as exc:
                    last_error = str(exc)
                    time.sleep(5)
            if probe is None:
                ssh_up = False
                print(f"  ! ssh is open but the probe failed: {last_error}")

        verdict, detail = evaluate_leg(leg, medium=medium, ssh_up=ssh_up,
                                       telnet_up=telnet_up)
        tftp_note = ""
        if leg == "net" and args.router:
            tftp_note = _net_tftp_summary(args.router)
            if tftp_note:
                print(f"  tftp: {tftp_note}")
                detail = f"{detail} [{tftp_note}]"
        print(f"  {verdict}: {detail}")
        if probe and leg != "net":
            print("  " + render_probe(probe).replace("\n", "\n  "))
        results.append({
            "leg": leg,
            "verdict": verdict,
            "detail": detail,
            "tftp": tftp_note,
            "probe": probe,
        })

    print("\n" + render_matrix(results))
    if args.json:
        Path(args.json).write_text(json.dumps(
            {"host": args.host, "results": results}, indent=2) + "\n")
    failed = [r for r in results if r["verdict"] != "PASS"]
    return 0 if not failed else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add_target(sp: argparse.ArgumentParser, host_required: bool = True) -> None:
        sp.add_argument("--host", required=host_required,
                        help="address the Pi has (or should get) on this L2")
        sp.add_argument("--user", default="root",
                        help="ssh user (pi / ubuntu / root; default root)")
        sp.add_argument("--key", default=None, help="ssh identity file")
        sp.add_argument("--timeout", type=int, default=30,
                        help="per-ssh-command timeout (seconds)")
        sp.add_argument("--json", default=None, help="write the report as JSON")

    sp = sub.add_parser("scan", help="find Raspberry Pi MACs on this L2")
    sp.add_argument("--sweep", default=None,
                    help="CIDR to ICMP-sweep first so the ARP table is populated")
    sp.add_argument("--timeout", type=float, default=2.0,
                    help="per-probe timeout (seconds)")
    sp.add_argument("--json", default=None, help="write the hit list as JSON")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("probe", help="read boot facts from a booted Pi over SSH")
    add_target(sp, host_required=False)
    sp.add_argument("--from-file", default=None,
                    help="replay a saved probe dump instead of using SSH "
                         "(--host then only labels the report)")
    sp.add_argument("--dump", default=None,
                    help="save the raw probe output to this path for replay")
    sp.set_defaults(func=cmd_probe)

    sp = sub.add_parser("detect", help="classify an address: OS / rescue shell / silent")
    add_target(sp)
    sp.set_defaults(func=cmd_detect)

    sp = sub.add_parser("capability", help="offline firmware/BOOT_ORDER capability matrix")
    sp.add_argument("--firmware", default=None,
                    help="bootloader date from vcgencmd (2020-04-16 or 'Apr 16 2020')")
    sp.add_argument("--boot-order", default=None, help="BOOT_ORDER, e.g. 0xf41")
    sp.set_defaults(func=cmd_capability)

    sp = sub.add_parser("matrix", help="walk SD -> USB -> network, verdict per leg")
    add_target(sp)
    sp.add_argument("--legs", default="sd,usb,net",
                    help="comma-separated legs to test (default sd,usb,net)")
    sp.add_argument("--power-cmd", default=None,
                    help="shell command that power-cycles the board")
    sp.add_argument("--power-timeout", type=int, default=120,
                    help="seconds to allow the power command (default 120)")
    sp.add_argument("--router", default=None,
                    help="OpenWrt router running dnsmasq (root SSH); adds the "
                         "TFTP-side view to the net leg")
    sp.add_argument("--boot-timeout", type=int, default=180,
                    help="seconds to wait for evidence after power-up")
    sp.add_argument("--yes", action="store_true",
                    help="skip the per-leg Enter prompt (unattended runs)")
    sp.set_defaults(func=cmd_matrix)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
