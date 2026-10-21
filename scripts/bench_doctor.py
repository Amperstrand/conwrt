#!/usr/bin/env python3
"""bench_doctor — level-by-level health check of the OPTIONAL labgrid bench stack.

Read-only: TCP connects plus one console newline; NEVER a power action, NEVER
a DUT write, NEVER a password/note from places.json in the output. Each level
reports PASS | DEGRADED | ABSENT — ABSENT is healthy for standalone conwrt
(labgrid is optional everywhere). Exit 0 when healthy or unconfigured, 1 on
any DEGRADED level. `crosscheck` mode is the offline `make labgrid-check`
engine (no network, no coordinator).

  L1 coordinator   reachable when configured (--coordinator > [labgrid]
                   coordinator in config.toml > LG_COORDINATOR; else ABSENT)
  L2 exporter       exporter.yaml stanzas vs places.json, OFFLINE, via the
                   bench_consistency engine
  L3 bridges        each exported NetworkSerialPort answers connect+newline+
                   bytes <=10s; loopback-bound endpoints are probed over ssh
                   on the exporter host ([labgrid] exporter_host / --probe-host)
  L4 registry       places.json parses; every place carries mac/dut_ip/
                   reset_allowed; reset_allowed=false places are PROTECTED
                   (never power-probed by anything here)
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))
from bench_consistency import (SERIAL_RESOURCE, DoctorError, ExporterParseError,
                               Stanzas, crosscheck, load_places, parse_exporter)
from config import load_config  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
PLACES_JSON = REPO_ROOT / "data" / "bench" / "places.json"
EXPORTER_YAML = REPO_ROOT / "labgrid" / "exporter.yaml"

PASS, DEGRADED, ABSENT = "PASS", "DEGRADED", "ABSENT"
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null"]


@dataclass(frozen=True)
class CheckResult:
    status: str
    lines: tuple[str, ...] = ()


@dataclass(frozen=True)
class Options:
    mode: str = "doctor"
    places: Path = PLACES_JSON
    exporter: Path = EXPORTER_YAML
    coordinator: str | None = None
    probe_host: str | None = None
    timeout_s: int = 10
    save: Path | None = None


# ------------------------------------------------- probes (read-only)

def tcp_console_probe(host: str, port: int, timeout_s: int) -> tuple[bool, str]:
    """Connect + newline + expect bytes. Never writes anything but the newline."""
    try:
        sock = socket.create_connection((host, port), timeout=timeout_s)
    except OSError as e:
        return False, f"connect failed: {e}"
    try:
        sock.settimeout(timeout_s)
        sock.sendall(b"\n")
        try:
            data = sock.recv(256)
        except socket.timeout:
            return False, f"connected but silent (no bytes within {timeout_s}s)"
        if not data:
            return False, "connected but EOF after newline (bridge closed)"
        return True, f"answered with {len(data)} byte(s)"
    finally:
        sock.close()


_REMOTE_PROBE = (
    "import socket, sys\n"
    "s = socket.create_connection((sys.argv[1], int(sys.argv[2])), 5)\n"
    "s.settimeout(float(sys.argv[3])); s.sendall(b'\\n'); d = s.recv(256)\n"
    "print('BRIDGE-OK' if d else 'BRIDGE-EMPTY')\n"
)


def ssh_console_probe(ssh_host: str, host: str, port: int, timeout_s: int) -> tuple[bool, str]:
    """Probe a loopback-bound bridge from the exporter host (python3 via ssh
    stdin — quoting-proof; the remote needs no labgrid)."""
    cmd = f"python3 - {host} {port} {timeout_s}"
    try:
        proc = subprocess.run(["ssh", *SSH_OPTS, ssh_host, cmd], input=_REMOTE_PROBE,
                              capture_output=True, text=True, timeout=timeout_s + 20)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"ssh probe via {ssh_host} failed: {e}"
    out = (proc.stdout or "").strip()
    if proc.returncode == 0 and "BRIDGE-OK" in out:
        return True, f"answered (probe via {ssh_host})"
    if "BRIDGE-EMPTY" in out:
        return False, f"connected but silent (probe via {ssh_host})"
    return False, f"probe failed ({proc.returncode}): {(proc.stderr or out)[-160:]}".strip()


# ------------------------------------------------- levels

def level_coordinator(coordinator: str, timeout_s: int) -> CheckResult:
    if not coordinator:
        return CheckResult(ABSENT, ("no coordinator configured — standalone conwrt, this is healthy",))
    host, _, port = coordinator.partition(":")
    try:
        socket.create_connection((host, int(port or 20408)), timeout=timeout_s).close()
    except (OSError, ValueError) as e:
        return CheckResult(DEGRADED, (f"{coordinator} configured but unreachable: {e}",))
    return CheckResult(PASS, (f"{coordinator} reachable",))


def level_exporter(stanzas: Stanzas | None, parse_error: str | None,
                   registry: dict | None) -> CheckResult:
    if stanzas is None and parse_error is None:
        return CheckResult(ABSENT, ("labgrid/exporter.yaml not present (standalone checkout)",))
    if parse_error:
        return CheckResult(DEGRADED, (parse_error,))
    clean, lines = crosscheck(registry, stanzas)
    return CheckResult(PASS if clean else DEGRADED, tuple(lines))


def level_bridges(stanzas: Stanzas | None, probe_host: str, timeout_s: int) -> CheckResult:
    if not stanzas:
        return CheckResult(ABSENT, ("no serial bridges exported (exporter.yaml absent/unparsable, or no NetworkSerialPort stanzas)",))
    lines, worst, probed = [], PASS, False
    for place in sorted(stanzas):
        if SERIAL_RESOURCE not in stanzas[place]:
            continue
        params = stanzas[place][SERIAL_RESOURCE]
        host = params.get("host", "")
        try:
            port = int(params.get("port", ""))
        except ValueError:
            port = -1
        endpoint = f"{place} {host}:{params.get('port', '')}"
        probed = True
        if port <= 0:
            lines.append(f"DEGRADED {endpoint}: bad/missing port in stanza")
            worst = DEGRADED
            continue
        if host in LOOPBACK_HOSTS and not probe_host:
            lines.append(f"DEGRADED {endpoint}: loopback-bound on the exporter host — "
                         "set [labgrid] exporter_host (or --probe-host) to probe it")
            worst = DEGRADED
            continue
        probe = (ssh_console_probe(probe_host, host, port, timeout_s)
                 if host in LOOPBACK_HOSTS else tcp_console_probe(host, port, timeout_s))
        ok, detail = probe
        lines.append(f"{'PASS' if ok else 'DEGRADED'} {endpoint}: {detail}")
        worst = DEGRADED if not ok else worst
    if not probed:
        return CheckResult(ABSENT, ("no serial bridges exported (no NetworkSerialPort stanzas)",))
    return CheckResult(worst, tuple(lines))


def level_registry(registry: dict | None, parse_error: str | None) -> CheckResult:
    if parse_error:
        return CheckResult(DEGRADED, (parse_error,))
    if registry is None:
        return CheckResult(ABSENT, ("data/bench/places.json not present (standalone checkout)",))
    lines, problems, protected = [], [], []
    for entry in registry["places"]:
        if not isinstance(entry, dict) or not entry.get("name"):
            problems.append("entry without a name")
            continue
        name = entry["name"]
        for field in ("mac", "dut_ip", "reset_allowed"):
            if field not in entry:
                problems.append(f"{name}: missing field {field!r}")
        if entry.get("reset_allowed") is not True:
            protected.append(name)
    if protected:
        lines.append("protected places (reset_allowed!=true — never power-probed): " + ", ".join(protected))
    lines.append(f"{len(registry['places'])} place(s) registered")
    if problems:
        return CheckResult(DEGRADED, (*problems, *lines))
    return CheckResult(PASS, tuple(lines))


# ------------------------------------------------- run / CLI

def _resolve(coordinator: str | None, probe_host: str | None) -> tuple[str, str]:
    lg = load_config().labgrid
    coord = coordinator or (lg.coordinator if lg else "") or os.environ.get("LG_COORDINATOR", "")
    host = probe_host or (lg.exporter_host if lg else "") or os.environ.get("LG_EXPORTER_HOST", "")
    return coord, host


def _read_stanzas(path: Path) -> tuple[Stanzas | None, str | None]:
    if not path.is_file():
        return None, None
    try:
        return parse_exporter(path.read_text(encoding="utf-8")), None
    except (OSError, ExporterParseError) as e:
        return None, str(e)


def run_doctor(opts: Options) -> int:
    try:
        registry: dict | None = load_places(opts.places)
        registry_error = None
    except DoctorError as e:
        registry, registry_error = None, str(e)
    stanzas, exporter_error = _read_stanzas(opts.exporter)

    if opts.mode == "crosscheck":
        if fatal := registry_error or exporter_error:
            clean, lines = False, [f"FAIL unparsable input: {fatal}"]
        else:
            clean, lines = crosscheck(registry, stanzas)
        _emit(["labgrid offline cross-check (no network, no coordinator)",
               f"exporter: {opts.exporter}", f"registry: {opts.places}", *lines,
               "result: " + ("DRIFT" if not clean else "OK")], opts.save)
        return 0 if clean else 1

    coordinator, probe_host = _resolve(opts.coordinator, opts.probe_host)
    results = [
        ("L1 coordinator", level_coordinator(coordinator, opts.timeout_s)),
        ("L2 exporter", level_exporter(stanzas, exporter_error, registry)),
        ("L3 bridges", level_bridges(stanzas, probe_host, opts.timeout_s)),
        ("L4 registry", level_registry(registry, registry_error)),
    ]
    report = []
    for level, res in results:
        report.append(f"{level}: {res.status}" + (f" — {res.lines[0]}" if res.lines else ""))
        report.extend(f"  {line}" for line in res.lines[1:])
    statuses = [res.status for _, res in results]
    if DEGRADED in statuses:
        summary, code = "bench stack: DEGRADED — see level lines above", 1
    elif all(s == ABSENT for s in statuses):
        summary, code = "bench stack: UNCONFIGURED — standalone conwrt (healthy)", 0
    else:
        summary, code = "bench stack: HEALTHY", 0
    report.append(summary)
    _emit(report, opts.save)
    return code


def _emit(report: list[str], save: Path | None) -> None:
    print("\n".join(report))
    if save:
        save.parent.mkdir(parents=True, exist_ok=True)
        save.write_text("\n".join(report) + "\n", encoding="utf-8")
        print(f"\nreport saved: {save}")


def add_doctor_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("mode", nargs="?", choices=("doctor", "crosscheck"), default="doctor",
                        help="doctor: all levels incl. read-only network probes; "
                             "crosscheck: offline exporter-vs-places only")
    parser.add_argument("--places", default=str(PLACES_JSON),
                        help=f"places.json path (default: {PLACES_JSON})")
    parser.add_argument("--exporter", default=str(EXPORTER_YAML),
                        help=f"exporter.yaml path (default: {EXPORTER_YAML})")
    parser.add_argument("--coordinator", default=None,
                        help="coordinator host:port (default: [labgrid] coordinator > LG_COORDINATOR)")
    parser.add_argument("--probe-host", default=None,
                        help="ssh host able to reach loopback-bound bridges "
                             "(default: [labgrid] exporter_host > LG_EXPORTER_HOST)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="per-probe seconds (default: 10)")
    parser.add_argument("--save", default=None,
                        help="also write the report to this file")


def _options_from_args(args: argparse.Namespace) -> Options:
    return Options(mode=args.mode, places=Path(args.places), exporter=Path(args.exporter),
                   coordinator=args.coordinator, probe_host=args.probe_host,
                   timeout_s=args.timeout, save=Path(args.save) if args.save else None)


def cmd_bench_doctor(args: argparse.Namespace) -> int:
    return run_doctor(_options_from_args(args))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bench_doctor.py",
                                     description="Validate the optional labgrid bench stack (read-only)")
    add_doctor_arguments(parser)
    return run_doctor(_options_from_args(parser.parse_args(argv)))


if __name__ == "__main__":
    sys.exit(main())
