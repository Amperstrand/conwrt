#!/usr/bin/env python3
"""bench_run — run a labgrid pytest with a full evidence bundle.

Implements the aparcar/openwrt-tests CI pattern as a wrapper so every bench
test run keeps its own evidence (LAVA/KernelCI job-scoped correlation):

    runs/<ts>-<name>/
      manifest.json     run_id, device, boot_id, argv, rc, timestamps
      pytest.log        full console output (tee)
      report.xml        --junitxml (labgrid adds env/target metadata)
      console_*         --lg-log console captures (per target/driver)

Injected pytest flags (overridable by passing your own): --lg-log <dir>,
--junitxml <dir>/report.xml, --log-cli-level=CONSOLE.

Usage:
  python3 scripts/bench_run.py --name serial-smoke -- pytest labgrid/test_bench_serial.py
  make labgrid-test T=labgrid/test_bench_power.py

boot_id in the manifest requires --device-host (read-only ssh probe);
omit it for VM/hardware-free runs.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNS_DIR = REPO_ROOT / "runs"
SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
            "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]


def probe_boot_id(host: str) -> str:
    try:
        proc = subprocess.run(["ssh", *SSH_OPTS, f"root@{host}",
                               "cat /proc/sys/kernel/random/boot_id"],
                              capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""


def build_argv(pytest_args: list[str], out_dir: Path) -> list[str]:
    argv = [sys.executable, "-m", "pytest", *pytest_args]
    def has(flag_prefix: str) -> bool:
        return any(a.startswith(flag_prefix) for a in pytest_args)
    if not has("--lg-log"):
        argv += ["--lg-log", str(out_dir)]
    if not has("--junitxml"):
        argv += ["--junitxml", str(out_dir / "report.xml")]
    if not has("--log-cli-level"):
        argv += ["--log-cli-level=CONSOLE"]
    return argv


def run(name: str, pytest_args: list[str], device_host: str,
        runs_dir: Path = RUNS_DIR,
        boot_prober: Callable[[str], str] = probe_boot_id,
        spawn=None) -> dict:
    run_id = f"{time.strftime('%Y%m%d-%H%M%S')}-{name}"
    out_dir = runs_dir / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    argv = build_argv(pytest_args, out_dir)
    started = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    if spawn is None:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
        assert proc.stdout is not None
        with (out_dir / "pytest.log").open("w") as log:
            for line in proc.stdout:
                sys.stdout.write(line)
                log.write(line)
        rc = proc.wait()
    else:
        rc = spawn(argv, out_dir)
    manifest = {
        "run_id": run_id,
        "started": started,
        "finished": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "rc": rc,
        "argv": pytest_args,
        "device": device_host or "",
        "boot_id": boot_prober(device_host) if device_host else "",
    }
    manifest["evidence"] = sorted(
        p.name for p in out_dir.iterdir()) + ["manifest.json"]
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--name", required=True, help="short run name (run_id suffix)")
    ap.add_argument("--device-host", default="",
                    help="DUT host for boot_id correlation (optional)")
    ap.add_argument("pytest_args", nargs=argparse.REMAINDER,
                    help="pytest args (put -- before them)")
    args = ap.parse_args(argv)
    pytest_args = [a for a in args.pytest_args if a != "--"]
    if not pytest_args:
        print("FAIL: no pytest args (usage: bench_run.py --name X -- pytest ...)")
        return 2
    manifest = run(args.name, pytest_args, args.device_host)
    print(f"\n[bench_run] rc={manifest['rc']} evidence -> {RUNS_DIR / manifest['run_id']}")
    return int(manifest["rc"])


if __name__ == "__main__":
    sys.exit(main())
