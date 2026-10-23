"""#487 pins: the bench tier is opt-in and its ASU profile comes from the model.

- The suite must SKIP when CONWRT_BENCH_ROUTER is unset — before any
  reachability probe. The old default ("192.168.1.1") defeated the
  documented "unset skips" contract: on a bench host with a live router
  at that address, a bare ``pytest tests/`` ran hardware benchmarks and
  live ASU builds, producing the 16-test standing red.
- The ASU profile is resolved from the bench model's ``openwrt.profile``
  (dash form, e.g. ``dlink_covr-x1860-a1``). The hardcoded
  all-underscore spelling was rejected by live ASU with HTTP 400
  ("Unsupported profile") once upstream dropped those names.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location(
    "bench_conftest", Path(__file__).parent / "bench" / "conftest.py")
bench_conftest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bench_conftest)

BENCH_MODEL_ID = bench_conftest.BENCH_MODEL_ID
_bench_asu_profile = bench_conftest._bench_asu_profile


def test_asu_profile_resolves_from_the_model():
    # The species-level source of truth (models/*.json), not a hardcode:
    # underscore/hyphen spelling is exactly where the old hardcode went
    # wrong (all-underscore → ASU HTTP 400).
    assert BENCH_MODEL_ID == "dlink-covr-x1860-a1"
    assert _bench_asu_profile() == "dlink_covr-x1860-a1"


def test_bench_tier_skips_without_router_env(tmp_path):
    # Subprocess so the module-level env read is exercised for real. The
    # host HAS a router at the old default address — if the gate
    # regresses, this run attempts real hardware + live ASU and fails
    # loudly instead of skipping.
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("CONWRT_BENCH") and k != "CONWRT_VENUES"}
    env["PATH"] = os.environ.get("PATH", "/usr/bin:/bin")
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/bench", "-m", "bench", "-q",
         "--basetemp", str(tmp_path / "b")],
        cwd=str(REPO), capture_output=True, text=True, env=env, timeout=300,
    )
    tail = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
    assert "skipped" in tail, f"expected skips, got: {tail} (stderr: {r.stderr[-300:]})"
    assert "failed" not in tail and "passed" not in tail.replace("skipped", "")
