#!/usr/bin/env python3
"""sdk_rust_version — audit conwrt's pinned OpenWrt rust toolchain against the live feed.

The OpenWrt SDK does not pin a rust version itself: the packages feed branch
does (openwrt/packages "openwrt-<series>", lang/rust Makefile PKG_VERSION).
This is the tollgate-module-basic-go scripts/sdk-go-version.sh pattern
ported for rust, minus one leg: OpenWrt publishes the golang host toolchain
into released feeds but ships no rust toolchain there (released feeds carry
only rust-BUILT applications), so feed BRANCHES are the only authority for
rust — there is no released-feed cross-check to run.

Why conwrt needs this: the mipsel zycast cross lane (#109) builds inside a
pinned openwrt/sdk image with the feed's own rustc, because upstream rust
demoted mipsel-unknown-linux-musl std to tier 3 after 1.85 — no rustup
channel ships it. The pins in scripts/openwrt-toolchain.json
(rust_per_release) document which rustc each OpenWrt line builds with, and
this guard fails when the feed moves and the manifest has not been updated.
A pin that silently rots is how rust-toolchain.toml ended up claiming the
OpenWrt lane would be "1.94.x" (the 24.10 line, and 1.94.0 exactly) while
the NR7101's line (25.12) was already on 1.96.0.

Modes:
  check          (default) verify every rust_per_release pin against its
                 live feed branch; exit 1 on drift
  update         rewrite drifted pins from the live branches (manual tool)
  print <series> print the live feed rust of a release line (e.g. 25.12)
  --self-test    prove the detector on seeded-drift fixture copies of the
                 manifest (no network); run alone or after check

Wired in as `make openwrt-toolchain-check` and as a step in the `rust` job
of .github/workflows/rust.yml.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "scripts" / "openwrt-toolchain.json"

FEED_URL = "https://raw.githubusercontent.com/openwrt/packages/openwrt-{series}/lang/rust/Makefile"
PKG_VERSION_RE = re.compile(r"^PKG_VERSION:=(\S+)$", re.MULTILINE)
SEMVER_RE = re.compile(r"\d+\.\d+\.\d+")
FETCH_TIMEOUT_S = 20.0

#: Injected feed reader: series -> live rust version, or None when the
#: branch is unreachable / lang/rust unreadable (check reports that as drift).
Fetch = Callable[[str], "str | None"]


class AuditError(Exception):
    """Raised when the manifest cannot be read or is structurally broken."""


def fetch_feed_rust(series: str) -> str | None:
    """Live lang/rust PKG_VERSION of an openwrt/packages release line.

    Returns None on ANY failure (network, missing branch, missing file,
    unparseable version) so `check` reports it as drift instead of passing.
    """
    url = FEED_URL.format(series=series)
    try:
        with urllib.request.urlopen(url, timeout=FETCH_TIMEOUT_S) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError):
        return None
    match = PKG_VERSION_RE.search(body)
    if match is None:
        return None
    version = match.group(1)
    if SEMVER_RE.fullmatch(version) is None:
        return None
    return version


def load_manifest(path: Path) -> dict[str, Any]:
    """Load and structurally validate the pin manifest."""
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except OSError as err:
        raise AuditError(f"cannot read {path}: {err}") from err
    except json.JSONDecodeError as err:
        raise AuditError(f"{path} is not valid JSON: {err}") from err
    sdk = manifest.get("openwrt_sdk")
    if not isinstance(sdk, dict) or not isinstance(sdk.get("rust_per_release"), dict):
        raise AuditError(f"{path}: missing .openwrt_sdk.rust_per_release")
    if not isinstance(sdk.get("releases"), dict):
        raise AuditError(f"{path}: missing .openwrt_sdk.releases")
    return manifest


def series_pins(manifest: dict[str, Any]) -> dict[str, str]:
    """rust_per_release entries, comment keys ('_*') skipped."""
    raw = manifest["openwrt_sdk"]["rust_per_release"]
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def era_series_list(manifest: dict[str, Any]) -> list[str]:
    """Series of every pinned SDK era — each MUST have a rust pin."""
    releases = manifest["openwrt_sdk"]["releases"]
    return [era["series"] for era in releases.values() if isinstance(era, dict) and "series" in era]


def check_failures(manifest: dict[str, Any], fetch: Fetch) -> list[str]:
    """Human-readable failure lines; empty when every pin matches the live feed."""
    pins = series_pins(manifest)
    failures: list[str] = []
    for series, pinned in pins.items():
        live = fetch(series)
        if live is None:
            failures.append(
                f"rust pin {series}={pinned}: feed branch openwrt-{series} unreachable "
                "or lang/rust unreadable (no negative without a reachable feed)"
            )
        elif live != pinned:
            failures.append(f"DRIFT rust pin {series}: manifest={pinned} live={live}")
    for series in era_series_list(manifest):
        if series not in pins:
            failures.append(
                f"rust_per_release has no entry for '{series}' (series of a pinned SDK era) "
                f"— eras: {', '.join(era_series_list(manifest))}"
            )
    return failures


def run_check(manifest_path: Path, fetch: Fetch) -> int:
    try:
        manifest = load_manifest(manifest_path)
    except AuditError as err:
        print(f"FAIL: {err}", file=sys.stderr)
        return 1
    failures = check_failures(manifest, fetch)
    if failures:
        for line in failures:
            print(f"FAIL: {line}", file=sys.stderr)
        print(f"{len(failures)} rust pin(s) drifted from the live feed. Run: python3 scripts/sdk_rust_version.py update", file=sys.stderr)
        return 1
    pins = series_pins(manifest)
    summary = ", ".join(f"{s}={v}" for s, v in sorted(pins.items()))
    print(f"OpenWrt rust pins match the live packages feed: {summary}")
    return 0


def run_update(manifest_path: Path, fetch: Fetch) -> int:
    """Rewrite drifted pins from the live branches (order and comments preserved)."""
    try:
        manifest = load_manifest(manifest_path)
    except AuditError as err:
        print(f"FAIL: {err}", file=sys.stderr)
        return 1
    changed = 0
    for series, pinned in series_pins(manifest).items():
        live = fetch(series)
        if live is None:
            print(f"NOTE {series}: branch unreachable — pin {pinned} left untouched", file=sys.stderr)
        elif live != pinned:
            manifest["openwrt_sdk"]["rust_per_release"][series] = live
            print(f"UPDATED rust_per_release {series} -> {live} (was {pinned})")
            changed += 1
    if changed:
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return run_check(manifest_path, fetch)


def run_print(series: str, fetch: Fetch) -> int:
    live = fetch(series)
    if live is None:
        print(f"cannot resolve the official rust for openwrt/{series} (branch or lang/rust not found)", file=sys.stderr)
        return 1
    print(live)
    return 0


def run_self_test(manifest_path: Path) -> int:
    """Prove the detector on seeded-drift fixture copies (stubbed feed, no network)."""
    known: dict[str, str] = {"25.12": "1.96.0", "24.10": "1.94.0"}

    def stub(series: str) -> str | None:
        return known.get(series)

    def stub_dead(series: str) -> str | None:
        return None

    steps: list[tuple[str, bool, bool]] = []
    with tempfile.TemporaryDirectory(prefix="sdk-rust-version-") as tmp:
        tmpdir = Path(tmp)

        def variant(name: str, mutate: Callable[[dict[str, Any]], None]) -> Path:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            mutate(data)
            path = tmpdir / name
            path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            return path

        # Step 0 — positive control: the real manifest against the stubbed
        # feed must PASS (proves the fixture, not just the failures).
        try:
            control = load_manifest(manifest_path)
            got = bool(check_failures(control, stub))
        except AuditError:
            got = True
        steps.append(("control: real manifest passes against stubbed feed", False, got))

        # Step 1 — a bumped pin (the stale-comment failure mode) is detected.
        bumped = variant("bumped.json", lambda d: d["openwrt_sdk"]["rust_per_release"].__setitem__("25.12", "9.9.9"))
        steps.append(
            ("pin bumped to 9.9.9 is detected", True, bool(check_failures(load_manifest(bumped), stub)))
        )

        # Step 2 — unreachable branch is drift, never a silent pass.
        steps.append(
            ("unreachable feed branch is detected", True, bool(check_failures(load_manifest(manifest_path), stub_dead)))
        )

        # Step 3 — an SDK era whose series has no rust pin is detected.
        missing = variant(
            "missing-era.json", lambda d: d["openwrt_sdk"]["rust_per_release"].pop("24.10")
        )
        steps.append(
            ("era series missing from rust_per_release is detected", True, bool(check_failures(load_manifest(missing), stub)))
        )

        # Step 4 — update() repairs a drifted manifest back to the live value.
        repaired = variant("repair.json", lambda d: d["openwrt_sdk"]["rust_per_release"].__setitem__("24.10", "0.0.1"))
        run_update(repaired, stub)
        after = json.loads(repaired.read_text(encoding="utf-8"))["openwrt_sdk"]["rust_per_release"]["24.10"]
        steps.append((f"update() repairs a drifted pin (got {after})", True, after != "0.0.1" and after == known["24.10"]))

    ok = True
    for i, (name, want_fail, got_fail) in enumerate(steps):
        if want_fail != got_fail:
            ok = False
            verdict = "drift NOT detected" if want_fail else "clean state reported drift"
            print(f"self-test step {i} FAILED: {name} ({verdict})", file=sys.stderr)
        else:
            print(f"self-test step {i} ok: {name}")
    if not ok:
        return 1
    print("self-test PASS: every seeded divergence was detected")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", type=Path, default=MANIFEST,
                        help="pin manifest to audit (default: scripts/openwrt-toolchain.json)")
    parser.add_argument("--self-test", action="store_true",
                        help="prove the detector on seeded-drift fixture copies (no network)")
    sub = parser.add_subparsers(dest="mode")
    sub.add_parser("check", help="verify pins against the live feed (default)")
    sub.add_parser("update", help="rewrite drifted pins from the live branches")
    p_print = sub.add_parser("print", help="print the live feed rust of a release line")
    p_print.add_argument("series", help="release line, e.g. 25.12")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test(args.manifest)
    if args.mode == "update":
        return run_update(args.manifest, fetch_feed_rust)
    if args.mode == "print":
        return run_print(args.series, fetch_feed_rust)
    return run_check(args.manifest, fetch_feed_rust)


if __name__ == "__main__":
    sys.exit(main())
