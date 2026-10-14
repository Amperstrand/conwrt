#!/usr/bin/env python3
"""Weekly VPN provider drift watch — early warning, not a dependency.

Two signals, one report:

1. Runs the live API contract tests (``tests/live``, marker ``live``) —
   public endpoints only in CI; credential-gated tests skip. A failure
   means a provider API conwrt parses has drifted.
2. Scans gluetun (qdm12/gluetun) releases — the best-maintained tracker of
   provider-side changes — for lines mentioning conwrt's providers. Any
   such line with a change verb escalates. gluetun is referenced for
   research only (AGENTS.md external-repo etiquette); it is NOT a
   dependency.

Exit code 1 = live contract failure OR provider-relevant gluetun change —
the scheduled workflow turns that into a maintainer notification.

Usage:
  python3 scripts/vpn-drift-watch.py [--skip-tests] [--days N]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

PROVIDER_ALIASES: dict[str, list[str]] = {
    "nordvpn": ["nordvpn"],
    "pia": ["pia", "private internet access"],
    "mullvad": ["mullvad"],
    "ivpn": ["ivpn"],
    "surfshark": ["surfshark"],
}

CHANGE_VERBS = (
    "update", "updated", "changed", "fixed", "fix", "removed", "remove",
    "renamed", "broken", "broke", "dead", "404", "no longer", "deprecated",
    "migrat", "endpoint", "api",
)

GLUETUN_RELEASES_URL = (
    "https://api.github.com/repos/qdm12/gluetun/releases?per_page=10"
)


def _matching_provider(line: str) -> str | None:
    lowered = line.lower()
    for provider, aliases in PROVIDER_ALIASES.items():
        if any(alias in lowered for alias in aliases):
            return provider
    return None


def provider_lines(body: str) -> list[tuple[str, str]]:
    """(provider, line) for lines mentioning a provider — with section context.

    gluetun release notes group changes under provider headers
    (``- NordVPN:``) with the actual change lines indented beneath and not
    repeating the provider name; those inherit the header's attribution
    until the next header.
    """
    hits: list[tuple[str, str]] = []
    current: str | None = None
    for line in body.splitlines():
        stripped = line.strip()
        provider = _matching_provider(stripped)
        if provider is not None:
            hits.append((provider, stripped))
            if stripped.endswith(":"):
                current = provider
                continue
            current = None if not stripped.endswith(":") else provider
            continue
        if current is not None and line.startswith((" ", "\t")) and stripped:
            hits.append((current, stripped))
        elif stripped and not line.startswith((" ", "\t")):
            current = None
    return hits


def escalates(line: str) -> bool:
    lowered = line.lower()
    return any(verb in lowered for verb in CHANGE_VERBS)


def fetch_gluetun_releases(since: datetime) -> list[dict]:
    req = urllib.request.Request(
        GLUETUN_RELEASES_URL,
        headers={"User-Agent": "conwrt-drift-watch", "Accept": "application/vnd.github+json"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        releases = json.loads(resp.read().decode())
    recent = []
    for release in releases:
        published = release.get("published_at") or ""
        if not published:
            continue
        try:
            ts = datetime.fromisoformat(published.replace("Z", "+00:00"))
        except ValueError:
            continue
        if ts >= since:
            recent.append(release)
    return recent


def run_live_tests() -> int:
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/live", "-m", "live", "-q"],
        cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=600,
    )
    tail = (r.stdout or r.stderr).strip().splitlines()
    for line in tail[-15:]:
        print(f"  {line}")
    return r.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-tests", action="store_true",
                        help="only scan gluetun releases")
    parser.add_argument("--days", type=int, default=10,
                        help="gluetun release lookback window (default 10)")
    args = parser.parse_args()

    live_rc = 0
    if not args.skip_tests:
        print("== Live API contract tests ==")
        live_rc = run_live_tests()

    print(f"\n== gluetun releases (last {args.days} days) ==")
    since = datetime.now(timezone.utc) - timedelta(days=args.days)
    try:
        releases = fetch_gluetun_releases(since)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"  gluetun scan failed (not fatal): {exc}")
        releases = []
    if not releases:
        print("  no releases in window")

    escalated = False
    for release in releases:
        hits = provider_lines(release.get("body") or "")
        if not hits:
            continue
        print(f"  {release['tag_name']} ({release.get('published_at', '?')}):")
        for provider, line in hits:
            hot = escalates(line)
            escalated = escalated or hot
            print(f"    [{'!' if hot else ' '}] {provider}: {line}")

    if live_rc != 0:
        print("\nRESULT: FAIL — live API contract tests failed (provider drift?)")
        return 1
    if escalated:
        print("\nRESULT: FAIL — provider-relevant changes upstream in gluetun; "
              "run `make test-live` locally and check the provider")
        return 1
    print("\nRESULT: OK — no drift signals")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
