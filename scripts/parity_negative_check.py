#!/usr/bin/env python3
"""parity_negative_check — the Rust half of schema-negative attribution.

`make parity-check` runs every tests/fixtures/schema-negative/ fixture
through BOTH validators. Until #489 the loop only checked that Rust
EXITS nonzero — a fixture rejected for the wrong reason (e.g. missing a
required section while the intended defect went unnoticed) passed the
gate. That is not hypothetical: the default-ip-empty fixture shipped
exactly that way and a Codex review caught it, not the gate.

Each fixture records its intended violating FIELD in
tests/fixtures/schema-negative/manifest.json (`expect` — the leaf field
name, e.g. "default_ip"; it appears in the Rust problem text
"openwrt.default_ip: must not be empty", and in the jsonschema error
path or message — see the Python half for the path-vs-message nuance).
This script runs the Rust validator over every fixture and asserts the
exit is nonzero AND the intended problem is the one being reported. The Python half (schema rejects, same attribution) lives in
tests/test_model_schema_parity.py.

Dependency-free (Makefile context). Wired via `make parity-check`.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
NEGATIVES = REPO / "tests" / "fixtures" / "schema-negative"


def problem_text_only(output: str) -> str:
    """The validator's PROBLEM lines with fixture-path noise stripped.

    The CLI prints `  <fixture-path>: <problems>` — and the fixture DIR
    NAMES carry the expected substrings themselves (baud-too-high et
    al.), so attribution against raw output matches the path, not the
    reason (#497 post-merge finding). Keep only what follows the
    path+colon separator on problem lines.
    """
    kept: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        if "schema-negative" in stripped and ": " in stripped:
            kept.append(stripped.split(": ", 1)[1])
        elif stripped and not stripped.startswith(("invalid models",)):
            kept.append(stripped)
    return "\n".join(kept)


def main() -> int:
    manifest = json.loads((NEGATIVES / "manifest.json").read_text())["fixtures"]
    dirs = sorted(p.name for p in NEGATIVES.iterdir() if p.is_dir())
    failures: list[str] = []

    unrecorded = [d for d in dirs if d not in manifest]
    if unrecorded:
        failures.append(f"fixtures missing from manifest.json: {unrecorded}")
    stale = [s for s in manifest if s not in dirs]
    if stale:
        failures.append(f"manifest entries with no fixture dir: {stale}")

    for stem in dirs:
        expect = manifest.get(stem, {}).get("expect")
        if not expect:
            continue
        proc = subprocess.run(
            ["cargo", "run", "--quiet", "-p", "conwrt-cli", "--",
             "models", "--dir", str(NEGATIVES / stem)],
            cwd=REPO, capture_output=True, text=True, timeout=300,
        )
        output = proc.stdout + proc.stderr
        attribution = problem_text_only(output)
        if proc.returncode == 0:
            failures.append(f"{stem}: Rust ACCEPTED a schema-negative fixture")
        elif expect not in attribution:
            failures.append(
                f"{stem}: rejected, but not for the intended reason — "
                f"expected a problem mentioning {expect!r}, got:\n{output.strip()}"
            )

    if failures:
        print("PARITY DRIFT:", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(f"parity OK: {len(dirs)} negative fixtures rejected for their "
          f"intended reason by the Rust validator")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
