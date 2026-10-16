#!/usr/bin/env python3
"""rust_nostd_parity — guard against Makefile/rust.yml no_std crate-list drift.

PR #227 round 1 shipped a no_std-only break (`to_string` needing `ToString`
in scope) that passed local `make rust-ci` because the Makefile's
`rust-ci` recipe listed a STALE set of `-p <crate>` arguments for the
`cargo check --no-default-features --target thumbv7em-none-eabihf`
cross-check, while CI's `.github/workflows/rust.yml` listed the fresh set
(incl. the new crate). Local green, CI red — the lists had drifted.

This guard makes that drift a hard failure on BOTH sides: it parses the
real `Makefile` and `.github/workflows/rust.yml` as text (dependency-free),
collects the union of `-p <crate>` / `--package <crate>` arguments over
every line that is a no_std cross-check (`cargo check` + `--no-default-features`
+ the `thumbv7em-none-eabihf` target), and fails when the two unions differ
— including when the cross-check line disappears from either file (an empty
union is an error, not a silent pass).

Wired in twice: `make rust-nostd-parity` (called first by `make rust-ci`)
and as a dedicated step in the `rust` job of `.github/workflows/rust.yml`.

Modes:
  (default)      check the real repo files; exit 1 on drift
  --self-test    additionally prove the detector: run the real-files check,
                 then deliberately diverge fixture COPIES of both files in a
                 temp dir (extra crate in rust.yml / missing crate in
                 Makefile / cross-check line deleted) and assert each
                 divergence is caught with a message naming both files.
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MAKEFILE = REPO_ROOT / "Makefile"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "rust.yml"

NO_STD_TARGET = "thumbv7em-none-eabihf"
# A no_std cross-check line: cargo check ... --no-default-features ...
# --target thumbv7em-none-eabihf (feature-specific variants such as the
# embassy-net check count too — their -p crates join the union).
NEEDLES = ("cargo check", "--no-default-features", NO_STD_TARGET)
# `-p crate`, `--package crate`, `--package=crate`
PACKAGE_RE = re.compile(r"(?:^|\s)(?:-p|--package)(?:\s+|=)([A-Za-z0-9_-]+)")

EXTRA_CRATE = "conwrt-image"  # not in the real lists; the self-test's imposter
DROPPED_CRATE = "conwrt-executor"  # the exact crate the #227 round-1 drift lost


class ParityError(Exception):
    """Raised when the no_std crate lists cannot be compared or have drifted."""


@dataclass(frozen=True)
class Lists:
    """Extracted `-p` crate unions for one side."""

    source: Path
    crates: set[str]
    matching_lines: int


def logical_lines(text: str, join_continuations: bool) -> list[str]:
    """Split into lines, optionally joining `\\`-continued shell lines.

    Makefile recipes may wrap long cargo invocations with `\\`; a YAML `|`
    block would treat a trailing backslash as a literal character, so the
    workflow is scanned line-per-line.
    """
    lines = text.splitlines()
    if not join_continuations:
        return lines
    joined: list[str] = []
    pending = ""
    for line in lines:
        stripped = line.lstrip("\t ").rstrip()
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            continue
        joined.append(pending + stripped)
        pending = ""
    if pending:
        joined.append(pending)
    return joined


def extract(text: str, source: Path, join_continuations: bool) -> Lists:
    """Union of -p crates over every no_std cross-check line in `text`."""
    crates: set[str] = set()
    matching = 0
    for line in logical_lines(text, join_continuations):
        if all(needle in line for needle in NEEDLES):
            matching += 1
            crates.update(PACKAGE_RE.findall(line))
    if not matching or not crates:
        raise ParityError(
            f"{source}: no `cargo check ... --no-default-features ... "
            f"--target {NO_STD_TARGET}` line with -p crates found — "
            "the no_std cross-check was deleted or renamed; this guard "
            "refuses to pass silently"
        )
    return Lists(source=source, crates=crates, matching_lines=matching)


def load(path: Path, join_continuations: bool) -> Lists:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as err:
        raise ParityError(f"cannot read {path}: {err}") from err
    return extract(text, path, join_continuations)


def diff_report(mk: Lists, wf: Lists) -> list[str]:
    """Human-readable failure lines; empty when the unions agree."""
    if mk.crates == wf.crates:
        return []
    only_mk = mk.crates - wf.crates
    only_wf = wf.crates - mk.crates
    return [
        "no_std parity drift: the Makefile and .github/workflows/rust.yml "
        f"`-p` crate sets for the {NO_STD_TARGET} no_std cross-check differ",
        f"  (this exact drift let a no_std break pass local `make rust-ci` "
        "while CI failed — PR #227 review round 1)",
        f"  Makefile                  ({mk.matching_lines} line(s)): "
        + " ".join(sorted(mk.crates)),
        f"  .github/workflows/rust.yml ({wf.matching_lines} line(s)): "
        + " ".join(sorted(wf.crates)),
        f"  only in Makefile                  : {' '.join(sorted(only_mk)) or '-'}",
        f"  only in .github/workflows/rust.yml: {' '.join(sorted(only_wf)) or '-'}",
        "Fix BOTH sides to carry the same -p crate set.",
    ]


def check(makefile: Path, workflow: Path) -> tuple[Lists, Lists, list[str]]:
    """Compare both sides; returns (makefile-lists, workflow-lists, failure-lines)."""
    mk = load(makefile, join_continuations=True)
    wf = load(workflow, join_continuations=False)
    return mk, wf, diff_report(mk, wf)


def run_check(makefile: Path, workflow: Path) -> int:
    try:
        mk, wf, failures = check(makefile, workflow)
    except ParityError as err:
        print(f"FAIL: {err}", file=sys.stderr)
        return 1
    if failures:
        for line in failures:
            print(f"FAIL: {line}", file=sys.stderr)
        return 1
    print(
        f"no_std parity OK: {len(mk.crates)} crates on both sides "
        f"(Makefile: {mk.matching_lines} line(s), rust.yml: {wf.matching_lines} line(s)): "
        + " ".join(sorted(mk.crates))
    )
    return 0


def diverge_workflow_text(text: str) -> str:
    """Add an imposter crate to the first no_std cross-check line."""
    out = []
    injected = False
    for line in text.splitlines():
        if not injected and all(needle in line for needle in NEEDLES):
            line = line.replace(" -p conwrt-types", f" -p {EXTRA_CRATE} -p conwrt-types", 1)
            injected = True
        out.append(line)
    if not injected:
        raise ParityError("self-test: could not find a no_std line in the workflow copy")
    return "\n".join(out) + "\n"


def drop_crate_from_makefile_text(text: str) -> str:
    """Remove the round-1 crate from EVERY no_std cross-check line.

    Several no_std lines may carry the same crate (the multi-crate gate
    plus feature-specific checks) — dropping it from only one line can
    be masked by the others in the union, which would make this seeded
    divergence a non-divergence (caught live when #232 added the
    embassy-net lines).
    """
    out = []
    dropped = False
    for line in text.splitlines():
        if all(needle in line for needle in NEEDLES) and f" -p {DROPPED_CRATE}" in line:
            line = line.replace(f" -p {DROPPED_CRATE}", "", 1)
            dropped = True
        out.append(line)
    if not dropped:
        raise ParityError("self-test: no no_std line carrying the dropped crate found")
    return "\n".join(out) + "\n"


def delete_nostd_line_text(text: str) -> str:
    """Delete the no_std cross-check line entirely (silent-pass hazard)."""
    out = [line for line in text.splitlines() if not all(n in line for n in NEEDLES)]
    if len(out) == len(text.splitlines()):
        raise ParityError("self-test: no no_std line found to delete")
    return "\n".join(out) + "\n"


def run_self_test(makefile: Path, workflow: Path) -> int:
    """Prove the detector on deliberately diverged fixture copies."""
    # Each step: (name, expected_drift_detected, actual_drift_detected)
    steps: list[tuple[str, bool, bool]] = []
    with tempfile.TemporaryDirectory(prefix="rust-nostd-parity-") as tmp:
        tmpdir = Path(tmp)
        mk_copy = tmpdir / "Makefile"
        wf_copy = tmpdir / "rust.yml"
        shutil.copy(makefile, mk_copy)
        shutil.copy(workflow, wf_copy)

        # Step 0 — positive control: the untouched copies must PASS.
        _, _, failures = check(mk_copy, wf_copy)
        steps.append(("control: unmodified copies pass", False, bool(failures)))

        # Step 1 — rust.yml gains an extra crate: drift must be caught.
        wf_bad = tmpdir / "rust.yml-extra-crate"
        wf_bad.write_text(diverge_workflow_text(wf_copy.read_text(encoding="utf-8")), encoding="utf-8")
        _, _, failures = check(mk_copy, wf_bad)
        steps.append((f"rust.yml +extra -p {EXTRA_CRATE} is detected", True, bool(failures)))

        # Step 2 — Makefile loses the round-1 crate: drift must be caught.
        mk_bad = tmpdir / "Makefile-missing-crate"
        mk_bad.write_text(drop_crate_from_makefile_text(mk_copy.read_text(encoding="utf-8")), encoding="utf-8")
        _, _, failures = check(mk_bad, wf_copy)
        steps.append((f"Makefile -p {DROPPED_CRATE} removed is detected", True, bool(failures)))

        # Step 3 — cross-check line deleted from the workflow: must be an
        # error, not a silent pass.
        wf_gone = tmpdir / "rust.yml-line-deleted"
        wf_gone.write_text(delete_nostd_line_text(wf_copy.read_text(encoding="utf-8")), encoding="utf-8")
        try:
            _, _, failures = check(mk_copy, wf_gone)
            detected = bool(failures)
        except ParityError:
            detected = True
        steps.append(("rust.yml cross-check line deleted is an error", True, detected))

        ok = True
        for i, (name, want, got) in enumerate(steps):
            if want != got:
                ok = False
                verdict = "drift NOT detected" if want else "clean copies reported drift"
                print(f"self-test step {i} FAILED: {name} ({verdict})", file=sys.stderr)
            else:
                print(f"self-test step {i} ok: {name}")
        if not ok:
            return 1
    print("self-test PASS: every seeded divergence was detected")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--makefile", type=Path, default=MAKEFILE,
                        help="Makefile to check (default: repo Makefile)")
    parser.add_argument("--workflow", type=Path, default=WORKFLOW,
                        help="workflow yaml to check (default: .github/workflows/rust.yml)")
    parser.add_argument("--self-test", action="store_true",
                        help="prove the detector on deliberately diverged fixture copies")
    args = parser.parse_args()

    rc = run_check(args.makefile, args.workflow)
    if rc != 0 or not args.self_test:
        return rc
    return run_self_test(args.makefile, args.workflow)


if __name__ == "__main__":
    sys.exit(main())
