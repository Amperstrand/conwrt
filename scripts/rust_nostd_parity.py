#!/usr/bin/env python3
"""rust_nostd_parity — guard against Makefile/rust.yml no_std check drift.

PR #227 round 1 shipped a no_std-only break (`to_string` needing `ToString`
in scope) that passed local `make rust-ci` because the Makefile's
`rust-ci` recipe listed a STALE set of `-p <crate>` arguments for the
`cargo check --no-default-features --target thumbv7em-none-eabihf`
cross-check, while CI's `.github/workflows/rust.yml` listed the fresh set
(incl. the new crate). Local green, CI red — the lists had drifted.

This guard makes that drift a hard failure on BOTH sides. It parses the
real `Makefile` and `.github/workflows/rust.yml` as text (dependency-free),
finds every `cargo check` line that is a no_std cross-check
(`--no-default-features` + the `thumbv7em-none-eabihf` target), reduces
each line to an invocation signature — (sorted `-p`/`--package` crate
set, sorted `--features` set) — and requires both files to run the SAME
multiset of signatures. Per-invocation, not unioned: a crate dropped from
the featureless check while a `--features` check still names it changes
what actually gets built and must fail (Codex review, PR #231 round 1).
An empty signature list (all cross-check lines deleted) is an error, not
a silent pass. Line order between the files is irrelevant.

Wired in twice: `make rust-nostd-parity` (called first by `make rust-ci`)
and as a dedicated step in the `rust` job of `.github/workflows/rust.yml`.

Modes:
  (default)      check the real repo files; exit 1 on drift
  --self-test    additionally prove the detector: run the real-files check,
                 then deliberately diverge fixture COPIES of both files in a
                 temp dir (extra crate / crate removed everywhere / crate
                 removed from only the featureless check / cross-check lines
                 deleted) and assert each divergence is caught.
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parent.parent
MAKEFILE = REPO_ROOT / "Makefile"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "rust.yml"

NO_STD_TARGET = "thumbv7em-none-eabihf"
# A no_std cross-check line: cargo check ... --no-default-features ...
# --target thumbv7em-none-eabihf (feature-specific variants such as the
# embassy-net check count as their own invocations).
NEEDLES = ("cargo check", "--no-default-features", NO_STD_TARGET)
# `-p crate`, `--package crate`, `--package=crate`
PACKAGE_RE = re.compile(r"(?:^|\s)(?:-p|--package)(?:\s+|=)([A-Za-z0-9_-]+)")
# `--features a,b` / `--features=a,b`
FEATURES_RE = re.compile(r"(?:^|\s)--features(?:\s+|=)([^\s]+)")

EXTRA_CRATE = "conwrt-image"  # not in the real lists; the self-test's imposter
DROPPED_CRATE = "conwrt-executor"  # the exact crate the #227 round-1 drift lost


class ParityError(Exception):
    """Raised when the no_std checks cannot be compared or have drifted."""


#: One normalized cross-check invocation: (crates, features), both sorted.
Signature = tuple[tuple[str, ...], tuple[str, ...]]


@dataclass(frozen=True)
class Lists:
    """Extracted cross-check signatures for one side, in file order."""

    source: Path
    signatures: tuple[Signature, ...]


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


def line_signature(line: str) -> Signature | None:
    """`(crates, features)` for a no_std cross-check line, else None."""
    if not all(needle in line for needle in NEEDLES):
        return None
    crates = tuple(sorted(PACKAGE_RE.findall(line)))
    features = tuple(
        sorted({f for group in FEATURES_RE.findall(line) for f in group.split(",")})
    )
    return crates, features


def extract(text: str, source: Path, join_continuations: bool) -> Lists:
    """Signatures of every no_std cross-check line in `text`, in file order."""
    signatures: list[Signature] = []
    for line in logical_lines(text, join_continuations):
        sig = line_signature(line)
        if sig is None:
            continue
        if not sig[0]:
            raise ParityError(
                f"{source}: a `{NO_STD_TARGET}` cross-check line carries no -p "
                "crates — a bare check would drift silently; name the crates"
            )
        signatures.append(sig)
    if not signatures:
        raise ParityError(
            f"{source}: no `cargo check ... --no-default-features ... "
            f"--target {NO_STD_TARGET}` line found — the no_std cross-check "
            "was deleted or renamed; this guard refuses to pass silently"
        )
    return Lists(source=source, signatures=tuple(signatures))


def load(path: Path, join_continuations: bool) -> Lists:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as err:
        raise ParityError(f"cannot read {path}: {err}") from err
    return extract(text, path, join_continuations)


def describe(sig: Signature) -> str:
    """One-line rendering of an invocation signature."""
    crates, features = sig
    feat = f" (features: {', '.join(features)})" if features else ""
    return f"[{', '.join(crates)}]{feat}"


def diff_report(mk: Lists, wf: Lists) -> list[str]:
    """Human-readable failure lines; empty when the invocations agree."""
    mk_multi = Counter(mk.signatures)
    wf_multi = Counter(wf.signatures)
    if mk_multi == wf_multi:
        return []
    only_mk = list((mk_multi - wf_multi).elements())
    only_wf = list((wf_multi - mk_multi).elements())
    return [
        "no_std parity drift: the Makefile and .github/workflows/rust.yml "
        f"run different {NO_STD_TARGET} cross-checks "
        "(this exact drift let a no_std break pass local `make rust-ci` "
        "while CI failed — PR #227 review round 1)",
        f"  Makefile invocations ({len(mk.signatures)}):",
        *(f"    {describe(s)}" for s in mk.signatures),
        f"  .github/workflows/rust.yml invocations ({len(wf.signatures)}):",
        *(f"    {describe(s)}" for s in wf.signatures),
        "  checks only in Makefile                  : "
        + ("; ".join(describe(s) for s in only_mk) or "-"),
        "  checks only in .github/workflows/rust.yml: "
        + ("; ".join(describe(s) for s in only_wf) or "-"),
        "Fix BOTH sides to run the same cross-checks (same -p crate sets "
        "and features, per check).",
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
    crates = {c for sig in mk.signatures for c in sig[0]}
    print(
        f"no_std parity OK: {len(mk.signatures)} cross-check(s) covering "
        f"{len(crates)} crates agree on both sides "
        "(Makefile + .github/workflows/rust.yml): " + " ".join(sorted(crates))
    )
    return 0


def mutate_first_matching_line(text: str, mutation: Callable[[str], str]) -> str:
    """Apply `mutation` to the first line matching the no_std needles."""
    out = []
    mutated = False
    for line in text.splitlines():
        if not mutated and all(needle in line for needle in NEEDLES):
            line = mutation(line)
            mutated = True
        out.append(line)
    if not mutated:
        raise ParityError("self-test: no no_std line found to mutate")
    return "\n".join(out) + "\n"


def mutate_every_matching_line(text: str, mutation: Callable[[str], str]) -> str:
    """Apply `mutation` to every line matching the no_std needles."""
    out = []
    mutated = False
    for line in text.splitlines():
        if all(needle in line for needle in NEEDLES):
            line = mutation(line)
            mutated = True
        out.append(line)
    if not mutated:
        raise ParityError("self-test: no no_std line found to mutate")
    return "\n".join(out) + "\n"


def diverge_workflow_text(text: str) -> str:
    """Add an imposter crate to the first no_std cross-check line."""
    return mutate_first_matching_line(
        text,
        lambda line: line.replace(
            " -p conwrt-types", f" -p {EXTRA_CRATE} -p conwrt-types", 1
        ),
    )


def drop_crate_everywhere_text(text: str) -> str:
    """Remove the round-1 crate from EVERY no_std cross-check line."""
    return mutate_every_matching_line(
        text, lambda line: line.replace(f" -p {DROPPED_CRATE}", "", 1)
    )


def drop_crate_from_featureless_check_text(text: str) -> str:
    """Remove the round-1 crate from only the check without --features.

    The PR #231 review-round-1 repro: the crate stays on the
    `--features embassy-net` lines, so a union comparison would still
    pass — the per-invocation comparison must catch it.
    """

    def drop_if_featureless(line: str) -> str:
        return line.replace(f" -p {DROPPED_CRATE}", "", 1)

    out = []
    mutated = False
    for line in text.splitlines():
        if all(needle in line for needle in NEEDLES) and not FEATURES_RE.search(line):
            line = drop_if_featureless(line)
            mutated = True
        out.append(line)
    if not mutated:
        raise ParityError("self-test: no featureless no_std line found")
    return "\n".join(out) + "\n"


def delete_nostd_line_text(text: str) -> str:
    """Delete the no_std cross-check lines entirely (silent-pass hazard)."""
    out = [line for line in text.splitlines() if not all(n in line for n in NEEDLES)]
    if len(out) == len(text.splitlines()):
        raise ParityError("self-test: no no_std line found to delete")
    return "\n".join(out) + "\n"


def drift_detected(makefile: Path, workflow: Path) -> bool:
    """True when the comparison reports drift or refuses to compare.

    A refusal (ParityError: unparseable/deleted/bare checks) is a caught
    divergence — the guard never passes silently on a broken state.
    """
    try:
        _, _, failures = check(makefile, workflow)
    except ParityError:
        return True
    return bool(failures)


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

        def variant(name: str, base: Path, transform: Callable[[str], str]) -> Path:
            path = tmpdir / name
            path.write_text(transform(base.read_text(encoding="utf-8")), encoding="utf-8")
            return path

        # Step 0 — positive control: the untouched copies must PASS.
        steps.append(
            ("control: unmodified copies pass", False, drift_detected(mk_copy, wf_copy))
        )

        # Step 1 — rust.yml gains an extra crate on one check.
        wf_bad = variant("rust.yml-extra-crate", wf_copy, diverge_workflow_text)
        steps.append(
            (f"rust.yml +extra -p {EXTRA_CRATE} is detected", True, drift_detected(mk_copy, wf_bad))
        )

        # Step 2 — Makefile loses the round-1 crate everywhere (the
        # embassy-net line drops to bare and the guard refuses it).
        mk_bad = variant("Makefile-missing-crate", mk_copy, drop_crate_everywhere_text)
        steps.append(
            (
                f"Makefile -p {DROPPED_CRATE} removed everywhere is detected",
                True,
                drift_detected(mk_bad, wf_copy),
            )
        )

        # Step 3 — crate removed from ONLY the featureless check while the
        # --features checks keep it (PR #231 review round 1 repro).
        mk_masked = variant(
            "Makefile-masked-crate", mk_copy, drop_crate_from_featureless_check_text
        )
        steps.append(
            (
                f"Makefile -p {DROPPED_CRATE} removed from only the featureless "
                "check is detected (union-masking repro)",
                True,
                drift_detected(mk_masked, wf_copy),
            )
        )

        # Step 4 — cross-check lines deleted from the workflow: must be an
        # error, not a silent pass.
        wf_gone = variant("rust.yml-line-deleted", wf_copy, delete_nostd_line_text)
        steps.append(
            ("rust.yml cross-check lines deleted is an error", True, drift_detected(mk_copy, wf_gone))
        )

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
