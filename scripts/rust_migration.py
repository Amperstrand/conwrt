"""Soft-deprecation gate for commands migrated to the conwrt 2.0 Rust CLI.

The Python implementation stays fully functional while its Rust replacement
reaches (and is verified at) feature parity. A migrated command prints a
pointer to the Rust equivalent and pauses, so the Python path stays usable
but visibly second-class:

    $ python3 scripts/conwrt.py list
    ────────────────────────────────────────────────────────────────────────
    NOTE: `conwrt list` has a Rust replacement: `conwrt models`
    (conwrt 2.0 — feature parity reached for model listing/validation).
    This notice and delay will be removed when the Python command is
    retired. Delay is configurable: CONWRT_RUST_MIGRATION_DELAY=<seconds>
    ────────────────────────────────────────────────────────────────────────
    continuing in 15s ...

The delay is controlled by the ``CONWRT_RUST_MIGRATION_DELAY`` environment
variable (seconds, float, default 15). Set it to ``0`` to skip the delay —
the notice always prints. Tests and CI set it to ``0`` globally via
``tests/conftest.py`` / workflow env.

Migration status ledger: ``docs/rust-migration.md``.
"""

from __future__ import annotations

import os
import sys
import time

ENV_VAR = "CONWRT_RUST_MIGRATION_DELAY"
DEFAULT_DELAY_SECONDS = 15.0
_BAR = "─" * 72


def _delay_from_env() -> float:
    raw = os.environ.get(ENV_VAR, "")
    if not raw:
        return DEFAULT_DELAY_SECONDS
    try:
        value = float(raw)
    except ValueError as exc:
        raise SystemExit(
            f"{ENV_VAR} must be a number of seconds, got {raw!r}"
        ) from exc
    if value < 0:
        raise SystemExit(f"{ENV_VAR} must be >= 0, got {value}")
    return value


def soft_deprecated(rust_command: str, what: str) -> None:
    """Print the migration notice and pause before the Python path runs.

    ``rust_command`` is the exact Rust CLI invocation with equivalent
    behavior; ``what`` names the migrated capability (used in the notice).
    """
    delay = _delay_from_env()
    print(_BAR, file=sys.stderr)
    print(
        f"NOTE: this command has a Rust replacement: `{rust_command}`",
        file=sys.stderr,
    )
    print(
        f"(conwrt 2.0 — feature parity reached for {what};",
        file=sys.stderr,
    )
    print(
        "the Python implementation is in soft deprecation and will be",
        file=sys.stderr,
    )
    print(
        "retired once the Rust path is verified in production use.",
        file=sys.stderr,
    )
    print(
        f"Delay configurable via {ENV_VAR}=<seconds>; Ctrl-C to abort.",
        file=sys.stderr,
    )
    print(_BAR, file=sys.stderr, flush=True)
    if delay > 0:
        print(f"continuing in {delay:g}s ...", file=sys.stderr, flush=True)
        time.sleep(delay)
