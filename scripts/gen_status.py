#!/usr/bin/env python3
"""Generate the README's self-documenting test-status block.

The README carries hand-written status claims that go stale (the
"tested on OpenWrt 24.10.2" line survived long after the oracle moved
to 25.12.5). This script derives the block from the REAL sources —
tests/integration/_pins.py (harness image), docs/roadmap/parity-matrix.md
(§4 count), scripts/use_cases registry (preset census) — and a pytest
asserts the committed README matches regeneration exactly. Edit the
SOURCES, never the block; run `make gen-status` to refresh.

Markers: <!-- BEGIN generated:test-status --> … <!-- END -->.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
README = REPO / "README.md"
BEGIN = "<!-- BEGIN generated:test-status -->"
END = "<!-- END generated:test-status -->"


def _pins_version() -> str:
    sys.path.insert(0, str(REPO / "tests" / "integration"))
    import _pins  # noqa: PLC0415

    return _pins.OPENWRT_VERSION


def _matrix_count() -> str:
    text = (REPO / "docs" / "roadmap" / "parity-matrix.md").read_text()
    m = re.search(r"(\d+) of 34 use cases typed", text)
    return m.group(1) if m else "?"


def _preset_census() -> tuple[int, list[str], int]:
    sys.path.insert(0, str(REPO / "scripts"))
    from use_cases import registry  # noqa: PLC0415

    regs = registry()
    untested = [n for n, uc in regs.items() if uc.test_status == "untested"]
    return len(regs), untested, len(untested)


def generate() -> str:
    version = _pins_version()
    count = _matrix_count()
    total, untested_list, untested_count = _preset_census()
    untested_names = f" ({', '.join(sorted(untested_list))})" if untested_list else ""
    return (
        f"**Test status (generated — do not edit; sources: "
        f"`tests/integration/_pins.py`, `docs/roadmap/parity-matrix.md`, "
        f"the use-case registry; refresh: `make gen-status`):**\n"
        f"- QEMU/oracle image: OpenWrt **{version}** "
        f"(single pin: `tests/integration/_pins.py`)\n"
        f"- §4 typed-ops: **{count} of 34** presets ported with golden parity\n"
        f"- 1.x registry: **{total}** presets, "
        f"**{untested_count}** still 1.x-untested{untested_names}\n"
        f"- Policy: 24.x models plan with a deprecation warning "
        f"(CVE-2026-98432 / EoS — #607); mptcp-bonding requires ≥ 25.12 "
        f"and a kernel ≥ 6.12.113"
    )


def refresh() -> bool:
    """Rewrite the README block; True if anything changed."""
    text = README.read_text()
    if BEGIN not in text or END not in text:
        print(f"README missing {BEGIN}/{END} markers", file=sys.stderr)
        return False
    head, rest = text.split(BEGIN, 1)
    _, tail = rest.split(END, 1)
    updated = f"{head}{BEGIN}\n{generate()}\n{END}{tail}"
    if updated != text:
        README.write_text(updated)
        print("README status block refreshed")
        return True
    print("README status block already current")
    return False


def check() -> bool:
    """Read-only drift check: True (exit 0) when the committed block
    matches regeneration; False (exit 1) when stale. Never writes."""
    text = README.read_text()
    if BEGIN not in text or END not in text:
        print(f"README missing {BEGIN}/{END} markers", file=sys.stderr)
        return False
    head, rest = text.split(BEGIN, 1)
    _, tail = rest.split(END, 1)
    current = f"{head}{BEGIN}\n{generate()}\n{END}{tail}" == text
    if not current:
        print("README status block is STALE — run `make gen-status`", file=sys.stderr)
    else:
        print("README status block current")
    return current


if __name__ == "__main__":
    if "--check" in sys.argv:
        sys.exit(0 if check() else 1)
    refresh()
