"""Classified mtd readback verification (#776).

AGENTS.md irreversible-write rule 2: zeros, erased 0xFF, and a valid
image are THREE DIFFERENT boot outcomes — so a readback gate must say
WHICH failure it is looking at, because the recovery differs:

- ``MATCH``       the write landed; proceed.
- ``ERASED_NOOP`` the written span still reads as the erased pattern
                  (0xFF) — the write silently no-op'd (the MF286D
                  device-2 lockout class). Do NOT reboot: the running
                  OS is the recovery window.
- ``MISMATCH``    wrong bytes over the span. Re-read ONCE before
                  condemning — a single transport corruption must not
                  condemn the write (esptool's NAND bad-block lesson,
                  adopted here as contract).

The on-device half is deliberately busybox-only (head/tr/sha256sum)
and resolves the mtd device by NAME from /proc/mtd — the MTD-numbering
shift between stock and OpenWrt is a documented wrong-partition trap
(AP3915i CFG1 lesson).
"""
from __future__ import annotations

from enum import Enum


class MtdReadbackVerdict(str, Enum):
    MATCH = "match"
    ERASED_NOOP = "erased-noop"
    MISMATCH = "mismatch"


def classify(expected_sha: str, readback_sha: str, non_ff_bytes: int) -> MtdReadbackVerdict:
    """Classify one readback of the written span.

    ``non_ff_bytes`` is the count of bytes != 0xFF over the span the
    image should occupy (partial-file writes are legal: the unwritten
    tail of an erased block legitimately stays 0xFF, so only the span
    is judged — never the whole partition).
    """
    if readback_sha == expected_sha:
        return MtdReadbackVerdict.MATCH
    if non_ff_bytes == 0:
        return MtdReadbackVerdict.ERASED_NOOP
    return MtdReadbackVerdict.MISMATCH


def should_condemn(first: MtdReadbackVerdict, recheck: MtdReadbackVerdict | None) -> bool:
    """Re-read-before-condemn contract.

    MATCH never condemns. ERASED_NOOP condemns immediately (a clean
    erased span is deterministic evidence of a no-op'd write — waiting
    cannot improve it). MISMATCH condemns only when the single
    mandated re-read ALSO mismatches; otherwise the recheck verdict
    wins (a transport hiccup on the first read is not a flash defect).
    """
    if first is MtdReadbackVerdict.MATCH:
        return False
    if first is MtdReadbackVerdict.ERASED_NOOP:
        return True
    if recheck is None:
        return False  # contract: a MISMATCH requires the one re-read first
    return recheck is not MtdReadbackVerdict.MATCH


def verify_script_lines(mtd_name: str, image_remote: str) -> list[str]:
    """Busybox-safe on-device lines producing the classification inputs.

    Emits ``RB_SHA=<sha>`` and ``RB_NONFF=<count>`` over exactly the
    span the image file occupies. ``image_remote`` is the on-device
    path of the written image (used for both size and expected sha).
    """
    return [
        f'_mtd_dev=/dev/$(grep -m1 "{mtd_name}" /proc/mtd | cut -d: -f1)',
        f'[ -n "$_mtd_dev" ] && [ -b "$_mtd_dev" ] || {{ echo "MTD-NAME-FAIL: {mtd_name}"; exit 1; }}',
        f'_span=$(wc -c < "{image_remote}" | tr -d " ")',
        f'RB_SHA=$(head -c "$_span" "$_mtd_dev" | sha256sum | cut -d" " -f1)',
        f'RB_NONFF=$(head -c "$_span" "$_mtd_dev" | tr -d "\\377" | wc -c)',
        'echo "RB_SHA=$RB_SHA RB_NONFF=$RB_NONFF SPAN=$_span DEV=$_mtd_dev"',
    ]


def parse_rb_line(line: str) -> tuple[str, int]:
    """Parse the RB_SHA/RB_NONFF line emitted by verify_script_lines."""
    sha = ""
    nonff = -1
    for part in line.split():
        if part.startswith("RB_SHA="):
            sha = part.split("=", 1)[1]
        elif part.startswith("RB_NONFF="):
            nonff = int(part.split("=", 1)[1])
    if len(sha) != 64 or nonff < 0:
        raise ValueError(f"unparseable readback line: {line!r}")
    return sha, nonff


def verdict_message(verdict: MtdReadbackVerdict, mtd_name: str) -> str:
    if verdict is MtdReadbackVerdict.ERASED_NOOP:
        return (f"mtd readback {mtd_name}: write silently NO-OP'D — span still reads "
                f"as erased 0xFF. Do NOT reboot; the running OS is the recovery window "
                f"(MF286D device-2 lockout class).")
    if verdict is MtdReadbackVerdict.MISMATCH:
        return (f"mtd readback {mtd_name}: MISMATCH — wrong bytes over the span "
                f"(one re-read mandated before condemning).")
    return f"mtd readback {mtd_name}: match"
