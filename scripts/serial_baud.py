"""Baud rate detection and boot stage identification for serial console.

Extracted from serial-console.py for testability and reuse.
Scoring algorithm based on ComScope and baudowl auto-baud research.
"""
from __future__ import annotations

import math


# ─── Boot Stage Detection ───────────────────────────────────────────────────

BOOT_SIGNATURES: dict[str, list[bytes]] = {
    "uboot": [
        b"U-Boot", b"u-boot", b"Bootloader", b"bootmenu",
        b"Hit any key to stop autoboot",
        b"Net:   ", b"eth0: ", b"ethaddr=",
    ],
    "zloader": [
        b"Z-Loader", b"Z-LOADER", b"ZyNOS", b"BootBase",
        b"Multiboot", b"Press ENTER to debug mode",
        b"multiboot listening", b"Multiboot Listening",
    ],
    "kernel": [
        b"[    0.000000] Linux version",
        b"Starting kernel",
        b"Booting Linux",
        b"Decompressing Linux",
    ],
    "openwrt": [
        b"OpenWrt", b"LEDE", b"BusyBox", b"dropbear",
        b"Starting OpenWrt", b"Router login",
    ],
    "panic": [
        b"Kernel panic", b"not syncing",
    ],
}


def detect_boot_stage(data: bytes, current_stage: str = "unknown") -> str:
    for stage, patterns in BOOT_SIGNATURES.items():
        for pattern in patterns:
            if pattern in data:
                return stage
    return current_stage


# ─── Baud Rate Detection ────────────────────────────────────────────────────

# Common baud rates for router bootloaders, ranked by frequency
COMMON_BAUDS = [
    115200,  # Most common (OpenWrt, U-Boot, Zyxel, most modern routers)
    57600,   # Some MediaTek, some Zyxel ZyNOS after ATBA5
    38400,   # Older devices, some bare-metal debug
    9600,    # ZyNOS BootBase default, very old devices
    19200,   # Rare
    4800,    # Very rare
    230400,  # High-speed debug
    460800,  # Rare high-speed
    921600,  # Very rare
]

# Known boot patterns that indicate correct baud rate
BOOT_PATTERNS = [
    b"U-Boot", b"u-boot", b"uboot",
    b"Z-Loader", b"Z-LOADER", b"ZyNOS", b"BootBase",
    b"Linux version", b"Starting kernel", b"Booting",
    b"OpenWrt", b"LEDE", b"BusyBox",
    b"Decompressing", b"Loading",
    b"\r\n",
]


def score_baud_data(data: bytes) -> tuple[int, str]:
    """Score received data for likelihood of being valid at the current baud.

    Uses three metrics from ComScope/baudowl auto-baud research:
    - Printable ASCII ratio (higher = more likely correct baud)
    - Known boot pattern matches (strong signal)
    - Byte distribution entropy + error byte penalties
    """
    if not data:
        return (0, "no data")

    printable = sum(1 for b in data if 0x20 <= b < 0x7f or b in (0x0a, 0x0d, 0x08, 0x09))
    ascii_ratio = printable / len(data)

    pattern_hits = sum(1 for p in BOOT_PATTERNS if p in data)

    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    total = len(data)
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)

    null_bytes = sum(1 for b in data if b == 0x00)
    ff_bytes = sum(1 for b in data if b == 0xFF)
    high_bit_bytes = sum(1 for b in data if 0x80 <= b <= 0xFE)

    max_printable_run = 0
    current_run = 0
    for b in data:
        if 0x20 <= b < 0x7f or b in (0x0a, 0x0d, 0x08, 0x09):
            current_run += 1
            if current_run > max_printable_run:
                max_printable_run = current_run
        else:
            current_run = 0

    has_newlines = b'\n' in data or b'\r' in data

    score = 0
    score += int(ascii_ratio * 100)
    score += pattern_hits * 50
    if entropy < 5.0:
        score += int((5.0 - entropy) * 20)
    if max_printable_run > 6:
        score += 20
    if has_newlines:
        score += 15
    if null_bytes > 0:
        score -= int(80 * (null_bytes / total))
    if ff_bytes > 0:
        score -= int(80 * (ff_bytes / total))
    if ascii_ratio < 0.5:
        score -= 40
    if high_bit_bytes > total * 0.1:
        score -= 20

    score = max(0, score)
    reason = (f"ascii={ascii_ratio:.0%}, patterns={pattern_hits}, "
              f"entropy={entropy:.1f}, nulls={null_bytes}, run={max_printable_run}")
    return (score, reason)
