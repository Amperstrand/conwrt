"""Shared checksum utilities for conwrt."""
from __future__ import annotations


def internet_checksum(data: bytes) -> int:
    if not data:
        return 0
    if len(data) % 2:
        data += b"\0"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        if total > 0xFFFF:
            total = (total & 0xFFFF) + 1
    return total & 0xFFFF
