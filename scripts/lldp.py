"""lldp — LLDP frame capture and parsing for conwrt.

Provides LLDPInfo dataclass and functions to capture/parse LLDP frames
from tcpdump output. Used by auto_detect and model_match modules.
"""

from __future__ import annotations

import re
import socket
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class LLDPInfo:
    """Parsed LLDP neighbor information."""
    chassis_mac: str = ""
    chassis_name: str = ""
    management_ip: str = ""
    management_url: str = ""
    system_description: str = ""
    port_id: str = ""
    port_description: str = ""
    vendor_specific: dict = field(default_factory=dict)
    raw_tlvs: list = field(default_factory=list)


def lldp_probe(interface: str, timeout: int = 15) -> dict[str, LLDPInfo]:
    """Capture and parse LLDP frames on an interface.

    Returns dict mapping management_ip -> LLDPInfo.
    Uses tcpdump (no scapy dependency).
    """
    results: dict[str, LLDPInfo] = {}

    try:
        proc = subprocess.Popen(
            [
                "sudo", "-n", "tcpdump",
                "-i", interface,
                "-n", "-e", "-XX",
                "-c", "1",
                "-t",
                "ether", "proto", "0x88cc",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except FileNotFoundError:
        return results

    output_lines: list[str] = []
    end_time = time.monotonic() + timeout
    try:
        while time.monotonic() < end_time:
            line = proc.stdout.readline()
            if not line:
                break
            output_lines.append(line)
    except OSError:
        pass
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()

    if not output_lines:
        return results

    full_output = "".join(output_lines)
    hex_blocks = re.split(r"(?=\n\S)", full_output)
    for block in hex_blocks:
        info = _parse_lldp_hex_block(block)
        if info and (info.management_ip or info.chassis_mac):
            key = info.management_ip or info.chassis_mac
            if key not in results:
                results[key] = info

    return results


def _parse_lldp_hex_block(block: str) -> Optional[LLDPInfo]:
    """Parse a single tcpdump hex dump block into LLDPInfo.

    TODO: Replace with tshark JSON output (`tshark -T json -e lldp`) or
    scapy LLDP layer (scapy.layers.l2.LLDP) for proper vendor-specific TLV
    decoding. The hand-roll parser handles standard TLVs + ZyXEL OUI
    (00:a0:c5) subtypes 2-5 but will miss other vendor TLVs.
    """
    hex_bytes: list[str] = []
    for line in block.splitlines():
        m = re.search(r':\s+((?:[0-9a-fA-F]{4}\s)+)', line)
        if m:
            for word in m.group(1).split():
                hex_bytes.append(word[0:2])
                hex_bytes.append(word[2:4])

    if len(hex_bytes) < 14:
        return None

    raw_bytes = bytes(int(h, 16) for h in hex_bytes)

    eth_dst = raw_bytes[0:6]
    if eth_dst != b"\x01\x80\xc2\x00\x00\x0e" and eth_dst != b"\x01\x80\xc2\x00\x00\x03":
        return None
    if len(raw_bytes) < 14 or raw_bytes[12:14] != b"\x88\xcc":
        return None

    lldp_data = raw_bytes[14:]
    info = LLDPInfo()

    offset = 0
    while offset + 2 <= len(lldp_data):
        tlv_header = (lldp_data[offset] << 8) | lldp_data[offset + 1]
        tlv_type = (tlv_header >> 9) & 0x7F
        tlv_len = tlv_header & 0x1FF
        offset += 2

        if tlv_type == 0:
            break

        if offset + tlv_len > len(lldp_data):
            break

        tlv_value = lldp_data[offset:offset + tlv_len]

        if tlv_type == 1:  # Chassis ID
            if tlv_len > 1:
                subtype = tlv_value[0]
                if subtype == 4:  # MAC address
                    info.chassis_mac = ":".join(f"{b:02X}" for b in tlv_value[1:7])

        elif tlv_type == 2:  # Port ID
            if tlv_len > 1:
                subtype = tlv_value[0]
                if subtype == 3:  # MAC address
                    info.port_id = ":".join(f"{b:02X}" for b in tlv_value[1:7])
                elif subtype == 7:  # Locally assigned
                    info.port_id = tlv_value[1:].decode("utf-8", errors="replace")

        elif tlv_type == 5:  # System Name
            info.chassis_name = tlv_value.decode("utf-8", errors="replace").strip()

        elif tlv_type == 6:  # System Description
            info.system_description = tlv_value.decode("utf-8", errors="replace").strip()

        elif tlv_type == 8:  # Management Address
            if tlv_len > 2:
                addr_len = tlv_value[0]
                addr_subtype = tlv_value[1]
                if addr_subtype == 1 and addr_len >= 5:  # IPv4
                    ip_bytes = tlv_value[2:6]
                    info.management_ip = socket.inet_ntoa(ip_bytes)

        elif tlv_type == 127:  # Org-specific
            if tlv_len >= 4:
                oui = tlv_value[0:3]
                sub = tlv_value[3]
                oui.hex().upper()
                oui_str = ":".join(f"{b:02X}" for b in oui)
                payload = tlv_value[4:]

                if oui == b"\x00\xa0\xc5":
                    _parse_zyxel_lldp(info, sub, payload)
                else:
                    info.vendor_specific.setdefault(f"oui_{oui_str}_{sub}", payload.hex())

        info.raw_tlvs.append((tlv_type, tlv_value.hex()))

        offset += tlv_len

    return info if (info.chassis_mac or info.management_ip) else None


def _parse_zyxel_lldp(info: LLDPInfo, subtype: int, payload: bytes) -> None:
    """Parse ZyXEL OUI (00:a0:c5) TLV subtypes."""
    # ZyXEL subtypes: 2=device model, 3=firmware, 4=serial/MAC, 5=management URL
    # Payload starts with a 1-byte length prefix before the actual string data
    try:
        if len(payload) > 1:
            data = payload[1:]
        else:
            data = payload

        if subtype == 2:
            info.vendor_specific["zyxel_device"] = data.decode("utf-8", errors="replace").strip()
        elif subtype == 3:
            info.vendor_specific["zyxel_firmware"] = data.decode("utf-8", errors="replace").strip()
        elif subtype == 4:
            text = data.decode("utf-8", errors="replace").strip()
            info.vendor_specific["zyxel_serial"] = text
        elif subtype == 5:
            info.management_url = data.decode("utf-8", errors="replace").strip()
            info.vendor_specific["zyxel_mgmt_url"] = info.management_url
        else:
            info.vendor_specific[f"zyxel_sub{subtype}"] = data.decode("utf-8", errors="replace").strip()
    except (UnicodeDecodeError, ValueError):
        pass
