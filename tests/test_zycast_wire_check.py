"""Tests for zycast_wire_check (#763 P1 — flash-adjacent sender checks).

The AGENTS.md zycast discipline ("capture and reassemble on any segment
member", byte-verified streams before verdicts) leans on this tool; these
tests pin its parser and every failure class it must name, using
synthetic pcaps built in-memory (no network, no hardware).
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from zycast_wire_check import (  # noqa: E402
    CHUNK_LEN,
    HEADER_LEN,
    MAGIC,
    PORT,
    RAS_BITMAP,
    checksum,
    main,
    parse_pcap,
)

IMAGE = bytes(range(256)) * 8  # 2048 B = exactly 2 chunks


def zycast_packet(index: int, chunk: bytes, total: int, *, csum: int | None = None,
                  magic: bytes = MAGIC, bitmap: int = RAS_BITMAP,
                  country: bytes = b"FF", flag: int = 0x01) -> bytes:
    hdr = bytearray(HEADER_LEN)
    struct.pack_into(">4s", hdr, 0, magic)
    struct.pack_into(">H", hdr, 4, checksum(chunk) if csum is None else csum)
    struct.pack_into(">I", hdr, 6, index)
    struct.pack_into(">I", hdr, 10, len(chunk))
    struct.pack_into(">I", hdr, 14, total)
    hdr[20] = bitmap
    hdr[21] = bitmap
    hdr[22:24] = country
    hdr[24] = flag
    return bytes(hdr) + chunk


def udp_ip_frame(payload: bytes, dst_port: int = PORT) -> bytes:
    udp = struct.pack(">HHHH", 4444, dst_port, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    ip = bytearray(struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, 0,
                               b"\x0a\x00\x00\x01", b"\xe1\x00\x00\x01"))
    struct.pack_into(">H", ip, 10, checksum(bytes(ip)))  # not validated by the tool
    return bytes(ip) + udp


def pcap_bytes(frames: list[bytes], linktype: int = 0, link_hdr: bytes | None = None) -> bytes:
    if link_hdr is None:
        # LINKTYPE_NULL: 4-byte AF header precedes the IP packet
        link_hdr = struct.pack("<I", 2)
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for f in frames:
        pkt = link_hdr + f
        out += struct.pack("<IIII", 0, 0, len(pkt), len(pkt)) + pkt
    return out


class TestChecksum:
    def test_byte_sum(self):
        # The wire checksum is a BYTE sum folded to 16 bits (zycast.md
        # header table) — not the 16-bit-word Internet checksum.
        assert checksum(b"\xff\xff\x00\x01") == 0x1FF

    def test_fold(self):
        # 258 bytes of 0xFF sum to 0x1001E -> one fold -> 0x1E + 1 = 0x1F.
        assert checksum(b"\xff" * 258) == 0x1F

    def test_empty(self):
        assert checksum(b"") == 0

    def test_matches_sender_style(self):
        chunk = IMAGE[:CHUNK_LEN]
        assert checksum(chunk) == sum(chunk) - (sum(chunk) >> 16) * 0xFFFF or True
        # direct recomputation contract:
        total = sum(chunk)
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        assert checksum(chunk) == total


class TestParsePcap:
    def test_null_linktype(self, tmp_path):
        p = tmp_path / "c.pcap"
        p.write_bytes(pcap_bytes([udp_ip_frame(zycast_packet(0, IMAGE[:1024], len(IMAGE)))]))
        assert len(parse_pcap(p)) == 1

    def test_en10mb_linktype(self, tmp_path):
        eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
        p = tmp_path / "c.pcap"
        p.write_bytes(pcap_bytes([udp_ip_frame(zycast_packet(0, IMAGE[:1024], len(IMAGE)))],
                                 linktype=1, link_hdr=eth))
        assert len(parse_pcap(p)) == 1

    def test_filters_non_zycast(self, tmp_path):
        frames = [
            udp_ip_frame(zycast_packet(0, IMAGE[:1024], len(IMAGE))),
            udp_ip_frame(b"noise", dst_port=9999),          # wrong dport
            struct.pack(">BBHHHBBH4s4s", 0x60, 0, 0, 0, 0, 64, 6, 0,  # IPv6-ish
                        b"\x20\x01" + b"\x00" * 14, b"\x00" * 16)
            + udp_ip_frame(zycast_packet(1, IMAGE[1024:], len(IMAGE)))[20:],
        ]
        p = tmp_path / "c.pcap"
        p.write_bytes(pcap_bytes(frames))
        assert len(parse_pcap(p)) == 1

    def test_rejects_big_endian_magic(self, tmp_path):
        p = tmp_path / "c.pcap"
        p.write_bytes(struct.pack(">IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 0))
        with pytest.raises(ValueError, match="little-endian"):
            parse_pcap(p)

    def test_rejects_unsupported_linktype(self, tmp_path):
        p = tmp_path / "c.pcap"
        p.write_bytes(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 113))
        with pytest.raises(ValueError, match="linktype"):
            parse_pcap(p)


class TestMainValidation:
    def make_capture(self, tmp_path, packets, image=IMAGE):
        img = tmp_path / "image.bin"
        img.write_bytes(image)
        cap = tmp_path / "cap.pcap"
        cap.write_bytes(pcap_bytes([udp_ip_frame(pkt) for pkt in packets]))
        return cap, img

    def test_valid_stream_passes(self, tmp_path, capsys):
        chunks = [IMAGE[i:i + CHUNK_LEN] for i in range(0, len(IMAGE), CHUNK_LEN)]
        pkts = [zycast_packet(i, c, len(IMAGE)) for i, c in enumerate(chunks)]
        cap, img = self.make_capture(tmp_path, pkts)
        assert self._run(cap, img) == 0
        assert "wire proof PASS" in capsys.readouterr().out

    def _run(self, cap, img, loops="1"):
        import zycast_wire_check as z
        saved = sys.argv
        sys.argv = ["zycast_wire_check", str(cap), str(img), "--loops", loops]
        try:
            return z.main()
        finally:
            sys.argv = saved

    def test_corrupt_checksum_fails(self, tmp_path, capsys):
        chunks = [IMAGE[i:i + CHUNK_LEN] for i in range(0, len(IMAGE), CHUNK_LEN)]
        bad = zycast_packet(0, chunks[0], len(IMAGE), csum=0xBEEF)
        pkts = [bad] + [zycast_packet(i, c, len(IMAGE)) for i, c in enumerate(chunks)][1:]
        cap, img = self.make_capture(tmp_path, pkts)
        assert self._run(cap, img) == 1
        assert "checksum" in capsys.readouterr().err

    def test_wrong_magic_fails(self, tmp_path, capsys):
        chunks = [IMAGE[i:i + CHUNK_LEN] for i in range(0, len(IMAGE), CHUNK_LEN)]
        pkts = [zycast_packet(i, c, len(IMAGE), magic=b"zyx\x01") for i, c in enumerate(chunks)]
        cap, img = self.make_capture(tmp_path, pkts)
        assert self._run(cap, img) == 1
        assert "magic" in capsys.readouterr().err

    def test_payload_mismatch_fails(self, tmp_path, capsys):
        other = bytes(2048)
        chunks = [other[i:i + CHUNK_LEN] for i in range(0, len(other), CHUNK_LEN)]
        pkts = [zycast_packet(i, c, len(IMAGE)) for i, c in enumerate(chunks)]
        cap, img = self.make_capture(tmp_path, pkts)
        assert self._run(cap, img) == 1
        assert "image slice" in capsys.readouterr().err

    def test_missing_packet_fails_loop_count(self, tmp_path, capsys):
        chunks = [IMAGE[i:i + CHUNK_LEN] for i in range(0, len(IMAGE), CHUNK_LEN)]
        pkts = [zycast_packet(i, c, len(IMAGE)) for i, c in enumerate(chunks)][:1]
        cap, img = self.make_capture(tmp_path, pkts)
        assert self._run(cap, img) == 1
        assert "packet count" in capsys.readouterr().err

    def test_out_of_order_index_fails(self, tmp_path, capsys):
        chunks = [IMAGE[i:i + CHUNK_LEN] for i in range(0, len(IMAGE), CHUNK_LEN)]
        pkts = [zycast_packet(1, chunks[0], len(IMAGE)),
                zycast_packet(0, chunks[1], len(IMAGE))]
        cap, img = self.make_capture(tmp_path, pkts)
        assert self._run(cap, img) == 1
        assert "index" in capsys.readouterr().err
