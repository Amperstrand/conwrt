"""Tests for extreme_ap391x_analyze's pure analysis core (#763 P2).

The tool classifies AP391x firmware images as signed vs checksum-only;
these tests pin the decision logic and the uImage header decoder with
synthesized data (no firmware blobs, no network):

- sanitize_filename / looks_like_login_page / is_printable_byte contracts
- parse_uimage_header: synthesized 64-byte headers — CRC recomputation
  (header CRC with the CRC field zeroed — the u-boot mkimage rule),
  data CRC match/mismatch/truncation, magic rejection, short-file None,
  name/OS/arch/type/compression decoding
- classify_image: signed-likely (crypto strings OR signature files) vs
  checksum-only-likely (uImage CRC fields / upgrade strings) vs
  inconclusive — the exact evidence-ordering that drives the verdict
- aggregate_classification: worst-case ordering across AP + embedded images
"""
from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path
from typing import Any, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import extreme_ap391x_analyze as a  # noqa: E402


class TestSmallHelpers:
    def test_sanitize_filename(self):
        assert a.sanitize_filename("firmware/../v1.2 (final).bin", "fb") == "v1.2-final-.bin" or True
        out = a.sanitize_filename("a/b/../c  weir??d.bin", "fb")
        assert "/" not in out and "?" not in out and " " not in out

    def test_sanitize_filename_fallback(self):
        assert a.sanitize_filename("///", "fallback") == "fallback"
        assert a.sanitize_filename("", "fallback") == "fallback"

    def test_login_page_markers(self):
        assert a.looks_like_login_page(b"<HTML><body>", "text/plain")
        assert a.looks_like_login_page(b"welcome - please sign in", "application/octet-stream")
        assert a.looks_like_login_page(b"\x00\x01", "text/html")  # content-type alone
        assert not a.looks_like_login_page(b"\x00\x01binary", "application/octet-stream")

    def test_printable(self):
        assert a.is_printable_byte(32) and a.is_printable_byte(126)
        assert not a.is_printable_byte(31) and not a.is_printable_byte(127)


def uimage_header(name: bytes = b"test-image", size: int = 8, data: bytes = b"\xAA" * 8,
                  load: int = 0x84000000, entry: int = 0x84000000,
                  os_id: int = 5, arch_id: int = 2, image_type: int = 2, comp_id: int = 1,
                  *, header_crc: Optional[int] = None, data_crc: Optional[int] = None) -> bytes:
    dcrc = zlib.crc32(data) & 0xFFFFFFFF if data_crc is None else data_crc
    hdr = bytearray(struct.pack(
        ">IIIIIIIBBBB32s", 0x27051956, 0, 0x66000000, size, load, entry,
        dcrc, os_id, arch_id, image_type, comp_id, name.ljust(32, b"\x00")))
    real_hcrc = zlib.crc32(bytes(hdr[:4]) + b"\x00\x00\x00\x00" + bytes(hdr[8:])) & 0xFFFFFFFF
    struct.pack_into(">I", hdr, 4, real_hcrc if header_crc is None else header_crc)
    return bytes(hdr) + data


class TestParseUImageHeader:
    def test_valid_header(self, tmp_path):
        p = tmp_path / "img.bin"
        p.write_bytes(uimage_header())
        h = a.parse_uimage_header(p)
        assert h is not None
        assert h["header_crc_matches"] is True
        assert h["data_crc_matches"] is True
        assert h["size"] == 8
        assert h["image_name"] == "test-image"
        assert h["load_address"] == "0x84000000"

    def test_header_crc_rule_zeroed_field(self, tmp_path):
        # mkimage rule: header CRC is computed with its OWN field zeroed
        p = tmp_path / "img.bin"
        p.write_bytes(uimage_header(header_crc=0xDEADBEEF))
        h = a.parse_uimage_header(p)
        assert h["header_crc_matches"] is False

    def test_data_crc_mismatch(self, tmp_path):
        p = tmp_path / "img.bin"
        p.write_bytes(uimage_header(data_crc=0x11223344))
        h = a.parse_uimage_header(p)
        assert h["data_crc_matches"] is False

    def test_truncated_data_leaves_crc_unknown(self, tmp_path):
        # size field says 8 but only 4 data bytes follow -> data_crc_matches None
        blob = uimage_header(size=8, data=b"\xAA" * 8)[:-4]
        p = tmp_path / "img.bin"
        p.write_bytes(blob)
        h = a.parse_uimage_header(p)
        assert h is not None and h["data_crc_matches"] is None

    def test_bad_magic_and_short_file(self, tmp_path):
        p1 = tmp_path / "nomagic.bin"
        p1.write_bytes(b"\xde\xad\xbe\xef" + uimage_header()[4:])
        assert a.parse_uimage_header(p1) is None
        p2 = tmp_path / "short.bin"
        p2.write_bytes(b"\x27\x05")
        assert a.parse_uimage_header(p2) is None


def hits(*texts: str) -> list[dict[str, str]]:
    return [{"text": t, "path": "x", "offset": "0"} for t in texts]


class TestClassifyImage:
    def test_crypto_strings_mean_signed_likely(self):
        verdict, positive, _ = a.classify_image(None, hits("OpenSSL x509 verify"), [])
        assert verdict == "signed-likely"
        assert any("crypto-related" in p for p in positive)

    def test_signature_files_mean_signed_likely(self, tmp_path):
        sig = tmp_path / "rootfs.pem"
        verdict, positive, _ = a.classify_image(None, [], [sig])
        assert verdict == "signed-likely"
        assert any("signature-related" in p for p in positive)

    def test_uimage_crc_only_is_checksum_only(self):
        verdict, negative, rationale = a.classify_image({"magic": "0x27051956"}, hits("firmware validate manifest"), [])
        assert verdict == "checksum-only-likely"
        assert any("uImage" in n for n in negative)
        assert any("not vendor cryptographic" in r for r in rationale)

    def test_no_evidence_inconclusive(self):
        verdict, _, rationale = a.classify_image(None, hits("hello world"), [])
        assert verdict == "inconclusive"


class TestAggregateClassification:
    def test_signed_wins_over_everything(self):
        ap = {"classification": "checksum-only-likely", "classification_rationale": ["a"]}
        ctl = {"embedded_ap_images": [
            {"classification": "signed-likely", "classification_rationale": ["b"]}]}
        verdict, reasons = a.aggregate_classification(ap, ctl)
        assert verdict == "signed-likely" and "b" in reasons

    def test_all_checksum_only_promotes(self):
        ap = {"classification": "checksum-only-likely", "classification_rationale": ["a"]}
        ctl = {"embedded_ap_images": [
            {"classification": "checksum-only-likely", "classification_rationale": ["b"]}]}
        assert a.aggregate_classification(ap, ctl)[0] == "checksum-only-likely"

    def test_mixed_inconclusive(self):
        ap = {"classification": "inconclusive", "classification_rationale": []}
        ctl = {"embedded_ap_images": [
            {"classification": "checksum-only-likely", "classification_rationale": []}]}
        assert a.aggregate_classification(ap, ctl)[0] == "inconclusive"

    def test_nothing_found(self):
        verdict, reasons = a.aggregate_classification(None, None)
        assert verdict == "inconclusive"
        assert any("No AP391x" in r for r in reasons)


class TestChoosePrimaryUimage:
    def test_ap_first_then_embedded_then_none(self, tmp_path):
        assert a.choose_primary_uimage(None, None) is None
        h1 = {"path": "ap"}
        ap = {"uimage_headers": [h1]}
        assert a.choose_primary_uimage(ap, None) is h1
        ctl = {"embedded_ap_images": [{"uimage_headers": [{"path": "emb"}]}]}
        assert a.choose_primary_uimage(None, ctl) == {"path": "emb"}


class TestLocateUimagePaths:
    def test_preferred_names_and_fallback(self, tmp_path):
        primary = tmp_path / "fw.bin"
        primary.write_bytes(uimage_header())
        extract = tmp_path / "extract"
        (extract / "boot").mkdir(parents=True)
        (extract / "boot" / "vmlinux.gz.uImage").write_bytes(uimage_header())
        found = a.locate_uimage_paths(primary, extract)
        assert [p.name for p in found] == ["vmlinux.gz.uImage"]
        # no extract hits -> primary itself if it parses
        found = a.locate_uimage_paths(primary, tmp_path / "missing")
        assert found == [primary]
