import importlib.util
import io
import lzma
import struct
import sys
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch


_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS))


def _load_repack():
    spec = importlib.util.spec_from_file_location(
        "gs1920_repack", _SCRIPTS / "gs1920-repack-firmware.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["gs1920_repack"] = module
    spec.loader.exec_module(module)
    return module


rp = _load_repack()


def _make_header(
    addr=0x80100000,
    sig=b"SIG",
    type_=0x03,
    osize=0,
    csize=0,
    flags=0x40,
    ocsum=0,
    ccsum=0,
    ver=b"v1.00",
    mmap_addr=0x80200000,
    res2=0,
    res3=0,
):
    return struct.pack(
        rp.ROMBIN_HDR_FMT,
        addr,
        0,
        sig,
        type_,
        osize,
        csize,
        flags,
        0,
        ocsum,
        ccsum,
        ver.ljust(15, b"\0")[:15],
        mmap_addr,
        res2,
        res3,
    )


class TestInternetChecksumBasic(TestCase):
    def test_empty_returns_zero(self):
        self.assertEqual(rp.internet_checksum(b""), 0)

    def test_single_word(self):
        self.assertEqual(rp.internet_checksum(b"\x00\x01"), 1)

    def test_two_words_no_overflow(self):
        self.assertEqual(rp.internet_checksum(b"\x00\x01\x00\x02"), 3)

    def test_odd_length_zero_padded(self):
        self.assertEqual(
            rp.internet_checksum(b"\x00\x01\x00"),
            rp.internet_checksum(b"\x00\x01\x00\x00"),
        )


class TestInternetChecksumOverflow(TestCase):
    def test_carry_wraps(self):
        self.assertEqual(rp.internet_checksum(b"\xFF\xFF\x00\x01"), 0x0001)

    def test_all_ones_two_words(self):
        self.assertEqual(rp.internet_checksum(b"\xFF\xFF\xFF\xFF"), 0xFFFF)

    def test_odd_single_high_byte(self):
        self.assertEqual(rp.internet_checksum(b"\xFF"), 0xFF00)


class TestRombinHeaderFormat(TestCase):
    def test_header_size_constant(self):
        self.assertEqual(rp.ROMBIN_HDR_SIZE, 48)

    def test_format_size_matches_constant(self):
        self.assertEqual(struct.calcsize(rp.ROMBIN_HDR_FMT), rp.ROMBIN_HDR_SIZE)


class TestParseRombinHeader(TestCase):
    def test_too_short_raises(self):
        with self.assertRaises(ValueError):
            rp.parse_rombin_header(b"\x00" * 10)

    def test_parses_all_fields(self):
        raw = _make_header(
            addr=0x80100000,
            type_=0x03,
            osize=0x12345,
            csize=0x6789,
            flags=0xE0,
            ocsum=0xABCD,
            ccsum=0x1234,
            ver=b"v2.00",
            mmap_addr=0x80200000,
        )
        h = rp.parse_rombin_header(raw)
        self.assertEqual(h["addr"], 0x80100000)
        self.assertEqual(h["sig"], b"SIG")
        self.assertEqual(h["type"], 0x03)
        self.assertEqual(h["osize"], 0x12345)
        self.assertEqual(h["csize"], 0x6789)
        self.assertEqual(h["flags"], 0xE0)
        self.assertEqual(h["ocsum"], 0xABCD)
        self.assertEqual(h["ccsum"], 0x1234)
        self.assertTrue(h["ver"].startswith(b"v2.00"))
        self.assertEqual(h["mmap_addr"], 0x80200000)

    def test_accepts_data_longer_than_header(self):
        raw = _make_header() + b"\xAA" * 100
        h = rp.parse_rombin_header(raw)
        self.assertEqual(h["sig"], b"SIG")


class TestBuildRombinHeader(TestCase):
    def test_roundtrip_preserves_fields(self):
        raw = _make_header(
            addr=0xDEADBEEF,
            type_=0x04,
            osize=0x1000,
            csize=0x800,
            flags=0xE0,
            ocsum=0x1234,
            ccsum=0x5678,
            ver=b"abcdef",
            mmap_addr=0xCAFEBABE,
        )
        parsed = rp.parse_rombin_header(raw)
        rebuilt = rp.build_rombin_header(parsed)
        self.assertEqual(rebuilt, raw)

    def test_output_is_48_bytes(self):
        parsed = rp.parse_rombin_header(_make_header())
        self.assertEqual(len(rp.build_rombin_header(parsed)), 48)


class TestDumpHeader(TestCase):
    def test_prints_without_error(self):
        h = rp.parse_rombin_header(_make_header(ver=b"v1.00"))
        with patch("sys.stdout", new_callable=io.StringIO) as out:
            rp.dump_header("test-label", h)
            text = out.getvalue()
        self.assertIn("test-label", text)
        self.assertIn("sig='SIG'", text)
        self.assertIn("v1.00", text)

    def test_handles_non_ascii_ver(self):
        h = rp.parse_rombin_header(_make_header(ver=b"\xFF\xFE"))
        with patch("sys.stdout", new_callable=io.StringIO) as out:
            rp.dump_header("label", h)
        self.assertIn("label", out.getvalue())


class TestFindSectionsSingleBootext(TestCase):
    def test_single_section_found(self):
        data = b"\x00" * 10
        hdr = _make_header(type_=0x03, osize=len(data), csize=0, flags=0x40)
        fw = hdr + data
        with patch("sys.stdout", new_callable=io.StringIO):
            sections = rp.find_sections(fw)
        self.assertEqual(len(sections), 1)
        self.assertEqual(sections[0]["offset"], 0)
        self.assertEqual(sections[0]["header"]["type"], 0x03)


class TestFindSectionsMultiSection(TestCase):
    def test_envelope_with_two_subsections(self):
        # RasCode data (type=0x04) is small, embedded
        rascode_data = b"R" * 32
        rascode_hdr = _make_header(
            type_=0x04, osize=len(rascode_data), csize=0, flags=0x40
        )
        rascode_section = rascode_hdr + rascode_data

        romdefa_data = b"D" * 16
        romdefa_hdr = _make_header(
            type_=0x04, osize=len(romdefa_data), csize=0, flags=0x40
        )
        romdefa_section = romdefa_hdr + romdefa_data

        # BootExt envelope covers everything after its header
        envelope_body = romdefa_section + rascode_section
        bootext_hdr = _make_header(
            type_=0x03, osize=len(envelope_body), csize=0, flags=0x40
        )
        fw = bootext_hdr + envelope_body

        with patch("sys.stdout", new_callable=io.StringIO):
            sections = rp.find_sections(fw)

        self.assertEqual(len(sections), 3)
        self.assertEqual(sections[0]["header"]["type"], 0x03)
        self.assertEqual(sections[1]["header"]["type"], 0x04)
        self.assertEqual(sections[2]["header"]["type"], 0x04)

    def test_compressed_csize_used_for_data(self):
        rascode_data = b"Z" * 40
        rascode_hdr = _make_header(
            type_=0x04, osize=200, csize=len(rascode_data), flags=0xE0
        )
        fw = rascode_hdr + rascode_data
        with patch("sys.stdout", new_callable=io.StringIO):
            sections = rp.find_sections(fw)
        self.assertEqual(len(sections), 1)
        self.assertEqual(len(sections[0]["data"]), len(rascode_data))


class TestFindSectionsClamping(TestCase):
    def test_truncates_section_to_file_size(self):
        # Header claims 1000 bytes but only 50 follow
        data = b"X" * 50
        hdr = _make_header(type_=0x04, osize=1000, csize=0, flags=0x40)
        fw = hdr + data
        with patch("sys.stdout", new_callable=io.StringIO):
            sections = rp.find_sections(fw)
        self.assertEqual(len(sections), 1)
        self.assertEqual(len(sections[0]["data"]), 50)


class TestFindSectionsSkipsInvalid(TestCase):
    def test_skips_unknown_type(self):
        # type=0x99 is not BOOTEXT or ROMBIN
        hdr = _make_header(type_=0x99)
        fw = hdr + b"\x00" * 50
        with patch("sys.stdout", new_callable=io.StringIO):
            sections = rp.find_sections(fw)
        self.assertEqual(sections, [])

    def test_no_sig_returns_empty(self):
        fw = b"\x00" * 200
        with patch("sys.stdout", new_callable=io.StringIO):
            sections = rp.find_sections(fw)
        self.assertEqual(sections, [])

    def test_skips_sig_inside_rombin_data(self):
        # ROMBIN section whose body contains a fake 'SIG' string
        inner = b"AAAA\x00\x00SIG\x04" + b"\x00" * 50
        rascode_hdr = _make_header(
            type_=0x04, osize=len(inner), csize=0, flags=0x40
        )
        fw = rascode_hdr + inner
        with patch("sys.stdout", new_callable=io.StringIO):
            sections = rp.find_sections(fw)
        self.assertEqual(len(sections), 1)
        self.assertEqual(sections[0]["offset"], 0)


class TestFindSectionsSortedByOffset(TestCase):
    def test_sections_in_offset_order(self):
        # Two ROMBIN sections back-to-back (no envelope)
        d1 = b"A" * 8
        d2 = b"B" * 8
        h1 = _make_header(type_=0x04, osize=len(d1), csize=0, flags=0x40)
        h2 = _make_header(type_=0x04, osize=len(d2), csize=0, flags=0x40)
        fw = h1 + d1 + h2 + d2
        with patch("sys.stdout", new_callable=io.StringIO):
            sections = rp.find_sections(fw)
        offsets = [s["offset"] for s in sections]
        self.assertEqual(offsets, sorted(offsets))


def _build_three_section_firmware(rascode_size=64, mmt_count=10):
    """Assemble a fake official-style firmware with BootExt + RomDefa + RasCode.

    Includes a MemMapT table inside BootExt so the repack path's MMT csum logic exercises.
    """
    mmap_addr = 0x80200000

    mmt = bytearray(24 + 16)
    struct.pack_into(">H", mmt, 0, mmt_count)
    struct.pack_into(">I", mmt, 2, mmap_addr)
    struct.pack_into(">I", mmt, 6, mmap_addr + 0x100)
    struct.pack_into(">H", mmt, 10, 0)
    mmt[24:40] = b"\xAA" * 16

    romdefa_data = b"D" * 32
    romdefa_hdr = _make_header(
        type_=0x04, osize=len(romdefa_data), csize=0, flags=0x40, mmap_addr=mmap_addr
    )

    rascode_data = b"R" * rascode_size
    rascode_hdr = _make_header(
        type_=0x04, osize=len(rascode_data), csize=0, flags=0x40, mmap_addr=mmap_addr
    )

    envelope = bytes(mmt) + romdefa_hdr + romdefa_data + rascode_hdr + rascode_data
    bootext_hdr = _make_header(
        type_=0x03, osize=len(envelope), csize=0, flags=0x40, mmap_addr=mmap_addr
    )
    return bootext_hdr + envelope


class TestMainSuccessPath(TestCase):
    def test_repack_uncompressed_writes_output(self, *args):
        official = _build_three_section_firmware(rascode_size=128)
        initramfs = b"K" * 200

        files = {}

        def fake_open(path, mode="r", *a, **kw):
            if "b" in mode and "w" in mode:
                buf = io.BytesIO()
                old_close = buf.close
                def closer():
                    files[path] = buf.getvalue()
                    old_close()
                buf.close = closer
                return buf
            if path == "/in/official.bin":
                return io.BytesIO(official)
            if path == "/in/initramfs.bin":
                return io.BytesIO(initramfs)
            if path in files:
                return io.BytesIO(files[path])
            raise FileNotFoundError(path)

        argv = [
            "gs1920-repack-firmware.py",
            "--official", "/in/official.bin",
            "--initramfs", "/in/initramfs.bin",
            "--output", "/out/new.bin",
        ]
        with patch.object(sys, "argv", argv), \
             patch("builtins.open", side_effect=fake_open), \
             patch("os.path.getsize", return_value=len(official)), \
             patch("sys.stdout", new_callable=io.StringIO):
            rp.main()

        self.assertIn("/out/new.bin", files)
        self.assertGreater(len(files["/out/new.bin"]), 48)


class TestMainVerifyFlag(TestCase):
    def test_verify_path_prints_checksums(self):
        official = _build_three_section_firmware(rascode_size=64)
        initramfs = b"K" * 64

        files = {}

        def fake_open(path, mode="r", *a, **kw):
            if "b" in mode and "w" in mode:
                buf = io.BytesIO()
                old_close = buf.close
                def closer():
                    files[path] = buf.getvalue()
                    old_close()
                buf.close = closer
                return buf
            if path == "/in/o.bin":
                return io.BytesIO(official)
            if path == "/in/k.bin":
                return io.BytesIO(initramfs)
            if path in files:
                return io.BytesIO(files[path])
            raise FileNotFoundError(path)

        argv = [
            "gs1920-repack-firmware.py",
            "--official", "/in/o.bin",
            "--initramfs", "/in/k.bin",
            "--output", "/out/v.bin",
            "--verify",
        ]
        with patch.object(sys, "argv", argv), \
             patch("builtins.open", side_effect=fake_open), \
             patch("os.path.getsize", return_value=len(official)), \
             patch("sys.stdout", new_callable=io.StringIO) as out:
            rp.main()

        text = out.getvalue()
        self.assertIn("Verifying official firmware checksums", text)
        self.assertIn("BootExt ocsum", text)


class TestMainCompressedFlag(TestCase):
    def test_compress_uses_lzma(self):
        official = _build_three_section_firmware(rascode_size=64)
        initramfs = b"K" * 512

        files = {}

        def fake_open(path, mode="r", *a, **kw):
            if "b" in mode and "w" in mode:
                buf = io.BytesIO()
                old_close = buf.close
                def closer():
                    files[path] = buf.getvalue()
                    old_close()
                buf.close = closer
                return buf
            if path == "/in/o.bin":
                return io.BytesIO(official)
            if path == "/in/k.bin":
                return io.BytesIO(initramfs)
            if path in files:
                return io.BytesIO(files[path])
            raise FileNotFoundError(path)

        argv = [
            "gs1920-repack-firmware.py",
            "--official", "/in/o.bin",
            "--initramfs", "/in/k.bin",
            "--output", "/out/c.bin",
            "--compress",
        ]
        with patch.object(sys, "argv", argv), \
             patch("builtins.open", side_effect=fake_open), \
             patch("os.path.getsize", return_value=len(official)), \
             patch("sys.stdout", new_callable=io.StringIO) as out:
            rp.main()

        text = out.getvalue()
        self.assertIn("Compressing initramfs with LZMA", text)
        self.assertIn("/out/c.bin", files)
        result = files["/out/c.bin"]
        sections = rp.find_sections(result)
        self.assertEqual(len(sections), 3)
        rascode_hdr = sections[2]["header"]
        self.assertTrue(rascode_hdr["flags"] & 0x80)
        decompressed = lzma.decompress(sections[2]["data"], format=lzma.FORMAT_ALONE)
        self.assertEqual(decompressed, initramfs)


class TestMainSectionCountError(TestCase):
    def test_too_few_sections_exits_1(self):
        # Only a single ROMBIN section, no envelope
        data = b"X" * 32
        hdr = _make_header(type_=0x04, osize=len(data), csize=0, flags=0x40)
        official = hdr + data

        def fake_open(path, mode="r", *a, **kw):
            return io.BytesIO(official) if path == "/in/o.bin" else io.BytesIO(b"K" * 32)

        argv = [
            "gs1920-repack-firmware.py",
            "--official", "/in/o.bin",
            "--initramfs", "/in/k.bin",
            "--output", "/out/x.bin",
        ]
        with patch.object(sys, "argv", argv), \
             patch("builtins.open", side_effect=fake_open), \
             patch("sys.stdout", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as cm:
                rp.main()
            self.assertEqual(cm.exception.code, 1)


class TestMainWrongTypeOrdering(TestCase):
    def _run_with(self, sections_blob):
        def fake_open(path, mode="r", *a, **kw):
            return io.BytesIO(sections_blob) if path == "/in/o.bin" else io.BytesIO(b"K" * 32)

        argv = [
            "gs1920-repack-firmware.py",
            "--official", "/in/o.bin",
            "--initramfs", "/in/k.bin",
            "--output", "/out/x.bin",
        ]
        with patch.object(sys, "argv", argv), \
             patch("builtins.open", side_effect=fake_open), \
             patch("sys.stdout", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as cm:
                rp.main()
            return cm.exception.code

    def test_first_not_bootext_exits_1(self):
        # Three ROMBIN sections, first is type=0x04 instead of 0x03
        d = b"D" * 16
        h = _make_header(type_=0x04, osize=len(d), csize=0, flags=0x40)
        fw = h + d + h + d + h + d
        self.assertEqual(self._run_with(fw), 1)
