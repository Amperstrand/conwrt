"""Tests for scripts/zycast.py — pure logic, packet construction, checksum,
subprocess-mockable functions, and ZycastPythonSender Popen shim."""

import os
import struct
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from zycast import (
    _IMAGE_TYPE_MAP,
    _ZYCAST_CHUNK_SIZE,
    _ZYCAST_HEADER_FMT,
    _ZYCAST_HEADER_SIZE,
    _ZYCAST_MAGIC,
    ZYCAST_SOURCE_SHA256,
    ZycastPythonSender,
    _binary_matches_source,
    _compile,
    _download_source,
    _zycast_checksum,
    ensure_zycast_binary,
    run_zycast,
    run_zycast_auto,
    zycast_send_python,
)


# ---------------------------------------------------------------------------
# 1. Pure logic: constants
# ---------------------------------------------------------------------------


class TestConstants(TestCase):
    def test_image_type_map_values(self):
        self.assertEqual(_IMAGE_TYPE_MAP["bootbase"], 0x01)
        self.assertEqual(_IMAGE_TYPE_MAP["rom"], 0x02)
        self.assertEqual(_IMAGE_TYPE_MAP["ras"], 0x04)
        self.assertEqual(_IMAGE_TYPE_MAP["romd"], 0x08)
        self.assertEqual(_IMAGE_TYPE_MAP["backup"], 0x10)

    def test_header_size_is_30(self):
        self.assertEqual(_ZYCAST_HEADER_SIZE, 30)

    def test_chunk_size_is_1024(self):
        self.assertEqual(_ZYCAST_CHUNK_SIZE, 1024)

    def test_magic_value(self):
        self.assertEqual(_ZYCAST_MAGIC, 0x7A797800)


# ---------------------------------------------------------------------------
# 2. Pure logic: checksum
# ---------------------------------------------------------------------------


class TestZycastChecksum(TestCase):
    def test_empty_bytes(self):
        self.assertEqual(_zycast_checksum(b""), 0)

    def test_single_byte(self):
        self.assertEqual(_zycast_checksum(b"\x01"), 1)

    def test_known_pattern(self):
        data = bytes(range(256))
        total = sum(data)
        expected = ((total >> 16) + total) & 0xFFFF
        self.assertEqual(_zycast_checksum(data), expected)

    def test_folding_overflow(self):
        data = b"\xff" * 4
        result = _zycast_checksum(data)
        self.assertIsInstance(result, int)
        self.assertLessEqual(result, 0xFFFF)


# ---------------------------------------------------------------------------
# 3. Header construction roundtrip
# ---------------------------------------------------------------------------


class TestHeaderConstruction(TestCase):
    def test_pack_unpack_roundtrip(self):
        chunk = b"\xAB" * 128
        checksum = _zycast_checksum(chunk)
        header = struct.pack(
            _ZYCAST_HEADER_FMT,
            _ZYCAST_MAGIC,
            checksum,
            42,          # packet_id
            128,         # chunk_len
            65536,       # file_len
            0,           # unused
            0x04,        # type (ras)
            0x04,        # images
            b"FF",       # country code
            0x01,        # flags
            b"\x00" * 5, # reserved
        )
        self.assertEqual(len(header), 30)
        fields = struct.unpack(_ZYCAST_HEADER_FMT, header)
        self.assertEqual(fields[0], _ZYCAST_MAGIC)
        self.assertEqual(fields[1], checksum)
        self.assertEqual(fields[2], 42)
        self.assertEqual(fields[3], 128)
        self.assertEqual(fields[4], 65536)
        self.assertEqual(fields[7], 0x04)
        self.assertEqual(fields[8], b"FF")

    def test_header_payload_concatenation_size(self):
        chunk = b"\x00" * _ZYCAST_CHUNK_SIZE
        header = struct.pack(
            _ZYCAST_HEADER_FMT,
            _ZYCAST_MAGIC, 0, 0, _ZYCAST_CHUNK_SIZE, _ZYCAST_CHUNK_SIZE,
            0, 0x04, 0x04, b"FF", 0x01, b"\x00" * 5,
        )
        packet = header + chunk
        self.assertEqual(len(packet), 30 + 1024)


# ---------------------------------------------------------------------------
# 4. _binary_matches_source (mocked Path)
# ---------------------------------------------------------------------------


class TestBinaryMatchesSource(TestCase):
    def test_binary_missing_returns_false(self):
        binary = MagicMock()
        binary.is_file.return_value = False
        source = MagicMock()
        self.assertFalse(_binary_matches_source(binary, source))

    def test_binary_newer_returns_true(self):
        binary = MagicMock()
        binary.is_file.return_value = True
        binary.stat.return_value.st_mtime = 100.0
        source = MagicMock()
        source.stat.return_value.st_mtime = 50.0
        self.assertTrue(_binary_matches_source(binary, source))

    def test_binary_older_returns_false(self):
        binary = MagicMock()
        binary.is_file.return_value = True
        binary.stat.return_value.st_mtime = 10.0
        source = MagicMock()
        source.stat.return_value.st_mtime = 50.0
        self.assertFalse(_binary_matches_source(binary, source))


# ---------------------------------------------------------------------------
# 5. _compile (mocked subprocess)
# ---------------------------------------------------------------------------


class TestCompile(TestCase):
    @patch("zycast.subprocess.run")
    @patch("platform.system", return_value="Linux")
    def test_compile_success(self, mock_platform, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        result = _compile(Path("/tmp/zycast.c"), Path("/tmp/zycast"))
        self.assertTrue(result)
        cmd = mock_run.call_args[0][0]
        self.assertIn("-o", cmd)

    @patch("zycast.subprocess.run")
    @patch("platform.system", return_value="Darwin")
    def test_compile_nonlinux_adds_msg_more_flag(self, mock_platform, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        _compile(Path("/tmp/zycast.c"), Path("/tmp/zycast"))
        cmd = mock_run.call_args[0][0]
        self.assertIn("-DMSG_MORE=0", cmd)

    @patch("zycast.subprocess.run")
    @patch("platform.system", return_value="Linux")
    def test_compile_failure_returns_false(self, mock_platform, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stderr="error")
        result = _compile(Path("/tmp/zycast.c"), Path("/tmp/zycast"))
        self.assertFalse(result)

    @patch("zycast.subprocess.run")
    @patch("platform.system", return_value="Linux")
    def test_compile_uses_cc_env_var(self, mock_platform, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        with patch.dict(os.environ, {"CC": "gcc-12"}):
            _compile(Path("/tmp/zycast.c"), Path("/tmp/zycast"))
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[0], "gcc-12")


# ---------------------------------------------------------------------------
# 6. run_zycast command construction (mocked Popen)
# ---------------------------------------------------------------------------


class TestRunZycast(TestCase):
    @patch("zycast.subprocess.Popen")
    def test_minimal_command(self, mock_popen):
        mock_popen.return_value = MagicMock()
        proc = run_zycast(Path("/bin/zycast"), "/tmp/fw.bin")
        cmd = mock_popen.call_args[0][0]
        self.assertEqual(cmd[0], "/bin/zycast")
        self.assertIn("/tmp/fw.bin", cmd)
        self.assertNotIn("-i", cmd)

    @patch("zycast.subprocess.Popen")
    def test_with_interface(self, mock_popen):
        mock_popen.return_value = MagicMock()
        run_zycast(Path("/bin/zycast"), "/tmp/fw.bin", interface="eth0")
        cmd = mock_popen.call_args[0][0]
        self.assertIn("-i", cmd)
        self.assertIn("eth0", cmd)

    @patch("zycast.subprocess.Popen")
    def test_custom_multicast_params(self, mock_popen):
        mock_popen.return_value = MagicMock()
        run_zycast(
            Path("/bin/zycast"), "/tmp/fw.bin",
            multicast_group="239.1.1.1", multicast_port=9000,
        )
        cmd = mock_popen.call_args[0][0]
        self.assertIn("-g", cmd)
        self.assertIn("239.1.1.1", cmd)
        self.assertIn("-p", cmd)
        self.assertIn("9000", cmd)

    @patch("zycast.subprocess.Popen")
    def test_image_type_passed(self, mock_popen):
        mock_popen.return_value = MagicMock()
        run_zycast(Path("/bin/zycast"), "/tmp/fw.bin", image_type="bootbase")
        cmd = mock_popen.call_args[0][0]
        self.assertIn("-t", cmd)
        self.assertIn("bootbase", cmd)

    @patch("zycast.subprocess.Popen")
    def test_extra_args_appended(self, mock_popen):
        mock_popen.return_value = MagicMock()
        run_zycast(
            Path("/bin/zycast"), "/tmp/fw.bin",
            extra_args=["--verbose", "--retry=3"],
        )
        cmd = mock_popen.call_args[0][0]
        self.assertIn("--verbose", cmd)
        self.assertIn("--retry=3", cmd)

    @patch("zycast.subprocess.Popen")
    def test_image_path_is_last_arg(self, mock_popen):
        mock_popen.return_value = MagicMock()
        run_zycast(Path("/bin/zycast"), "/tmp/myimage.bin")
        cmd = mock_popen.call_args[0][0]
        self.assertEqual(cmd[-1], "/tmp/myimage.bin")


# ---------------------------------------------------------------------------
# 7. ensure_zycast_binary (mocked download + compile + subprocess)
# ---------------------------------------------------------------------------


class TestEnsureZycastBinary(TestCase):
    @patch("zycast._compile", return_value=True)
    @patch("zycast._download_source")
    @patch("zycast._binary_matches_source", return_value=False)
    def test_compiles_when_no_cached_binary(self, mock_match, mock_dl, mock_compile):
        mock_dl.return_value = Path("/fake/zycast.c")
        with patch.object(Path, "chmod"):
            result = ensure_zycast_binary()
        mock_compile.assert_called_once()
        self.assertEqual(result, mock_compile.call_args[0][1])

    @patch("zycast.subprocess.run")
    @patch("zycast._download_source")
    @patch("zycast._binary_matches_source", return_value=True)
    def test_uses_cached_binary(self, mock_match, mock_dl, mock_run):
        mock_dl.return_value = Path("/fake/zycast.c")
        mock_run.return_value = MagicMock(returncode=0)
        result = ensure_zycast_binary()
        self.assertEqual(result.name, "zycast")

    @patch("zycast._compile", return_value=False)
    @patch("zycast._download_source")
    @patch("zycast._binary_matches_source", return_value=False)
    def test_raises_on_compile_failure(self, mock_match, mock_dl, mock_compile):
        mock_dl.return_value = Path("/fake/zycast.c")
        with self.assertRaises(RuntimeError):
            ensure_zycast_binary()

    @patch("zycast._compile", return_value=True)
    @patch("zycast._download_source")
    @patch("zycast._binary_matches_source", return_value=False)
    def test_force_rebuild_ignores_cache(self, mock_match, mock_dl, mock_compile):
        mock_dl.return_value = Path("/fake/zycast.c")
        with patch.object(Path, "chmod"):
            ensure_zycast_binary(force_rebuild=True)
        mock_match.assert_not_called()
        mock_compile.assert_called_once()


# ---------------------------------------------------------------------------
# 8. _download_source (mocked file I/O + urllib)
# ---------------------------------------------------------------------------


class TestDownloadSource(TestCase):
    @patch("zycast.ZYCAST_HASH_FILE", new_callable=MagicMock)
    @patch("zycast.ZYCAST_SOURCE_CACHED", new_callable=MagicMock)
    @patch("zycast.CACHE_DIR", new_callable=MagicMock)
    def test_uses_cached_source_when_hash_matches(
        self, mock_cache_dir, mock_cached, mock_hash_file
    ):
        mock_cached.is_file.return_value = True
        mock_hash_file.is_file.return_value = True
        mock_hash_file.read_text.return_value = ZYCAST_SOURCE_SHA256
        mock_cached.read_bytes.return_value = b"fake source"
        with patch("hashlib.sha256") as mock_sha:
            mock_sha.return_value.hexdigest.return_value = ZYCAST_SOURCE_SHA256
            result = _download_source()
        self.assertEqual(result, mock_cached)

    @patch("zycast.urllib.request.urlopen")
    @patch("zycast.ZYCAST_HASH_FILE", new_callable=MagicMock)
    @patch("zycast.ZYCAST_SOURCE_CACHED", new_callable=MagicMock)
    @patch("zycast.CACHE_DIR", new_callable=MagicMock)
    def test_raises_on_sha_mismatch(
        self, mock_cache_dir, mock_cached, mock_hash_file, mock_urlopen
    ):
        mock_cached.is_file.return_value = False
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"wrong content"
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        with patch("hashlib.sha256") as mock_sha:
            mock_sha.return_value.hexdigest.return_value = "badhash"
            with self.assertRaises(RuntimeError) as ctx:
                _download_source()
            self.assertIn("SHA-256 mismatch", str(ctx.exception))


# ---------------------------------------------------------------------------
# 9. ZycastPythonSender (mocked socket + file I/O)
# ---------------------------------------------------------------------------


class TestZycastPythonSender(TestCase):
    @patch("zycast.socket.socket")
    def test_terminate_stops_sender(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x00" * 2048)
            tmp = f.name
        try:
            sender = ZycastPythonSender(tmp)
            sender.terminate()
            sender.wait(timeout=5)
            self.assertEqual(sender.returncode, 0)
            self.assertIsNotNone(sender.poll())
        finally:
            os.unlink(tmp)

    @patch("zycast.socket.socket")
    def test_kill_alias(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x00" * 512)
            tmp = f.name
        try:
            sender = ZycastPythonSender(tmp)
            sender.kill()
            sender.wait(timeout=5)
            self.assertEqual(sender.returncode, 0)
        finally:
            os.unlink(tmp)

    @patch("zycast.socket.socket")
    def test_stdout_stderr_are_none(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x00" * 256)
            tmp = f.name
        try:
            sender = ZycastPythonSender(tmp)
            self.assertIsNone(sender.stdout)
            self.assertIsNone(sender.stderr)
            sender.terminate()
            sender.wait(timeout=5)
        finally:
            os.unlink(tmp)


# ---------------------------------------------------------------------------
# 10. zycast_send_python (mocked socket)
# ---------------------------------------------------------------------------


class TestZycastSendPython(TestCase):
    @patch("zycast.socket.socket")
    def test_sends_correct_number_of_packets(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            # 2048 bytes = 2 chunks of 1024
            f.write(b"\xAA" * 2048)
            tmp = f.name
        try:
            stop = threading.Event()
            # Stop after one loop iteration via timer
            threading.Timer(0.2, stop.set).start()
            zycast_send_python(tmp, _stop_event=stop)
            # Should have sent at least 2 calls (header+chunk per packet)
            self.assertGreaterEqual(mock_sock.send.call_count, 2)
        finally:
            os.unlink(tmp)

    @patch("zycast.socket.socket")
    def test_packet_has_magic_header(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\xBB" * 100)
            tmp = f.name
        try:
            stop = threading.Event()
            threading.Timer(0.2, stop.set).start()
            zycast_send_python(tmp, _stop_event=stop)
            first_packet = mock_sock.send.call_args_list[0][0][0]
            magic = struct.unpack("!I", first_packet[:4])[0]
            self.assertEqual(magic, _ZYCAST_MAGIC)
        finally:
            os.unlink(tmp)


# ---------------------------------------------------------------------------
# 11. run_zycast_auto fallback
# ---------------------------------------------------------------------------


class TestRunZycastAuto(TestCase):
    @patch("zycast.ensure_zycast_binary", side_effect=RuntimeError("no cc"))
    @patch("zycast.ZycastPythonSender")
    def test_falls_back_to_python_sender(self, mock_sender_cls, mock_ensure):
        mock_sender = MagicMock()
        mock_sender_cls.return_value = mock_sender
        result = run_zycast_auto("/tmp/fw.bin")
        mock_sender_cls.assert_called_once()
        self.assertEqual(result, mock_sender)

    @patch("zycast.run_zycast")
    @patch("zycast.ensure_zycast_binary")
    def test_uses_c_binary_when_available(self, mock_ensure, mock_run):
        mock_ensure.return_value = Path("/bin/zycast")
        mock_proc = MagicMock()
        mock_run.return_value = mock_proc
        result = run_zycast_auto("/tmp/fw.bin")
        mock_run.assert_called_once()
        self.assertEqual(result, mock_proc)
