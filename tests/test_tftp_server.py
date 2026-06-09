import importlib.util
import socket
import struct
import sys
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock, mock_open, patch


_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS))


def _load_tftp_server():
    spec = importlib.util.spec_from_file_location(
        "tftp_server", _SCRIPTS / "tftp-server.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["tftp_server"] = module
    spec.loader.exec_module(module)
    return module


tftp_server = _load_tftp_server()


class TestSendError(TestCase):
    def test_packs_opcode_code_and_message(self):
        sock = MagicMock()
        tftp_server._send_error(sock, ("1.2.3.4", 6900), 1, "File not found")
        sock.sendto.assert_called_once()
        payload, addr = sock.sendto.call_args[0]
        self.assertEqual(addr, ("1.2.3.4", 6900))
        # OP_ERROR=5, code=1, message + null terminator
        op, code = struct.unpack("!HH", payload[:4])
        self.assertEqual(op, tftp_server.OP_ERROR)
        self.assertEqual(code, 1)
        self.assertEqual(payload[4:], b"File not found\x00")

    def test_packs_zero_code_with_arbitrary_message(self):
        sock = MagicMock()
        tftp_server._send_error(sock, ("10.0.0.1", 12345), 0, "Malformed request")
        payload, _ = sock.sendto.call_args[0]
        op, code = struct.unpack("!HH", payload[:4])
        self.assertEqual(op, 5)
        self.assertEqual(code, 0)
        self.assertTrue(payload.endswith(b"\x00"))


class TestHandleRrqMalformed(TestCase):
    def test_too_few_parts_sends_error(self):
        sock = MagicMock()
        tftp_server._handle_rrq(b"filename\x00", ("addr", 1), sock, "/tmp")
        sock.sendto.assert_called_once()
        payload, _ = sock.sendto.call_args[0]
        self.assertIn(b"Malformed request", payload)


class TestHandleRrqUnsupportedMode(TestCase):
    def test_non_octet_mode_sends_error(self):
        sock = MagicMock()
        # parts = ["foo.bin", "netascii", ""]
        data = b"foo.bin\x00netascii\x00\x00"
        tftp_server._handle_rrq(data, ("a", 1), sock, "/tmp")
        sock.sendto.assert_called_once()
        payload, _ = sock.sendto.call_args[0]
        self.assertIn(b"Unsupported mode: netascii", payload)


class TestHandleRrqAccessViolation(TestCase):
    def test_path_traversal_sends_access_violation(self):
        sock = MagicMock()
        data = b"../etc/passwd\x00octet\x00\x00"
        tftp_server._handle_rrq(data, ("a", 1), sock, "/tmp")
        payload, _ = sock.sendto.call_args[0]
        op, code = struct.unpack("!HH", payload[:4])
        self.assertEqual(code, 2)
        self.assertIn(b"Access violation", payload)

    def test_absolute_path_sends_access_violation(self):
        sock = MagicMock()
        data = b"/etc/passwd\x00octet\x00\x00"
        tftp_server._handle_rrq(data, ("a", 1), sock, "/tmp")
        payload, _ = sock.sendto.call_args[0]
        op, code = struct.unpack("!HH", payload[:4])
        self.assertEqual(code, 2)


class TestHandleRrqFileNotFound(TestCase):
    @patch("tftp_server.os.path.isfile", return_value=False)
    def test_missing_file_sends_error_code_1(self, mock_isfile):
        sock = MagicMock()
        data = b"missing.bin\x00octet\x00\x00"
        tftp_server._handle_rrq(data, ("a", 1), sock, "/tmp")
        payload, _ = sock.sendto.call_args[0]
        op, code = struct.unpack("!HH", payload[:4])
        self.assertEqual(code, 1)
        self.assertIn(b"File not found", payload)


class TestHandleRrqSuccessfulTransfer(TestCase):
    @patch("tftp_server.os.path.isfile", return_value=True)
    @patch("tftp_server.socket.socket")
    def test_single_block_transfer(self, mock_socket_cls, mock_isfile):
        xfer = MagicMock()
        # context manager
        mock_socket_cls.return_value.__enter__.return_value = xfer
        # ACK for block 1
        ack = struct.pack("!HH", tftp_server.OP_ACK, 1)
        xfer.recvfrom.return_value = (ack, ("a", 1))

        m = mock_open(read_data=b"hello")
        with patch("builtins.open", m):
            tftp_server._handle_rrq(
                b"foo.bin\x00octet\x00\x00",
                ("client", 6900),
                MagicMock(),
                "/tmp",
            )
        # Sent one DATA packet
        sent_payload, sent_addr = xfer.sendto.call_args[0]
        op, block = struct.unpack("!HH", sent_payload[:4])
        self.assertEqual(op, tftp_server.OP_DATA)
        self.assertEqual(block, 1)
        self.assertEqual(sent_payload[4:], b"hello")
        self.assertEqual(sent_addr, ("client", 6900))

    @patch("tftp_server.os.path.isfile", return_value=True)
    @patch("tftp_server.socket.socket")
    def test_multi_block_transfer_increments_block_number(self, mock_socket_cls, mock_isfile):
        xfer = MagicMock()
        mock_socket_cls.return_value.__enter__.return_value = xfer

        def ack_for_block_n():
            n = 1
            while True:
                yield (struct.pack("!HH", tftp_server.OP_ACK, n), ("a", 1))
                n = (n % 65535) + 1
        gen = ack_for_block_n()
        xfer.recvfrom.side_effect = lambda *_a, **_k: next(gen)

        # 2 full blocks + 1 partial: BLOCK_SIZE=512
        data = b"A" * 512 + b"B" * 512 + b"C" * 100
        with patch("builtins.open", mock_open(read_data=data)):
            tftp_server._handle_rrq(
                b"foo.bin\x00octet\x00\x00",
                ("client", 6900),
                MagicMock(),
                "/tmp",
            )

        # Should have sent 3 DATA packets
        sent_blocks = []
        for call in xfer.sendto.call_args_list:
            payload = call[0][0]
            op, block = struct.unpack("!HH", payload[:4])
            sent_blocks.append((op, block, len(payload) - 4))
        self.assertEqual(sent_blocks[0], (tftp_server.OP_DATA, 1, 512))
        self.assertEqual(sent_blocks[1], (tftp_server.OP_DATA, 2, 512))
        self.assertEqual(sent_blocks[2], (tftp_server.OP_DATA, 3, 100))

    @patch("tftp_server.os.path.isfile", return_value=True)
    @patch("tftp_server.socket.socket")
    def test_exact_block_size_sends_final_empty_data(self, mock_socket_cls, mock_isfile):
        xfer = MagicMock()
        mock_socket_cls.return_value.__enter__.return_value = xfer
        block_seq = iter([
            (struct.pack("!HH", tftp_server.OP_ACK, 1), ("a", 1)),
            (struct.pack("!HH", tftp_server.OP_ACK, 2), ("a", 1)),
        ])
        xfer.recvfrom.side_effect = lambda *_a, **_k: next(block_seq)

        data = b"X" * 512  # exactly one block
        with patch("builtins.open", mock_open(read_data=data)):
            tftp_server._handle_rrq(
                b"foo.bin\x00octet\x00\x00",
                ("client", 6900),
                MagicMock(),
                "/tmp",
            )
        # 2 sends: block 1 (full), block 2 (empty terminator)
        sent_lens = []
        for call in xfer.sendto.call_args_list:
            payload = call[0][0]
            sent_lens.append(len(payload) - 4)
        self.assertEqual(sent_lens, [512, 0])


class TestHandleRrqTimeout(TestCase):
    @patch("tftp_server.os.path.isfile", return_value=True)
    @patch("tftp_server.socket.socket")
    def test_timeout_retries_then_gives_up(self, mock_socket_cls, mock_isfile):
        xfer = MagicMock()
        mock_socket_cls.return_value.__enter__.return_value = xfer
        xfer.recvfrom.side_effect = socket.timeout()

        with patch("builtins.open", mock_open(read_data=b"hello")):
            tftp_server._handle_rrq(
                b"foo.bin\x00octet\x00\x00",
                ("client", 6900),
                MagicMock(),
                "/tmp",
            )
        # RETRIES=5 sends attempted before giving up
        self.assertEqual(xfer.sendto.call_count, tftp_server.RETRIES)


class TestHandleRrqOsError(TestCase):
    @patch("tftp_server.os.path.isfile", return_value=True)
    @patch("tftp_server.socket.socket")
    def test_open_oserror_sends_error_packet(self, mock_socket_cls, mock_isfile):
        xfer = MagicMock()
        mock_socket_cls.return_value.__enter__.return_value = xfer

        with patch("builtins.open", side_effect=OSError("disk gone")):
            tftp_server._handle_rrq(
                b"foo.bin\x00octet\x00\x00",
                ("client", 6900),
                MagicMock(),
                "/tmp",
            )
        # _send_error called with the xfer socket
        xfer.sendto.assert_called_once()
        payload, _ = xfer.sendto.call_args[0]
        op, code = struct.unpack("!HH", payload[:4])
        self.assertEqual(op, tftp_server.OP_ERROR)
        self.assertIn(b"disk gone", payload)


class TestMainArgvValidation(TestCase):
    @patch.object(sys, "argv", ["tftp-server.py"])
    def test_no_args_exits_with_usage(self):
        with self.assertRaises(SystemExit) as cm:
            tftp_server.main()
        self.assertEqual(cm.exception.code, 1)

    @patch.object(sys, "argv", ["tftp-server.py", "a", "b", "c"])
    def test_too_many_args_exits_with_usage(self):
        with self.assertRaises(SystemExit) as cm:
            tftp_server.main()
        self.assertEqual(cm.exception.code, 1)


class TestMainDirectoryValidation(TestCase):
    @patch("tftp_server.os.path.isdir", return_value=False)
    @patch.object(sys, "argv", ["tftp-server.py", "/does/not/exist"])
    def test_invalid_directory_exits(self, mock_isdir):
        with self.assertRaises(SystemExit) as cm:
            tftp_server.main()
        self.assertEqual(cm.exception.code, 1)


class TestMainBindFailure(TestCase):
    @patch("tftp_server.os.path.isdir", return_value=True)
    @patch("tftp_server.socket.socket")
    @patch.object(sys, "argv", ["tftp-server.py", "/tmp"])
    def test_permission_error_on_bind_exits(self, mock_socket_cls, mock_isdir):
        sock = MagicMock()
        sock.bind.side_effect = PermissionError("port 69")
        mock_socket_cls.return_value = sock
        with self.assertRaises(SystemExit) as cm:
            tftp_server.main()
        self.assertEqual(cm.exception.code, 1)


class TestMainServeLoop(TestCase):
    @patch("tftp_server.os.path.isdir", return_value=True)
    @patch("tftp_server.socket.socket")
    @patch.object(sys, "argv", ["tftp-server.py", "/tmp"])
    def test_keyboard_interrupt_closes_socket(self, mock_socket_cls, mock_isdir):
        sock = MagicMock()
        sock.recvfrom.side_effect = KeyboardInterrupt()
        mock_socket_cls.return_value = sock
        tftp_server.main()
        sock.close.assert_called_once()

    @patch("tftp_server.os.path.isdir", return_value=True)
    @patch("tftp_server.socket.socket")
    @patch("tftp_server._handle_rrq")
    @patch.object(sys, "argv", ["tftp-server.py", "/tmp", "127.0.0.1"])
    def test_rrq_packet_dispatched_to_handler(self, mock_handle, mock_socket_cls, mock_isdir):
        sock = MagicMock()
        rrq_packet = struct.pack("!H", tftp_server.OP_RRQ) + b"foo\x00octet\x00\x00"
        sock.recvfrom.side_effect = [
            (rrq_packet, ("client", 6900)),
            KeyboardInterrupt(),
        ]
        mock_socket_cls.return_value = sock
        tftp_server.main()
        mock_handle.assert_called_once()
        sock.bind.assert_called_with(("127.0.0.1", 69))

    @patch("tftp_server.os.path.isdir", return_value=True)
    @patch("tftp_server.socket.socket")
    @patch("tftp_server._handle_rrq")
    @patch.object(sys, "argv", ["tftp-server.py", "/tmp"])
    def test_non_rrq_packet_ignored(self, mock_handle, mock_socket_cls, mock_isdir):
        sock = MagicMock()
        non_rrq = struct.pack("!H", tftp_server.OP_ACK) + b"junk"
        sock.recvfrom.side_effect = [
            (non_rrq, ("client", 6900)),
            KeyboardInterrupt(),
        ]
        mock_socket_cls.return_value = sock
        tftp_server.main()
        mock_handle.assert_not_called()
