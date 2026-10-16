"""Unit tests for the MAAS WoL webhook helper (#183).

Network calls are patched — these pin the pure logic: MAC validation,
magic-packet construction (6x0xFF + 16xMAC), and the dual-port send.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))

from maas_wol_webhook import send_wol  # noqa: E402


def recorder_socket():
    sock = MagicMock()
    sock.sendto = MagicMock()
    return sock


def test_magic_packet_shape_and_dual_port():
    sock = recorder_socket()
    with patch("socket.socket", return_value=sock):
        assert send_wol("AA:BB:CC:11:22:33") is True
    assert sock.sendto.call_count == 2
    payload, dest = sock.sendto.call_args_list[0].args
    assert dest == ("255.255.255.255", 9)
    assert sock.sendto.call_args_list[1].args[1] == ("255.255.255.255", 7)
    mac = bytes.fromhex("aabbcc112233")
    assert payload == b"\xff" * 6 + mac * 16


def test_mac_format_tolerance():
    sock = recorder_socket()
    with patch("socket.socket", return_value=sock):
        assert send_wol("AA-BB-CC-11-22-33") is True
        assert send_wol("aabbcc112233") is True


def test_invalid_macs_refused_without_sending():
    for bad in ["", "aa:bb", "zz:bb:cc:11:22:33", "aa:bb:cc:11:22:33:44"]:
        sock = recorder_socket()
        with patch("socket.socket", return_value=sock):
            assert send_wol(bad) is False, bad
        sock.sendto.assert_not_called()
