"""Unit tests for the MAAS WoL webhook helper (#183).

Network calls are patched — these pin the pure logic: MAC validation,
magic-packet construction (6x0xFF + 16xMAC), and the dual-port send.
"""

import sys
from pathlib import Path
from types import SimpleNamespace
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


# #367 regression tests (PR #183 review debt)
class Test367Fixes:
    def test_ping_host_never_reports_stopped_on_flaky_path(self):
        """Item 1: some-but-not-all successes → 'degraded', never a
        confident 'stopped' that triggers unnecessary MAAS wakes."""
        from maas_wol_webhook import ping_host
        with patch("maas_wol_webhook.subprocess.run") as mock_run:
            # attempt 1 fails (transient), attempts 2-3 succeed
            mock_run.return_value = SimpleNamespace(returncode=1)
            # use side_effect for per-attempt results
            mock_run.side_effect = None
            results = [SimpleNamespace(returncode=rc) for rc in (1, 0, 0)]
            mock_run.side_effect = results
            assert ping_host("10.0.0.5") == "degraded"
            # all-fail → stopped (the honest verdict)
            mock_run.side_effect = [SimpleNamespace(returncode=1)] * 3
            assert ping_host("10.0.0.5") == "stopped"
            # all-pass → running
            mock_run.side_effect = [SimpleNamespace(returncode=0)] * 3
            assert ping_host("10.0.0.5") == "running"

    def test_wol_send_fails_loudly_when_interface_unbindable(self):
        """Item 2: an unbindable --interface must fail the send, not
        silently broadcast via the default route."""
        import socket as socket_mod
        from maas_wol_webhook import send_wol
        real_socket = socket_mod.socket

        class RefusingSocket:
            def __init__(self, *a, **k):
                self._s = real_socket(*a, **k)
            def setsockopt(self, *a, **k):
                if a[1] == 25:  # SO_BINDTODEVICE
                    raise OSError(1, "Operation not permitted")
                return self._s.setsockopt(*a, **k)
            def sendto(self, *a, **k):
                raise AssertionError("sendto reached despite unbindable interface")
            def close(self):
                self._s.close()

        with patch("socket.socket", RefusingSocket):
            assert send_wol("aa:bb:cc:dd:ee:ff", interface="bench0") is False
