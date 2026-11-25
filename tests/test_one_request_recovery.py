"""One-request recovery gate (#241): flagged models never issue an HTTP
request before the firmware POST.

The detection contract under test:
- one_request=True -> detect_uboot_http dispatches to the ARP check
  (ping solicitation + ip neigh); ZERO curl invocations.
- one_request=False (GL.iNet multi-request class) -> the legacy GET
  probe is untouched.
- The ARP check follows the flash-recovery.sh doctrine: lladdr + a
  live-ish neighbor state = armed; INCOMPLETE/FAILED/no entry = not.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from flash.upload import detect_uboot_arp, detect_uboot_http  # noqa: E402


def _run(stdout="", returncode=0):
    return MagicMock(stdout=stdout, stderr="", returncode=returncode)


class TestDetectUbootArp(unittest.TestCase):
    @patch("flash.upload.subprocess.run")
    def test_armed_neighbor(self, mock_run):
        # call 1: ping solicitation (no ICMP reply — rc 1 is expected);
        # call 2: ip neigh shows a MAC in a live state.
        mock_run.side_effect = [
            _run(returncode=1),
            _run(stdout="192.168.0.1 dev eth0 lladdr 3e:85:be:87:55:42 REACHABLE\n"),
        ]
        armed, reason = detect_uboot_arp("192.168.0.1", interface="eth0")
        self.assertTrue(armed)
        self.assertIn("REACHABLE", reason)
        self.assertIn("3e:85:be:87:55:42", reason)
        cmds = [c.args[0][:3] for c in mock_run.call_args_list]
        self.assertEqual(cmds[0][0], "ping")  # ARP solicited first
        self.assertEqual(cmds[1][0], "ip")

    @patch("flash.upload.subprocess.run")
    def test_stale_counts_but_failed_does_not(self, mock_run):
        for state, armed in (("STALE", True), ("FAILED", False),
                             ("INCOMPLETE", False)):
            mock_run.side_effect = [
                _run(returncode=1),
                _run(stdout=f"192.168.0.1 dev eth0 lladdr aa:bb:cc:dd:ee:01 {state}\n"),
            ]
            got, _ = detect_uboot_arp("192.168.0.1")
            self.assertEqual(got, armed, state)

    @patch("flash.upload.subprocess.run")
    def test_no_entry_not_armed(self, mock_run):
        mock_run.side_effect = [_run(returncode=1), _run(stdout="")]
        armed, reason = detect_uboot_arp("192.168.0.1")
        self.assertFalse(armed)
        self.assertIn("no neighbor entry", reason)

    @patch("flash.upload.subprocess.run")
    def test_interface_scopes_the_neigh_query(self, mock_run):
        mock_run.side_effect = [_run(returncode=1), _run(stdout="")]
        detect_uboot_arp("192.168.0.1", interface="enp0s31f6")
        neigh_cmd = mock_run.call_args_list[1].args[0]
        self.assertEqual(neigh_cmd[:3], ["ip", "neigh", "show"])
        self.assertIn("enp0s31f6", neigh_cmd)

    @patch("flash.upload.subprocess.run")
    def test_ip_tool_failure_is_not_armed(self, mock_run):
        mock_run.side_effect = OSError("no iproute2")
        armed, reason = detect_uboot_arp("192.168.0.1")
        self.assertFalse(armed)
        self.assertIn("arp probe failed", reason)


class TestOneRequestDispatch(unittest.TestCase):
    @patch("platform_utils.configure_interface_ip", lambda *a, **k: None)
    @patch("flash.upload.subprocess.run")
    def test_flagged_model_never_curls(self, mock_run):
        """THE #241 contract: one_request=True -> zero HTTP requests,
        arming read from the neighbor table only. (The client-alias
        setup is stubbed at its own seam — it shells out too.)"""
        mock_run.side_effect = [
            _run(returncode=1),  # ping
            _run(stdout="192.168.0.1 dev eth0 lladdr 3e:85:be:87:55:42 STALE\n"),
        ]
        found, detail = detect_uboot_http(
            "192.168.0.1", interface="eth0", client_ip="192.168.0.10",
            one_request=True)
        self.assertTrue(found)
        self.assertIn("ARP", detail)
        for call in mock_run.call_args_list:
            argv = call.args[0]
            self.assertNotEqual(argv[0], "curl",
                                 "one-request class must never be GET-probed")

    @patch("flash.upload.subprocess.run")
    def test_flagged_model_unarmed_flows_through(self, mock_run):
        mock_run.side_effect = [
            _run(returncode=1),  # ping
            _run(stdout=""),     # no neighbor
        ]
        found, detail = detect_uboot_http("192.168.0.1", one_request=True)
        self.assertFalse(found)
        self.assertIn("no neighbor entry", detail)

    @patch("flash.upload.subprocess.run")
    def test_unflagged_model_keeps_get_probe(self, mock_run):
        """GL.iNet multi-request class: the GET probe is unchanged."""
        mock_run.return_value = _run(stdout="<html>FIRMWARE UPDATE</html>")
        found, detail = detect_uboot_http("192.168.1.1", one_request=False)
        self.assertTrue(found)
        self.assertEqual(mock_run.call_args_list[0].args[0][0], "curl")


class TestProfileFlag(unittest.TestCase):
    def test_x1860_flagged_glinet_not(self):
        from flash.device_profile import build_profile_from_model
        self.assertTrue(build_profile_from_model(
            "dlink-covr-x1860-a1").one_request_recovery)
        self.assertFalse(build_profile_from_model(
            "glinet-gl-ar300m-lite").one_request_recovery)


class TestDispatcherPassesFlag(unittest.TestCase):
    def test_resolve_initial_state_uses_flag(self):
        """_resolve_initial_state forwards the profile flag: on a flagged
        model the uboot fast-path probe is ARP-only."""
        from conwrt.flash_dispatcher import _resolve_initial_state, State
        profile = SimpleNamespace(
            recovery_ip="192.168.0.1", client_ip="192.168.0.10",
            one_request_recovery=True, flash_method="recovery-http")
        with patch("conwrt.flash_dispatcher.detect_uboot_http",
                   wraps=__import__("flash.upload",
                                    fromlist=["detect_uboot_http"]).detect_uboot_http) as spy:
            with patch("flash.upload.subprocess.run") as mock_run:
                mock_run.side_effect = [
                    _run(returncode=1),  # ping solicitation
                    _run(stdout="192.168.0.1 dev eth0 lladdr "
                                "3e:85:be:87:55:42 REACHABLE\n"),
                ]
                state = _resolve_initial_state("uboot", profile, "uboot")
            self.assertEqual(state, State.UBOOT_UPLOADING)
            self.assertEqual(spy.call_args.kwargs.get("one_request"), True)
            for call in mock_run.call_args_list:
                self.assertNotEqual(call.args[0][0], "curl")
