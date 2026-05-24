"""Tests for device fingerprinting."""
import json
import sys
import tempfile
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from flash.device_detect import (
    DeviceCandidate,
    FingerprintResult,
    _vendor_from_ssh_banner,
    active_fingerprint,
    grab_ssh_banner,
    lookup_oui,
    match_models,
    parse_arp,
    parse_tcpdump_dhcp,
    passive_fingerprint,
    probe_http_title,
)


class TestLookupOui(TestCase):
    def test_known_oui_returns_vendor(self):
        self.assertEqual(lookup_oui("4C:9E:FF:12:34:56"), "Zyxel")

    def test_known_oui_bc_cf_4f(self):
        self.assertEqual(lookup_oui("BC:CF:4F:AA:BB:CC"), "Zyxel")

    def test_known_oui_ubiquiti(self):
        self.assertEqual(lookup_oui("04:18:D6:00:00:00"), "Ubiquiti")

    def test_unknown_oui_returns_none(self):
        self.assertIsNone(lookup_oui("AA:BB:CC:DD:EE:FF"))

    def test_mac_with_dashes(self):
        self.assertEqual(lookup_oui("4C-9E-FF-12-34-56"), "Zyxel")

    def test_case_insensitive(self):
        self.assertEqual(lookup_oui("4c:9e:ff:12:34:56"), "Zyxel")

    def test_invalid_mac_too_short(self):
        self.assertIsNone(lookup_oui("AA:BB"))

    def test_empty_string(self):
        self.assertIsNone(lookup_oui(""))

    def test_single_octet(self):
        self.assertIsNone(lookup_oui("AA"))


class TestParseTcpdumpDhcp(TestCase):
    def test_valid_dhcp_with_all_fields(self):
        line = (
            "BOOTP/DHCP, Request from 4c:9e:ff:12:34:56\n"
            "Vendor-Class: \"ZyXEL\"\n"
            "Requested-IP 192.168.1.1"
        )
        result = parse_tcpdump_dhcp(line)
        assert result is not None
        self.assertEqual(result["mac"], "4c:9e:ff:12:34:56")
        self.assertEqual(result["vendor_class"], "ZyXEL")
        self.assertEqual(result["requested_ip"], "192.168.1.1")

    def test_dhcp_with_mac_only(self):
        line = "BOOTP/DHCP, Request from aa:bb:cc:dd:ee:ff"
        result = parse_tcpdump_dhcp(line)
        assert result is not None
        self.assertEqual(result["mac"], "aa:bb:cc:dd:ee:ff")
        self.assertNotIn("hostname", result)
        self.assertNotIn("vendor_class", result)

    def test_non_dhcp_line(self):
        self.assertIsNone(parse_tcpdump_dhcp("some random tcp line"))

    def test_dhcp_keyword_without_mac(self):
        self.assertIsNone(parse_tcpdump_dhcp("DHCP something happened"))

    def test_dhcp_with_requested_ip(self):
        line = (
            "BOOTP/DHCP, Request from 4c:9e:ff:12:34:56, "
            "Requested-IP 10.0.0.5"
        )
        result = parse_tcpdump_dhcp(line)
        assert result is not None
        self.assertEqual(result["requested_ip"], "10.0.0.5")


class TestParseArp(TestCase):
    def test_valid_arp_line(self):
        line = "4c:9e:ff:12:34:56 on eth0, 192.168.1.1"
        result = parse_arp(line)
        assert result is not None
        self.assertEqual(result, ("4c:9e:ff:12:34:56", "192.168.1.1"))

    def test_arp_uppercase_mac(self):
        line = "4C:9E:FF:12:34:56 on eth0, 10.0.0.1"
        result = parse_arp(line)
        assert result is not None
        self.assertEqual(result[0], "4c:9e:ff:12:34:56")
        self.assertEqual(result[1], "10.0.0.1")

    def test_non_arp_line(self):
        self.assertIsNone(parse_arp("not an arp line at all"))

    def test_arp_no_ip(self):
        line = "4c:9e:ff:12:34:56 on eth0"
        self.assertIsNone(parse_arp(line))


class TestGrabSshBanner(TestCase):
    @patch("flash.device_detect.socket.socket")
    def test_returns_banner(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"

        result = grab_ssh_banner("192.168.1.1")
        self.assertEqual(result, "SSH-2.0-OpenSSH_8.9")
        mock_sock.connect.assert_called_once_with(("192.168.1.1", 22))
        mock_sock.close.assert_called_once()

    @patch("flash.device_detect.socket.socket")
    def test_custom_port(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recv.return_value = b"SSH-2.0-dropbear\r\n"

        result = grab_ssh_banner("10.0.0.1", port=2222)
        mock_sock.connect.assert_called_once_with(("10.0.0.1", 2222))
        self.assertEqual(result, "SSH-2.0-dropbear")

    @patch("flash.device_detect.socket.socket")
    def test_connection_failure(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.connect.side_effect = OSError("Connection refused")

        result = grab_ssh_banner("192.168.1.1")
        self.assertIsNone(result)

    @patch("flash.device_detect.socket.socket")
    def test_timeout(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.connect.side_effect = OSError("timed out")

        result = grab_ssh_banner("192.168.1.1")
        self.assertIsNone(result)

    @patch("flash.device_detect.socket.socket")
    def test_recv_timeout(self, mock_socket_cls):
        import socket
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.recv.side_effect = socket.timeout("timed out")

        result = grab_ssh_banner("192.168.1.1")
        self.assertIsNone(result)


class TestProbeHttpTitle(TestCase):
    @patch("flash.device_detect.socket.socket")
    def test_extracts_title(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        html = b"HTTP/1.1 200 OK\r\n\r\n<html><title>GS1900</title></html>"
        mock_sock.recv.side_effect = [html, b""]

        result = probe_http_title("192.168.1.1")
        self.assertEqual(result, "GS1900")

    @patch("flash.device_detect.socket.socket")
    def test_html_without_title(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        html = b"HTTP/1.1 200 OK\r\n\r\n<html><body>No title</body></html>"
        mock_sock.recv.side_effect = [html, b""]

        result = probe_http_title("192.168.1.1")
        self.assertIsNone(result)

    @patch("flash.device_detect.socket.socket")
    def test_connection_failure(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        mock_sock.connect.side_effect = OSError("refused")

        result = probe_http_title("192.168.1.1")
        self.assertIsNone(result)

    @patch("flash.device_detect.socket.socket")
    def test_case_insensitive_title(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        html = b"<HTML><TITLE>MyDevice</TITLE></HTML>"
        mock_sock.recv.side_effect = [html, b""]

        result = probe_http_title("192.168.1.1")
        self.assertEqual(result, "MyDevice")


class TestPassiveFingerprint(TestCase):
    def test_dhcp_lines_produce_candidates(self):
        lines = [
            "BOOTP/DHCP, Request from 4c:9e:ff:12:34:56, "
            "Vendor-Class: \"Zyxel\""
        ]
        result = passive_fingerprint(lines)
        self.assertTrue(result.passive_complete)
        self.assertFalse(result.active_complete)
        self.assertEqual(len(result.candidates), 1)
        c = result.candidates[0]
        self.assertEqual(c.vendor, "Zyxel")
        self.assertEqual(c.dhcp_vendor_class, "Zyxel")
        self.assertEqual(c.mac_oui, "4c:9e:ff")

    def test_arp_lines_produce_candidates(self):
        lines = ["4c:9e:ff:12:34:56 on eth0, 192.168.1.1"]
        result = passive_fingerprint(lines)
        self.assertEqual(len(result.candidates), 1)
        c = result.candidates[0]
        self.assertEqual(c.vendor, "Zyxel")
        self.assertIn("OUI=Zyxel", c.evidence)

    def test_duplicate_mac_single_candidate(self):
        lines = [
            "BOOTP/DHCP, Request from 4c:9e:ff:12:34:56",
            "4c:9e:ff:12:34:56 on eth0, 192.168.1.1",
        ]
        result = passive_fingerprint(lines)
        self.assertEqual(len(result.candidates), 1)

    def test_with_models_enriches(self):
        lines = [
            "BOOTP/DHCP, Request from 4c:9e:ff:12:34:56, hostname 'GS1900'"
        ]
        models = [
            {
                "id": "zyxel-gs1900-8hp",
                "vendor": "Zyxel",
                "mac_oui": ["4C:9E:FF"],
            }
        ]
        result = passive_fingerprint(lines, models=models)
        c = result.candidates[0]
        self.assertEqual(c.model_id, "zyxel-gs1900-8hp")

    def test_empty_lines_no_candidates(self):
        result = passive_fingerprint([])
        self.assertEqual(len(result.candidates), 0)

    def test_raw_signals_populated(self):
        lines = [
            "BOOTP/DHCP, Request from 4c:9e:ff:12:34:56",
            "aa:bb:cc:dd:ee:ff on eth0, 10.0.0.1",
        ]
        result = passive_fingerprint(lines)
        self.assertEqual(len(result.raw_signals["dhcp"]), 1)
        self.assertEqual(len(result.raw_signals["arp"]), 1)

    def test_arp_unknown_oui_is_low_confidence(self):
        lines = ["aa:bb:cc:dd:ee:ff on eth0, 10.0.0.1"]
        result = passive_fingerprint(lines)
        self.assertEqual(result.candidates[0].confidence, "low")
        self.assertEqual(result.candidates[0].vendor, "unknown")

    def test_dhcp_all_signals_high_confidence(self):
        lines = [
            "BOOTP/DHCP, Request from 4c:9e:ff:12:34:56\n"
            "Vendor-Class: \"Zyxel\"\n"
            "hostname 'GS1900'"
        ]
        result = passive_fingerprint(lines)
        self.assertEqual(result.candidates[0].confidence, "high")


class TestActiveFingerprint(TestCase):
    @patch("flash.device_detect._scan_port", return_value=False)
    @patch("flash.device_detect.probe_http_title", return_value="GS1900")
    @patch("flash.device_detect.grab_ssh_banner", return_value="SSH-2.0-OpenSSH_8.9")
    def test_ssh_and_http_high_confidence(self, mock_ssh, mock_http, mock_port):
        result = active_fingerprint("192.168.1.1")
        self.assertTrue(result.active_complete)
        self.assertFalse(result.passive_complete)
        c = result.candidates[0]
        self.assertEqual(c.confidence, "high")
        self.assertEqual(c.ssh_banner, "SSH-2.0-OpenSSH_8.9")
        self.assertIn("ssh_banner=", c.evidence[0])
        self.assertIn("http_title=", c.evidence[1])

    @patch("flash.device_detect._scan_port", return_value=False)
    @patch("flash.device_detect.probe_http_title", return_value=None)
    @patch("flash.device_detect.grab_ssh_banner", return_value="SSH-2.0-OpenSSH_8.9")
    def test_ssh_only_medium_confidence(self, mock_ssh, mock_http, mock_port):
        result = active_fingerprint("192.168.1.1")
        c = result.candidates[0]
        self.assertEqual(c.confidence, "medium")

    @patch("flash.device_detect._scan_port", return_value=False)
    @patch("flash.device_detect.probe_http_title", return_value="WebUI")
    @patch("flash.device_detect.grab_ssh_banner", return_value=None)
    def test_http_only_medium_confidence(self, mock_ssh, mock_http, mock_port):
        result = active_fingerprint("192.168.1.1")
        c = result.candidates[0]
        self.assertEqual(c.confidence, "medium")

    @patch("flash.device_detect._scan_port", return_value=False)
    @patch("flash.device_detect.probe_http_title", return_value=None)
    @patch("flash.device_detect.grab_ssh_banner", return_value=None)
    def test_nothing_low_confidence(self, mock_ssh, mock_http, mock_port):
        result = active_fingerprint("192.168.1.1")
        c = result.candidates[0]
        self.assertEqual(c.confidence, "low")
        self.assertEqual(c.vendor, "unknown")

    @patch("flash.device_detect._scan_port", return_value=True)
    @patch("flash.device_detect.probe_http_title", return_value=None)
    @patch("flash.device_detect.grab_ssh_banner", return_value="SSH-2.0-OpenSSH_8.9")
    def test_open_ports_included(self, mock_ssh, mock_http, mock_port):
        result = active_fingerprint("192.168.1.1")
        c = result.candidates[0]
        self.assertTrue(len(c.open_ports) > 0)
        self.assertIn("open_ports=", c.evidence[-1])

    @patch("flash.device_detect._scan_port", return_value=False)
    @patch("flash.device_detect.probe_http_title", return_value=None)
    @patch("flash.device_detect.grab_ssh_banner", return_value="SSH-2.0-EdgeOS")
    def test_vendor_from_ssh_banner(self, mock_ssh, mock_http, mock_port):
        result = active_fingerprint("192.168.1.1")
        c = result.candidates[0]
        self.assertEqual(c.vendor, "Ubiquiti")


class TestVendorFromSshBanner(TestCase):
    def test_edgeos(self):
        self.assertEqual(_vendor_from_ssh_banner("SSH-2.0-EdgeOS"), "Ubiquiti")

    def test_ubnt(self):
        self.assertEqual(_vendor_from_ssh_banner("SSH-2.0-ubnt"), "Ubiquiti")

    def test_extreme(self):
        self.assertEqual(
            _vendor_from_ssh_banner("SSH-2.0-ExtremeXOS"), "Extreme Networks"
        )

    def test_zyxel(self):
        self.assertEqual(_vendor_from_ssh_banner("SSH-2.0-Zyxel"), "Zyxel")

    def test_zywall(self):
        self.assertEqual(_vendor_from_ssh_banner("SSH-2.0-Zywall"), "Zyxel")

    def test_dlink(self):
        self.assertEqual(_vendor_from_ssh_banner("SSH-2.0-D-Link"), "D-Link")

    def test_dlink_no_dash(self):
        self.assertEqual(_vendor_from_ssh_banner("SSH-2.0-DLink"), "D-Link")

    def test_dropbear_returns_none(self):
        self.assertIsNone(_vendor_from_ssh_banner("SSH-2.0-dropbear_2022.83"))

    def test_unknown_banner_returns_none(self):
        self.assertIsNone(_vendor_from_ssh_banner("SSH-2.0-OpenSSH_8.9"))

    def test_case_insensitive(self):
        self.assertEqual(_vendor_from_ssh_banner("SSH-2.0-EDGEOS"), "Ubiquiti")


class TestMatchModels(TestCase):
    def test_oui_match_scores_points(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            model_file = Path(tmpdir) / "zyxel-gs1900.json"
            model_file.write_text(json.dumps({
                "id": "zyxel-gs1900",
                "vendor": "Zyxel",
                "mac_oui": ["4C:9E:FF"],
                "signatures": {},
            }))

            candidate = DeviceCandidate(
                vendor="Zyxel",
                model_id=None,
                confidence="medium",
                evidence=["OUI=Zyxel"],
                mac_oui="4c:9e:ff",
            )
            fp_result = FingerprintResult(candidates=[candidate])

            matches = match_models(fp_result, model_dir=tmpdir)
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0].model_id, "zyxel-gs1900")

    def test_ssh_banner_match_scores_3(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            model_file = Path(tmpdir) / "ubiquiti-edgerouter.json"
            model_file.write_text(json.dumps({
                "id": "ubiquiti-edgerouter",
                "vendor": "Ubiquiti",
                "signatures": {"edgeos": {"ssh_banner": "EdgeOS"}},
            }))

            candidate = DeviceCandidate(
                vendor="Ubiquiti",
                model_id=None,
                confidence="medium",
                evidence=["ssh=EdgeOS"],
                ssh_banner="SSH-2.0-EdgeOS",
            )
            fp_result = FingerprintResult(candidates=[candidate])

            matches = match_models(fp_result, model_dir=tmpdir)
            self.assertEqual(len(matches), 1)
            self.assertEqual(matches[0].model_id, "ubiquiti-edgerouter")
            self.assertIn("ssh_banner_match=", matches[0].evidence[0])

    def test_results_sorted_by_confidence(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # High-score model: OUI (2) + ssh_banner (3) = 5
            high_model = Path(tmpdir) / "high.json"
            high_model.write_text(json.dumps({
                "id": "high-match",
                "vendor": "Zyxel",
                "mac_oui": ["4C:9E:FF"],
                "signatures": {"active": {"ssh_banner": "Zyxel"}},
            }))

            # Low-score model: OUI only = 2
            low_model = Path(tmpdir) / "low.json"
            low_model.write_text(json.dumps({
                "id": "low-match",
                "vendor": "Zyxel",
                "mac_oui": ["4C:9E:FF"],
                "signatures": {},
            }))

            candidate = DeviceCandidate(
                vendor="Zyxel",
                model_id=None,
                confidence="medium",
                evidence=[],
                mac_oui="4c:9e:ff",
                ssh_banner="SSH-2.0-Zyxel",
            )
            fp_result = FingerprintResult(candidates=[candidate])

            matches = match_models(fp_result, model_dir=tmpdir)
            self.assertEqual(len(matches), 2)
            # High confidence (score 5) should come first
            self.assertEqual(matches[0].model_id, "high-match")
            self.assertEqual(matches[0].confidence, "high")
            self.assertEqual(matches[1].confidence, "low")

    def test_no_matches_empty_list(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            model_file = Path(tmpdir) / "nomatch.json"
            model_file.write_text(json.dumps({
                "id": "other-device",
                "vendor": "Other",
                "mac_oui": ["AA:BB:CC"],
                "signatures": {},
            }))

            candidate = DeviceCandidate(
                vendor="Zyxel",
                model_id=None,
                confidence="low",
                evidence=[],
                mac_oui="4c:9e:ff",
            )
            fp_result = FingerprintResult(candidates=[candidate])

            matches = match_models(fp_result, model_dir=tmpdir)
            self.assertEqual(len(matches), 0)

    def test_nonexistent_dir_returns_empty(self):
        fp_result = FingerprintResult()
        matches = match_models(fp_result, model_dir="/nonexistent/path")
        self.assertEqual(matches, [])

    def test_invalid_json_skipped(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_file = Path(tmpdir) / "broken.json"
            bad_file.write_text("not valid json{{{")

            fp_result = FingerprintResult()
            matches = match_models(fp_result, model_dir=tmpdir)
            self.assertEqual(matches, [])
