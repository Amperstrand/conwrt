"""Tests for scripts/oui.py — OUI vendor lookup and DHCP passive probe parsing.

Covers:
  - oui_lookup() with colon, hyphen, dot, compact, and mixed-case MAC formats
  - oui_lookup() edge cases (empty, too short, non-hex, unknown OUI)
  - Database sanity (vendor count, prefix count, no dupes)
  - probe_dhcp() parsing of sample tcpdump -vv output (MAC, hostname, vendor class)
  - probe_dhcp() error handling (timeout, missing tcpdump, permission denied)
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


def _load_oui():
    spec = importlib.util.spec_from_file_location("oui", ROOT / "scripts" / "oui.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["oui"] = module
    spec.loader.exec_module(module)
    return module


def _load_router_probe():
    spec = importlib.util.spec_from_file_location(
        "router_probe", ROOT / "scripts" / "router-probe.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["router_probe"] = module
    spec.loader.exec_module(module)
    return module


oui = _load_oui()
router_probe = _load_router_probe()


def _cp(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


# ---------------------------------------------------------------------------
# oui_lookup — MAC format handling
# ---------------------------------------------------------------------------

class TestOuiLookupFormats(unittest.TestCase):
    """Verify oui_lookup handles every common MAC address format."""

    def test_colon_separated_lowercase(self) -> None:
        self.assertEqual(oui.oui_lookup("d8:5d:84:11:22:33"), "ZyXEL")

    def test_colon_separated_uppercase(self) -> None:
        self.assertEqual(oui.oui_lookup("D8:5D:84:11:22:33"), "ZyXEL")

    def test_colon_separated_mixed_case(self) -> None:
        self.assertEqual(oui.oui_lookup("D8:5d:84:11:22:33"), "ZyXEL")

    def test_hyphen_separated(self) -> None:
        self.assertEqual(oui.oui_lookup("d8-5d-84-11-22-33"), "ZyXEL")

    def test_dot_separated_cisco_format(self) -> None:
        self.assertEqual(oui.oui_lookup("d85d.8411.2233"), "ZyXEL")

    def test_no_separators_compact(self) -> None:
        self.assertEqual(oui.oui_lookup("d85d84112233"), "ZyXEL")

    def test_uppercase_no_separators(self) -> None:
        self.assertEqual(oui.oui_lookup("D85D84112233"), "ZyXEL")

    def test_all_formats_return_same_vendor(self) -> None:
        """Colon, hyphen, dot, and bare must all resolve to the same vendor."""
        formats = [
            "00:13:46:aa:bb:cc",
            "00-13-46-aa-bb-cc",
            "0013.46aa.bbcc",
            "001346aabbcc",
            "00:13:46:AA:BB:CC",
            "00-13-46-AA-BB-CC",
        ]
        for mac in formats:
            with self.subTest(mac=mac):
                self.assertEqual(oui.oui_lookup(mac), "D-Link")


class TestOuiLookupVendors(unittest.TestCase):
    """Verify oui_lookup returns the correct vendor for known OUIs."""

    def test_zyxel(self) -> None:
        self.assertEqual(oui.oui_lookup("d8:5d:84:11:22:33"), "ZyXEL")
        self.assertEqual(oui.oui_lookup("c4:30:18:11:22:33"), "ZyXEL")

    def test_dlink(self) -> None:
        self.assertEqual(oui.oui_lookup("00:13:46:11:22:33"), "D-Link")
        self.assertEqual(oui.oui_lookup("00:15:e9:11:22:33"), "D-Link")

    def test_tplink(self) -> None:
        self.assertEqual(oui.oui_lookup("50:c7:bf:11:22:33"), "TP-Link")
        self.assertEqual(oui.oui_lookup("4c:11:bf:11:22:33"), "TP-Link")

    def test_netgear(self) -> None:
        self.assertEqual(oui.oui_lookup("c0:3f:0e:11:22:33"), "Netgear")
        self.assertEqual(oui.oui_lookup("9c:3d:cf:11:22:33"), "Netgear")

    def test_linksys(self) -> None:
        self.assertEqual(oui.oui_lookup("00:14:6c:11:22:33"), "Linksys")

    def test_glinet(self) -> None:
        self.assertEqual(oui.oui_lookup("94:83:c4:11:22:33"), "GL.iNet")

    def test_asus(self) -> None:
        self.assertEqual(oui.oui_lookup("00:1a:92:11:22:33"), "ASUS")

    def test_huawei(self) -> None:
        self.assertEqual(oui.oui_lookup("00:25:9e:11:22:33"), "Huawei")

    def test_cisco(self) -> None:
        self.assertEqual(oui.oui_lookup("00:00:0c:11:22:33"), "Cisco")
        self.assertEqual(oui.oui_lookup("00:01:42:11:22:33"), "Cisco")

    def test_aruba(self) -> None:
        self.assertEqual(oui.oui_lookup("00:0b:86:11:22:33"), "Aruba")

    def test_ubiquiti(self) -> None:
        self.assertEqual(oui.oui_lookup("00:27:22:11:22:33"), "Ubiquiti")

    def test_mikrotik(self) -> None:
        self.assertEqual(oui.oui_lookup("00:0c:42:11:22:33"), "MikroTik")

    def test_extreme_networks(self) -> None:
        self.assertEqual(oui.oui_lookup("00:04:96:11:22:33"), "Extreme Networks")

    def test_juniper(self) -> None:
        self.assertEqual(oui.oui_lookup("00:05:85:11:22:33"), "Juniper")

    def test_realtek(self) -> None:
        self.assertEqual(oui.oui_lookup("00:e0:4c:11:22:33"), "Realtek")

    def test_qualcomm_atheros(self) -> None:
        self.assertEqual(oui.oui_lookup("00:03:7f:11:22:33"), "Qualcomm Atheros")

    def test_marvell(self) -> None:
        self.assertEqual(oui.oui_lookup("00:50:43:11:22:33"), "Marvell")

    def test_broadcom(self) -> None:
        self.assertEqual(oui.oui_lookup("00:10:18:11:22:33"), "Broadcom")

    def test_xiaomi(self) -> None:
        self.assertEqual(oui.oui_lookup("64:09:80:11:22:33"), "Xiaomi")


class TestOuiLookupEdgeCases(unittest.TestCase):
    """Verify oui_lookup handles invalid inputs gracefully."""

    def test_unknown_oui_returns_none(self) -> None:
        # 00:00:00 is not in the curated database
        self.assertIsNone(oui.oui_lookup("00:00:00:11:22:33"))

    def test_empty_string_returns_none(self) -> None:
        self.assertIsNone(oui.oui_lookup(""))

    def test_too_short_returns_none(self) -> None:
        # Only 2 octets — need at least 3 for OUI
        self.assertIsNone(oui.oui_lookup("d8:5d"))

    def test_non_hex_chars_returns_none(self) -> None:
        self.assertIsNone(oui.oui_lookup("xx:yy:zz:11:22:33"))

    def test_random_garbage_returns_none(self) -> None:
        self.assertIsNone(oui.oui_lookup("not a mac"))

    def test_six_zeros_not_in_db(self) -> None:
        self.assertIsNone(oui.oui_lookup("00:00:00:00:00:00"))

    def test_only_oui_prefix_works(self) -> None:
        """A bare 6-char OUI prefix should also resolve."""
        self.assertEqual(oui.oui_lookup("d85d84"), "ZyXEL")

    def test_with_leading_trailing_whitespace(self) -> None:
        self.assertEqual(oui.oui_lookup("  d8:5d:84:11:22:33  "), "ZyXEL")


class TestOuiDatabaseIntegrity(unittest.TestCase):
    """Sanity checks on the OUI database itself."""

    def test_has_at_least_30_vendors(self) -> None:
        self.assertGreaterEqual(oui.oui_vendor_count(), 30)

    def test_has_at_least_60_prefixes(self) -> None:
        self.assertGreaterEqual(oui.oui_prefix_count(), 60)

    def test_all_keys_are_lowercase_colon_format(self) -> None:
        for key in oui._OUI_DATABASE:
            self.assertEqual(key, key.lower(),
                             f"OUI key {key!r} must be lowercase")
            self.assertRegex(key, r"^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$",
                             f"OUI key {key!r} must be xx:xx:xx format")

    def test_no_duplicate_vendors_are_empty(self) -> None:
        for prefix, vendor in oui._OUI_DATABASE.items():
            self.assertTrue(vendor, f"OUI {prefix} maps to empty vendor")


# ---------------------------------------------------------------------------
# probe_dhcp — DHCP packet parsing from tcpdump output
# ---------------------------------------------------------------------------

# Realistic tcpdump -vv output for a DHCP DISCOVER packet from a ZyXEL device.
_DHCP_SAMPLE_OUTPUT = """\
12:34:56.789012 IP (tos 0x0, ttl 64, id 0, offset 0, flags [none], proto UDP (17), length 328)
    0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP, Request from d8:5d:84:aa:bb:cc, length 300, hops 1, xid 0x1234abcd, Flags [Broadcast]
          Client-IP 0.0.0.0
          Your-IP 0.0.0.0
          Server-IP 0.0.0.0
          Gateway-IP 0.0.0.0
          Client-Ethernet-Address d8:5d:84:aa:bb:cc
          Vendor-rfc1044 Extensions
            Magic Cookie 0x63825363
            DHCP-Message Option (53), length 1: Discover
            Hostname Option (12), length 14: "tollgate-37c0"
            Vendor-Class Option (60), length 7: "MSFT 5.0"
"""

_DHCP_SAMPLE_MINIMAL = """\
12:34:56.789012 IP 0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP, Request from 00:13:46:de:ad:be, length 300
          Client-Ethernet-Address 00:13:46:de:ad:be
"""

_DHCP_SAMPLE_NO_OPTIONS = """\
12:34:56.789012 IP 0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP, Request from aa:bb:cc:dd:ee:ff, length 300
          Client-Ethernet-Address aa:bb:cc:dd:ee:ff
"""

_DHCP_SAMPLE_NON_DHCP = """\
12:34:56.789012 IP6 fe80::1.546 > ff02::1.546: UDP, bad length 0
"""


class TestProbeDhcp(unittest.TestCase):
    """Tests for probe_dhcp() — DHCP packet capture and parsing."""

    def test_full_dhcp_discover_parsed(self) -> None:
        """DHCP DISCOVER with all fields: MAC, hostname, vendor class."""
        with patch.object(router_probe, "run_cmd",
                          return_value=_cp(stdout=_DHCP_SAMPLE_OUTPUT)):
            name, status, detail = router_probe.probe_dhcp("en0", timeout=5)
        self.assertEqual(name, "dhcp")
        self.assertEqual(status, "detected")
        self.assertIn("mac=d8:5d:84:aa:bb:cc", detail)
        self.assertIn("hostname=tollgate-37c0", detail)
        self.assertIn("vendor_class=MSFT 5.0", detail)

    def test_dhcp_oui_lookup_from_detected_mac(self) -> None:
        """MAC extracted from DHCP output can be used for OUI lookup."""
        with patch.object(router_probe, "run_cmd",
                          return_value=_cp(stdout=_DHCP_SAMPLE_OUTPUT)):
            _, _, detail = router_probe.probe_dhcp("en0", timeout=5)
        mac_m = detail.split("mac=")[1].split(",")[0]
        self.assertEqual(oui.oui_lookup(mac_m), "ZyXEL")

    def test_minimal_dhcp_only_mac(self) -> None:
        """DHCP packet with MAC but no hostname/vendor-class options."""
        with patch.object(router_probe, "run_cmd",
                          return_value=_cp(stdout=_DHCP_SAMPLE_MINIMAL)):
            name, status, detail = router_probe.probe_dhcp("en0")
        self.assertEqual(name, "dhcp")
        self.assertEqual(status, "detected")
        self.assertIn("mac=00:13:46:de:ad:be", detail)
        self.assertNotIn("hostname=", detail)
        self.assertNotIn("vendor_class=", detail)

    def test_dhcp_packet_no_mac_line(self) -> None:
        """Packet has no recognizable MAC → not_seen."""
        with patch.object(router_probe, "run_cmd",
                          return_value=_cp(stdout=_DHCP_SAMPLE_NON_DHCP)):
            _, status, detail = router_probe.probe_dhcp("en0")
        self.assertEqual(status, "not_seen")

    def test_timeout(self) -> None:
        with patch.object(router_probe, "run_cmd",
                          side_effect=subprocess.TimeoutExpired(cmd="tcpdump", timeout=30)):
            _, status, detail = router_probe.probe_dhcp("en0", timeout=30)
        self.assertEqual(status, "timeout")
        self.assertIn("30s", detail)

    def test_tcpdump_not_installed(self) -> None:
        with patch.object(router_probe, "run_cmd", side_effect=FileNotFoundError("tcpdump")):
            _, status, detail = router_probe.probe_dhcp("en0")
        self.assertEqual(status, "unavailable")
        self.assertIn("tcpdump", detail)

    def test_permission_denied(self) -> None:
        with patch.object(router_probe, "run_cmd",
                          return_value=_cp(returncode=1, stderr="tcpdump: Permission denied")):
            _, status, detail = router_probe.probe_dhcp("en0")
        self.assertEqual(status, "permission_denied")
        self.assertIn("sudo", detail)

    def test_os_error_caught(self) -> None:
        with patch.object(router_probe, "run_cmd", side_effect=OSError("io error")):
            _, status, detail = router_probe.probe_dhcp("en0")
        self.assertEqual(status, "not_seen")
        self.assertEqual(detail, "io error")

    def test_uses_correct_tcpdump_filter(self) -> None:
        """Verify the tcpdump command matches the spec: port 67 or port 68."""
        captured_cmd: list = []

        def capture(cmd, **kw):
            captured_cmd.extend(cmd)
            return _cp(stdout="")

        with patch.object(router_probe, "run_cmd", side_effect=capture):
            router_probe.probe_dhcp("en6", timeout=5)

        self.assertIn("tcpdump", captured_cmd)
        self.assertIn("-i", captured_cmd)
        self.assertIn("en6", captured_cmd)
        filter_arg = captured_cmd[captured_cmd.index("-vv") + 1]
        self.assertIn("67", filter_arg)
        self.assertIn("68", filter_arg)
        self.assertIn("port", filter_arg)
        self.assertIn("-c", captured_cmd)
        self.assertIn("1", captured_cmd)


# ---------------------------------------------------------------------------
# probe_tftp — TFTP RRQ parsing from tcpdump output
# ---------------------------------------------------------------------------

_TFTP_SAMPLE_OUTPUT = """\
12:34:56.789012 IP (tos 0x0, ttl 64, id 1, offset 0, flags [none], proto UDP (17), length 60)
    192.168.1.1.tftp > 192.168.1.10.54321: TFTP, read request, filename vmlinux.gz.uImage.3912
"""

_TFTP_SAMPLE_NO_RRQ = """\
12:34:56.789012 IP 192.168.1.10.54321 > 192.168.1.1.tftp: TFTP, Data block 1
"""


class TestProbeTftp(unittest.TestCase):
    """Tests for probe_tftp() — TFTP read request capture and parsing."""

    def test_rrq_filename_extracted(self) -> None:
        with patch.object(router_probe, "run_cmd",
                          return_value=_cp(stdout=_TFTP_SAMPLE_OUTPUT)):
            name, status, detail = router_probe.probe_tftp("en0", timeout=5)
        self.assertEqual(name, "tftp")
        self.assertEqual(status, "detected")
        self.assertIn("vmlinux.gz.uImage.3912", detail)

    def test_non_rrq_packet(self) -> None:
        with patch.object(router_probe, "run_cmd",
                          return_value=_cp(stdout=_TFTP_SAMPLE_NO_RRQ)):
            _, status, _ = router_probe.probe_tftp("en0")
        self.assertEqual(status, "not_seen")

    def test_timeout(self) -> None:
        with patch.object(router_probe, "run_cmd",
                          side_effect=subprocess.TimeoutExpired(cmd="tcpdump", timeout=30)):
            _, status, detail = router_probe.probe_tftp("en0", timeout=30)
        self.assertEqual(status, "timeout")
        self.assertIn("30s", detail)

    def test_tcpdump_not_installed(self) -> None:
        with patch.object(router_probe, "run_cmd", side_effect=FileNotFoundError("tcpdump")):
            _, status, detail = router_probe.probe_tftp("en0")
        self.assertEqual(status, "unavailable")
        self.assertIn("tcpdump", detail)

    def test_permission_denied(self) -> None:
        with patch.object(router_probe, "run_cmd",
                          return_value=_cp(returncode=1, stderr="Permission denied")):
            _, status, _ = router_probe.probe_tftp("en0")
        self.assertEqual(status, "permission_denied")

    def test_uses_correct_tcpdump_filter(self) -> None:
        """Verify the tcpdump command matches the spec: port 69."""
        captured_cmd: list = []

        def capture(cmd, **kw):
            captured_cmd.extend(cmd)
            return _cp(stdout="")

        with patch.object(router_probe, "run_cmd", side_effect=capture):
            router_probe.probe_tftp("en6", timeout=5)

        self.assertIn("tcpdump", captured_cmd)
        self.assertIn("en6", captured_cmd)
        filter_arg = captured_cmd[captured_cmd.index("-vv") + 1]
        self.assertIn("69", filter_arg)
        self.assertIn("port", filter_arg)
        self.assertIn("-c", captured_cmd)


if __name__ == "__main__":
    unittest.main()
