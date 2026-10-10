"""Tests for pi_netboot.py pure helpers (no network or router I/O)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from pi_netboot import (
    is_armed,
    netboot_loop_candidates,
    parse_dhcp_log,
    render_block,
    strip_block,
)


class TestRenderBlock(unittest.TestCase):
    def test_block_contains_essentials(self):
        block = render_block("192.168.13.1", ["E4:5F:01:14:A4:66"],
                             "/tmp/dnsmasq.cfg01411c.d/tftpboot")
        self.assertIn("dhcp-host=e4:5f:01:14:a4:66,set:pinetboot", block)
        self.assertIn("dhcp-option=tag:pinetboot,66,192.168.13.1", block)
        self.assertIn("dhcp-option=tag:pinetboot,67,config.txt", block)
        self.assertIn("enable-tftp", block)
        self.assertIn("tftp-root=/tmp/dnsmasq.cfg01411c.d/tftpboot", block)
        self.assertIn("log-dhcp", block)

    def test_block_lowercases_macs(self):
        block = render_block("10.0.0.1", ["AA:BB:CC:DD:EE:FF"], "/tmp/x")
        self.assertIn("dhcp-host=aa:bb:cc:dd:ee:ff", block)

    def test_multiple_macs(self):
        block = render_block("10.0.0.1", ["aa:bb:cc:dd:ee:ff",
                                          "11:22:33:44:55:66"], "/tmp/x")
        self.assertIn("aa:bb:cc:dd:ee:ff", block)
        self.assertIn("11:22:33:44:55:66", block)


class TestStripBlock(unittest.TestCase):
    BASE = "dhcp end\n"

    def test_strip_removes_managed_block(self):
        conf = self.BASE + "\n" + render_block("10.0.0.1",
                                               ["aa:bb:cc:dd:ee:ff"], "/tmp/x")
        new, removed = strip_block(conf)
        self.assertTrue(removed)
        self.assertNotIn("pinetboot", new)
        self.assertNotIn("enable-tftp", new)
        self.assertIn("dhcp end", new)

    def test_strip_when_not_armed(self):
        new, removed = strip_block(self.BASE)
        self.assertFalse(removed)
        self.assertIn("dhcp end", new)

    def test_roundtrip_arm_strip_arm(self):
        block = render_block("10.0.0.1", ["aa:bb:cc:dd:ee:ff"], "/tmp/x")
        conf = self.BASE + "\n" + block
        stripped, _ = strip_block(conf)
        reconf = stripped.rstrip() + "\n\n" + block + "\n"
        self.assertTrue(is_armed(reconf))
        self.assertEqual(strip_block(conf), strip_block(reconf))


class TestLegacyBlockVariants(unittest.TestCase):
    """Manual re-arm scripts used a different marker and no end marker."""

    LEGACY = """dhcp end
# --- Pi netboot rescue (temporary) ---
dhcp-host=aa:bb:cc:dd:ee:ff,set:pinetboot
dhcp-option=tag:pinetboot,66,10.0.0.1
dhcp-option=tag:pinetboot,67,config.txt
enable-tftp
tftp-root=/tmp/dnsmasq.cfg01411c.d/tftpboot
log-dhcp
after lines"""

    def test_is_armed_detects_legacy_block(self):
        self.assertTrue(is_armed(self.LEGACY))

    def test_strip_removes_legacy_block(self):
        new, removed = strip_block(self.LEGACY)
        self.assertTrue(removed)
        self.assertNotIn("pinetboot", new)
        self.assertNotIn("enable-tftp", new)
        self.assertIn("dhcp end", new)
        self.assertIn("after lines", new)

    def test_strip_legacy_then_arm_roundtrip(self):
        stripped, _ = strip_block(self.LEGACY)
        reconf = stripped.rstrip() + "\n\n" + render_block(
            "10.0.0.1", ["aa:bb:cc:dd:ee:ff"], "/tmp/x") + "\n"
        self.assertTrue(is_armed(reconf))
        new, removed = strip_block(reconf)
        self.assertTrue(removed)
        self.assertNotIn("pinetboot", new)


class TestIsArmed(unittest.TestCase):
    def test_armed(self):
        self.assertTrue(is_armed("x\n" + render_block("10.0.0.1",
                                                      ["aa:bb:cc:dd:ee:ff"],
                                                      "/tmp/x")))

    def test_not_armed(self):
        self.assertFalse(is_armed("# just a comment\n"))


class TestParseDhcpLog(unittest.TestCase):
    LOG = """
Thu Oct  8 09:45:05 2026 daemon.info dnsmasq-dhcp[1]: 123 DHCPDISCOVER(br-lan.13) e4:5f:01:14:a4:66
Thu Oct  8 09:45:05 2026 daemon.info dnsmasq-dhcp[1]: 123 DHCPOFFER(br-lan.13) 192.168.13.240 e4:5f:01:14:a4:66
Thu Oct  8 09:45:05 2026 daemon.info dnsmasq-dhcp[1]: 123 DHCPREQUEST(br-lan.13) 192.168.13.240 e4:5f:01:14:a4:66
Thu Oct  8 09:45:05 2026 daemon.info dnsmasq-dhcp[1]: 123 DHCPACK(br-lan.13) 192.168.13.240 e4:5f:01:14:a4:66 pidebug
Thu Oct  8 09:46:00 2026 daemon.info dnsmasq-dhcp[1]: 456 DHCPDISCOVER(br-lan.13) dc:a6:32:11:22:33
Thu Oct  8 09:46:20 2026 daemon.info dnsmasq-dhcp[1]: 456 DHCPDISCOVER(br-lan.13) dc:a6:32:11:22:33
Thu Oct  8 09:46:40 2026 daemon.info dnsmasq-dhcp[1]: 456 DHCPDISCOVER(br-lan.13) dc:a6:32:11:22:33
Thu Oct  8 09:47:00 2026 daemon.info dnsmasq[1]: unrelated non-dhcp line
"""

    def test_counts(self):
        counts = parse_dhcp_log(self.LOG)
        self.assertEqual(counts["e4:5f:01:14:a4:66"]["discover"], 1)
        self.assertEqual(counts["e4:5f:01:14:a4:66"]["request"], 1)
        self.assertEqual(counts["e4:5f:01:14:a4:66"]["ack"], 1)
        self.assertEqual(counts["dc:a6:32:11:22:33"]["discover"], 3)
        self.assertEqual(counts["dc:a6:32:11:22:33"].get("request", 0), 0)

    def test_loop_candidates(self):
        counts = parse_dhcp_log(self.LOG)
        loops = netboot_loop_candidates(counts)
        self.assertEqual(loops, ["dc:a6:32:11:22:33"])

    def test_no_candidates_when_all_complete(self):
        counts = parse_dhcp_log(self.LOG)
        self.assertEqual(netboot_loop_candidates(counts, min_discover=99), [])


if __name__ == "__main__":
    unittest.main()
