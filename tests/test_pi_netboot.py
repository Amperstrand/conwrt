"""Tests for pi_netboot.py pure helpers (no network or router I/O)."""
import sys
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from pi_netboot import (
    DEFAULT_CMDLINE,
    MARKER_END,
    MARKER_START,
    is_armed,
    missing_firmware,
    netboot_loop_candidates,
    parse_dhcp_log,
    render_block,
    render_cmdline_txt,
    render_config_txt,
    strip_block,
)


class TestRenderBlock(unittest.TestCase):
    def test_block_contains_essentials(self):
        block = render_block("192.168.1.1", ["E4:5F:01:12:34:56"],
                             "/tmp/dnsmasq.cfg01411c.d/tftpboot")
        self.assertIn("dhcp-host=e4:5f:01:12:34:56,set:pinetboot", block)
        self.assertIn("dhcp-option=tag:pinetboot,66,192.168.1.1", block)
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
Thu Oct  8 09:45:05 2026 daemon.info dnsmasq-dhcp[1]: 123 DHCPDISCOVER(br-lan) e4:5f:01:12:34:56
Thu Oct  8 09:45:05 2026 daemon.info dnsmasq-dhcp[1]: 123 DHCPOFFER(br-lan) 192.168.1.240 e4:5f:01:12:34:56
Thu Oct  8 09:45:05 2026 daemon.info dnsmasq-dhcp[1]: 123 DHCPREQUEST(br-lan) 192.168.1.240 e4:5f:01:12:34:56
Thu Oct  8 09:45:05 2026 daemon.info dnsmasq-dhcp[1]: 123 DHCPACK(br-lan) 192.168.1.240 e4:5f:01:12:34:56 pidebug
Thu Oct  8 09:46:00 2026 daemon.info dnsmasq-dhcp[1]: 456 DHCPDISCOVER(br-lan) dc:a6:32:11:22:33
Thu Oct  8 09:46:20 2026 daemon.info dnsmasq-dhcp[1]: 456 DHCPDISCOVER(br-lan) dc:a6:32:11:22:33
Thu Oct  8 09:46:40 2026 daemon.info dnsmasq-dhcp[1]: 456 DHCPDISCOVER(br-lan) dc:a6:32:11:22:33
Thu Oct  8 09:47:00 2026 daemon.info dnsmasq[1]: unrelated non-dhcp line
"""

    def test_counts(self):
        counts = parse_dhcp_log(self.LOG)
        self.assertEqual(counts["e4:5f:01:12:34:56"]["discover"], 1)
        self.assertEqual(counts["e4:5f:01:12:34:56"]["request"], 1)
        self.assertEqual(counts["e4:5f:01:12:34:56"]["ack"], 1)
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


class TestRenderBlockPins(unittest.TestCase):
    def test_pin_appends_ip_to_dhcp_host(self):
        block = render_block("10.0.0.1", ["aa:bb:cc:dd:ee:ff"], "/tmp/x",
                             pin_ips=["10.0.0.50"])
        self.assertIn("dhcp-host=aa:bb:cc:dd:ee:ff,set:pinetboot,10.0.0.50",
                      block)

    def test_none_pin_keeps_plain_host(self):
        block = render_block("10.0.0.1", ["aa:bb:cc:dd:ee:ff"], "/tmp/x",
                             pin_ips=[None])
        self.assertIn("dhcp-host=aa:bb:cc:dd:ee:ff,set:pinetboot\n", block)

    def test_mixed_pins(self):
        block = render_block("10.0.0.1", ["aa:aa:aa:aa:aa:aa",
                                          "bb:bb:bb:bb:bb:bb"], "/tmp/x",
                             pin_ips=[None, "10.0.0.9"])
        self.assertIn("dhcp-host=aa:aa:aa:aa:aa:aa,set:pinetboot\n", block)
        self.assertIn("dhcp-host=bb:bb:bb:bb:bb:bb,set:pinetboot,10.0.0.9",
                      block)

    def test_pin_list_length_mismatch_raises(self):
        with self.assertRaises(ValueError):
            render_block("10.0.0.1", ["aa:aa:aa:aa:aa:aa"], "/tmp/x",
                         pin_ips=["10.0.0.1", "10.0.0.2"])


class TestRenderConfigTxt(unittest.TestCase):
    def test_single_file_kernel_no_initramfs_directive(self):
        txt = render_config_txt("openwrt-initramfs-kernel.bin",
                                "bcm2711-rpi-4-b.dtb")
        self.assertIn("arm_64bit=1", txt)
        self.assertIn("kernel=openwrt-initramfs-kernel.bin", txt)
        self.assertIn("device_tree=bcm2711-rpi-4-b.dtb", txt)
        directive_lines = [ln for ln in txt.splitlines()
                           if ln.startswith("initramfs")]
        self.assertEqual(directive_lines, [])
        self.assertTrue(txt.endswith("\n"))

    def test_extra_lines_appended(self):
        txt = render_config_txt("k.bin", "d.dtb", extra_lines=["hdmi=off"])
        self.assertIn("hdmi=off", txt)
        self.assertLess(txt.index("device_tree="), txt.index("hdmi=off"))


class TestRenderCmdline(unittest.TestCase):
    def test_default_and_custom(self):
        self.assertEqual(render_cmdline_txt(), DEFAULT_CMDLINE + "\n")
        self.assertEqual(render_cmdline_txt("quiet"), "quiet\n")


class TestMissingFirmware(unittest.TestCase):
    def test_empty_tree_reports_all(self):
        self.assertEqual(missing_firmware([]),
                         ["start4.elf", "fixup4.dat"])

    def test_populated_tree_reports_none(self):
        self.assertEqual(
            missing_firmware(["config.txt", "start4.elf", "fixup4.dat",
                              "kernel8.img"]), [])

    def test_partial_tree(self):
        self.assertEqual(missing_firmware(["start4.elf"]), ["fixup4.dat"])


class TestDeployParser(unittest.TestCase):
    def test_deploy_subcommand_requires_kernel_and_dtb(self):
        import pi_netboot as pn
        with self.assertRaises(SystemExit) as cm:
            pn.main(["deploy", "--router", "10.0.0.1"])
        self.assertEqual(cm.exception.code, 2)

        with self.assertRaises(SystemExit) as cm:
            pn.main(["deploy", "--router", "10.0.0.1", "--kernel", "/k",
                     "--dtb", "/d", "--help"])
        self.assertEqual(cm.exception.code, 0)


class TestArmTransitionOrder(unittest.TestCase):
    """Re-arming must stop serving the OLD allowlist before the tree changes (#267)."""

    ARMED_A = ("# dnsmasq\n" + MARKER_START + "\n"
               "dhcp-host=dc:a6:32:11:22:33,set:pinetboot\n"
               "dhcp-option=tag:pinetboot,66,192.168.1.1\n"
               "dhcp-option=tag:pinetboot,67,config.txt\n"
               "enable-tftp\ntftp-root=/tmp/tftp\nlog-dhcp\n" + MARKER_END + "\n")

    def _run_arm(self, armed_conf, healthy_plan):
        from types import SimpleNamespace
        import pi_netboot
        events = []
        health = iter(healthy_plan)

        def fake_write(router, text):
            events.append(("write", "pinetboot" in text))

        def fake_upload(router, tree, root):
            events.append(("upload", root))

        def fake_restart(router):
            events.append(("restart",))

        def fake_healthy(router, tftp_root=None):
            return next(health)

        args = SimpleNamespace(
            router="192.168.1.1", tree="/tmp/tree", mac=["E4:5F:01:12:34:56"],
            tftp_root="/tmp/tftp", bootfile="config.txt", ip=None)
        patches = [
            mock.patch.object(pi_netboot, "remote_detect_tftp_root",
                              return_value="/tmp/tftp"),
            mock.patch.object(pi_netboot, "read_remote_config",
                              return_value=armed_conf),
            mock.patch.object(pi_netboot, "write_remote_config", fake_write),
            mock.patch.object(pi_netboot, "upload_tree", fake_upload),
            mock.patch.object(pi_netboot, "restart_dnsmasq", fake_restart),
            mock.patch.object(pi_netboot, "dnsmasq_healthy", fake_healthy),
        ]
        with patches[0], patches[1], patches[2], patches[3], \
                patches[4], patches[5]:
            rc = pi_netboot.cmd_arm(args)
        return rc, events

    def test_rearm_disarms_before_upload_and_never_re_serves_old_mac(self):
        rc, events = self._run_arm(self.ARMED_A, [True, True])
        self.assertEqual(rc, 0)
        kinds = [e[0] for e in events]
        self.assertEqual(kinds.index("upload") - kinds.index("write"), 2,
                         "disarm write+restart must precede the tree upload")
        disarm_write = events[0]
        self.assertEqual(disarm_write, ("write", False),
                         "first write must strip the managed block")
        final_write = [e for e in events if e[0] == "write"][-1]
        self.assertEqual(final_write, ("write", True))

    def test_fresh_arm_uploads_before_config(self):
        rc, events = self._run_arm("# dnsmasq stock\n", [True])
        self.assertEqual(rc, 0)
        kinds = [e[0] for e in events]
        self.assertLess(kinds.index("upload"), kinds.index("write"))

    def test_unhealthy_final_arm_rolls_back_to_disarmed_not_old_allowlist(self):
        rc, events = self._run_arm(self.ARMED_A, [True, False])
        self.assertEqual(rc, 1)
        writes = [e for e in events if e[0] == "write"]
        self.assertEqual(writes[-1], ("write", False),
                         "rollback must be the DISARMED base — old allowlist "
                         "+ new tree is the #267 hazard")

    def test_unhealthy_disarm_step_restores_and_never_touches_tree(self):
        rc, events = self._run_arm(self.ARMED_A, [False, True])
        self.assertEqual(rc, 1)
        kinds = [e[0] for e in events]
        self.assertNotIn("upload", kinds)
        writes = [e for e in events if e[0] == "write"]
        self.assertEqual(writes[-1], ("write", True),
                         "tree untouched — restore the still-consistent old config")
