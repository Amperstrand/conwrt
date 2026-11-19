"""Tests for pi_boot.py — boot-medium classification and capability matrix.

No hardware and no network I/O: every assertion runs against captured output
shapes from a real Pi 4B (Raspberry Pi OS + OpenWrt initramfs) and the
rpi-eeprom release notes.
"""
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import pi_boot
from pi_boot import (
    LEGS,
    boot_medium,
    capability_notes,
    capability_rows,
    classify,
    evaluate_leg,
    parse_boot_order,
    parse_bootloader_config,
    parse_fw_date,
    parse_lsblk,
    render_probe,
    split_sections,
    wait_for,
)

# Captured shapes -----------------------------------------------------------

VERSION_ISO = "2020-04-16 12:00:00\nversion 5a4a8b3c (release)\ntimestamp 1587038400\n"
VERSION_C = "Apr 16 2020 12:00:00\nversion 5a4a8b3c (release)\n"
CONFIG_TEXT = """# bootloader config\n[all]\nBOOT_UART=0\nWAKE_ON_GPIO=1\nBOOT_ORDER=0xf41\n"""

LSBLK_SD = (
    'NAME="mmcblk0" TRAN="mmc" TYPE="disk" PARTUUID="" SIZE="29.7G"\n'
    'NAME="mmcblk0p1" TRAN="mmc" TYPE="part" PARTUUID="abcd1234-01" SIZE="512M"\n'
    'NAME="mmcblk0p2" TRAN="mmc" TYPE="part" PARTUUID="abcd1234-02" SIZE="29.2G"\n'
)
LSBLK_USB = (
    'NAME="sda" TRAN="usb" TYPE="disk" PARTUUID="" SIZE="28.7G"\n'
    'NAME="sda1" TRAN="usb" TYPE="part" PARTUUID="deadbeef-01" SIZE="512M"\n'
    'NAME="sda2" TRAN="usb" TYPE="part" PARTUUID="deadbeef-02" SIZE="28.2G"\n'
)
LSBLK_BOTH = LSBLK_SD + LSBLK_USB


class TestParseFirmwareDate(unittest.TestCase):
    def test_iso_first_line(self):
        self.assertEqual(parse_fw_date(VERSION_ISO), (2020, 4, 16))

    def test_c_locale_first_line(self):
        self.assertEqual(parse_fw_date(VERSION_C), (2020, 4, 16))

    def test_locale_independent_month_table(self):
        self.assertEqual(parse_fw_date("Sep 3 2020 10:00:00"), (2020, 9, 3))

    def test_empty_and_garbage(self):
        self.assertIsNone(parse_fw_date(""))
        self.assertIsNone(parse_fw_date(None))
        self.assertIsNone(parse_fw_date("unknown command"))

    def test_unknown_month_is_not_guessed(self):
        # A non-English locale must not silently map to a wrong month.
        self.assertIsNone(parse_fw_date("Avr 16 2020 12:00:00"))


class TestParseBootloaderConfig(unittest.TestCase):
    def test_reads_keys(self):
        conf = parse_bootloader_config(CONFIG_TEXT)
        self.assertEqual(conf["BOOT_ORDER"], "0xf41")
        self.assertEqual(conf["BOOT_UART"], "0")
        self.assertNotIn("# bootloader config", conf)

    def test_section_headers_ignored(self):
        conf = parse_bootloader_config("[all]\nBOOT_ORDER=0xf241\n")
        self.assertEqual(conf, {"BOOT_ORDER": "0xf241"})

    def test_empty(self):
        self.assertEqual(parse_bootloader_config(""), {})


class TestParseBootOrder(unittest.TestCase):
    def test_standard_order(self):
        modes, error = parse_boot_order("0xf41")
        self.assertIsNone(error)
        self.assertEqual(modes, ["sd", "usb", "restart"])

    def test_network_in_order(self):
        modes, error = parse_boot_order("0xf241")
        self.assertIsNone(error)
        self.assertEqual(modes, ["sd", "usb", "network", "restart"])

    def test_invalid_order_reports_error(self):
        modes, error = parse_boot_order("0xzz")
        self.assertEqual(modes, [])
        self.assertIsNotNone(error)


class TestCapabilityMatrix(unittest.TestCase):
    def _rows(self, fw, order="0xf41"):
        modes, _ = parse_boot_order(order)
        return {row["mode"]: row for row in capability_rows(fw, modes)}

    def test_2019_firmware_has_only_sd(self):
        rows = self._rows((2019, 7, 15))
        self.assertEqual(rows["sd"]["supported"], "yes")
        self.assertEqual(rows["usb"]["supported"], "no")
        self.assertEqual(rows["network"]["supported"], "no")

    def test_2020_04_16_can_netboot_but_not_usb(self):
        # The load-bearing asymmetry: network boot became default five months
        # before USB mass-storage boot.
        rows = self._rows((2020, 4, 16))
        self.assertEqual(rows["network"]["supported"], "yes")
        self.assertEqual(rows["usb"]["supported"], "no")

    def test_usb_beta_window(self):
        rows = self._rows((2020, 5, 15))
        self.assertEqual(rows["usb"]["supported"], "beta")
        self.assertEqual(rows["network"]["supported"], "yes")

    def test_2020_09_03_supports_everything(self):
        rows = self._rows((2020, 9, 3))
        for mode in ("sd", "usb", "network"):
            self.assertEqual(rows[mode]["supported"], "yes")

    def test_unknown_firmware_is_unknown_not_false(self):
        # "unknown" must never collapse to "no": the tool would then tell an
        # operator to re-flash a Pi it simply could not read.
        rows = self._rows(None)
        self.assertEqual(rows["usb"]["supported"], "unknown")
        self.assertEqual(rows["sd"]["supported"], "yes")

    def test_stock_order_does_not_include_network(self):
        rows = self._rows((2020, 9, 3), order="0xf41")
        self.assertFalse(rows["network"]["ordered"])
        self.assertTrue(rows["usb"]["ordered"])


class TestCapabilityNotes(unittest.TestCase):
    def _row(self, **kwargs):
        base = {"mode": "network", "medium": "net", "supported": "yes",
                "ordered": True, "stable_floor": "2020-04-16",
                "beta_floor": "2019-09-23"}
        base.update(kwargs)
        return base

    def test_capable_but_unordered_names_the_nibble(self):
        note = capability_notes(self._row(ordered=False))
        self.assertIn("NOT in BOOT_ORDER", note)
        self.assertIn("0x2", note)

    def test_predates_feature_points_at_sd_and_update(self):
        note = capability_notes(self._row(supported="no"))
        self.assertIn("predates", note)
        self.assertIn("rpi-eeprom-update", note)

    def test_unknown_is_explicit(self):
        self.assertIn("unknown", capability_notes(self._row(supported="unknown")))


class TestParseLsblk(unittest.TestCase):
    def test_partitions_inherit_transport(self):
        rows = parse_lsblk(LSBLK_USB)
        parts = {row["NAME"]: row for row in rows}
        self.assertEqual(parts["sda2"]["TRAN"], "usb")
        self.assertEqual(parts["sda2"]["PARTUUID"], "deadbeef-02")

    def test_blank_and_garbage_lines_skipped(self):
        self.assertEqual(parse_lsblk("\n\nnot a row\n"), [])


class TestBootMedium(unittest.TestCase):
    def test_usb_root_by_partuuid(self):
        cmdline = "console=tty1 root=PARTUUID=deadbeef-02 rootfstype=ext4 ro"
        self.assertEqual(boot_medium(cmdline, parse_lsblk(LSBLK_BOTH)), "usb")

    def test_sd_root_by_partuuid(self):
        cmdline = "console=tty1 root=PARTUUID=abcd1234-02 rootwait"
        self.assertEqual(boot_medium(cmdline, parse_lsblk(LSBLK_BOTH)), "sd")

    def test_sd_root_by_device_name(self):
        cmdline = "root=/dev/mmcblk0p2 rootwait"
        self.assertEqual(boot_medium(cmdline, parse_lsblk(LSBLK_BOTH)), "sd")

    def test_usb_root_by_device_name(self):
        cmdline = "root=/dev/sda2 rootwait"
        self.assertEqual(boot_medium(cmdline, parse_lsblk(LSBLK_BOTH)), "usb")

    def test_nfsroot_is_net(self):
        cmdline = "console=ttyAMA0 root=/dev/nfs nfsroot=192.168.1.1:/srv,vers=3"
        self.assertEqual(boot_medium(cmdline, []), "net")

    def test_dev_nfs_is_net(self):
        self.assertEqual(boot_medium("root=/dev/nfs ip=dhcp", []), "net")

    def test_ram_boot_is_net(self):
        # An initramfs netboot has no block root at all.
        self.assertEqual(boot_medium("console=tty1", [], "rootfs rootfs"), "net")

    def test_unknown_partuuid_is_not_a_guess(self):
        self.assertEqual(boot_medium("root=PARTUUID=ffffffff-01", parse_lsblk(LSBLK_SD)),
                         "unknown")

    def test_empty_cmdline_is_unknown(self):
        self.assertEqual(boot_medium("", []), "unknown")

    def test_malformed_quoting_does_not_raise(self):
        self.assertEqual(boot_medium('root="/dev/sda2', []), "usb")


class TestSplitSections(unittest.TestCase):
    def test_sections_are_separated(self):
        text = "@@model\nRaspberry Pi 4 Model B\n@@serial\n10000000abcd\n@@section-end\n"
        sections = split_sections(text)
        self.assertEqual(sections["model"], "Raspberry Pi 4 Model B")
        self.assertEqual(sections["serial"], "10000000abcd")

    def test_empty_output(self):
        self.assertEqual(split_sections(""), {})


class TestClassify(unittest.TestCase):
    def test_ssh_means_os(self):
        self.assertEqual(classify(True, False), "os")

    def test_telnet_means_rescue_shell(self):
        self.assertEqual(classify(False, True), "rescue-shell")

    def test_neither_means_silent(self):
        self.assertEqual(classify(False, False), "silent")


class TestEvaluateLeg(unittest.TestCase):
    def test_sd_leg_passes_on_mmc(self):
        verdict, detail = evaluate_leg("sd", medium="sd", ssh_up=True)
        self.assertEqual(verdict, "PASS")
        self.assertIn("sd", detail)

    def test_sd_leg_fails_when_it_booted_from_usb(self):
        # A pass on the wrong medium is exactly the false green this test
        # exists to prevent: the Pi booted, just not from the card.
        verdict, detail = evaluate_leg("sd", medium="usb", ssh_up=True)
        self.assertEqual(verdict, "FAIL")
        self.assertIn("expected sd", detail)

    def test_leg_fails_without_ssh(self):
        verdict, _ = evaluate_leg("usb", medium=None, ssh_up=False)
        self.assertEqual(verdict, "FAIL")

    def test_net_leg_passes_on_telnet(self):
        verdict, _ = evaluate_leg("net", telnet_up=True)
        self.assertEqual(verdict, "PASS")

    def test_net_leg_fails_without_telnet(self):
        verdict, _ = evaluate_leg("net", telnet_up=False)
        self.assertEqual(verdict, "FAIL")


class TestRenderProbe(unittest.TestCase):
    def _report(self, medium="usb", fw=(2020, 9, 3), order="0xf41"):
        modes, _ = parse_boot_order(order)
        return {
            "host": "192.168.1.50",
            "model": "Raspberry Pi 4 Model B Rev 1.4",
            "serial": "10000000abcd1234",
            "os": "Debian GNU/Linux 12 (bookworm)",
            "root": "PARTUUID=deadbeef-02",
            "boot_medium": medium,
            "boot_order": order,
            "boot_order_modes": modes,
            "boot_order_error": None,
            "firmware_date": pi_boot._fmt_date(fw),
            "firmware_version": "version 5a4a8b3c (release)",
            "capabilities": capability_rows(fw, modes),
        }

    def test_renders_medium_and_verdicts(self):
        out = render_probe(self._report())
        self.assertIn("boot medium     usb", out)
        self.assertIn("Raspberry Pi 4 Model B", out)
        self.assertIn("NOT in BOOT_ORDER", out)

    def test_unknown_firmware_renders_without_crashing(self):
        out = render_probe(self._report(fw=None))
        self.assertIn("unknown", out)


class TestWaitFor(unittest.TestCase):
    def test_returns_true_when_predicate_succeeds_later(self):
        state = {"n": 0}

        def predicate():
            state["n"] += 1
            return state["n"] >= 3

        self.assertTrue(wait_for(predicate, timeout=5, interval=0.01))
        self.assertEqual(state["n"], 3)

    def test_times_out(self):
        with mock.patch.object(pi_boot.time, "monotonic",
                               side_effect=[0, 0, 0.05, 1.0]):
            with mock.patch.object(pi_boot.time, "sleep"):
                self.assertFalse(wait_for(lambda: False, timeout=0.5))


class TestNeighbourScan(unittest.TestCase):
    NEIGH = (
        "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
        "192.168.1.50 dev eth0 lladdr e4:5f:01:99:88:77 STALE\n"
        "10.42.0.2 dev legion0  FAILED\n"
        "192.168.1.99 dev eth0 lladdr E4:5F:01:AA:BB:CC DELAY\n"
        "garbage line\n"
    )

    def test_parses_rows_and_drops_unresolved(self):
        rows = pi_boot.parse_ip_neigh(self.NEIGH)
        self.assertEqual([r["ip"] for r in rows],
                         ["192.168.1.1", "192.168.1.50", "192.168.1.99"])
        # an entry with no lladdr can never be a candidate
        self.assertNotIn("10.42.0.2", [r["ip"] for r in rows])

    def test_flag_entries_are_kept(self):
        # `ip neigh` marks routers with an extra flag token; a strict
        # single-token tail regex silently dropped those lines.
        rows = pi_boot.parse_ip_neigh(
            "fe80::1 dev eth0 lladdr e4:5f:01:aa:bb:cc router REACHABLE\n")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["mac"], "e4:5f:01:aa:bb:cc")

    def test_macs_normalised_to_lowercase(self):
        rows = pi_boot.parse_ip_neigh(self.NEIGH)
        self.assertEqual(rows[-1]["mac"], "e4:5f:01:aa:bb:cc")

    def test_pi_prefixes_come_from_the_model(self):
        prefixes = pi_boot.pi_prefixes()
        self.assertIn("e4:5f:01", prefixes)
        self.assertIn("dc:a6:32", prefixes)
        self.assertTrue(pi_boot.is_pi_mac("E4:5F:01:99:88:77", prefixes))

    def test_non_pi_mac_rejected(self):
        prefixes = pi_boot.pi_prefixes()
        self.assertFalse(pi_boot.is_pi_mac("3c:5a:b4:66:55:44", prefixes))

    def test_empty_prefixes_never_match(self):
        self.assertFalse(pi_boot.is_pi_mac("e4:5f:01:99:88:77", ()))

    def test_empty_scan_explains_the_next_step(self):
        self.assertIn("no Raspberry Pi MAC prefixes", pi_boot.render_scan([]))

    def test_scan_table_lists_listeners(self):
        out = pi_boot.render_scan([{
            "ip": "192.168.1.50", "mac": "e4:5f:01:99:88:77",
            "dev": "eth0", "state": "REACHABLE", "ssh": True, "telnet": False,
        }])
        self.assertIn("192.168.1.50", out)
        self.assertIn("22", out)
        self.assertNotIn("23", out.splitlines()[-1])


class TestModelAgreement(unittest.TestCase):
    """models/raspberrypi-4b.json is the SSOT for boot facts; pi_boot.py
    encodes the same firmware floors. Editing one without the other is drift,
    and drift here silently changes what "this Pi can netboot" means."""

    MODEL = Path(__file__).resolve().parent.parent / "models" / "raspberrypi-4b.json"

    def test_firmware_floors_match_the_model(self):
        floors = json.loads(self.MODEL.read_text())["boot"]["boot_order"]["firmware_floors"]
        for mode, _medium, beta, stable in pi_boot.CAPABILITY:
            self.assertEqual(pi_boot._fmt_date(beta), floors[mode]["beta"],
                             f"{mode} beta floor drifted from the model")
            self.assertEqual(pi_boot._fmt_date(stable), floors[mode]["stable"],
                             f"{mode} stable floor drifted from the model")

    def test_documented_examples_decode(self):
        examples = json.loads(self.MODEL.read_text())["boot"]["boot_order"]["examples"]
        modes, error = parse_boot_order("0xf41")
        self.assertIsNone(error)
        self.assertEqual(modes, ["sd", "usb", "restart"])
        self.assertIn("network is NOT included", examples["0xf41"])
        self.assertEqual(parse_boot_order("0xf241")[0],
                         ["sd", "usb", "network", "restart"])


class TestLegTable(unittest.TestCase):
    def test_every_capability_mode_has_a_leg_or_is_expected(self):
        # sd/usb/net are testable; the table drives the matrix CLI.
        for leg in ("sd", "usb", "net"):
            self.assertIn(leg, LEGS)
            self.assertIn("precondition", LEGS[leg])

    def test_net_leg_uses_telnet_evidence(self):
        self.assertEqual(LEGS["net"]["evidence"], "telnet")


if __name__ == "__main__":
    unittest.main()
