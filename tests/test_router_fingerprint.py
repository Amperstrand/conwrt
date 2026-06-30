import importlib.util
import json
import socket
import subprocess
import sys
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock, patch


_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS))


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "router_fingerprint", _SCRIPTS / "router-fingerprint.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["router_fingerprint"] = module
    spec.loader.exec_module(module)
    return module


rf = _load_module()


def _completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class TestGetDefaultGatewayLinux(TestCase):
    @patch("router_fingerprint.platform.system", return_value="Linux")
    @patch("router_fingerprint.subprocess.run")
    def test_parses_via_field(self, mock_run, mock_platform):
        mock_run.return_value = _completed(stdout="default via 192.168.1.1 dev eth0\n")
        result = rf.get_default_gateway()
        self.assertEqual(result, "192.168.1.1")

    @patch("router_fingerprint.platform.system", return_value="Linux")
    @patch("router_fingerprint.subprocess.run")
    def test_interface_inserted_into_cmd(self, mock_run, mock_platform):
        mock_run.return_value = _completed(stdout="default via 10.0.0.1 dev en0\n")
        rf.get_default_gateway(interface="en0")
        cmd = mock_run.call_args[0][0]
        self.assertIn("dev", cmd)
        self.assertIn("en0", cmd)

    @patch("router_fingerprint.platform.system", return_value="Linux")
    @patch("router_fingerprint.subprocess.run")
    def test_no_via_returns_none(self, mock_run, mock_platform):
        mock_run.return_value = _completed(stdout="no default route\n")
        self.assertIsNone(rf.get_default_gateway())

    @patch("router_fingerprint.platform.system", return_value="Linux")
    @patch("router_fingerprint.subprocess.run")
    def test_nonzero_return_code_returns_none(self, mock_run, mock_platform):
        mock_run.return_value = _completed(returncode=2)
        self.assertIsNone(rf.get_default_gateway())


class TestGetDefaultGatewayDarwin(TestCase):
    @patch("router_fingerprint.platform.system", return_value="Darwin")
    @patch("router_fingerprint.os.path.exists", return_value=False)
    @patch("router_fingerprint.subprocess.run")
    def test_parses_gateway_field(self, mock_run, mock_exists, mock_platform):
        mock_run.return_value = _completed(stdout="    gateway: 192.168.0.1\n")
        result = rf.get_default_gateway()
        self.assertEqual(result, "192.168.0.1")

    @patch("router_fingerprint.platform.system", return_value="Darwin")
    @patch("router_fingerprint.os.path.exists", return_value=False)
    @patch("router_fingerprint.subprocess.run")
    def test_ifscope_added_with_interface(self, mock_run, mock_exists, mock_platform):
        mock_run.return_value = _completed(stdout="    gateway: 10.0.0.1\n")
        rf.get_default_gateway(interface="en6")
        cmd = mock_run.call_args[0][0]
        self.assertIn("-ifscope", cmd)
        self.assertIn("en6", cmd)


class TestGetDefaultGatewayError(TestCase):
    @patch("router_fingerprint.platform.system", return_value="Linux")
    @patch("router_fingerprint.subprocess.run", side_effect=subprocess.SubprocessError("boom"))
    def test_subprocess_error_returns_none(self, mock_run, mock_platform):
        self.assertIsNone(rf.get_default_gateway())


class TestParseSshOutput(TestCase):
    def test_parses_section_markers(self):
        output = "===HOST===\nrouter1\n===VERSION===\nopenwrt\n"
        sections = rf.parse_ssh_output(output)
        self.assertEqual(sections["HOST"], "router1")
        self.assertEqual(sections["VERSION"], "openwrt")

    def test_multiline_section(self):
        output = "===CPU===\nline1\nline2\nline3\n===EOF===\n"
        sections = rf.parse_ssh_output(output)
        self.assertEqual(sections["CPU"], "line1\nline2\nline3")

    def test_empty_output(self):
        self.assertEqual(rf.parse_ssh_output(""), {})

    def test_ignores_lines_outside_sections(self):
        output = "before\nstuff\n===A===\ncontent\n"
        sections = rf.parse_ssh_output(output)
        self.assertNotIn("", sections)
        self.assertEqual(sections["A"], "content")


class TestExtractAllMacs(TestCase):
    def test_extracts_interface_equals_mac_format(self):
        text = "eth0=aa:bb:cc:dd:ee:ff\nbr-lan=11:22:33:44:55:66\n"
        macs = rf.extract_all_macs(text)
        self.assertEqual(macs["eth0"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(macs["br-lan"], "11:22:33:44:55:66")

    def test_extracts_link_ether_format(self):
        # Real ip-addr-show output has the iface name on a separate line;
        # after `grep -E 'inet |link/ether'` only the link/ether line survives,
        # so parts[0] is "link/ether" and parts[1] is the MAC.
        text = "link/ether de:ad:be:ef:00:01 brd ff:ff:ff:ff:ff:ff"
        macs = rf.extract_all_macs(text)
        self.assertEqual(macs.get("link/ether"), "de:ad:be:ef:00:01")

    def test_link_ether_with_iface_prefix_not_extracted(self):
        # If the iface name and link/ether are on the same line, parts[1] is
        # "link/ether" which fails the MAC regex, so nothing is extracted.
        text = "eth0: link/ether de:ad:be:ef:00:01 brd ff:ff:ff:ff:ff:ff"
        macs = rf.extract_all_macs(text)
        self.assertEqual(macs, {})

    def test_ignores_invalid_mac_format(self):
        text = "eth0=not-a-mac\nbad=zz:zz:zz:zz:zz:zz\n"
        macs = rf.extract_all_macs(text)
        self.assertEqual(macs, {})

    def test_empty_text(self):
        self.assertEqual(rf.extract_all_macs(""), {})


class TestRunSshCommandSuccess(TestCase):
    @patch("router_fingerprint.run_ssh")
    def test_returns_stdout_on_success(self, mock_run_ssh):
        mock_run_ssh.return_value = _completed(stdout="===HOST===\nrouter\n")
        ok, output = rf.run_ssh_command("192.168.1.1", quiet=True)
        self.assertTrue(ok)
        self.assertIn("===HOST===", output)


class TestRunSshCommandFailure(TestCase):
    @patch("router_fingerprint.run_ssh")
    def test_nonzero_return_code(self, mock_run_ssh):
        mock_run_ssh.return_value = _completed(returncode=1, stderr="connection refused")
        ok, output = rf.run_ssh_command("192.168.1.1", quiet=True)
        self.assertFalse(ok)
        self.assertIn("connection refused", output)

    @patch("router_fingerprint.run_ssh", side_effect=subprocess.TimeoutExpired("ssh", 40))
    def test_timeout(self, mock_run_ssh):
        ok, output = rf.run_ssh_command("192.168.1.1", quiet=True)
        self.assertFalse(ok)
        self.assertEqual(output, "")

    @patch("router_fingerprint.run_ssh", side_effect=OSError("network unreachable"))
    def test_oserror(self, mock_run_ssh):
        ok, output = rf.run_ssh_command("192.168.1.1", quiet=True)
        self.assertFalse(ok)
        self.assertEqual(output, "")


class TestParseOutputBasicSections(TestCase):
    def test_hostname_section(self):
        output = "===HOSTNAME===\nrouter1\n"
        result = rf.parse_output_to_json(output)
        self.assertEqual(result["identity"]["hostname"], "router1")
        self.assertEqual(result["identity"]["vendor"], "OpenWrt")

    def test_model_section(self):
        output = "===MODEL===\nGL.iNet MT3000\n"
        result = rf.parse_output_to_json(output)
        self.assertEqual(result["identity"]["model"], "GL.iNet MT3000")

    def test_serial_section(self):
        output = "===SERIAL===\nABC123XYZ\n"
        result = rf.parse_output_to_json(output)
        self.assertEqual(result["identity"]["serial"], "ABC123XYZ")


class TestParseOutputBoard(TestCase):
    def test_board_json_parsed(self):
        # board JSON output
        board_json = json.dumps({"model": {"id": "dlink-covr-x1860-a1"}})
        output = f"===BOARD===\n{board_json}\n"
        result = rf.parse_output_to_json(output)
        self.assertEqual(result["identity"]["board"], "dlink-covr-x1860-a1")

    def test_board_plain_text_fallback(self):
        # jsonfilter outputs plain string when not valid JSON
        output = "===BOARD===\ndlink_covr-x1860-a1\n"
        result = rf.parse_output_to_json(output)
        self.assertEqual(result["identity"]["board"], "dlink_covr-x1860-a1")


class TestParseOutputFirmware(TestCase):
    def test_openwrt_release_parsed(self):
        release = (
            "DISTRIB_ID='OpenWrt'\n"
            "DISTRIB_RELEASE='24.10.2'\n"
            "DISTRIB_REVISION='r28739'\n"
            "DISTRIB_TARGET='mediatek/filogic'\n"
        )
        output = f"===OPENWRT_RELEASE===\n{release}===END===\n"
        result = rf.parse_output_to_json(output)
        # Inline parser populates firmware keys directly
        self.assertEqual(result["firmware"]["DISTRIB_RELEASE"], "24.10.2")
        self.assertEqual(result["firmware"]["DISTRIB_TARGET"], "mediatek/filogic")
        # Derived state set from raw release re-parse
        self.assertEqual(result["state"], "openwrt_running")

    def test_kernel_section_three_parts(self):
        output = "===KERNEL===\nLinux 6.6.86 mips\n"
        result = rf.parse_output_to_json(output)
        self.assertEqual(result["firmware"]["kernel"], "Linux 6.6.86 mips")

    def test_kernel_section_short(self):
        output = "===KERNEL===\nLinux\n"
        result = rf.parse_output_to_json(output)
        self.assertEqual(result["firmware"]["kernel"], "Linux")

    def test_no_firmware_state_unknown(self):
        result = rf.parse_output_to_json("===HOSTNAME===\nrouter\n")
        self.assertEqual(result["state"], "unknown")


class TestParseOutputNetwork(TestCase):
    def test_mac_brlan(self):
        output = "===MAC_BRLAN===\naa:bb:cc:dd:ee:ff\n"
        result = rf.parse_output_to_json(output)
        self.assertEqual(result["network"]["macs"]["br-lan"], "aa:bb:cc:dd:ee:ff")

    def test_mac_eth0_after_brlan(self):
        output = (
            "===MAC_BRLAN===\naa:bb:cc:dd:ee:01\n"
            "===MAC_ETH0===\naa:bb:cc:dd:ee:02\n"
        )
        result = rf.parse_output_to_json(output)
        self.assertEqual(result["network"]["macs"]["br-lan"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(result["network"]["macs"]["eth0"], "aa:bb:cc:dd:ee:02")

    def test_mac_all_merges_into_existing(self):
        output = (
            "===MAC_BRLAN===\naa:bb:cc:dd:ee:01\n"
            "===MAC_ALL===\nwlan0=aa:bb:cc:dd:ee:10\neth1=aa:bb:cc:dd:ee:11\n"
        )
        result = rf.parse_output_to_json(output)
        self.assertEqual(result["network"]["macs"]["br-lan"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(result["network"]["macs"]["wlan0"], "aa:bb:cc:dd:ee:10")
        self.assertEqual(result["network"]["macs"]["eth1"], "aa:bb:cc:dd:ee:11")

    def test_network_addresses(self):
        output = "===NETWORK===\ninet 192.168.1.1/24\nlink/ether aa:bb:cc:dd:ee:ff\n"
        result = rf.parse_output_to_json(output)
        self.assertEqual(result["network"]["addresses"], [
            "inet 192.168.1.1/24",
            "link/ether aa:bb:cc:dd:ee:ff",
        ])

    def test_dns_section(self):
        output = "===DNS===\nnameserver 1.1.1.1\nnameserver 8.8.8.8\n"
        result = rf.parse_output_to_json(output)
        self.assertEqual(result["network"]["dns"], ["nameserver 1.1.1.1", "nameserver 8.8.8.8"])


class TestParseOutputHardware(TestCase):
    def test_cpu_section(self):
        output = "===CPU===\nmodel name : MIPS 1004Kc\n"
        result = rf.parse_output_to_json(output)
        self.assertIn("MIPS 1004Kc", result["hardware"]["cpu"])

    def test_memory_free_format(self):
        output = (
            "===MEMORY===\n"
            "              total        used        free      shared  buff/cache   available\n"
            "Mem:            256          50         150           0          56         180\n"
        )
        result = rf.parse_output_to_json(output)
        self.assertEqual(result["hardware"]["memory_mb"]["total"], "256")
        self.assertEqual(result["hardware"]["memory_mb"]["used"], "50")
        self.assertEqual(result["hardware"]["memory_mb"]["free"], "150")
        self.assertEqual(result["hardware"]["memory_mb"]["available"], "180")

    def test_memory_no_mem_line(self):
        output = "===MEMORY===\nno memory info\n"
        result = rf.parse_output_to_json(output)
        self.assertEqual(result["hardware"]["memory_mb"], {})

    def test_flash_overlay_section(self):
        output = (
            "===FLASH===\n"
            "overlayfs:/overlay  100M  20M  80M  20% /overlay\n"
        )
        result = rf.parse_output_to_json(output)
        flash = result["hardware"]["flash_overlay"]
        self.assertEqual(flash["device"], "overlayfs:/overlay")
        self.assertEqual(flash["size"], "100M")
        self.assertEqual(flash["used"], "20M")
        self.assertEqual(flash["available"], "80M")
        self.assertEqual(flash["use_percent"], "20%")

    def test_partitions_section(self):
        output = "===PARTITIONS===\nmtd0: 00040000 00010000 \"u-boot\"\n"
        result = rf.parse_output_to_json(output)
        self.assertIn("u-boot", result["hardware"]["partitions"])


class TestParseOutputSecurity(TestCase):
    def test_ssh_key_count(self):
        output = "===SSH_KEY===\n3\n"
        result = rf.parse_output_to_json(output)
        self.assertEqual(result["security"]["ssh_key_count"], 3)

    def test_ssh_key_count_invalid(self):
        output = "===SSH_KEY===\nnot a number\n"
        result = rf.parse_output_to_json(output)
        self.assertEqual(result["security"]["ssh_key_count"], 0)

    def test_ssh_fingerprint(self):
        output = "===SSH_FINGERPRINT===\nSHA256:abc123def\n"
        result = rf.parse_output_to_json(output)
        self.assertEqual(result["security"]["ssh_fingerprint"], "SHA256:abc123def")

    def test_firewall_rule_count(self):
        output = "===FIREWALL===\n2\n"
        result = rf.parse_output_to_json(output)
        self.assertEqual(result["security"]["wan_ssh_rules"], 2)

    def test_packages_installed(self):
        output = "===PACKAGES===\n142\n"
        result = rf.parse_output_to_json(output)
        self.assertEqual(result["security"]["packages_installed"], 142)


class TestParseOutputDiagnostics(TestCase):
    def test_uptime(self):
        output = "===UPTIME===\n13:42:00 up 1 day,  3:14, load average: 0.05, 0.04, 0.02\n"
        result = rf.parse_output_to_json(output)
        self.assertIn("load average", result["diagnostics"]["uptime"])

    def test_dmesg_boot_split(self):
        output = "===DMESG_BOOT===\nline1\nline2\nline3\n"
        result = rf.parse_output_to_json(output)
        self.assertEqual(result["diagnostics"]["dmesg_boot"], ["line1", "line2", "line3"])

    def test_logread_last_split(self):
        output = "===LOGREAD_LAST===\nevent1\nevent2\n"
        result = rf.parse_output_to_json(output)
        self.assertEqual(result["diagnostics"]["logread_last"], ["event1", "event2"])


class TestParseOutputModem(TestCase):
    def test_modem_section_parsed(self):
        output = (
            "===MODEM===\n"
            "ati=Quectel|EC25-AFFA|Revision: EC25AFFAR\n"
            "imei=123456789012345\n"
            "iccid=8910\n"
        )
        result = rf.parse_output_to_json(output)
        self.assertEqual(result["modem"]["imei"], "123456789012345")
        self.assertIn("Quectel", result["modem"]["ati"])

    def test_modem_no_port_omitted(self):
        output = "===MODEM===\nno_modem_port\n"
        result = rf.parse_output_to_json(output)
        self.assertNotIn("modem", result)

    def test_modem_error_values_filtered(self):
        output = (
            "===MODEM===\n"
            "ati=ERROR\n"
            "imei=123\n"
        )
        result = rf.parse_output_to_json(output)
        self.assertNotIn("ati", result["modem"])
        self.assertEqual(result["modem"]["imei"], "123")


class TestFingerprintRouter(TestCase):
    @patch("router_fingerprint.run_ssh_command", return_value=(True, "===HOSTNAME===\nrouter\n"))
    def test_success_returns_dict_with_ip_and_timestamp(self, mock_ssh):
        result = rf.fingerprint_router("192.168.1.1")
        self.assertIsNotNone(result)
        self.assertEqual(result["ip"], "192.168.1.1")
        self.assertIsNotNone(result["timestamp"])
        self.assertEqual(result["identity"]["hostname"], "router")

    @patch("router_fingerprint.run_ssh_command", return_value=(False, ""))
    def test_ssh_failure_returns_none(self, mock_ssh):
        self.assertIsNone(rf.fingerprint_router("192.168.1.1"))


class TestSaveFingerprint(TestCase):
    def test_writes_file_to_fingerprints_dir(self):
        fp = {
            "timestamp": "2026-06-09T12:00:00",
            "identity": {"board": "test_board"},
        }
        with patch.object(rf, "FINGERPRINTS_DIR") as mock_dir:
            mock_dir.mkdir = MagicMock()
            mock_dir.__truediv__ = MagicMock(return_value=MagicMock())
            written_path = mock_dir.__truediv__.return_value
            written_path.write_text = MagicMock()
            result = rf.save_fingerprint(fp)
            self.assertIs(result, written_path)
            written_path.write_text.assert_called_once()

    def test_filename_uses_board_id_when_provided(self):
        fp = {"timestamp": "2026-06-09T12:00:00"}
        with patch.object(rf, "FINGERPRINTS_DIR") as mock_dir:
            mock_dir.mkdir = MagicMock()
            mock_dir.__truediv__ = MagicMock(return_value=MagicMock(write_text=MagicMock()))
            rf.save_fingerprint(fp, board_id="explicit-board")
            filename = mock_dir.__truediv__.call_args[0][0]
            self.assertIn("explicit-board", filename)

    def test_falls_back_to_unknown_when_no_board(self):
        fp = {"timestamp": "2026-06-09T12:00:00", "identity": {}}
        with patch.object(rf, "FINGERPRINTS_DIR") as mock_dir:
            mock_dir.mkdir = MagicMock()
            mock_dir.__truediv__ = MagicMock(return_value=MagicMock(write_text=MagicMock()))
            rf.save_fingerprint(fp)
            filename = mock_dir.__truediv__.call_args[0][0]
            self.assertIn("unknown", filename)

    def test_sanitizes_special_chars_in_filename(self):
        fp = {
            "timestamp": "2026-06-09T12:00:00.123456",
            "identity": {"board": "vendor,with space"},
        }
        with patch.object(rf, "FINGERPRINTS_DIR") as mock_dir:
            mock_dir.mkdir = MagicMock()
            mock_dir.__truediv__ = MagicMock(return_value=MagicMock(write_text=MagicMock()))
            rf.save_fingerprint(fp)
            filename = mock_dir.__truediv__.call_args[0][0]
            self.assertNotIn(",", filename)
            self.assertNotIn(" ", filename)
            self.assertNotIn(":", filename)

    def test_oserror_returns_none(self):
        fp = {"timestamp": "ts", "identity": {"board": "b"}}
        with patch.object(rf, "FINGERPRINTS_DIR") as mock_dir:
            mock_dir.mkdir = MagicMock()
            path_mock = MagicMock()
            path_mock.write_text.side_effect = OSError("disk full")
            mock_dir.__truediv__ = MagicMock(return_value=path_mock)
            result = rf.save_fingerprint(fp)
            self.assertIsNone(result)


class TestMainWithExplicitIp(TestCase):
    @patch("router_fingerprint.run_ssh_command", return_value=(True, "===HOSTNAME===\nrouter\n"))
    @patch.object(sys, "argv", ["router-fingerprint.py", "--ip", "10.1.2.3", "--quiet"])
    def test_explicit_ip_used(self, mock_ssh):
        with patch("sys.stdout"):
            with self.assertRaises(SystemExit) as cm:
                rf.main()
            self.assertEqual(cm.exception.code, 0)
        mock_ssh.assert_called_with("10.1.2.3", True)


class TestMainSshFailureExits(TestCase):
    @patch("router_fingerprint.run_ssh_command", return_value=(False, ""))
    @patch.object(sys, "argv", ["router-fingerprint.py", "--ip", "10.1.2.3", "--quiet"])
    def test_ssh_failure_exits_with_code_1(self, mock_ssh):
        with self.assertRaises(SystemExit) as cm:
            rf.main()
        self.assertEqual(cm.exception.code, 1)


class TestMainAutoDetect(TestCase):
    @patch("router_fingerprint.get_default_gateway", return_value="192.168.1.1")
    @patch("router_fingerprint.run_ssh_command", return_value=(True, "===HOSTNAME===\nr\n"))
    @patch.object(sys, "argv", ["router-fingerprint.py", "--quiet"])
    def test_uses_gateway_when_no_ip(self, mock_ssh, mock_gw):
        with patch("sys.stdout"):
            with self.assertRaises(SystemExit) as cm:
                rf.main()
            self.assertEqual(cm.exception.code, 0)
        mock_ssh.assert_called_with("192.168.1.1", True)


class TestMainCommonIpsFallback(TestCase):
    @patch("router_fingerprint.get_default_gateway", return_value=None)
    @patch("router_fingerprint.socket.socket")
    @patch("router_fingerprint.run_ssh_command", return_value=(True, "===HOSTNAME===\nr\n"))
    @patch.object(sys, "argv", ["router-fingerprint.py", "--quiet"])
    def test_falls_back_to_common_ips_on_success(self, mock_ssh, mock_sock_cls, mock_gw):
        sock = MagicMock()
        mock_sock_cls.return_value = sock
        with patch("sys.stdout"):
            with self.assertRaises(SystemExit) as cm:
                rf.main()
            self.assertEqual(cm.exception.code, 0)
        sock.connect.assert_called()

    @patch("router_fingerprint.get_default_gateway", return_value=None)
    @patch("router_fingerprint.socket.socket")
    @patch.object(sys, "argv", ["router-fingerprint.py", "--quiet"])
    def test_no_reachable_router_exits_1(self, mock_sock_cls, mock_gw):
        sock = MagicMock()
        sock.connect.side_effect = socket.error("unreachable")
        mock_sock_cls.return_value = sock
        with self.assertRaises(SystemExit) as cm:
            rf.main()
        self.assertEqual(cm.exception.code, 1)


class TestMainOutputFile(TestCase):
    @patch("router_fingerprint.run_ssh_command", return_value=(True, "===HOSTNAME===\nr\n"))
    @patch("builtins.open")
    def test_writes_to_output_file(self, mock_open, mock_ssh):
        argv = ["router-fingerprint.py", "--ip", "10.0.0.1", "--output", "/tmp/out.json", "--quiet"]
        with patch.object(sys, "argv", argv):
            with self.assertRaises(SystemExit) as cm:
                rf.main()
            self.assertEqual(cm.exception.code, 0)
        mock_open.assert_called_with("/tmp/out.json", "w")

    @patch("router_fingerprint.run_ssh_command", return_value=(True, "===HOSTNAME===\nr\n"))
    @patch("builtins.open", side_effect=OSError("permission denied"))
    def test_output_oserror_exits_1(self, mock_open, mock_ssh):
        argv = ["router-fingerprint.py", "--ip", "10.0.0.1", "--output", "/no/write/access.json", "--quiet"]
        with patch.object(sys, "argv", argv):
            with self.assertRaises(SystemExit) as cm:
                rf.main()
            self.assertEqual(cm.exception.code, 1)
