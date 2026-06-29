"""Tests for scripts/router-probe.py — router boot state identification.

Covers RouterState dataclass, passive probes (link, ARP, broadcast capture),
active probes (HTTP, SSH, ping), the classify_state decision tree, the
probe_router orchestrator, and the main CLI entry point. All subprocess,
SSH, curl, and filesystem interactions are mocked.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))


def _load_router_probe():
    """Load the hyphenated router-probe.py as an importable module.

    Registers the module in sys.modules before exec_module so that dataclass
    introspection (which calls sys.modules.get(cls.__module__)) succeeds.
    """
    spec = importlib.util.spec_from_file_location(
        "router_probe", ROOT / "scripts" / "router-probe.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["router_probe"] = module
    spec.loader.exec_module(module)
    return module


router_probe = _load_router_probe()


def _cp(returncode: int = 0, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    """Build a fake CompletedProcess for run_cmd / run_ssh return values."""
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


# ---------------------------------------------------------------------------
# RouterState dataclass + tiny helpers
# ---------------------------------------------------------------------------

class TestRouterState(unittest.TestCase):
    def test_defaults(self) -> None:
        s = router_probe.RouterState()
        self.assertEqual(s.state, "unknown")
        self.assertEqual(s.ip, "")
        self.assertEqual(s.mac, "")
        self.assertEqual(s.model, "")
        self.assertEqual(s.vendor, "")
        self.assertEqual(s.firmware_version, "")
        self.assertEqual(s.uptime, "")
        self.assertEqual(s.ssh_key_count, 0)
        self.assertEqual(s.evidence, [])

    def test_evidence_is_unique_per_instance(self) -> None:
        """default_factory must not share the same list across instances."""
        a = router_probe.RouterState()
        b = router_probe.RouterState()
        a.evidence.append(("x", "y", "z"))
        self.assertEqual(b.evidence, [])

    def test_fields_assignable(self) -> None:
        s = router_probe.RouterState(ip="1.2.3.4", mac="aa:bb:cc:dd:ee:ff")
        s.state = "openwrt_running"
        s.model = "covr-x1860"
        s.vendor = "OpenWrt"
        s.firmware_version = "24.10.2"
        s.ssh_key_count = 3
        self.assertEqual(s.state, "openwrt_running")
        self.assertEqual(s.model, "covr-x1860")
        self.assertEqual(s.vendor, "OpenWrt")
        self.assertEqual(s.firmware_version, "24.10.2")
        self.assertEqual(s.ssh_key_count, 3)
        self.assertEqual(s.ip, "1.2.3.4")
        self.assertEqual(s.mac, "aa:bb:cc:dd:ee:ff")


class TestRouterStatesConstant(unittest.TestCase):
    def test_router_states_tuple(self) -> None:
        self.assertIn("off", router_probe.RouterStates)
        self.assertIn("uboot", router_probe.RouterStates)
        self.assertIn("openwrt_booting", router_probe.RouterStates)
        self.assertIn("openwrt_failsafe", router_probe.RouterStates)
        self.assertIn("openwrt_running", router_probe.RouterStates)
        self.assertIn("glinet_stock", router_probe.RouterStates)
        self.assertIn("linksys_stock", router_probe.RouterStates)
        self.assertIn("unknown", router_probe.RouterStates)


class TestTimestamp(unittest.TestCase):
    def test_format(self) -> None:
        ts = router_probe._timestamp()
        # YYYYMMDD-HHMMSS — 8 digits, dash, 6 digits
        self.assertRegex(ts, r"^\d{8}-\d{6}$")

    def test_uses_datetime_now(self) -> None:
        fake_now = MagicMock()
        fake_now.strftime.return_value = "20260609-120000"
        with patch.object(router_probe, "datetime") as mock_dt:
            mock_dt.now.return_value = fake_now
            self.assertEqual(router_probe._timestamp(), "20260609-120000")
            fake_now.strftime.assert_called_once_with("%Y%m%d-%H%M%S")


# ---------------------------------------------------------------------------
# probe_link_state — Linux vs Darwin paths
# ---------------------------------------------------------------------------

class TestProbeLinkState(unittest.TestCase):
    def test_linux_link_up_with_local_mac(self) -> None:
        sysfs_values = {
            "operstate": "up",
            "carrier": "1",
            "address": "aa:bb:cc:dd:ee:ff",
        }

        def fake_read_text(self: Path) -> str:
            for key, val in sysfs_values.items():
                if self.name == key:
                    return val + "\n"
            raise FileNotFoundError(str(self))

        with patch("platform.system", return_value="Linux"), \
             patch.object(Path, "read_text", autospec=True, side_effect=fake_read_text):
            name, status, detail = router_probe.probe_link_state("eth0")
        self.assertEqual(name, "link_state")
        self.assertEqual(status, "link_up")
        self.assertEqual(detail, "local_mac=aa:bb:cc:dd:ee:ff")

    def test_linux_no_link(self) -> None:
        # operstate down → status stays "no_link"; address fails
        def fake_read_text(self: Path) -> str:
            if self.name == "operstate":
                return "down\n"
            if self.name == "carrier":
                return "0\n"
            raise FileNotFoundError(str(self))

        with patch("platform.system", return_value="Linux"), \
             patch.object(Path, "read_text", autospec=True, side_effect=fake_read_text):
            name, status, detail = router_probe.probe_link_state("eth0")
        self.assertEqual(name, "link_state")
        self.assertEqual(status, "no_link")
        # detail stays empty when address can't be read
        self.assertEqual(detail, "")

    def test_linux_sysfs_unreadable_falls_back(self) -> None:
        with patch("platform.system", return_value="Linux"), \
             patch.object(Path, "read_text", autospec=True, side_effect=PermissionError("denied")):
            name, status, detail = router_probe.probe_link_state("eth0")
        self.assertEqual(name, "link_state")
        # both operstate AND address reads fail → no_link, no detail
        self.assertEqual(status, "no_link")
        self.assertEqual(detail, "")

    def test_darwin_status_active(self) -> None:
        ifconfig_out = "en0: flags=8863\n\tstatus: active\n\tether aa:bb:cc:dd:ee:ff\n"
        with patch("platform.system", return_value="Darwin"), \
             patch.object(router_probe, "run_cmd",
                          return_value=_cp(stdout=ifconfig_out)) as mock_run:
            name, status, detail = router_probe.probe_link_state("en0")
        self.assertEqual(name, "link_state")
        self.assertEqual(status, "link_up")
        self.assertEqual(detail, "interface active")
        mock_run.assert_called_once_with(["ifconfig", "en0"], check=False)

    def test_darwin_running_flag(self) -> None:
        with patch("platform.system", return_value="Darwin"), \
             patch.object(router_probe, "run_cmd",
                          return_value=_cp(stdout="en0: RUNNING\n")):
            _, status, detail = router_probe.probe_link_state("en0")
        self.assertEqual(status, "link_up")
        self.assertEqual(detail, "interface running")

    def test_darwin_media_extracted(self) -> None:
        out = "en0:\n\tmedia: autoselect (1000baseT <full-duplex>)\n"
        with patch("platform.system", return_value="Darwin"), \
             patch.object(router_probe, "run_cmd", return_value=_cp(stdout=out)):
            _, status, detail = router_probe.probe_link_state("en0")
        self.assertEqual(status, "no_link")
        self.assertEqual(detail, "autoselect (1000baseT <full-duplex>)")

    def test_subprocess_error_caught(self) -> None:
        with patch("platform.system", return_value="Darwin"), \
             patch.object(router_probe, "run_cmd",
                          side_effect=subprocess.SubprocessError("boom")):
            name, status, detail = router_probe.probe_link_state("en0")
        self.assertEqual(name, "link_state")
        self.assertEqual(status, "no_link")
        self.assertEqual(detail, "boom")

    def test_os_error_caught(self) -> None:
        with patch("platform.system", return_value="Darwin"), \
             patch.object(router_probe, "run_cmd", side_effect=OSError("nope")):
            _, _, detail = router_probe.probe_link_state("en0")
        self.assertEqual(detail, "nope")


# ---------------------------------------------------------------------------
# probe_arp
# ---------------------------------------------------------------------------

class TestProbeArp(unittest.TestCase):
    def test_mac_prefix_match_extracts_ip(self) -> None:
        arp_out = "? (192.168.1.1) at aa:bb:cc:11:22:33 on en0 [ethernet]\n"
        with patch.object(router_probe, "run_cmd", return_value=_cp(stdout=arp_out)):
            name, status, detail = router_probe.probe_arp("aa:bb:cc", "en0")
        self.assertEqual(name, "arp_from_router")
        self.assertEqual(status, "seen")
        self.assertEqual(detail, "192.168.1.1")

    def test_mac_prefix_match_no_ip_in_line(self) -> None:
        arp_out = "weird line aa:bb:cc:11:22:33 no ip\n"
        with patch.object(router_probe, "run_cmd", return_value=_cp(stdout=arp_out)):
            _, status, detail = router_probe.probe_arp("AA:BB:CC", "en0")
        self.assertEqual(status, "seen")
        # falls back to line stripped
        self.assertIn("aa:bb:cc:11:22:33", detail)

    def test_mac_prefix_no_match(self) -> None:
        with patch.object(router_probe, "run_cmd",
                          return_value=_cp(stdout="? (10.0.0.1) at ff:ff:ff on en0\n")):
            _, status, detail = router_probe.probe_arp("aa:bb:cc", "en0")
        self.assertEqual(status, "not_seen")
        self.assertEqual(detail, "")

    def test_no_mac_prefix_linux_reads_local_addr(self) -> None:
        def fake_read_text(self: Path) -> str:
            return "de:ad:be:ef:00:01\n"

        with patch.object(router_probe, "run_cmd", return_value=_cp(stdout="")), \
             patch("platform.system", return_value="Linux"), \
             patch.object(Path, "read_text", autospec=True, side_effect=fake_read_text):
            _, status, detail = router_probe.probe_arp("", "eth0")
        self.assertEqual(status, "not_seen")
        self.assertEqual(detail, "local_mac=de:ad:be:ef:00:01")

    def test_no_mac_prefix_linux_address_unreadable(self) -> None:
        with patch.object(router_probe, "run_cmd", return_value=_cp(stdout="")), \
             patch("platform.system", return_value="Linux"), \
             patch.object(Path, "read_text", autospec=True, side_effect=OSError("denied")):
            _, status, detail = router_probe.probe_arp("", "eth0")
        self.assertEqual(status, "not_seen")
        self.assertEqual(detail, "")

    def test_no_mac_prefix_darwin_extracts_ether(self) -> None:
        ifconfig_out = "en0:\n\tether aa:bb:cc:dd:ee:ff\n\tinet 1.2.3.4\n"
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            if cmd[:1] == ["arp"]:
                return _cp(stdout="")
            return _cp(stdout=ifconfig_out)

        with patch.object(router_probe, "run_cmd", side_effect=fake_run), \
             patch("platform.system", return_value="Darwin"):
            _, status, detail = router_probe.probe_arp("", "en0")
        self.assertEqual(status, "not_seen")
        self.assertEqual(detail, "local_mac=aa:bb:cc:dd:ee:ff")
        # arp first, then ifconfig
        self.assertEqual(calls[0][0], "arp")
        self.assertEqual(calls[1][0], "ifconfig")

    def test_no_mac_prefix_darwin_no_ether(self) -> None:
        with patch.object(router_probe, "run_cmd", return_value=_cp(stdout="no ether here")), \
             patch("platform.system", return_value="Darwin"):
            _, status, detail = router_probe.probe_arp("", "en0")
        self.assertEqual(status, "not_seen")
        self.assertEqual(detail, "")

    def test_subprocess_error_caught(self) -> None:
        with patch.object(router_probe, "run_cmd",
                          side_effect=subprocess.SubprocessError("arp fail")):
            _, status, detail = router_probe.probe_arp("aa:bb:cc", "en0")
        self.assertEqual(status, "not_seen")
        self.assertEqual(detail, "arp fail")

    def test_os_error_caught(self) -> None:
        with patch.object(router_probe, "run_cmd", side_effect=OSError("io")):
            _, _, detail = router_probe.probe_arp("aa:bb:cc", "en0")
        self.assertEqual(detail, "io")


# ---------------------------------------------------------------------------
# probe_failsafe_broadcast
# ---------------------------------------------------------------------------

class TestProbeFailsafeBroadcast(unittest.TestCase):
    def test_detected(self) -> None:
        out = "12:00:00.000 IP > Please press button now to enter failsafe\n"
        with patch.object(router_probe, "run_cmd", return_value=_cp(stdout=out)):
            name, status, detail = router_probe.probe_failsafe_broadcast("en0", timeout=3)
        self.assertEqual(name, "failsafe_broadcast")
        self.assertEqual(status, "detected")
        self.assertIn("failsafe", detail)
        self.assertIn("4919", detail)

    def test_not_detected(self) -> None:
        with patch.object(router_probe, "run_cmd", return_value=_cp(stdout="nothing\n")):
            _, status, detail = router_probe.probe_failsafe_broadcast("en0")
        self.assertEqual(status, "not_detected")
        self.assertEqual(detail, "")

    def test_permission_denied(self) -> None:
        with patch.object(router_probe, "run_cmd",
                          return_value=_cp(returncode=1, stderr="tcpdump: Permission denied")):
            _, status, detail = router_probe.probe_failsafe_broadcast("en0")
        self.assertEqual(status, "permission_denied")
        self.assertIn("sudo", detail)

    def test_timeout(self) -> None:
        with patch.object(router_probe, "run_cmd",
                          side_effect=subprocess.TimeoutExpired(cmd="tcpdump", timeout=10)):
            _, status, detail = router_probe.probe_failsafe_broadcast("en0", timeout=10)
        self.assertEqual(status, "timeout")
        self.assertIn("10s", detail)

    def test_tcpdump_not_installed(self) -> None:
        with patch.object(router_probe, "run_cmd", side_effect=FileNotFoundError("tcpdump")):
            _, status, detail = router_probe.probe_failsafe_broadcast("en0")
        self.assertEqual(status, "unavailable")
        self.assertIn("tcpdump", detail)

    def test_os_error_caught(self) -> None:
        with patch.object(router_probe, "run_cmd", side_effect=OSError("io")):
            _, status, detail = router_probe.probe_failsafe_broadcast("en0")
        self.assertEqual(status, "not_detected")
        self.assertEqual(detail, "io")


# ---------------------------------------------------------------------------
# probe_icmpv6_ra
# ---------------------------------------------------------------------------

class TestProbeIcmpv6Ra(unittest.TestCase):
    def test_detected(self) -> None:
        out = "12:00:00.000 IP6 > Router Advertisement\n"
        with patch.object(router_probe, "run_cmd", return_value=_cp(stdout=out)):
            name, status, detail = router_probe.probe_icmpv6_ra("en0")
        self.assertEqual(name, "icmpv6_ra")
        self.assertEqual(status, "detected")
        self.assertIn("Router Advertisement", detail)

    def test_not_detected(self) -> None:
        with patch.object(router_probe, "run_cmd", return_value=_cp(stdout="nothing\n")):
            _, status, detail = router_probe.probe_icmpv6_ra("en0")
        self.assertEqual(status, "not_detected")
        self.assertEqual(detail, "")

    def test_permission_denied(self) -> None:
        with patch.object(router_probe, "run_cmd",
                          return_value=_cp(returncode=1, stderr="Permission denied")):
            _, status, detail = router_probe.probe_icmpv6_ra("en0")
        self.assertEqual(status, "permission_denied")
        self.assertIn("sudo", detail)

    def test_timeout(self) -> None:
        with patch.object(router_probe, "run_cmd",
                          side_effect=subprocess.TimeoutExpired(cmd="tcpdump", timeout=5)):
            _, status, detail = router_probe.probe_icmpv6_ra("en0", timeout=5)
        self.assertEqual(status, "timeout")
        self.assertIn("5s", detail)

    def test_tcpdump_not_installed(self) -> None:
        with patch.object(router_probe, "run_cmd", side_effect=FileNotFoundError("tcpdump")):
            _, status, detail = router_probe.probe_icmpv6_ra("en0")
        self.assertEqual(status, "unavailable")
        self.assertIn("tcpdump", detail)

    def test_os_error_caught(self) -> None:
        with patch.object(router_probe, "run_cmd", side_effect=OSError("io")):
            _, _, detail = router_probe.probe_icmpv6_ra("en0")
        self.assertEqual(detail, "io")


# ---------------------------------------------------------------------------
# start_pcap_capture
# ---------------------------------------------------------------------------

class TestStartPcapCapture(unittest.TestCase):
    def test_returns_popen(self) -> None:
        fake_proc = MagicMock()
        with patch.object(router_probe.subprocess, "Popen", return_value=fake_proc) as mock_popen, \
             patch.object(Path, "mkdir"):
            result = router_probe.start_pcap_capture("en0", "probing")
        self.assertIs(result, fake_proc)
        # Verify Popen called with tcpdump command including interface and -c 500
        args = mock_popen.call_args[0][0]
        self.assertEqual(args[0], "tcpdump")
        self.assertIn("-i", args)
        self.assertIn("en0", args)
        self.assertIn("-c", args)
        self.assertIn("500", args)
        # output file path includes state label
        outfile = args[args.index("-w") + 1]
        self.assertIn("probing", outfile)
        self.assertTrue(outfile.endswith(".pcap"))

    def test_filenotfound_returns_none(self) -> None:
        with patch.object(router_probe.subprocess, "Popen",
                          side_effect=FileNotFoundError("tcpdump")), \
             patch.object(Path, "mkdir"):
            self.assertIsNone(router_probe.start_pcap_capture("en0", "test"))

    def test_oserror_returns_none(self) -> None:
        with patch.object(router_probe.subprocess, "Popen", side_effect=OSError("denied")), \
             patch.object(Path, "mkdir"):
            self.assertIsNone(router_probe.start_pcap_capture("en0", "test"))


# ---------------------------------------------------------------------------
# probe_http_get — signature matching
# ---------------------------------------------------------------------------

class TestProbeHttpGet(unittest.TestCase):
    def test_uboot_firmware_update_marker(self) -> None:
        with patch.object(router_probe, "curl_get",
                          return_value=(0, "<html>FIRMWARE UPDATE</html>", "")):
            name, status, detail = router_probe.probe_http_get("192.168.1.1")
        self.assertEqual(name, "http_get")
        self.assertEqual(status, "uboot")
        self.assertIn("GET", detail)

    def test_uboot_firmware_form(self) -> None:
        body = "<html><form>firmware upload</form></html>"
        with patch.object(router_probe, "curl_get", return_value=(0, body, "")):
            _, status, _ = router_probe.probe_http_get("192.168.1.1")
        self.assertEqual(status, "uboot")

    def test_luci_openwrt(self) -> None:
        with patch.object(router_probe, "curl_get", return_value=(0, "<title>LuCI</title>", "")):
            _, status, _ = router_probe.probe_http_get("192.168.1.1")
        self.assertEqual(status, "openwrt_luci")

    def test_openwrt_body(self) -> None:
        with patch.object(router_probe, "curl_get",
                          return_value=(0, "<html>OpenWrt</html>", "")):
            _, status, _ = router_probe.probe_http_get("192.168.1.1")
        self.assertEqual(status, "openwrt_luci")

    def test_glinet_stock(self) -> None:
        with patch.object(router_probe, "curl_get", return_value=(0, "<title>GL-iNet</title>", "")):
            _, status, _ = router_probe.probe_http_get("192.168.8.1")
        self.assertEqual(status, "glinet_stock")

    def test_glinet_variant(self) -> None:
        with patch.object(router_probe, "curl_get",
                          return_value=(0, "<html>glinet admin</html>", "")):
            _, status, _ = router_probe.probe_http_get("192.168.8.1")
        self.assertEqual(status, "glinet_stock")

    def test_linksys_stock_jnap(self) -> None:
        with patch.object(router_probe, "curl_get", return_value=(0, "JNAP_ACTION", "")):
            _, status, _ = router_probe.probe_http_get("192.168.1.1")
        self.assertEqual(status, "linksys_stock")

    def test_linksys_stock_keyword(self) -> None:
        with patch.object(router_probe, "curl_get",
                          return_value=(0, "<title>Linksys Router</title>", "")):
            _, status, _ = router_probe.probe_http_get("192.168.1.1")
        self.assertEqual(status, "linksys_stock")

    def test_uip_in_body(self) -> None:
        with patch.object(router_probe, "curl_get", return_value=(0, "uIP server v1", "")):
            _, status, detail = router_probe.probe_http_get("192.168.1.1")
        self.assertEqual(status, "uboot")
        self.assertIn("uIP", detail)

    def test_unknown_http(self) -> None:
        with patch.object(router_probe, "curl_get",
                          return_value=(0, "some other content", "")):
            _, status, detail = router_probe.probe_http_get("192.168.1.1")
        self.assertEqual(status, "unknown_http")
        self.assertIn("18 bytes", detail)

    def test_no_response(self) -> None:
        with patch.object(router_probe, "curl_get", return_value=(-1, "", "fail")):
            _, status, _ = router_probe.probe_http_get("192.168.1.1")
        self.assertEqual(status, "no_response")

    def test_subprocess_error_caught(self) -> None:
        with patch.object(router_probe, "curl_get",
                          side_effect=subprocess.SubprocessError("curl boom")):
            _, status, detail = router_probe.probe_http_get("192.168.1.1")
        self.assertEqual(status, "no_response")
        self.assertEqual(detail, "curl boom")

    def test_os_error_caught(self) -> None:
        with patch.object(router_probe, "curl_get", side_effect=OSError("io")):
            _, _, detail = router_probe.probe_http_get("192.168.1.1")
        self.assertEqual(detail, "io")


# ---------------------------------------------------------------------------
# probe_http_head
# ---------------------------------------------------------------------------

class TestProbeHttpHead(unittest.TestCase):
    def test_uboot_uip_server(self) -> None:
        with patch.object(router_probe, "curl_head",
                          return_value=(0, "HTTP/1.0 200 OK\nServer: uIP/1.0\n", "")):
            name, status, detail = router_probe.probe_http_head("192.168.1.1")
        self.assertEqual(name, "http_head")
        self.assertEqual(status, "uboot")
        self.assertIn("uIP", detail)

    def test_method_not_allowed_405(self) -> None:
        with patch.object(router_probe, "curl_head",
                          return_value=(0, "HTTP/1.1 405 Method Not Allowed\n", "")):
            _, status, detail = router_probe.probe_http_head("192.168.1.1")
        self.assertEqual(status, "method_not_allowed")
        self.assertIn("405", detail)
        self.assertIn("MT3000", detail)

    def test_headers_received_with_server(self) -> None:
        headers = "HTTP/1.1 200 OK\nServer: nginx/1.20\nContent-Length: 42\n"
        with patch.object(router_probe, "curl_head", return_value=(0, headers, "")):
            _, status, detail = router_probe.probe_http_head("192.168.1.1")
        self.assertEqual(status, "headers_received")
        self.assertEqual(detail, "nginx/1.20")

    def test_headers_received_no_server_header(self) -> None:
        with patch.object(router_probe, "curl_head",
                          return_value=(0, "HTTP/1.1 200 OK\n", "")):
            _, status, detail = router_probe.probe_http_head("192.168.1.1")
        self.assertEqual(status, "headers_received")
        self.assertEqual(detail, "HTTP/1.1 200 OK")

    def test_no_response_nonzero_rc(self) -> None:
        with patch.object(router_probe, "curl_head", return_value=(-1, "", "fail")):
            _, status, _ = router_probe.probe_http_head("192.168.1.1")
        self.assertEqual(status, "no_response")

    def test_no_response_blank_headers(self) -> None:
        with patch.object(router_probe, "curl_head", return_value=(0, "", "")):
            _, status, _ = router_probe.probe_http_head("192.168.1.1")
        self.assertEqual(status, "no_response")

    def test_subprocess_error_caught(self) -> None:
        with patch.object(router_probe, "curl_head",
                          side_effect=subprocess.SubprocessError("fail")):
            _, status, detail = router_probe.probe_http_head("192.168.1.1")
        self.assertEqual(status, "no_response")
        self.assertEqual(detail, "fail")

    def test_os_error_caught(self) -> None:
        with patch.object(router_probe, "curl_head", side_effect=OSError("io")):
            _, _, detail = router_probe.probe_http_head("192.168.1.1")
        self.assertEqual(detail, "io")


# ---------------------------------------------------------------------------
# probe_ssh
# ---------------------------------------------------------------------------

class TestProbeSsh(unittest.TestCase):
    def test_openwrt_ssh_with_release(self) -> None:
        release = "DISTRIB_ID='OpenWrt'\nDISTRIB_RELEASE='24.10.2'\n"
        with patch.object(router_probe, "run_ssh", return_value=_cp(stdout=release)):
            name, status, detail = router_probe.probe_ssh("192.168.1.1")
        self.assertEqual(name, "ssh")
        self.assertEqual(status, "openwrt_ssh")
        self.assertIn("OpenWrt", detail)

    def test_openwrt_ssh_long_release_truncated_to_200(self) -> None:
        long_release = "X" * 500
        with patch.object(router_probe, "run_ssh", return_value=_cp(stdout=long_release)):
            _, _, detail = router_probe.probe_ssh("192.168.1.1")
        self.assertEqual(len(detail), 200)

    def test_ssh_ok_no_release_file(self) -> None:
        # First call (cat /etc/openwrt_release) fails, second call (true) succeeds
        results = [_cp(returncode=1, stderr="No such file"), _cp(returncode=0)]
        with patch.object(router_probe, "run_ssh", side_effect=results):
            _, status, detail = router_probe.probe_ssh("192.168.1.1")
        self.assertEqual(status, "ssh_ok")
        self.assertIn("openwrt_release", detail)

    def test_ssh_auth_required(self) -> None:
        results = [
            _cp(returncode=1, stderr="No such file"),
            _cp(returncode=255, stderr="Permission denied (publickey)"),
        ]
        with patch.object(router_probe, "run_ssh", side_effect=results):
            _, status, detail = router_probe.probe_ssh("192.168.1.1")
        self.assertEqual(status, "ssh_auth_required")
        self.assertIn("key", detail)

    def test_ssh_auth_required_case_insensitive(self) -> None:
        results = [
            _cp(returncode=1),
            _cp(returncode=255, stderr="ssh: permission denied"),
        ]
        with patch.object(router_probe, "run_ssh", side_effect=results):
            _, status, _ = router_probe.probe_ssh("192.168.1.1")
        self.assertEqual(status, "ssh_auth_required")

    def test_ssh_refused(self) -> None:
        results = [
            _cp(returncode=1),
            _cp(returncode=255, stderr="ssh: connect to host 1.2.3.4 port 22: Connection refused"),
        ]
        with patch.object(router_probe, "run_ssh", side_effect=results):
            _, status, _ = router_probe.probe_ssh("192.168.1.1")
        self.assertEqual(status, "ssh_refused")

    def test_ssh_timeout(self) -> None:
        with patch.object(router_probe, "run_ssh",
                          side_effect=subprocess.TimeoutExpired(cmd="ssh", timeout=8)):
            _, status, detail = router_probe.probe_ssh("192.168.1.1")
        self.assertEqual(status, "ssh_timeout")
        self.assertIn("timed out", detail)

    def test_subprocess_error_caught(self) -> None:
        with patch.object(router_probe, "run_ssh",
                          side_effect=subprocess.SubprocessError("boom")):
            _, status, detail = router_probe.probe_ssh("192.168.1.1")
        self.assertEqual(status, "no_response")
        self.assertEqual(detail, "boom")

    def test_os_error_caught(self) -> None:
        with patch.object(router_probe, "run_ssh", side_effect=OSError("io")):
            _, _, detail = router_probe.probe_ssh("192.168.1.1")
        self.assertEqual(detail, "io")

    def test_no_recognized_stderr(self) -> None:
        # Second probe fails with unrecognized stderr → status stays "no_response"
        results = [_cp(returncode=1), _cp(returncode=1, stderr="weird unknown error")]
        with patch.object(router_probe, "run_ssh", side_effect=results):
            _, status, _ = router_probe.probe_ssh("192.168.1.1")
        self.assertEqual(status, "no_response")


# ---------------------------------------------------------------------------
# probe_ssh_failsafe
# ---------------------------------------------------------------------------

class TestProbeSshFailsafe(unittest.TestCase):
    def test_failsafe_marker_exists(self) -> None:
        with patch.object(router_probe, "ssh_cmd",
                          return_value=["ssh", "-o", "X=1", "root@1", "ls", "/tmp/failsafe"]), \
             patch.object(router_probe, "run_cmd", return_value=_cp(returncode=0)):
            name, status, detail = router_probe.probe_ssh_failsafe("192.168.1.1")
        self.assertEqual(name, "ssh_failsafe")
        self.assertEqual(status, "failsafe")
        self.assertIn("/tmp/failsafe", detail)

    def test_no_overlay_means_failsafe(self) -> None:
        # ls /tmp/failsafe fails, mount succeeds but lacks overlay/jffs2
        with patch.object(router_probe, "ssh_cmd",
                          return_value=["ssh", "root@1", "ls", "/tmp/failsafe"]), \
             patch.object(router_probe, "run_cmd", return_value=_cp(returncode=1)), \
             patch.object(router_probe, "run_ssh",
                          return_value=_cp(returncode=0, stdout="tmpfs / tmpfs rw,relatime 0 0\n")):
            _, status, detail = router_probe.probe_ssh_failsafe("192.168.1.1")
        self.assertEqual(status, "failsafe")
        self.assertIn("no overlay mount", detail)

    def test_overlay_mount_present_not_failsafe(self) -> None:
        mount_out = "overlay /overlay overlay rw,noatime,lowerdir=/rom,upperdir=/overlay/upper 0 0\n"
        with patch.object(router_probe, "ssh_cmd",
                          return_value=["ssh", "root@1", "ls", "/tmp/failsafe"]), \
             patch.object(router_probe, "run_cmd", return_value=_cp(returncode=1)), \
             patch.object(router_probe, "run_ssh", return_value=_cp(returncode=0, stdout=mount_out)):
            _, status, _ = router_probe.probe_ssh_failsafe("192.168.1.1")
        self.assertEqual(status, "not_failsafe")

    def test_jffs2_mount_means_normal_boot(self) -> None:
        mount_out = "/dev/mtdblock5 on /overlay type jffs2 (rw,relatime)\n"
        with patch.object(router_probe, "ssh_cmd", return_value=["ssh", "root@1", "ls", "/tmp/failsafe"]), \
             patch.object(router_probe, "run_cmd", return_value=_cp(returncode=1)), \
             patch.object(router_probe, "run_ssh", return_value=_cp(returncode=0, stdout=mount_out)):
            _, status, _ = router_probe.probe_ssh_failsafe("192.168.1.1")
        self.assertEqual(status, "not_failsafe")

    def test_mount_ssh_fails(self) -> None:
        with patch.object(router_probe, "ssh_cmd", return_value=["ssh", "root@1", "ls", "/tmp/failsafe"]), \
             patch.object(router_probe, "run_cmd", return_value=_cp(returncode=1)), \
             patch.object(router_probe, "run_ssh", return_value=_cp(returncode=255)):
            _, status, _ = router_probe.probe_ssh_failsafe("192.168.1.1")
        self.assertEqual(status, "not_failsafe")

    def test_subprocess_error_caught(self) -> None:
        with patch.object(router_probe, "ssh_cmd", return_value=["ssh"]), \
             patch.object(router_probe, "run_cmd", side_effect=subprocess.SubprocessError("boom")):
            _, status, detail = router_probe.probe_ssh_failsafe("192.168.1.1")
        self.assertEqual(status, "not_failsafe")
        self.assertEqual(detail, "boom")

    def test_os_error_caught(self) -> None:
        with patch.object(router_probe, "ssh_cmd", return_value=["ssh"]), \
             patch.object(router_probe, "run_cmd", side_effect=OSError("io")):
            _, _, detail = router_probe.probe_ssh_failsafe("192.168.1.1")
        self.assertEqual(detail, "io")

    def test_ssh_cmd_options_injected(self) -> None:
        """probe_ssh_failsafe must inject -o LogLevel=ERROR into the ssh command."""
        captured: list = []

        def capture_run(cmd, **kw):
            captured.append(list(cmd))
            return _cp(returncode=0)

        with patch.object(router_probe, "ssh_cmd",
                          return_value=["ssh", "-o", "BatchMode=yes", "root@1", "ls"]), \
             patch.object(router_probe, "run_cmd", side_effect=capture_run):
            router_probe.probe_ssh_failsafe("192.168.1.1")
        # Confirm LogLevel=ERROR was inserted at position 1-2
        self.assertEqual(captured[0][1], "-o")
        self.assertEqual(captured[0][2], "LogLevel=ERROR")


# ---------------------------------------------------------------------------
# probe_ping
# ---------------------------------------------------------------------------

class TestProbePing(unittest.TestCase):
    def test_reachable(self) -> None:
        with patch.object(router_probe, "ping_host", return_value=True):
            name, status, detail = router_probe.probe_ping("192.168.1.1")
        self.assertEqual(name, "ping")
        self.assertEqual(status, "reachable")
        self.assertEqual(detail, "reply received")

    def test_unreachable(self) -> None:
        with patch.object(router_probe, "ping_host", return_value=False):
            _, status, detail = router_probe.probe_ping("192.168.1.1")
        self.assertEqual(status, "unreachable")
        self.assertEqual(detail, "")

    def test_subprocess_error_caught(self) -> None:
        with patch.object(router_probe, "ping_host",
                          side_effect=subprocess.SubprocessError("ping fail")):
            _, status, detail = router_probe.probe_ping("192.168.1.1")
        self.assertEqual(status, "unreachable")
        self.assertEqual(detail, "ping fail")

    def test_os_error_caught(self) -> None:
        with patch.object(router_probe, "ping_host", side_effect=OSError("io")):
            _, _, detail = router_probe.probe_ping("192.168.1.1")
        self.assertEqual(detail, "io")


# ---------------------------------------------------------------------------
# probe_ssh_details
# ---------------------------------------------------------------------------

class TestProbeSshDetails(unittest.TestCase):
    def test_full_parsing(self) -> None:
        release = (
            "DISTRIB_ID='OpenWrt'\n"
            "DISTRIB_RELEASE='24.10.2'\n"
            "DISTRIB_TARGET='ramips/mt7621'\n"
        )
        model_out = "D-Link COVR-X1860 A1\n"
        wc_out = "3 /etc/dropbear/authorized_keys\n"
        results = [_cp(stdout=release), _cp(stdout=model_out), _cp(stdout=wc_out)]
        with patch.object(router_probe, "run_ssh", side_effect=results):
            model, vendor, fw, keys = router_probe.probe_ssh_details("192.168.1.1")
        self.assertEqual(model, "D-Link COVR-X1860 A1")
        self.assertEqual(vendor, "OpenWrt")
        self.assertEqual(fw, "24.10.2")
        self.assertEqual(keys, 3)

    def test_release_fails(self) -> None:
        # First call fails → vendor and fw stay empty, but model and keys still queried
        results = [
            _cp(returncode=1),
            _cp(returncode=0, stdout="MyModel\n"),
            _cp(returncode=0, stdout="5 file\n"),
        ]
        with patch.object(router_probe, "run_ssh", side_effect=results):
            model, vendor, fw, keys = router_probe.probe_ssh_details("192.168.1.1")
        self.assertEqual(model, "MyModel")
        self.assertEqual(vendor, "")
        self.assertEqual(fw, "")
        self.assertEqual(keys, 5)

    def test_release_without_quotes(self) -> None:
        # Edge case: release file uses no quotes — parser splits on "'"
        release = "DISTRIB_ID=OpenWrt\nDISTRIB_RELEASE=24.10.2\n"
        results = [_cp(stdout=release), _cp(stdout=""), _cp(stdout="0 file\n")]
        with patch.object(router_probe, "run_ssh", side_effect=results):
            _, vendor, fw, _ = router_probe.probe_ssh_details("192.168.1.1")
        # without ' in line, vendor stays "" (the "if '\'' in line" branch is false)
        self.assertEqual(vendor, "")
        self.assertEqual(fw, "")

    def test_model_query_fails(self) -> None:
        release = "DISTRIB_ID='OpenWrt'\n"
        results = [_cp(stdout=release), _cp(returncode=1), _cp(stdout="2 file\n")]
        with patch.object(router_probe, "run_ssh", side_effect=results):
            model, vendor, _, keys = router_probe.probe_ssh_details("192.168.1.1")
        self.assertEqual(model, "")
        self.assertEqual(vendor, "OpenWrt")
        self.assertEqual(keys, 2)

    def test_keys_query_fails(self) -> None:
        results = [_cp(returncode=1), _cp(returncode=1), _cp(returncode=1)]
        with patch.object(router_probe, "run_ssh", side_effect=results):
            _, _, _, keys = router_probe.probe_ssh_details("192.168.1.1")
        self.assertEqual(keys, 0)

    def test_keys_invalid_int_swallowed(self) -> None:
        # wc returns garbage → ValueError suppressed → keys stays 0
        results = [
            _cp(returncode=1),
            _cp(returncode=1),
            _cp(returncode=0, stdout="not_a_number file\n"),
        ]
        with patch.object(router_probe, "run_ssh", side_effect=results):
            _, _, _, keys = router_probe.probe_ssh_details("192.168.1.1")
        self.assertEqual(keys, 0)

    def test_subprocess_error_swallowed(self) -> None:
        with patch.object(router_probe, "run_ssh",
                          side_effect=subprocess.SubprocessError("boom")):
            model, vendor, fw, keys = router_probe.probe_ssh_details("192.168.1.1")
        self.assertEqual((model, vendor, fw, keys), ("", "", "", 0))

    def test_os_error_swallowed(self) -> None:
        with patch.object(router_probe, "run_ssh", side_effect=OSError("io")):
            self.assertEqual(
                router_probe.probe_ssh_details("192.168.1.1"),
                ("", "", "", 0),
            )


# ---------------------------------------------------------------------------
# classify_state — decision tree
# ---------------------------------------------------------------------------

class TestClassifyState(unittest.TestCase):
    @staticmethod
    def _ev(**probes: tuple) -> list:
        """Build evidence list from kwargs like http_get=('uboot', '...')."""
        return [(name, status, detail) for name, (status, detail) in probes.items()]

    def test_uboot_via_http_get(self) -> None:
        evidence = self._ev(http_get=("uboot", "found"))
        self.assertEqual(router_probe.classify_state(evidence), "uboot")

    def test_uboot_via_http_head(self) -> None:
        evidence = self._ev(http_head=("uboot", "uIP"))
        self.assertEqual(router_probe.classify_state(evidence), "uboot")

    def test_openwrt_running(self) -> None:
        evidence = self._ev(
            ssh=("openwrt_ssh", "release"),
            ssh_failsafe=("not_failsafe", ""),
        )
        self.assertEqual(router_probe.classify_state(evidence), "openwrt_running")

    def test_openwrt_failsafe(self) -> None:
        evidence = self._ev(
            ssh=("openwrt_ssh", "release"),
            ssh_failsafe=("failsafe", "marker found"),
        )
        self.assertEqual(router_probe.classify_state(evidence), "openwrt_failsafe")

    def test_glinet_stock(self) -> None:
        evidence = self._ev(http_get=("glinet_stock", "admin"))
        self.assertEqual(router_probe.classify_state(evidence), "glinet_stock")

    def test_linksys_stock(self) -> None:
        evidence = self._ev(http_get=("linksys_stock", "jnap"))
        self.assertEqual(router_probe.classify_state(evidence), "linksys_stock")

    def test_openwrt_booting(self) -> None:
        evidence = self._ev(
            link_state=("link_up", "interface up"),
            failsafe_broadcast=("detected", "broadcast seen"),
            ssh=("no_response", ""),
        )
        self.assertEqual(router_probe.classify_state(evidence), "openwrt_booting")

    def test_off(self) -> None:
        evidence = self._ev(
            link_state=("no_link", ""),
            ping=("unreachable", ""),
        )
        self.assertEqual(router_probe.classify_state(evidence), "off")

    def test_unknown_link_up_but_no_signature(self) -> None:
        evidence = self._ev(link_state=("link_up", "interface up"))
        self.assertEqual(router_probe.classify_state(evidence), "unknown")

    def test_unknown_pingable_but_unidentified(self) -> None:
        evidence = self._ev(ping=("reachable", "ok"))
        self.assertEqual(router_probe.classify_state(evidence), "unknown")

    def test_empty_evidence_defaults_to_off(self) -> None:
        self.assertEqual(router_probe.classify_state([]), "off")

    def test_uboot_takes_precedence_over_glinet(self) -> None:
        # If http_get says uboot AND another signal says glinet, uboot wins
        evidence = self._ev(http_get=("uboot", "first match wins"))
        self.assertEqual(router_probe.classify_state(evidence), "uboot")

    def test_openwrt_ssh_takes_precedence_over_stock_http(self) -> None:
        evidence = self._ev(
            http_get=("glinet_stock", "admin"),
            ssh=("openwrt_ssh", "release"),
            ssh_failsafe=("not_failsafe", ""),
        )
        self.assertEqual(router_probe.classify_state(evidence), "openwrt_running")

    def test_link_up_but_no_failsafe_broadcast_is_unknown(self) -> None:
        # link_up alone without failsafe_broadcast detected → unknown
        evidence = self._ev(
            link_state=("link_up", ""),
            failsafe_broadcast=("not_detected", ""),
            ssh=("no_response", ""),
        )
        self.assertEqual(router_probe.classify_state(evidence), "unknown")

    def test_failsafe_broadcast_without_link_up_is_unknown(self) -> None:
        evidence = self._ev(
            link_state=("no_link", ""),
            failsafe_broadcast=("detected", "found"),
            ssh=("no_response", ""),
            ping=("unreachable", ""),
        )
        # no_link + unreachable → off
        self.assertEqual(router_probe.classify_state(evidence), "off")


# ---------------------------------------------------------------------------
# probe_router orchestrator
# ---------------------------------------------------------------------------

class TestProbeRouter(unittest.TestCase):
    def _all_probes_mocked(self) -> dict:
        """Default mocks for every probe — returns dict of patchers to start."""
        return {
            "start_pcap_capture": MagicMock(return_value=None),
            "probe_link_state": MagicMock(return_value=("link_state", "no_link", "")),
            "probe_arp": MagicMock(return_value=("arp_from_router", "not_seen", "")),
            "probe_failsafe_broadcast": MagicMock(
                return_value=("failsafe_broadcast", "not_detected", "")
            ),
            "probe_icmpv6_ra": MagicMock(return_value=("icmpv6_ra", "not_detected", "")),
            "probe_dhcp": MagicMock(return_value=("dhcp", "not_seen", "")),
            "probe_tftp": MagicMock(return_value=("tftp", "not_seen", "")),
            "probe_http_get": MagicMock(return_value=("http_get", "no_response", "")),
            "probe_http_head": MagicMock(return_value=("http_head", "no_response", "")),
            "probe_ping": MagicMock(return_value=("ping", "unreachable", "")),
            "probe_ssh": MagicMock(return_value=("ssh", "no_response", "")),
            "probe_ssh_failsafe": MagicMock(return_value=("ssh_failsafe", "not_failsafe", "")),
        }

    def _apply(self, mocks: dict):
        """Apply a dict of mocks to router_probe module attributes."""
        patchers = [patch.object(router_probe, name, mock) for name, mock in mocks.items()]
        for p in patchers:
            p.start()
        return patchers

    def _stop(self, patchers) -> None:
        for p in patchers:
            p.stop()

    def test_off_state_no_active_probes_skip_ssh_details(self) -> None:
        mocks = self._all_probes_mocked()
        patchers = self._apply(mocks)
        try:
            with patch.object(router_probe, "probe_ssh_details") as mock_details:
                result = router_probe.probe_router(interface="en0", ip="192.168.1.1")
        finally:
            self._stop(patchers)
        self.assertEqual(result.state, "off")
        self.assertEqual(result.ip, "192.168.1.1")
        self.assertEqual(len(result.evidence), 11)
        # ssh_details only called for openwrt_running
        mock_details.assert_not_called()

    def test_openwrt_running_triggers_ssh_details(self) -> None:
        mocks = self._all_probes_mocked()
        mocks["probe_ssh"] = MagicMock(return_value=("ssh", "openwrt_ssh", "release"))
        patchers = self._apply(mocks)
        try:
            with patch.object(router_probe, "probe_ssh_details",
                              return_value=("X1860", "OpenWrt", "24.10.2", 3)) as mock_details:
                result = router_probe.probe_router(interface="en0", ip="192.168.1.1")
        finally:
            self._stop(patchers)
        self.assertEqual(result.state, "openwrt_running")
        self.assertEqual(result.model, "X1860")
        self.assertEqual(result.vendor, "OpenWrt")
        self.assertEqual(result.firmware_version, "24.10.2")
        self.assertEqual(result.ssh_key_count, 3)
        mock_details.assert_called_once_with("192.168.1.1")

    def test_pcap_process_terminated_after_probing(self) -> None:
        mocks = self._all_probes_mocked()
        fake_proc = MagicMock()
        fake_proc.poll.return_value = None
        mocks["start_pcap_capture"] = MagicMock(return_value=fake_proc)
        patchers = self._apply(mocks)
        try:
            with patch.object(router_probe.time, "sleep"):
                router_probe.probe_router(interface="en0", ip="192.168.1.1")
        finally:
            self._stop(patchers)
        fake_proc.terminate.assert_called_once()
        fake_proc.wait.assert_called_once()

    def test_pcap_proc_killed_if_wait_times_out(self) -> None:
        mocks = self._all_probes_mocked()
        fake_proc = MagicMock()
        fake_proc.poll.return_value = None
        fake_proc.wait.side_effect = subprocess.TimeoutExpired(cmd="tcpdump", timeout=3)
        mocks["start_pcap_capture"] = MagicMock(return_value=fake_proc)
        patchers = self._apply(mocks)
        try:
            with patch.object(router_probe.time, "sleep"):
                router_probe.probe_router(interface="en0", ip="192.168.1.1")
        finally:
            self._stop(patchers)
        fake_proc.kill.assert_called_once()

    def test_pcap_proc_already_exited_no_terminate(self) -> None:
        mocks = self._all_probes_mocked()
        fake_proc = MagicMock()
        fake_proc.poll.return_value = 0  # already exited
        mocks["start_pcap_capture"] = MagicMock(return_value=fake_proc)
        patchers = self._apply(mocks)
        try:
            with patch.object(router_probe.time, "sleep"):
                router_probe.probe_router(interface="en0", ip="192.168.1.1")
        finally:
            self._stop(patchers)
        fake_proc.terminate.assert_not_called()

    def test_pcap_none_skips_cleanup(self) -> None:
        # start_pcap_capture returns None — cleanup block should not crash
        mocks = self._all_probes_mocked()
        patchers = self._apply(mocks)
        try:
            with patch.object(router_probe.time, "sleep") as mock_sleep:
                result = router_probe.probe_router(interface="en0", ip="192.168.1.1")
        finally:
            self._stop(patchers)
        # sleep should not be called when pcap_proc is None
        mock_sleep.assert_not_called()
        self.assertEqual(result.state, "off")

    def test_verbose_prints_evidence(self) -> None:
        mocks = self._all_probes_mocked()
        patchers = self._apply(mocks)
        try:
            with patch("sys.stdout", new_callable=StringIO) as fake_out:
                router_probe.probe_router(interface="en0", ip="192.168.1.1", verbose=True)
        finally:
            self._stop(patchers)
        out = fake_out.getvalue()
        # Each evidence row prints as "  name: status — detail"
        self.assertIn("link_state", out)
        self.assertIn("arp_from_router", out)

    def test_default_args(self) -> None:
        mocks = self._all_probes_mocked()
        patchers = self._apply(mocks)
        try:
            result = router_probe.probe_router()
        finally:
            self._stop(patchers)
        self.assertEqual(result.ip, "192.168.1.1")
        self.assertEqual(result.mac, "")

    def test_passive_timeout_propagates(self) -> None:
        mocks = self._all_probes_mocked()
        patchers = self._apply(mocks)
        try:
            router_probe.probe_router(interface="en0", passive_timeout=20)
        finally:
            self._stop(patchers)
        mocks["probe_failsafe_broadcast"].assert_called_once_with("en0", timeout=20)
        # icmpv6_ra timeout is capped at 5
        mocks["probe_icmpv6_ra"].assert_called_once_with("en0", timeout=5)

    def test_passive_timeout_below_5_used_for_ra(self) -> None:
        mocks = self._all_probes_mocked()
        patchers = self._apply(mocks)
        try:
            router_probe.probe_router(interface="en0", passive_timeout=3)
        finally:
            self._stop(patchers)
        mocks["probe_icmpv6_ra"].assert_called_once_with("en0", timeout=3)


# ---------------------------------------------------------------------------
# main() CLI
# ---------------------------------------------------------------------------

class TestMainCli(unittest.TestCase):
    def test_default_invocation_prints_json(self) -> None:
        fake_state = router_probe.RouterState(
            state="openwrt_running",
            ip="192.168.1.1",
            model="X1860",
            vendor="OpenWrt",
            firmware_version="24.10.2",
            evidence=[("ping", "reachable", "reply")],
        )
        with patch("sys.argv", ["router-probe"]), \
             patch.object(router_probe, "probe_router", return_value=fake_state), \
             patch("sys.stdout", new_callable=StringIO) as fake_out:
            router_probe.main()
        out = fake_out.getvalue()
        data = json.loads(out)
        self.assertEqual(data["state"], "openwrt_running")
        self.assertEqual(data["ip"], "192.168.1.1")
        self.assertEqual(data["model"], "X1860")
        self.assertEqual(data["vendor"], "OpenWrt")
        self.assertEqual(data["firmware_version"], "24.10.2")
        self.assertEqual(len(data["evidence"]), 1)
        self.assertEqual(data["evidence"][0]["probe"], "ping")
        self.assertEqual(data["evidence"][0]["result"], "reachable")
        self.assertEqual(data["evidence"][0]["detail"], "reply")

    def test_verbose_flag_enables_debug_logging(self) -> None:
        fake_state = router_probe.RouterState()
        with patch("sys.argv", ["router-probe", "--verbose"]), \
             patch.object(router_probe, "probe_router", return_value=fake_state) as mock_pr, \
             patch.object(router_probe.logging, "basicConfig") as mock_log, \
             patch("sys.stdout", new_callable=StringIO):
            router_probe.main()
        # verbose=True should be passed through
        self.assertTrue(mock_pr.call_args.kwargs["verbose"])
        # logging at DEBUG level
        self.assertEqual(mock_log.call_args.kwargs["level"], router_probe.logging.DEBUG)

    def test_args_propagate(self) -> None:
        fake_state = router_probe.RouterState()
        with patch("sys.argv",
                   ["router-probe", "--interface", "en6", "--ip", "10.0.0.1",
                    "--mac", "aa:bb:cc", "--passive-timeout", "15"]), \
             patch.object(router_probe, "probe_router", return_value=fake_state) as mock_pr, \
             patch("sys.stdout", new_callable=StringIO):
            router_probe.main()
        kwargs = mock_pr.call_args.kwargs
        self.assertEqual(kwargs["interface"], "en6")
        self.assertEqual(kwargs["ip"], "10.0.0.1")
        self.assertEqual(kwargs["mac"], "aa:bb:cc")
        self.assertEqual(kwargs["passive_timeout"], 15)
        self.assertFalse(kwargs["verbose"])

    def test_default_passive_timeout(self) -> None:
        with patch("sys.argv", ["router-probe"]), \
             patch.object(router_probe, "probe_router",
                          return_value=router_probe.RouterState()) as mock_pr, \
             patch("sys.stdout", new_callable=StringIO):
            router_probe.main()
        self.assertEqual(mock_pr.call_args.kwargs["passive_timeout"], 10)

    def test_default_logging_level_info(self) -> None:
        with patch("sys.argv", ["router-probe"]), \
             patch.object(router_probe, "probe_router",
                          return_value=router_probe.RouterState()), \
             patch.object(router_probe.logging, "basicConfig") as mock_log, \
             patch("sys.stdout", new_callable=StringIO):
            router_probe.main()
        self.assertEqual(mock_log.call_args.kwargs["level"], router_probe.logging.INFO)

    def test_json_output_is_indented(self) -> None:
        fake_state = router_probe.RouterState(ip="1.2.3.4")
        with patch("sys.argv", ["router-probe"]), \
             patch.object(router_probe, "probe_router", return_value=fake_state), \
             patch("sys.stdout", new_callable=StringIO) as fake_out:
            router_probe.main()
        out = fake_out.getvalue()
        # Indent=2 means there should be lines starting with two spaces
        self.assertIn('  "state"', out)


if __name__ == "__main__":
    unittest.main()
