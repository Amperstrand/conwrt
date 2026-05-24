"""Tests for flash.preflight pre-flight check system."""
from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import patch, MagicMock

import unittest

from flash.preflight import (
    PreflightResult,
    get_interface_ips,
    is_default_route,
    run_preflight_checks,
)


def _profile(
    client_ip: str = "192.168.0.10",
    recovery_ip: str = "192.168.0.1",
    openwrt_client_ip: str = "192.168.1.254",
    openwrt_ip: str = "192.168.1.1",
    flash_method: str = "recovery-http",
    name: str = "test-device",
) -> SimpleNamespace:
    return SimpleNamespace(
        client_ip=client_ip,
        recovery_ip=recovery_ip,
        openwrt_client_ip=openwrt_client_ip,
        openwrt_ip=openwrt_ip,
        flash_method=flash_method,
        name=name,
    )


class TestGetInterfaceIPs(unittest.TestCase):
    @patch("flash.preflight.detect_platform", return_value="darwin")
    @patch("flash.preflight.subprocess.run")
    def test_parses_ifconfig_output(self, mock_run: MagicMock, _mock_plat: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="inet 192.168.0.10 netmask 0xffffff00 broadcast 192.168.0.255\n"
                   "inet 10.0.0.5 netmask 0xff000000 broadcast 10.255.255.255\n",
        )
        ips = get_interface_ips("en6")
        self.assertEqual(sorted(ips), ["10.0.0.5", "192.168.0.10"])

    @patch("flash.preflight.detect_platform", return_value="linux")
    @patch("flash.preflight.subprocess.run")
    def test_parses_ip_output(self, mock_run: MagicMock, _mock_plat: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="inet 192.168.1.254/24 brd 192.168.1.255 scope global eth0\n",
        )
        ips = get_interface_ips("eth0")
        self.assertEqual(ips, ["192.168.1.254"])

    @patch("flash.preflight.detect_platform", return_value="darwin")
    @patch("flash.preflight.subprocess.run")
    def test_empty_on_failure(self, mock_run: MagicMock, _mock_plat: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        ips = get_interface_ips("en0")
        self.assertEqual(ips, [])


class TestIsDefaultRoute(unittest.TestCase):
    @patch("flash.preflight.detect_platform", return_value="darwin")
    @patch("flash.preflight.subprocess.run")
    def test_darwin_is_default(self, mock_run: MagicMock, _mock_plat: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="   gateway: 192.168.1.1\n    interface: en6\n      flags: <UP,GATEWAY,DONE,STATIC>\n",
        )
        self.assertTrue(is_default_route("en6"))

    @patch("flash.preflight.detect_platform", return_value="darwin")
    @patch("flash.preflight.subprocess.run")
    def test_darwin_not_default(self, mock_run: MagicMock, _mock_plat: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="   gateway: 192.168.1.1\n    interface: en0\n",
        )
        self.assertFalse(is_default_route("en6"))

    @patch("flash.preflight.detect_platform", return_value="linux")
    @patch("flash.preflight.subprocess.run")
    def test_linux_is_default(self, mock_run: MagicMock, _mock_plat: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="default via 192.168.1.1 dev eth0\n",
        )
        self.assertTrue(is_default_route("eth0"))

    @patch("flash.preflight.detect_platform", return_value="linux")
    @patch("flash.preflight.subprocess.run")
    def test_linux_not_default(self, mock_run: MagicMock, _mock_plat: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="default via 192.168.1.1 dev eth1\n",
        )
        self.assertFalse(is_default_route("eth0"))


class TestStaleIP(unittest.TestCase):
    @patch("flash.preflight.detect_platform", return_value="darwin")
    @patch("flash.preflight.subprocess.run")
    def test_stale_ip_detected(self, mock_run: MagicMock, _mock_plat: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="inet 192.168.0.10 netmask 0xffffff00 broadcast 192.168.0.255\n",
        )
        results = run_preflight_checks("en6", _profile(), "/tmp/fw.bin")
        stale = [r for r in results if r.name == "stale_ip"]
        self.assertEqual(len(stale), 1)
        self.assertEqual(stale[0].status, "fail")
        self.assertIn("192.168.0.10", stale[0].message)

    @patch("flash.preflight.detect_platform", return_value="darwin")
    @patch("flash.preflight.subprocess.run")
    def test_no_stale_ip(self, mock_run: MagicMock, _mock_plat: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        results = run_preflight_checks("en6", _profile(), "/tmp/fw.bin")
        stale = [r for r in results if r.name == "stale_ip"]
        self.assertEqual(len(stale), 1)
        self.assertEqual(stale[0].status, "pass")


class TestDefaultRouteCheck(unittest.TestCase):
    @patch("flash.preflight.detect_platform", return_value="darwin")
    @patch("flash.preflight.subprocess.run")
    def test_default_route_warn(self, mock_run: MagicMock, _mock_plat: MagicMock) -> None:
        def _run_side_effect(cmd: list[str], **kwargs: object) -> MagicMock:
            if "ifconfig" in cmd:
                return MagicMock(returncode=0, stdout="")
            if "route" in cmd:
                return MagicMock(returncode=0, stdout="interface: en6\n")
            return MagicMock(returncode=0, stdout="")

        mock_run.side_effect = _run_side_effect
        results = run_preflight_checks("en6", _profile(), "/tmp/fw.bin")
        dr = [r for r in results if r.name == "default_route"]
        self.assertEqual(len(dr), 1)
        self.assertEqual(dr[0].status, "warn")

    @patch("flash.preflight.detect_platform", return_value="darwin")
    @patch("flash.preflight.subprocess.run")
    def test_not_default_route(self, mock_run: MagicMock, _mock_plat: MagicMock) -> None:
        def _run_side_effect(cmd: list[str], **kwargs: object) -> MagicMock:
            if "ifconfig" in cmd:
                return MagicMock(returncode=0, stdout="")
            if "route" in cmd:
                return MagicMock(returncode=0, stdout="interface: en0\n")
            return MagicMock(returncode=0, stdout="")

        mock_run.side_effect = _run_side_effect
        results = run_preflight_checks("en6", _profile(), "/tmp/fw.bin")
        dr = [r for r in results if r.name == "default_route"]
        self.assertEqual(len(dr), 1)
        self.assertEqual(dr[0].status, "pass")


class TestSSHKeyCheck(unittest.TestCase):
    @patch("flash.preflight.os.path.isfile", return_value=False)
    def test_ssh_key_missing_request_image(self, _mock_isfile: MagicMock) -> None:
        results = run_preflight_checks("en6", _profile(), "/tmp/fw.bin", ssh_key_path="/no/key.pub", request_image=True)
        key = [r for r in results if r.name == "ssh_key"]
        self.assertEqual(len(key), 1)
        self.assertEqual(key[0].status, "fail")

    @patch("flash.preflight.os.path.isfile", return_value=False)
    def test_ssh_key_missing_no_request(self, _mock_isfile: MagicMock) -> None:
        results = run_preflight_checks("en6", _profile(), "/tmp/fw.bin", ssh_key_path="/no/key.pub", request_image=False)
        key = [r for r in results if r.name == "ssh_key"]
        self.assertEqual(len(key), 1)
        self.assertEqual(key[0].status, "warn")

    def test_ssh_key_none(self) -> None:
        results = run_preflight_checks("en6", _profile(), "/tmp/fw.bin", ssh_key_path=None, request_image=False)
        key = [r for r in results if r.name == "ssh_key"]
        self.assertEqual(len(key), 1)
        self.assertEqual(key[0].status, "warn")

    @patch("flash.preflight.os.path.getsize", return_value=5_000_000)
    @patch("flash.preflight.os.path.isfile", return_value=True)
    def test_ssh_key_exists(self, _mock_isfile: MagicMock, _mock_size: MagicMock) -> None:
        results = run_preflight_checks("en6", _profile(), "/tmp/fw.bin", ssh_key_path="/path/key.pub")
        key = [r for r in results if r.name == "ssh_key"]
        self.assertEqual(len(key), 1)
        self.assertEqual(key[0].status, "pass")


class TestImageCheck(unittest.TestCase):
    @patch("flash.preflight.os.path.isfile", return_value=False)
    def test_image_missing(self, _mock_isfile: MagicMock) -> None:
        results = run_preflight_checks("en6", _profile(), "/no/fw.bin")
        img = [r for r in results if r.name == "image"]
        self.assertEqual(len(img), 1)
        self.assertEqual(img[0].status, "fail")
        self.assertIn("not found", img[0].message)

    @patch("flash.preflight.os.path.getsize", return_value=0)
    @patch("flash.preflight.os.path.isfile", return_value=True)
    def test_image_empty(self, _mock_isfile: MagicMock, _mock_size: MagicMock) -> None:
        results = run_preflight_checks("en6", _profile(), "/tmp/fw.bin")
        img = [r for r in results if r.name == "image"]
        self.assertEqual(len(img), 1)
        self.assertEqual(img[0].status, "fail")
        self.assertIn("empty", img[0].message)

    @patch("flash.preflight.os.path.getsize", return_value=500_000)
    @patch("flash.preflight.os.path.isfile", return_value=True)
    def test_image_too_small(self, _mock_isfile: MagicMock, _mock_size: MagicMock) -> None:
        results = run_preflight_checks("en6", _profile(), "/tmp/fw.bin")
        img = [r for r in results if r.name == "image"]
        self.assertEqual(len(img), 1)
        self.assertEqual(img[0].status, "fail")
        self.assertIn("suspiciously small", img[0].message)

    @patch("flash.preflight.os.path.getsize", return_value=5_000_000)
    @patch("flash.preflight.os.path.isfile", return_value=True)
    def test_image_valid(self, _mock_isfile: MagicMock, _mock_size: MagicMock) -> None:
        results = run_preflight_checks("en6", _profile(), "/tmp/fw.bin")
        img = [r for r in results if r.name == "image"]
        self.assertEqual(len(img), 1)
        self.assertEqual(img[0].status, "pass")


class TestSubnetCheck(unittest.TestCase):
    @patch("flash.preflight.detect_platform", return_value="darwin")
    @patch("flash.preflight.subprocess.run")
    def test_subnet_mismatch(self, mock_run: MagicMock, _mock_plat: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        profile = _profile(client_ip="10.0.0.10", recovery_ip="192.168.0.1")
        results = run_preflight_checks("en6", profile, "/tmp/fw.bin")
        subnet = [r for r in results if r.name == "subnet_consistency"]
        self.assertEqual(len(subnet), 1)
        self.assertEqual(subnet[0].status, "warn")
        self.assertIn("different /24", subnet[0].message)

    @patch("flash.preflight.detect_platform", return_value="darwin")
    @patch("flash.preflight.subprocess.run")
    def test_subnet_match(self, mock_run: MagicMock, _mock_plat: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        results = run_preflight_checks("en6", _profile(), "/tmp/fw.bin")
        subnet = [r for r in results if r.name == "subnet_consistency"]
        self.assertEqual(len(subnet), 1)
        self.assertEqual(subnet[0].status, "pass")


class TestProfileCompleteness(unittest.TestCase):
    @patch("flash.preflight.detect_platform", return_value="darwin")
    @patch("flash.preflight.subprocess.run")
    def test_profile_missing_field(self, mock_run: MagicMock, _mock_plat: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        profile = _profile(recovery_ip="")
        results = run_preflight_checks("en6", profile, "/tmp/fw.bin")
        comp = [r for r in results if r.name == "profile_completeness"]
        self.assertEqual(len(comp), 1)
        self.assertEqual(comp[0].status, "warn")
        self.assertIn("recovery_ip", comp[0].message)

    @patch("flash.preflight.detect_platform", return_value="darwin")
    @patch("flash.preflight.subprocess.run")
    def test_profile_complete(self, mock_run: MagicMock, _mock_plat: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        results = run_preflight_checks("en6", _profile(), "/tmp/fw.bin")
        comp = [r for r in results if r.name == "profile_completeness"]
        self.assertEqual(len(comp), 1)
        self.assertEqual(comp[0].status, "pass")


class TestFullRun(unittest.TestCase):
    @patch("flash.preflight.detect_platform", return_value="darwin")
    @patch("flash.preflight.os.path.getsize", return_value=5_000_000)
    @patch("flash.preflight.os.path.isfile", return_value=True)
    @patch("flash.preflight.subprocess.run")
    def test_all_pass(self, mock_run: MagicMock, _mock_isfile: MagicMock, _mock_size: MagicMock, _mock_plat: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        results = run_preflight_checks("en6", _profile(), "/tmp/fw.bin", ssh_key_path="/path/key.pub")
        statuses = {r.status for r in results}
        self.assertNotIn("fail", statuses)

    @patch("flash.preflight.detect_platform", return_value="darwin")
    @patch("flash.preflight.os.path.isfile", return_value=False)
    @patch("flash.preflight.subprocess.run")
    def test_fail_on_stale_ip(self, mock_run: MagicMock, _mock_isfile: MagicMock, _mock_plat: MagicMock) -> None:
        def _run_side_effect(cmd: list[str], **kwargs: object) -> MagicMock:
            if "ifconfig" in cmd:
                return MagicMock(returncode=0, stdout="inet 192.168.0.10 netmask 0xffffff00\n")
            return MagicMock(returncode=0, stdout="")

        mock_run.side_effect = _run_side_effect
        results = run_preflight_checks("en6", _profile(), "/tmp/fw.bin")
        has_fail = any(r.status == "fail" for r in results)
        self.assertTrue(has_fail)


if __name__ == "__main__":
    unittest.main()
