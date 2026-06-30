"""Tests for LAN IP rollback (#17) and empty-IP abort (#20)."""
from __future__ import annotations

from unittest.mock import patch, call, DEFAULT

import pytest


def _make_cfg(lan_ip: str = "10.0.0.1"):
    from config import ConwrtConfig
    return ConwrtConfig(lan_ip=lan_ip)


@pytest.fixture(autouse=True)
def _no_sleep():
    with patch("conwrt.postflash.time.sleep"):
        yield


DEPS = {
    "subprocess": DEFAULT,
    "_wait_for_sysupgrade_reboot": DEFAULT,
    "configure_interface_ip": DEFAULT,
    "remove_interface_ip": DEFAULT,
    "detect_platform": DEFAULT,
    "poll_until": DEFAULT,
    "_interface_exists": DEFAULT,
    "auto_detect_interface": DEFAULT,
    "ssh_cmd": DEFAULT,
}


class TestLanIpRollback:
    def test_success_no_rollback_needed(self) -> None:
        from conwrt.postflash import _apply_lan_ip_post_flash

        with patch.multiple("conwrt.postflash", **DEPS) as m:
            m["_wait_for_sysupgrade_reboot"].return_value = True
            result = _apply_lan_ip_post_flash(
                ip="192.168.1.1",
                ssh_key="",
                cfg=_make_cfg("10.0.0.1"),
                interface="en0",
                old_client_ip="192.168.1.254",
            )
        assert result == "10.0.0.1"

    def test_rollback_succeeds_when_new_ip_fails(self) -> None:
        from conwrt.postflash import _apply_lan_ip_post_flash

        with patch.multiple("conwrt.postflash", **DEPS) as m:
            m["_wait_for_sysupgrade_reboot"].side_effect = [False, True]
            result = _apply_lan_ip_post_flash(
                ip="192.168.1.1",
                ssh_key="",
                cfg=_make_cfg("10.0.0.1"),
                interface="en0",
                old_client_ip="192.168.1.254",
            )
        assert result == "192.168.1.1"
        remove = m["remove_interface_ip"]
        configure = m["configure_interface_ip"]
        assert call("en0", "10.0.0.254", "24") in remove.call_args_list
        assert call("en0", "192.168.1.254", "24") in configure.call_args_list

    def test_rollback_fails_both_unreachable(self) -> None:
        from conwrt.postflash import _apply_lan_ip_post_flash

        with patch.multiple("conwrt.postflash", **DEPS) as m:
            m["_wait_for_sysupgrade_reboot"].return_value = False
            result = _apply_lan_ip_post_flash(
                ip="192.168.1.1",
                ssh_key="",
                cfg=_make_cfg("10.0.0.1"),
                interface="en0",
                old_client_ip="192.168.1.254",
            )
        assert result == ""
        assert m["_wait_for_sysupgrade_reboot"].call_count == 2

    def test_no_change_when_ip_same(self) -> None:
        from conwrt.postflash import _apply_lan_ip_post_flash

        with patch.multiple("conwrt.postflash", **DEPS) as m:
            result = _apply_lan_ip_post_flash(
                ip="10.0.0.1",
                ssh_key="",
                cfg=_make_cfg("10.0.0.1"),
                interface="en0",
                old_client_ip="",
            )
        assert result == "10.0.0.1"
        m["subprocess"].run.assert_not_called()

    def test_returns_empty_when_no_interface(self) -> None:
        from conwrt.postflash import _apply_lan_ip_post_flash

        with patch.multiple("conwrt.postflash", **DEPS):
            result = _apply_lan_ip_post_flash(
                ip="192.168.1.1",
                ssh_key="",
                cfg=_make_cfg("10.0.0.1"),
                interface="",
                old_client_ip="",
            )
        assert result == ""

    def test_returns_empty_when_no_cfg(self) -> None:
        from conwrt.postflash import _apply_lan_ip_post_flash

        with patch.multiple("conwrt.postflash", **DEPS):
            result = _apply_lan_ip_post_flash(
                ip="192.168.1.1",
                ssh_key="",
                cfg=None,
                interface="en0",
                old_client_ip="",
            )
        assert result == ""

    def test_returns_empty_when_no_lan_ip(self) -> None:
        from conwrt.postflash import _apply_lan_ip_post_flash

        with patch.multiple("conwrt.postflash", **DEPS):
            result = _apply_lan_ip_post_flash(
                ip="192.168.1.1",
                ssh_key="",
                cfg=_make_cfg(""),
                interface="en0",
                old_client_ip="",
            )
        assert result == ""

    def test_rollback_uses_derived_client_ip_when_old_missing(self) -> None:
        from conwrt.postflash import _apply_lan_ip_post_flash

        with patch.multiple("conwrt.postflash", **DEPS) as m:
            m["_wait_for_sysupgrade_reboot"].side_effect = [False, True]
            result = _apply_lan_ip_post_flash(
                ip="192.168.1.1",
                ssh_key="",
                cfg=_make_cfg("10.0.0.1"),
                interface="en0",
                old_client_ip="",
            )
        assert result == "192.168.1.1"
        configure = m["configure_interface_ip"]
        assert call("en0", "192.168.1.254", "24") in configure.call_args_list
