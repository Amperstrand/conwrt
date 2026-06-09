"""Tests for conwrt.commands_configure, commands_wifi, commands_profile.

These are thin command-dispatch wrappers; tests verify:
- Argument flow into underlying helpers
- Dry-run vs real-run branching
- Edge cases (missing SSH key, missing interface, verify flag)
- Correct return codes
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

# Ensure scripts/ on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from config import ConwrtConfig  # noqa: E402


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _mock_result(returncode: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


def _make_configure_args(**overrides):
    """argparse.Namespace shaped like `conwrt configure`."""
    defaults = dict(
        ip="192.168.1.1",
        model_id=None,
        interface=None,
        ssh_key=None,
        password=None,
        no_password=False,
        wan_ssh=False,
        hostname=None,
        wifi_disable=False,
        verify=False,
        lan_ip_mode=None,
        hostname_pattern=None,
        serial=None,
        dry_run=False,
        transport="ssh",
        ubus_user="root",
        ubus_password="",
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_wifi_args(ip: str = "192.168.1.1"):
    """argparse.Namespace shaped like `conwrt setup-mgmt-wifi`."""
    return SimpleNamespace(ip=ip, model_id=None)


def _make_profile_args(model_id=None):
    """argparse.Namespace shaped like `conwrt profile plan`."""
    return SimpleNamespace(model_id=model_id)


def _make_cfg(**overrides):
    cfg = ConwrtConfig()
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg


# ---------------------------------------------------------------------------
# commands_configure.cmd_configure
# ---------------------------------------------------------------------------


class TestCmdConfigureDryRun:
    """Dry-run path: no SSH key install, no inventory record, no verify."""

    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._verify_persistence")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_dry_run_returns_0(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_verify, mock_record,
    ):
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg()
        mock_resolve.return_value = ("", "/k", "", "", False)
        mock_iface.return_value = "en0"
        mock_apply.return_value = "192.168.1.1"

        result = cmd_configure(_make_configure_args(dry_run=True))

        assert result == 0
        mock_apply.assert_called_once()
        assert mock_apply.call_args.kwargs["dry_run"] is True
        mock_install.assert_not_called()
        mock_record.assert_not_called()
        mock_verify.assert_not_called()

    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_dry_run_skips_lan_ip_lookup(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_record,
    ):
        """Dry run must NOT call run_ssh for current LAN IP lookup."""
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg()
        mock_resolve.return_value = ("", "/k", "", "", False)
        mock_iface.return_value = "en0"
        mock_apply.return_value = "192.168.1.1"

        with patch("conwrt.commands_configure.run_ssh") as mock_ssh:
            cmd_configure(_make_configure_args(dry_run=True))
            mock_ssh.assert_not_called()


class TestCmdConfigureRealRun:
    """Real-run path: install SSH key, apply profile, record inventory."""

    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._verify_persistence")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_full_real_run(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_verify, mock_record,
    ):
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg()
        mock_resolve.return_value = ("pass", "/k", "/k.pub", "ssh-ed25519 AAA", False)
        mock_iface.return_value = "en0"
        mock_apply.return_value = "192.168.1.1"

        result = cmd_configure(_make_configure_args())

        assert result == 0
        mock_install.assert_called_once()
        # Real run: dry_run=False in apply call
        assert mock_apply.call_args.kwargs["dry_run"] is False
        mock_record.assert_called_once()

    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_install_skipped_without_ssh_key(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_record,
    ):
        """If no pub key path and no key text, _cfg_install_ssh_key must not be called."""
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg()
        mock_resolve.return_value = ("pass", "/k", "", "", False)
        mock_iface.return_value = "en0"
        mock_apply.return_value = "192.168.1.1"

        cmd_configure(_make_configure_args())

        mock_install.assert_not_called()

    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_install_called_with_pub_key_only(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_record,
    ):
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg()
        mock_resolve.return_value = ("pass", "/k", "/k.pub", "", False)
        mock_iface.return_value = "en0"
        mock_apply.return_value = "192.168.1.1"

        cmd_configure(_make_configure_args())

        mock_install.assert_called_once()

    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_install_called_with_key_text_only(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_record,
    ):
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg()
        mock_resolve.return_value = ("pass", "/k", "", "ssh-ed25519 AAA", False)
        mock_iface.return_value = "en0"
        mock_apply.return_value = "192.168.1.1"

        cmd_configure(_make_configure_args())

        mock_install.assert_called_once()


class TestCmdConfigureVerify:
    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._verify_persistence")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_verify_flag_triggers_persistence_check(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_verify, mock_record,
    ):
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg()
        mock_resolve.return_value = ("", "/k", "", "", False)
        mock_iface.return_value = "en0"
        mock_apply.return_value = "192.168.1.1"

        cmd_configure(_make_configure_args(verify=True))

        mock_verify.assert_called_once()

    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._verify_persistence")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_verify_skipped_when_dry_run(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_verify, mock_record,
    ):
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg()
        mock_resolve.return_value = ("", "/k", "", "", False)
        mock_iface.return_value = "en0"
        mock_apply.return_value = "192.168.1.1"

        cmd_configure(_make_configure_args(verify=True, dry_run=True))

        mock_verify.assert_not_called()

    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._verify_persistence")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_verify_default_false_skips(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_verify, mock_record,
    ):
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg()
        mock_resolve.return_value = ("", "/k", "", "", False)
        mock_iface.return_value = "en0"
        mock_apply.return_value = "192.168.1.1"

        cmd_configure(_make_configure_args())  # verify=False default

        mock_verify.assert_not_called()


class TestCmdConfigureFailure:
    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_empty_ip_after_apply_returns_1(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_record,
    ):
        """When _apply_profile_post_flash returns empty string, return 1."""
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg()
        mock_resolve.return_value = ("", "/k", "", "", False)
        mock_iface.return_value = "en0"
        mock_apply.return_value = ""  # signals failure

        result = cmd_configure(_make_configure_args())

        assert result == 1
        mock_record.assert_not_called()

    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_empty_ip_in_dry_run_does_not_fail(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_record,
    ):
        """In dry-run, empty IP is OK (no real apply happened)."""
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg()
        mock_resolve.return_value = ("", "/k", "", "", False)
        mock_iface.return_value = "en0"
        mock_apply.return_value = ""

        result = cmd_configure(_make_configure_args(dry_run=True))

        assert result == 0


class TestCmdConfigureEffectiveOptions:
    """Verify CLI overrides flow through to _apply_profile_post_flash."""

    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_cli_hostname_overrides_config(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_record,
    ):
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg(hostname="cfg-host")
        mock_resolve.return_value = ("", "/k", "", "", False)
        mock_iface.return_value = "en0"
        mock_apply.return_value = "192.168.1.1"

        cmd_configure(_make_configure_args(hostname="cli-host"))

        assert mock_apply.call_args.kwargs["hostname"] == "cli-host"

    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_config_hostname_used_when_cli_absent(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_record,
    ):
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg(hostname="cfg-host")
        mock_resolve.return_value = ("", "/k", "", "", False)
        mock_iface.return_value = "en0"
        mock_apply.return_value = "192.168.1.1"

        cmd_configure(_make_configure_args())

        assert mock_apply.call_args.kwargs["hostname"] == "cfg-host"

    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_cli_wifi_disable_or_with_config(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_record,
    ):
        """CLI --wifi-disable OR'd with cfg.wifi_disable (either enables)."""
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg(wifi_disable=False)
        mock_resolve.return_value = ("", "/k", "", "", False)
        mock_iface.return_value = "en0"
        mock_apply.return_value = "192.168.1.1"

        cmd_configure(_make_configure_args(wifi_disable=True))

        assert mock_apply.call_args.kwargs["wifi_disable"] is True

    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_cli_lan_ip_mode_overrides_config(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_record,
    ):
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg(lan_ip_mode="mac-hash")
        mock_resolve.return_value = ("", "/k", "", "", False)
        mock_iface.return_value = "en0"
        mock_apply.return_value = "192.168.1.1"

        cmd_configure(_make_configure_args(lan_ip_mode="static"))

        assert mock_apply.call_args.kwargs["lan_ip_mode"] == "static"

    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_cli_hostname_pattern_overrides_config(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_record,
    ):
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg(hostname_pattern="static")
        mock_resolve.return_value = ("", "/k", "", "", False)
        mock_iface.return_value = "en0"
        mock_apply.return_value = "192.168.1.1"

        cmd_configure(_make_configure_args(hostname_pattern="model_mac"))

        assert mock_apply.call_args.kwargs["hostname_pattern"] == "model_mac"

    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_transport_ubus_passes_credentials(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_record,
    ):
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg()
        mock_resolve.return_value = ("", "/k", "", "", False)
        mock_iface.return_value = "en0"
        mock_apply.return_value = "192.168.1.1"

        cmd_configure(_make_configure_args(
            transport="ubus", ubus_user="admin", ubus_password="secret",
        ))

        kw = mock_apply.call_args.kwargs
        assert kw["transport"] == "ubus"
        assert kw["ubus_user"] == "admin"
        assert kw["ubus_password"] == "secret"

    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_default_transport_is_ssh(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_record,
    ):
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg()
        mock_resolve.return_value = ("", "/k", "", "", False)
        mock_iface.return_value = "en0"
        mock_apply.return_value = "192.168.1.1"

        cmd_configure(_make_configure_args())  # default transport="ssh"

        assert mock_apply.call_args.kwargs["transport"] == "ssh"


class TestCmdConfigureInterfaceDetect:
    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_cli_interface_used_when_provided(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_record,
    ):
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg()
        mock_resolve.return_value = ("", "/k", "", "", False)
        mock_iface.return_value = "auto-en1"
        mock_apply.return_value = "192.168.1.1"

        cmd_configure(_make_configure_args(interface="my-eth0"))

        # auto_detect_interface should not affect; args.interface wins
        assert mock_apply.call_args.kwargs["interface"] == "my-eth0"

    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_auto_detected_interface_used(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_record,
    ):
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg()
        mock_resolve.return_value = ("", "/k", "", "", False)
        mock_iface.return_value = "auto-en1"
        mock_apply.return_value = "192.168.1.1"

        cmd_configure(_make_configure_args())

        assert mock_apply.call_args.kwargs["interface"] == "auto-en1"

    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_empty_string_when_no_interface_found(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_record,
    ):
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg()
        mock_resolve.return_value = ("", "/k", "", "", False)
        mock_iface.return_value = None
        mock_apply.return_value = "192.168.1.1"

        cmd_configure(_make_configure_args())

        assert mock_apply.call_args.kwargs["interface"] == ""


class TestCmdConfigureModelId:
    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_model_id_passed_to_apply(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_record,
    ):
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg()
        mock_resolve.return_value = ("", "/k", "", "", False)
        mock_iface.return_value = "en0"
        mock_apply.return_value = "192.168.1.1"

        cmd_configure(_make_configure_args(model_id="my-model"))

        assert mock_apply.call_args.kwargs["model_id"] == "my-model"

    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_empty_model_id_passes_empty_string(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_record,
    ):
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg()
        mock_resolve.return_value = ("", "/k", "", "", False)
        mock_iface.return_value = "en0"
        mock_apply.return_value = "192.168.1.1"

        cmd_configure(_make_configure_args(model_id=None))

        assert mock_apply.call_args.kwargs["model_id"] == ""


class TestCmdConfigureInventory:
    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_inventory_recorded_with_serial(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_record,
    ):
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg()
        mock_resolve.return_value = ("pw", "/k", "", "", True)
        mock_iface.return_value = "en0"
        mock_apply.return_value = "192.168.1.1"

        cmd_configure(_make_configure_args(serial="SN12345"))

        kw = mock_record.call_args.kwargs
        assert kw["serial"] == "SN12345"
        assert kw["password"] == "pw"
        assert kw["wan_ssh"] is True

    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_inventory_serial_defaults_empty(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_record,
    ):
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg()
        mock_resolve.return_value = ("pw", "/k", "", "", False)
        mock_iface.return_value = "en0"
        mock_apply.return_value = "192.168.1.1"

        cmd_configure(_make_configure_args())  # serial=None default

        assert mock_record.call_args.kwargs["serial"] == ""


class TestCmdConfigureLanIpLookup:
    """run_ssh is called once for current LAN IP only when iface exists."""

    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_no_run_ssh_when_no_interface(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_record,
    ):
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg()
        mock_resolve.return_value = ("", "/k", "", "", False)
        mock_iface.return_value = ""  # no interface
        mock_apply.return_value = "192.168.1.1"

        with patch("conwrt.commands_configure.run_ssh") as mock_ssh:
            cmd_configure(_make_configure_args(interface=""))
            mock_ssh.assert_not_called()

    @patch("conwrt.commands_configure._record_configure_inventory")
    @patch("conwrt.commands_configure._cfg_install_ssh_key")
    @patch("conwrt.commands_configure._apply_profile_post_flash")
    @patch("conwrt.commands_configure._resolve_configure_options")
    @patch("conwrt.commands_configure._load_config")
    @patch("conwrt.commands_configure.auto_detect_interface")
    @patch("conwrt.commands_configure.log")
    def test_run_ssh_skipped_when_interface_path_missing(
        self, _log, mock_iface, mock_load, mock_resolve, mock_apply,
        mock_install, mock_record,
    ):
        """When /sys/class/net/<iface> doesn't exist, skip the SSH lookup."""
        from conwrt.commands_configure import cmd_configure
        mock_load.return_value = _make_cfg()
        mock_resolve.return_value = ("", "/k", "", "", False)
        mock_iface.return_value = "totally-fake-iface-xyz"
        mock_apply.return_value = "192.168.1.1"

        with patch("conwrt.commands_configure.run_ssh") as mock_ssh:
            cmd_configure(_make_configure_args())
            mock_ssh.assert_not_called()


# ---------------------------------------------------------------------------
# commands_wifi.cmd_setup_mgmt_wifi
# ---------------------------------------------------------------------------


class TestCmdSetupMgmtWifi:
    @patch("conwrt.commands_wifi._detect_ssh_key_path")
    def test_no_ssh_key_returns_1(self, mock_key, capsys):
        from conwrt.commands_wifi import cmd_setup_mgmt_wifi
        mock_key.return_value = None

        result = cmd_setup_mgmt_wifi(_make_wifi_args())

        assert result == 1
        captured = capsys.readouterr()
        assert "No SSH private key found" in captured.err

    @patch("conwrt.commands_wifi.subprocess.run")
    @patch("conwrt.commands_wifi._detect_ssh_key_path")
    def test_already_configured_returns_0(
        self, mock_key, mock_run, capsys,
    ):
        """If verify_cmd returns 0, mgmt WiFi is already configured -> early return 0."""
        from conwrt.commands_wifi import cmd_setup_mgmt_wifi
        mock_key.return_value = "/k"
        mock_run.return_value = _mock_result(returncode=0)

        result = cmd_setup_mgmt_wifi(_make_wifi_args())

        assert result == 0
        captured = capsys.readouterr()
        assert "already configured" in captured.out
        # Only the verify call ran (no setup)
        assert mock_run.call_count == 1

    @patch("conwrt.commands_wifi.build_mgmt_wifi_script")
    @patch("conwrt.commands_wifi._load_config")
    @patch("conwrt.commands_wifi.subprocess.run")
    @patch("conwrt.commands_wifi._detect_ssh_key_path")
    def test_full_setup_path_returns_0(
        self, mock_key, mock_run, mock_load, mock_build, capsys,
    ):
        from conwrt.commands_wifi import cmd_setup_mgmt_wifi
        mock_key.return_value = "/k"
        mock_load.return_value = _make_cfg(mgmt_wifi_txpower=20)
        mock_build.return_value = "uci commands here"
        # 1: verify fails (not configured), 2: setup ok, 3: re-verify ok
        mock_run.side_effect = [
            _mock_result(returncode=1),  # verify before
            _mock_result(returncode=0, stdout="ok"),  # setup
            _mock_result(returncode=0),  # verify after
        ]

        result = cmd_setup_mgmt_wifi(_make_wifi_args())

        assert result == 0
        captured = capsys.readouterr()
        assert "Management WiFi configured" in captured.out
        # build_mgmt_wifi_script called with cfg txpower
        mock_build.assert_called_once_with(txpower=20)
        # Three subprocess.run calls total
        assert mock_run.call_count == 3

    @patch("conwrt.commands_wifi.build_mgmt_wifi_script")
    @patch("conwrt.commands_wifi._load_config")
    @patch("conwrt.commands_wifi.subprocess.run")
    @patch("conwrt.commands_wifi._detect_ssh_key_path")
    def test_setup_timeout_returns_1(
        self, mock_key, mock_run, mock_load, mock_build, capsys,
    ):
        from conwrt.commands_wifi import cmd_setup_mgmt_wifi
        mock_key.return_value = "/k"
        mock_load.return_value = _make_cfg()
        mock_build.return_value = "script"
        mock_run.side_effect = [
            _mock_result(returncode=1),  # verify before fails
            subprocess.TimeoutExpired(cmd="ssh", timeout=60),
        ]

        result = cmd_setup_mgmt_wifi(_make_wifi_args())

        assert result == 1
        captured = capsys.readouterr()
        assert "Timed out" in captured.err

    @patch("conwrt.commands_wifi.build_mgmt_wifi_script")
    @patch("conwrt.commands_wifi._load_config")
    @patch("conwrt.commands_wifi.subprocess.run")
    @patch("conwrt.commands_wifi._detect_ssh_key_path")
    def test_setup_subprocess_error_returns_1(
        self, mock_key, mock_run, mock_load, mock_build, capsys,
    ):
        from conwrt.commands_wifi import cmd_setup_mgmt_wifi
        mock_key.return_value = "/k"
        mock_load.return_value = _make_cfg()
        mock_build.return_value = "script"
        mock_run.side_effect = [
            _mock_result(returncode=1),
            OSError("ssh broken"),
        ]

        result = cmd_setup_mgmt_wifi(_make_wifi_args())

        assert result == 1
        captured = capsys.readouterr()
        assert "Failed to run setup script" in captured.err

    @patch("conwrt.commands_wifi.build_mgmt_wifi_script")
    @patch("conwrt.commands_wifi._load_config")
    @patch("conwrt.commands_wifi.subprocess.run")
    @patch("conwrt.commands_wifi._detect_ssh_key_path")
    def test_setup_nonzero_returncode_propagates(
        self, mock_key, mock_run, mock_load, mock_build, capsys,
    ):
        from conwrt.commands_wifi import cmd_setup_mgmt_wifi
        mock_key.return_value = "/k"
        mock_load.return_value = _make_cfg()
        mock_build.return_value = "script"
        mock_run.side_effect = [
            _mock_result(returncode=1),  # verify before fails
            _mock_result(returncode=42, stderr="uci failed"),  # setup fails
        ]

        result = cmd_setup_mgmt_wifi(_make_wifi_args())

        assert result == 42
        captured = capsys.readouterr()
        assert "uci failed" in captured.err

    @patch("conwrt.commands_wifi.build_mgmt_wifi_script")
    @patch("conwrt.commands_wifi._load_config")
    @patch("conwrt.commands_wifi.subprocess.run")
    @patch("conwrt.commands_wifi._detect_ssh_key_path")
    def test_setup_zero_returncode_with_empty_stderr_returns_1(
        self, mock_key, mock_run, mock_load, mock_build,
    ):
        """If returncode is 0 from `or 1` fallback for empty err, still return 1."""
        from conwrt.commands_wifi import cmd_setup_mgmt_wifi
        mock_key.return_value = "/k"
        mock_load.return_value = _make_cfg()
        mock_build.return_value = "script"
        # setup returns nonzero with no stderr to test the `or 1` fallback
        mock_run.side_effect = [
            _mock_result(returncode=1),
            _mock_result(returncode=0, stdout="ok"),  # setup ok
            _mock_result(returncode=1, stderr="not configured"),  # re-verify fails
        ]

        result = cmd_setup_mgmt_wifi(_make_wifi_args())

        assert result == 1

    @patch("conwrt.commands_wifi.build_mgmt_wifi_script")
    @patch("conwrt.commands_wifi._load_config")
    @patch("conwrt.commands_wifi.subprocess.run")
    @patch("conwrt.commands_wifi._detect_ssh_key_path")
    def test_reverify_fails_returns_1(
        self, mock_key, mock_run, mock_load, mock_build, capsys,
    ):
        """Setup succeeds but re-verify fails -> error."""
        from conwrt.commands_wifi import cmd_setup_mgmt_wifi
        mock_key.return_value = "/k"
        mock_load.return_value = _make_cfg()
        mock_build.return_value = "script"
        mock_run.side_effect = [
            _mock_result(returncode=1),  # before
            _mock_result(returncode=0, stdout="ok"),  # setup
            _mock_result(returncode=1, stderr="not configured"),  # re-verify fails
        ]

        result = cmd_setup_mgmt_wifi(_make_wifi_args())

        assert result == 1
        captured = capsys.readouterr()
        assert "verification failed" in captured.err

    @patch("conwrt.commands_wifi.build_mgmt_wifi_script")
    @patch("conwrt.commands_wifi._load_config")
    @patch("conwrt.commands_wifi.subprocess.run")
    @patch("conwrt.commands_wifi._detect_ssh_key_path")
    def test_passes_correct_ip_to_setup(
        self, mock_key, mock_run, mock_load, mock_build,
    ):
        """The IP in args.ip must flow to ssh_cmd calls."""
        from conwrt.commands_wifi import cmd_setup_mgmt_wifi
        mock_key.return_value = "/k"
        mock_load.return_value = _make_cfg()
        mock_build.return_value = "script"
        mock_run.side_effect = [
            _mock_result(returncode=1),
            _mock_result(returncode=0, stdout="ok"),
            _mock_result(returncode=0),
        ]

        with patch("conwrt.commands_wifi.ssh_cmd") as mock_ssh_cmd:
            mock_ssh_cmd.return_value = ["ssh", "x"]
            cmd_setup_mgmt_wifi(_make_wifi_args(ip="10.20.30.40"))
            # All ssh_cmd calls used the same IP
            for call in mock_ssh_cmd.call_args_list:
                assert call.args[0] == "10.20.30.40"


# ---------------------------------------------------------------------------
# commands_profile.cmd_profile_plan
# ---------------------------------------------------------------------------


class TestCmdProfilePlan:
    @patch("conwrt.commands_profile.print_plan")
    @patch("conwrt.commands_profile.build_plan")
    @patch("conwrt.commands_profile.load_model")
    @patch("conwrt.commands_profile._load_config")
    def test_no_model_id_uses_empty_capabilities(
        self, mock_load, mock_load_model, mock_build, mock_print,
    ):
        from conwrt.commands_profile import cmd_profile_plan
        mock_load.return_value = _make_cfg()
        mock_build.return_value = "PLAN"

        result = cmd_profile_plan(_make_profile_args(model_id=None))

        assert result == 0
        mock_load_model.assert_not_called()
        kw = mock_build.call_args.kwargs
        assert kw["mode"] == "preview"
        assert kw["model_capabilities"] == []
        mock_print.assert_called_once_with("PLAN")

    @patch("conwrt.commands_profile.print_plan")
    @patch("conwrt.commands_profile.build_plan")
    @patch("conwrt.commands_profile.load_model")
    @patch("conwrt.commands_profile._load_config")
    def test_with_model_id_loads_capabilities(
        self, mock_load, mock_load_model, mock_build, mock_print,
    ):
        from conwrt.commands_profile import cmd_profile_plan
        mock_load.return_value = _make_cfg()
        mock_load_model.return_value = {
            "id": "my-model",
            "capabilities": ["usb_storage", "wifi6"],
        }
        mock_build.return_value = "PLAN"

        result = cmd_profile_plan(_make_profile_args(model_id="my-model"))

        assert result == 0
        mock_load_model.assert_called_once_with("my-model")
        assert mock_build.call_args.kwargs["model_capabilities"] == [
            "usb_storage", "wifi6",
        ]

    @patch("conwrt.commands_profile.print_plan")
    @patch("conwrt.commands_profile.build_plan")
    @patch("conwrt.commands_profile.load_model")
    @patch("conwrt.commands_profile._load_config")
    def test_missing_model_warns_and_continues(
        self, mock_load, mock_load_model, mock_build, mock_print, capsys,
    ):
        from conwrt.commands_profile import cmd_profile_plan
        mock_load.return_value = _make_cfg()
        mock_load_model.side_effect = FileNotFoundError("model missing")
        mock_build.return_value = "PLAN"

        result = cmd_profile_plan(_make_profile_args(model_id="missing-model"))

        assert result == 0
        captured = capsys.readouterr()
        assert "Warning" in captured.err
        assert "model missing" in captured.err
        # Falls through with empty capabilities
        assert mock_build.call_args.kwargs["model_capabilities"] == []

    @patch("conwrt.commands_profile.print_plan")
    @patch("conwrt.commands_profile.build_plan")
    @patch("conwrt.commands_profile.load_model")
    @patch("conwrt.commands_profile._load_config")
    def test_model_without_capabilities_uses_empty(
        self, mock_load, mock_load_model, mock_build, mock_print,
    ):
        from conwrt.commands_profile import cmd_profile_plan
        mock_load.return_value = _make_cfg()
        mock_load_model.return_value = {"id": "m"}  # no capabilities key
        mock_build.return_value = "PLAN"

        result = cmd_profile_plan(_make_profile_args(model_id="m"))

        assert result == 0
        assert mock_build.call_args.kwargs["model_capabilities"] == []

    @patch("conwrt.commands_profile.print_plan")
    @patch("conwrt.commands_profile.build_plan")
    @patch("conwrt.commands_profile.load_model")
    @patch("conwrt.commands_profile._load_config")
    def test_always_uses_preview_mode(
        self, mock_load, mock_load_model, mock_build, mock_print,
    ):
        """cmd_profile_plan is the dry-run preview command — always 'preview' mode."""
        from conwrt.commands_profile import cmd_profile_plan
        mock_load.return_value = _make_cfg()
        mock_build.return_value = "P"

        cmd_profile_plan(_make_profile_args())

        assert mock_build.call_args.kwargs["mode"] == "preview"

    @patch("conwrt.commands_profile.print_plan")
    @patch("conwrt.commands_profile.build_plan")
    @patch("conwrt.commands_profile.load_model")
    @patch("conwrt.commands_profile._load_config")
    def test_print_plan_receives_build_result(
        self, mock_load, mock_load_model, mock_build, mock_print,
    ):
        from conwrt.commands_profile import cmd_profile_plan
        mock_load.return_value = _make_cfg()
        mock_build.return_value = {"some": "plan"}

        cmd_profile_plan(_make_profile_args())

        mock_print.assert_called_once_with({"some": "plan"})

    @patch("conwrt.commands_profile.print_plan")
    @patch("conwrt.commands_profile.build_plan")
    @patch("conwrt.commands_profile.load_model")
    @patch("conwrt.commands_profile._load_config")
    def test_passes_cfg_as_first_arg(
        self, mock_load, mock_load_model, mock_build, mock_print,
    ):
        from conwrt.commands_profile import cmd_profile_plan
        cfg = _make_cfg(hostname="x")
        mock_load.return_value = cfg
        mock_build.return_value = "P"

        cmd_profile_plan(_make_profile_args())

        # build_plan(cfg, mode=..., model_capabilities=...)
        assert mock_build.call_args.args[0] is cfg
