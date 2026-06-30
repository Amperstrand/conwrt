from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, PropertyMock

import subprocess

import pytest

from config import ConwrtConfig, UseCaseConfig, WireguardConfig, WifiAPConfig

# Ensure scripts/ is on sys.path for conwrt.* imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))


def _mock_result(returncode: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


def _make_args(**overrides):
    """Build a mock argparse.Namespace for _resolve_configure_options."""
    defaults = dict(ssh_key="", password="", no_password=False, wan_ssh=False)
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_cfg(**overrides):
    """Build a ConwrtConfig with optional field overrides."""
    cfg = ConwrtConfig()
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg


@pytest.fixture(autouse=True)
def _no_sleep():
    with patch("conwrt.postflash.time.sleep"):
        yield


# ---------------------------------------------------------------------------
# _client_ip_for_subnet
# ---------------------------------------------------------------------------


class TestClientIpForSubnet:
    def test_192_168_subnet(self):
        from conwrt.postflash import _client_ip_for_subnet
        assert _client_ip_for_subnet("192.168.1.1") == "192.168.1.254"

    def test_10_subnet(self):
        from conwrt.postflash import _client_ip_for_subnet
        assert _client_ip_for_subnet("10.0.0.1") == "10.0.0.254"

    def test_172_16_subnet(self):
        from conwrt.postflash import _client_ip_for_subnet
        assert _client_ip_for_subnet("172.16.0.1") == "172.16.0.254"

    def test_single_octet_various(self):
        from conwrt.postflash import _client_ip_for_subnet
        assert _client_ip_for_subnet("1.2.3.4") == "1.2.3.254"

    def test_invalid_string(self):
        from conwrt.postflash import _client_ip_for_subnet
        assert _client_ip_for_subnet("invalid") == ""

    def test_empty_string(self):
        from conwrt.postflash import _client_ip_for_subnet
        assert _client_ip_for_subnet("") == ""

    def test_three_octets(self):
        from conwrt.postflash import _client_ip_for_subnet
        assert _client_ip_for_subnet("1.2.3") == ""

    def test_five_octets(self):
        from conwrt.postflash import _client_ip_for_subnet
        assert _client_ip_for_subnet("192.168.1.1.5") == ""

    def test_not_an_ip(self):
        from conwrt.postflash import _client_ip_for_subnet
        assert _client_ip_for_subnet("not.an.ip") == ""

    def test_already_254(self):
        from conwrt.postflash import _client_ip_for_subnet
        assert _client_ip_for_subnet("10.0.0.254") == "10.0.0.254"


# ---------------------------------------------------------------------------
# _cfg_set_password
# ---------------------------------------------------------------------------


class TestCfgSetPassword:
    @patch("conwrt.postflash.run_ssh")
    def test_success(self, mock_run):
        from conwrt.postflash import _cfg_set_password
        mock_run.return_value = _mock_result(0)
        result = _cfg_set_password("1.2.3.4", "secret", ssh_key="key")
        assert result is True

    @patch("conwrt.postflash.run_ssh")
    def test_failure(self, mock_run):
        from conwrt.postflash import _cfg_set_password
        mock_run.return_value = _mock_result(1, stderr="passwd error")
        result = _cfg_set_password("1.2.3.4", "secret", ssh_key="key")
        assert result is False

    def test_empty_password(self):
        from conwrt.postflash import _cfg_set_password
        result = _cfg_set_password("1.2.3.4", "", ssh_key="key")
        assert result is False

    @patch("conwrt.postflash.run_ssh")
    def test_base64_encoding_in_command(self, mock_run):
        """Verify the password is base64-encoded in the SSH command."""
        from conwrt.postflash import _cfg_set_password
        mock_run.return_value = _mock_result(0)
        _cfg_set_password("1.2.3.4", "secret", ssh_key="key")
        call_args = mock_run.call_args
        cmd = call_args[0][1] if len(call_args[0]) > 1 else call_args[1].get("cmd", "")
        # The command should contain base64-encoded "secret"
        import base64
        expected_b64 = base64.b64encode(b"secret").decode()
        assert expected_b64 in cmd

    @patch("conwrt.postflash.run_ssh")
    def test_special_chars_password(self, mock_run):
        from conwrt.postflash import _cfg_set_password
        mock_run.return_value = _mock_result(0)
        result = _cfg_set_password("1.2.3.4", "p@$$w0rd!", ssh_key="key")
        assert result is True


# ---------------------------------------------------------------------------
# _cfg_install_ssh_key
# ---------------------------------------------------------------------------


class TestCfgInstallSshKey:
    @patch("conwrt.postflash.run_ssh")
    def test_key_already_present(self, mock_run):
        from conwrt.postflash import _cfg_install_ssh_key
        pub_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItestkey"
        mock_run.return_value = _mock_result(
            0, stdout=f"some-other-key\n{pub_key}\n"
        )
        result = _cfg_install_ssh_key(
            ip="1.2.3.4", key_path="", auth_key="", ssh_key=pub_key
        )
        assert result is True
        assert mock_run.call_count == 1

    @patch("conwrt.postflash.run_ssh")
    def test_key_not_present_installs_and_verifies(self, mock_run):
        from conwrt.postflash import _cfg_install_ssh_key
        pub_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItestkey"
        mock_run.side_effect = [
            _mock_result(0, stdout=""),
            _mock_result(0, stdout=""),
            _mock_result(0, stdout=pub_key),
        ]
        result = _cfg_install_ssh_key(
            ip="1.2.3.4", key_path="", auth_key="", ssh_key=pub_key
        )
        assert result is True
        assert mock_run.call_count == 3

    @patch("conwrt.postflash.run_ssh")
    def test_install_fails_nonzero_rc(self, mock_run):
        from conwrt.postflash import _cfg_install_ssh_key
        pub_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItestkey"
        mock_run.side_effect = [
            _mock_result(0, stdout=""),
            _mock_result(1, stderr="permission denied"),
        ]
        result = _cfg_install_ssh_key(
            ip="1.2.3.4", key_path="", auth_key="", ssh_key=pub_key
        )
        assert result is False

    @patch("conwrt.postflash.run_ssh")
    def test_install_succeeds_but_verification_fails(self, mock_run):
        from conwrt.postflash import _cfg_install_ssh_key
        pub_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItestkey"
        mock_run.side_effect = [
            _mock_result(0, stdout=""),
            _mock_result(0, stdout=""),
            _mock_result(0, stdout=""),
        ]
        result = _cfg_install_ssh_key(
            ip="1.2.3.4", key_path="", auth_key="", ssh_key=pub_key
        )
        assert result is False

    def test_no_key_provided_returns_false(self):
        from conwrt.postflash import _cfg_install_ssh_key
        result = _cfg_install_ssh_key(
            ip="1.2.3.4", key_path="", auth_key="", ssh_key=""
        )
        assert result is False

    @patch("conwrt.postflash.run_ssh")
    def test_key_from_ssh_key_text_parameter(self, mock_run):
        from conwrt.postflash import _cfg_install_ssh_key
        ssh_key_text = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItestkey user@host\n"
        expected_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItestkey"
        mock_run.side_effect = [
            _mock_result(0, stdout=""),
            _mock_result(0, stdout=""),
            _mock_result(0, stdout=expected_key),
        ]
        result = _cfg_install_ssh_key(
            ip="1.2.3.4", key_path="", auth_key="", ssh_key=ssh_key_text
        )
        assert result is True

    @patch("conwrt.postflash.run_ssh")
    def test_key_from_key_path(self, mock_run):
        """Test reading key from a file path."""
        from conwrt.postflash import _cfg_install_ssh_key
        key_content = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCtest user@host\n"
        expected_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCtest"
        mock_run.side_effect = [
            _mock_result(0, stdout=""),
            _mock_result(0, stdout=""),
            _mock_result(0, stdout=expected_key),
        ]
        with patch("pathlib.Path.read_text", return_value=key_content):
            result = _cfg_install_ssh_key(
                ip="1.2.3.4", key_path="/home/user/.ssh/id_rsa.pub", auth_key="", ssh_key=""
            )
        assert result is True

    def test_ssh_key_without_prefix_returns_false(self):
        """ssh_key text that doesn't start with 'ssh-' should not extract a key."""
        from conwrt.postflash import _cfg_install_ssh_key
        result = _cfg_install_ssh_key(
            ip="1.2.3.4", key_path="", auth_key="", ssh_key="just-a-plain-string"
        )
        assert result is False

    @patch("conwrt.postflash.run_ssh")
    def test_creates_file_when_missing(self, mock_run):
        """When authorized_keys doesn't exist, uses '>' operator."""
        from conwrt.postflash import _cfg_install_ssh_key
        pub_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItestkey"
        # First call: cat fails (stderr has "No such file")
        # Second call: install with >
        # Third call: verify
        mock_run.side_effect = [
            _mock_result(1, stdout="", stderr="No such file or directory"),
            _mock_result(0, stdout=""),
            _mock_result(0, stdout=pub_key),
        ]
        result = _cfg_install_ssh_key(
            ip="1.2.3.4", key_path="", auth_key="", ssh_key=pub_key
        )
        assert result is True
        # Verify the install command used '>' (create, not append)
        install_cmd = mock_run.call_args_list[1]
        assert ">" in str(install_cmd)


# ---------------------------------------------------------------------------
# _interface_exists
# ---------------------------------------------------------------------------


class TestInterfaceExists:
    @patch("conwrt.postflash.subprocess.run")
    def test_exists_returncode_0(self, mock_run):
        from conwrt.postflash import _interface_exists
        mock_run.return_value = _mock_result(0)
        assert _interface_exists("en0") is True

    @patch("conwrt.postflash.subprocess.run")
    def test_not_exists_returncode_1(self, mock_run):
        from conwrt.postflash import _interface_exists
        mock_run.return_value = _mock_result(1)
        assert _interface_exists("en999") is False

    @patch("conwrt.postflash.subprocess.run", side_effect=OSError("no ifconfig"))
    def test_subprocess_exception_returns_false(self, mock_run):
        from conwrt.postflash import _interface_exists
        # subprocess.run raising should propagate — but the function doesn't
        # catch exceptions. This test documents current behavior.
        with pytest.raises(OSError):
            _interface_exists("en0")

    @patch("conwrt.postflash.subprocess.run")
    def test_calls_ifconfig_with_interface(self, mock_run):
        from conwrt.postflash import _interface_exists
        mock_run.return_value = _mock_result(0)
        _interface_exists("en7")
        mock_run.assert_called_once_with(
            ["ifconfig", "en7"], capture_output=True, text=True, check=False,
        )


# ---------------------------------------------------------------------------
# _deploy_tollgate_post_flash
# ---------------------------------------------------------------------------


class TestDeployTollgatePostFlash:
    def test_no_conwrt_config_returns_early(self):
        from conwrt.postflash import _deploy_tollgate_post_flash
        _deploy_tollgate_post_flash("1.2.3.4", ssh_key="", cfg=None)

    def test_no_use_cases_returns_early(self):
        from conwrt.postflash import _deploy_tollgate_post_flash
        cfg = ConwrtConfig(use_cases=[])
        _deploy_tollgate_post_flash("1.2.3.4", ssh_key="", cfg=cfg)

    def test_no_tollgate_use_case_returns_early(self):
        from conwrt.postflash import _deploy_tollgate_post_flash
        cfg = ConwrtConfig(use_cases=[UseCaseConfig(name="sqm")])
        _deploy_tollgate_post_flash("1.2.3.4", ssh_key="", cfg=cfg)

    def test_has_tollgate_calls_deploy(self):
        from conwrt.postflash import _deploy_tollgate_post_flash
        mock_deploy = MagicMock()
        cfg = ConwrtConfig(use_cases=[UseCaseConfig(name="tollgate", params={"arch": "aarch64"})])
        with patch.dict("sys.modules", {"use_cases.tollgate": MagicMock(deploy_tollgate_post_flash=mock_deploy)}):
            _deploy_tollgate_post_flash("1.2.3.4", ssh_key="key", cfg=cfg)
        mock_deploy.assert_called_once()

    def test_tollgate_default_params(self):
        """When params are empty, defaults arch='', channel='stable', version='latest', source='auto'."""
        from conwrt.postflash import _deploy_tollgate_post_flash
        mock_deploy = MagicMock()
        cfg = ConwrtConfig(use_cases=[UseCaseConfig(name="tollgate", params={})])
        with patch.dict("sys.modules", {"use_cases.tollgate": MagicMock(deploy_tollgate_post_flash=mock_deploy)}):
            _deploy_tollgate_post_flash("1.2.3.4", ssh_key="key", cfg=cfg)
        call_kwargs = mock_deploy.call_args
        assert call_kwargs[1].get("arch", call_kwargs[0][1] if len(call_kwargs[0]) > 1 else "") == ""
        assert call_kwargs[1]["channel"] == "stable"
        assert call_kwargs[1]["version"] == "latest"
        assert call_kwargs[1]["source"] == "auto"

    def test_tollgate_custom_params_passed_through(self):
        from conwrt.postflash import _deploy_tollgate_post_flash
        mock_deploy = MagicMock()
        cfg = ConwrtConfig(use_cases=[UseCaseConfig(name="tollgate", params={
            "arch": "mips", "channel": "beta", "version": "1.2.3", "source": "github",
        })])
        with patch.dict("sys.modules", {"use_cases.tollgate": MagicMock(deploy_tollgate_post_flash=mock_deploy)}):
            _deploy_tollgate_post_flash("1.2.3.4", ssh_key="key", cfg=cfg)
        call_kwargs = mock_deploy.call_args
        assert call_kwargs[1]["arch"] == "mips"
        assert call_kwargs[1]["channel"] == "beta"
        assert call_kwargs[1]["version"] == "1.2.3"
        assert call_kwargs[1]["source"] == "github"

    def test_cfg_is_not_conwrtconfig(self):
        from conwrt.postflash import _deploy_tollgate_post_flash
        _deploy_tollgate_post_flash("1.2.3.4", ssh_key="", cfg="not_a_config")


# ---------------------------------------------------------------------------
# _resolve_configure_options
# ---------------------------------------------------------------------------


class TestResolveConfigureOptions:
    def test_not_conwrtconfig_returns_empty_tuple(self):
        from conwrt.postflash import _resolve_configure_options
        args = _make_args()
        result = _resolve_configure_options(args, cfg=None)
        assert result == ("", "", "", "", False)

    def test_cfg_is_string_returns_empty_tuple(self):
        from conwrt.postflash import _resolve_configure_options
        args = _make_args()
        result = _resolve_configure_options(args, cfg="not_a_config")
        assert result == ("", "", "", "", False)

    def test_ssh_key_override(self):
        from conwrt.postflash import _resolve_configure_options
        cfg = _make_cfg(ssh_private_key_path="/etc/ssh/id_ed25519")
        args = _make_args(ssh_key="/home/user/.ssh/custom_key")
        pw, key_path, pub_path, key_text, wan_ssh = _resolve_configure_options(args, cfg)
        assert key_path == "/home/user/.ssh/custom_key"

    def test_ssh_key_from_cfg_when_no_args(self):
        from conwrt.postflash import _resolve_configure_options
        cfg = _make_cfg(ssh_private_key_path="/etc/ssh/id_ed25519")
        args = _make_args()
        pw, key_path, pub_path, key_text, wan_ssh = _resolve_configure_options(args, cfg)
        assert key_path == "/etc/ssh/id_ed25519"

    def test_ssh_key_pub_file_sets_pub_path(self):
        from conwrt.postflash import _resolve_configure_options
        cfg = ConwrtConfig()
        args = _make_args(ssh_key="/home/user/.ssh/id_ed25519.pub")
        with patch("pathlib.Path.is_file", return_value=True), \
             patch("pathlib.Path.suffix", new_callable=PropertyMock, return_value=".pub"):
            pw, key_path, pub_path, key_text, wan_ssh = _resolve_configure_options(args, cfg)
        assert pub_path == "/home/user/.ssh/id_ed25519.pub"

    def test_ssh_key_non_pub_file_does_not_override_pub_path(self):
        from conwrt.postflash import _resolve_configure_options
        cfg = ConwrtConfig(ssh_public_key_path="/original/pub.key")
        args = _make_args(ssh_key="/home/user/.ssh/id_ed25519")
        with patch("pathlib.Path.is_file", return_value=True):
            pw, key_path, pub_path, key_text, wan_ssh = _resolve_configure_options(args, cfg)
        assert pub_path == "/original/pub.key"

    def test_no_password_flag(self):
        from conwrt.postflash import _resolve_configure_options
        cfg = _make_cfg(password_mode="mypassword")
        args = _make_args(no_password=True)
        pw, *_ = _resolve_configure_options(args, cfg)
        assert pw == ""

    def test_password_from_args(self):
        from conwrt.postflash import _resolve_configure_options
        cfg = ConwrtConfig()
        args = _make_args(password="cli-password")
        pw, *_ = _resolve_configure_options(args, cfg)
        assert pw == "cli-password"

    @patch("conwrt.postflash._generate_random_password", return_value="rand-pw-123")
    def test_random_password_from_cfg(self, mock_gen):
        from conwrt.postflash import _resolve_configure_options
        cfg = _make_cfg(password_mode="random")
        args = _make_args()
        pw, *_ = _resolve_configure_options(args, cfg)
        assert pw == "rand-pw-123"
        mock_gen.assert_called_once()

    def test_password_literal_from_cfg(self):
        from conwrt.postflash import _resolve_configure_options
        cfg = _make_cfg(password_mode="literal-password")
        args = _make_args()
        pw, *_ = _resolve_configure_options(args, cfg)
        assert pw == "literal-password"

    def test_wan_ssh_from_args_overrides_cfg(self):
        from conwrt.postflash import _resolve_configure_options
        cfg = _make_cfg(wan_ssh=False)
        args = _make_args(wan_ssh=True)
        *_, wan_ssh = _resolve_configure_options(args, cfg)
        assert wan_ssh is True

    def test_wan_ssh_from_cfg_default(self):
        from conwrt.postflash import _resolve_configure_options
        cfg = _make_cfg(wan_ssh=True)
        args = _make_args(wan_ssh=False)
        *_, wan_ssh = _resolve_configure_options(args, cfg)
        assert wan_ssh is True

    def test_no_wan_ssh_default(self):
        from conwrt.postflash import _resolve_configure_options
        cfg = ConwrtConfig()
        args = _make_args()
        *_, wan_ssh = _resolve_configure_options(args, cfg)
        assert wan_ssh is False

    def test_returns_5_tuple(self):
        from conwrt.postflash import _resolve_configure_options
        cfg = ConwrtConfig()
        args = _make_args()
        result = _resolve_configure_options(args, cfg)
        assert isinstance(result, tuple)
        assert len(result) == 5

    def test_key_only_mode_returns_empty_password(self):
        """When password_mode is 'key-only', password_literal returns None → pw=''.
        The code path: not no_password, not args.password, not password_is_random,
        falls to `password_literal or ""`. key-only returns None, so `None or ""` = ""."""
        from conwrt.postflash import _resolve_configure_options
        cfg = _make_cfg(password_mode="key-only")
        args = _make_args()
        pw, *_ = _resolve_configure_options(args, cfg)
        assert pw == ""


# ---------------------------------------------------------------------------
# _apply_sticker_credentials_post_flash
# ---------------------------------------------------------------------------


class TestApplyStickerCredentialsPostFlash:
    def test_no_conwrt_config_returns_early(self):
        from conwrt.postflash import _apply_sticker_credentials_post_flash
        _apply_sticker_credentials_post_flash("1.2.3.4", ssh_key="", model_id="m", cfg=None)

    def test_has_wifi_ap_returns_early(self):
        from conwrt.postflash import _apply_sticker_credentials_post_flash
        cfg = ConwrtConfig(wifi_aps=[WifiAPConfig(ssid="test")])
        with patch("conwrt.postflash.load_model"):
            _apply_sticker_credentials_post_flash("1.2.3.4", ssh_key="", model_id="m", cfg=cfg)

    def test_no_model_id_returns_early(self):
        from conwrt.postflash import _apply_sticker_credentials_post_flash
        cfg = ConwrtConfig()
        _apply_sticker_credentials_post_flash("1.2.3.4", ssh_key="", model_id="", cfg=cfg)

    @patch("conwrt.postflash.load_model", side_effect=FileNotFoundError)
    def test_model_not_found_returns_early(self, mock_load):
        from conwrt.postflash import _apply_sticker_credentials_post_flash
        cfg = ConwrtConfig()
        _apply_sticker_credentials_post_flash("1.2.3.4", ssh_key="", model_id="m", cfg=cfg)

    @patch("conwrt.postflash.load_model", return_value={})
    def test_model_without_sticker_credentials_returns_early(self, mock_load):
        from conwrt.postflash import _apply_sticker_credentials_post_flash
        cfg = ConwrtConfig()
        _apply_sticker_credentials_post_flash("1.2.3.4", ssh_key="", model_id="m", cfg=cfg)

    @patch("conwrt.postflash.apply_credentials_to_openwrt")
    @patch("conwrt.postflash.dump_and_extract_config2")
    @patch("conwrt.postflash.load_model", return_value={"sticker_credentials": {"ssid_field": "ssid_24g"}})
    def test_happy_path(self, mock_model, mock_dump, mock_apply):
        from conwrt.postflash import _apply_sticker_credentials_post_flash
        cfg = ConwrtConfig()
        mock_dump.return_value = {
            "wifi": {"ssid_24g": "FactorySSID", "ssid_5g": "Factory5G"},
            "macs": {"factory_mac": "AA:BB:CC:DD:EE:FF"},
        }
        _apply_sticker_credentials_post_flash("1.2.3.4", ssh_key="key", model_id="m", cfg=cfg)
        mock_dump.assert_called_once()
        mock_apply.assert_called_once()

    @patch("conwrt.postflash.dump_and_extract_config2", side_effect=RuntimeError("dump failed"))
    @patch("conwrt.postflash.load_model", return_value={"sticker_credentials": {"ssid_field": "ssid_24g"}})
    def test_dump_raises_runtime_error_returns_early(self, mock_model, mock_dump):
        from conwrt.postflash import _apply_sticker_credentials_post_flash
        cfg = ConwrtConfig()
        with patch("conwrt.postflash.log"):
            _apply_sticker_credentials_post_flash("1.2.3.4", ssh_key="key", model_id="m", cfg=cfg)

    @patch("conwrt.postflash.apply_credentials_to_openwrt", side_effect=RuntimeError("apply failed"))
    @patch("conwrt.postflash.dump_and_extract_config2", return_value={"wifi": {}, "macs": {}})
    @patch("conwrt.postflash.load_model", return_value={"sticker_credentials": {"ssid_field": "ssid_24g"}})
    def test_apply_raises_runtime_error_returns_early(self, mock_model, mock_dump, mock_apply):
        from conwrt.postflash import _apply_sticker_credentials_post_flash
        cfg = ConwrtConfig()
        with patch("conwrt.postflash.log"):
            _apply_sticker_credentials_post_flash("1.2.3.4", ssh_key="key", model_id="m", cfg=cfg)

    @patch("conwrt.postflash.apply_credentials_to_openwrt")
    @patch("conwrt.postflash.dump_and_extract_config2")
    @patch("conwrt.postflash.load_model", return_value={"sticker_credentials": {"ssid_field": "ssid_24g"}})
    def test_success_logs_applied_message(self, mock_model, mock_dump, mock_apply):
        from conwrt.postflash import _apply_sticker_credentials_post_flash
        cfg = ConwrtConfig()
        mock_dump.return_value = {
            "wifi": {"ssid_24g": "SSID24", "ssid_5g": "SSID5"},
            "macs": {},
        }
        with patch("conwrt.postflash.log") as mock_log:
            _apply_sticker_credentials_post_flash("1.2.3.4", ssh_key="key", model_id="m", cfg=cfg)
            # Check that "sticker credentials applied" was logged
            log_messages = [str(c) for c in mock_log.call_args_list]
            assert any("sticker credentials applied" in m for m in log_messages)


# ---------------------------------------------------------------------------
# _register_wireguard_post_flash
# ---------------------------------------------------------------------------


class TestRegisterWireguardPostFlash:
    def test_no_conwrt_config_returns_empty(self):
        from conwrt.postflash import _register_wireguard_post_flash
        assert _register_wireguard_post_flash("1.2.3.4", ssh_key="", cfg=None) == ""

    def test_no_wireguard_config_returns_empty(self):
        from conwrt.postflash import _register_wireguard_post_flash
        cfg = ConwrtConfig()
        assert _register_wireguard_post_flash("1.2.3.4", ssh_key="", cfg=cfg) == ""

    def test_no_registration_server_returns_empty(self):
        from conwrt.postflash import _register_wireguard_post_flash
        cfg = ConwrtConfig(wireguard=WireguardConfig(registration_server="", wg_interface="wg0"))
        assert _register_wireguard_post_flash("1.2.3.4", ssh_key="", cfg=cfg) == ""

    @patch("conwrt.postflash.subprocess")
    def test_public_key_from_wg_show_succeeds(self, mock_sp):
        from conwrt.postflash import _register_wireguard_post_flash
        cfg = ConwrtConfig(wireguard=WireguardConfig(registration_server="vpn-server", wg_interface="wg0"))
        long_key = "a" * 44
        mock_sp.run.side_effect = [
            _mock_result(0, stdout=long_key),
            _mock_result(0, stdout="10.0.0.2/32"),
            _mock_result(0),
            _mock_result(0),
        ]
        result = _register_wireguard_post_flash("1.2.3.4", ssh_key="", cfg=cfg)
        assert result == long_key

    @patch("conwrt.postflash.subprocess")
    def test_public_key_too_short_falls_back_to_private(self, mock_sp):
        from conwrt.postflash import _register_wireguard_post_flash
        cfg = ConwrtConfig(wireguard=WireguardConfig(registration_server="vpn-server", wg_interface="wg0"))
        long_key = "b" * 44
        priv_key = "c" * 44
        mock_sp.run.side_effect = [
            _mock_result(0, stdout="short"),
            _mock_result(0, stdout=priv_key),
            _mock_result(0, stdout=long_key),
            _mock_result(0, stdout="10.0.0.3/32"),
            _mock_result(0),
            _mock_result(0),
        ]
        result = _register_wireguard_post_flash("1.2.3.4", ssh_key="", cfg=cfg)
        assert result == long_key

    @patch("conwrt.postflash.subprocess")
    def test_no_private_key_returns_empty(self, mock_sp):
        from conwrt.postflash import _register_wireguard_post_flash
        cfg = ConwrtConfig(wireguard=WireguardConfig(registration_server="vpn-server", wg_interface="wg0"))
        mock_sp.run.side_effect = [
            _mock_result(0, stdout=""),
            _mock_result(0, stdout=""),
        ]
        result = _register_wireguard_post_flash("1.2.3.4", ssh_key="", cfg=cfg)
        assert result == ""


# ---------------------------------------------------------------------------
# verify_router
# ---------------------------------------------------------------------------


class TestVerifyRouter:
    @patch("conwrt.postflash.subprocess.run")
    def test_ssh_returns_valid_output(self, mock_run):
        from conwrt.postflash import verify_router
        mock_run.return_value = _mock_result(0, stdout=(
            "hostname=OpenWrt\n"
            "board=xiaomi,redmi-router-ax1800\n"
            "kernel=5.15.134\n"
            "sshkey_count=1\n"
            "wan_ssh=0\n"
        ))
        checks = verify_router("192.168.1.1")
        d = dict(checks)
        assert d["hostname"] == "OpenWrt"
        assert d["board"] == "xiaomi,redmi-router-ax1800"
        assert d["sshkey_count"] == "1"

    @patch("conwrt.postflash.subprocess.run", side_effect=OSError("timeout"))
    def test_ssh_fails_returns_empty_list(self, mock_run):
        from conwrt.postflash import verify_router
        checks = verify_router("192.168.1.1")
        assert checks == []

    @patch("conwrt.postflash.subprocess.run")
    def test_wan_ssh_expected_flag(self, mock_run):
        from conwrt.postflash import verify_router
        mock_run.return_value = _mock_result(0, stdout=(
            "hostname=OpenWrt\nwan_ssh=1\n"
        ))
        checks = verify_router("192.168.1.1", wan_ssh_expected=True)
        d = dict(checks)
        assert d["wan_ssh"] == "1"

    @patch("conwrt.postflash.subprocess.run")
    def test_mgmt_wifi_expected_flag(self, mock_run):
        from conwrt.postflash import verify_router
        mock_run.return_value = _mock_result(0, stdout=(
            "hostname=OpenWrt\n"
            "mgmt_wifi=192.168.100.1\n"
            "mgmt_ssid=MGMT-TestAP\n"
        ))
        checks = verify_router("192.168.1.1", mgmt_wifi_expected=True)
        d = dict(checks)
        assert d["mgmt_wifi"] == "192.168.100.1"
        assert d["mgmt_ssid"] == "MGMT-TestAP"

    @patch("conwrt.postflash.subprocess.run")
    def test_empty_stdout_returns_empty_list(self, mock_run):
        from conwrt.postflash import verify_router
        mock_run.return_value = _mock_result(0, stdout="")
        checks = verify_router("192.168.1.1")
        assert checks == []

    @patch("conwrt.postflash.subprocess.run")
    def test_subprocess_error_returns_empty_list(self, mock_run):
        from conwrt.postflash import verify_router
        mock_run.side_effect = subprocess.SubprocessError("broken pipe")
        checks = verify_router("192.168.1.1")
        assert checks == []

    @patch("conwrt.postflash.subprocess.run")
    def test_wan_ssh_zero_logs_no_firewall_rule(self, mock_run):
        from conwrt.postflash import verify_router
        mock_run.return_value = _mock_result(0, stdout="hostname=OpenWrt\nwan_ssh=0\n")
        with patch("conwrt.postflash.log") as mock_log:
            verify_router("192.168.1.1", wan_ssh_expected=True)
            log_msgs = [str(c) for c in mock_log.call_args_list]
            assert any("no firewall rule found" in m for m in log_msgs)

    @patch("conwrt.postflash.subprocess.run")
    def test_wan_ssh_nonzero_logs_firewall_present(self, mock_run):
        from conwrt.postflash import verify_router
        mock_run.return_value = _mock_result(0, stdout="hostname=OpenWrt\nwan_ssh=2\n")
        with patch("conwrt.postflash.log") as mock_log:
            verify_router("192.168.1.1", wan_ssh_expected=True)
            log_msgs = [str(c) for c in mock_log.call_args_list]
            assert any("firewall rule present" in m for m in log_msgs)

    @patch("conwrt.postflash.subprocess.run")
    def test_mgmt_ssid_with_mgmt_prefix_logs_ssid(self, mock_run):
        from conwrt.postflash import verify_router
        mock_run.return_value = _mock_result(0, stdout=(
            "hostname=OpenWrt\nmgmt_wifi=10.0.0.1\nmgmt_ssid=MGMT-MyAP\n"
        ))
        with patch("conwrt.postflash.log") as mock_log:
            verify_router("192.168.1.1", mgmt_wifi_expected=True)
            log_msgs = [str(c) for c in mock_log.call_args_list]
            assert any("MGMT-MyAP" in m for m in log_msgs)

    @patch("conwrt.postflash.subprocess.run")
    def test_uci_defaults_zero_logs_all_consumed(self, mock_run):
        from conwrt.postflash import verify_router
        mock_run.return_value = _mock_result(0, stdout="hostname=OpenWrt\nuci_defaults=0\n")
        with patch("conwrt.postflash.log") as mock_log:
            verify_router("192.168.1.1")
            log_msgs = [str(c) for c in mock_log.call_args_list]
            assert any("all consumed" in m for m in log_msgs)

    @patch("conwrt.postflash.subprocess.run")
    def test_ping_ok_yes_logs_connectivity(self, mock_run):
        from conwrt.postflash import verify_router
        mock_run.return_value = _mock_result(0, stdout="hostname=OpenWrt\nping_ok=yes\n")
        with patch("conwrt.postflash.log") as mock_log:
            verify_router("192.168.1.1")
            log_msgs = [str(c) for c in mock_log.call_args_list]
            assert any("connectivity confirmed" in m for m in log_msgs)

    @patch("conwrt.postflash.subprocess.run")
    def test_multi_value_key_parsed_correctly(self, mock_run):
        """Keys with multiple '=' signs should split on first '=' only."""
        from conwrt.postflash import verify_router
        mock_run.return_value = _mock_result(0, stdout="mac_all=br-lan=AA:BB:CC:DD:EE:FF eth0=11:22:33:44:55:66\n")
        checks = verify_router("192.168.1.1")
        d = dict(checks)
        assert "mac_all" in d
        assert d["mac_all"] == "br-lan=AA:BB:CC:DD:EE:FF eth0=11:22:33:44:55:66"

    @patch("conwrt.postflash.subprocess.run")
    def test_sshkey_count_zero_logs_warning(self, mock_run):
        from conwrt.postflash import verify_router
        mock_run.return_value = _mock_result(0, stdout="hostname=OpenWrt\nsshkey_count=0\n")
        with patch("conwrt.postflash.log") as mock_log:
            verify_router("192.168.1.1")
            log_msgs = [str(c) for c in mock_log.call_args_list]
            assert any("none found" in m for m in log_msgs)

    @patch("conwrt.postflash.subprocess.run")
    def test_sshkey_count_positive_logs_authorized(self, mock_run):
        from conwrt.postflash import verify_router
        mock_run.return_value = _mock_result(0, stdout="hostname=OpenWrt\nsshkey_count=3\n")
        with patch("conwrt.postflash.log") as mock_log:
            verify_router("192.168.1.1")
            log_msgs = [str(c) for c in mock_log.call_args_list]
            assert any("3 authorized" in m for m in log_msgs)


# ---------------------------------------------------------------------------
# _apply_profile_post_flash
# ---------------------------------------------------------------------------


class TestApplyProfilePostFlash:
    def test_no_conwrt_config_returns_ip_unchanged(self):
        from conwrt.postflash import _apply_profile_post_flash
        result = _apply_profile_post_flash("192.168.1.1", cfg=None)
        assert result == "192.168.1.1"

    @patch("conwrt.postflash.apply_plan", return_value="10.0.0.1")
    @patch("conwrt.postflash.build_plan")
    @patch("conwrt.postflash.load_model", return_value={"capabilities": []})
    def test_ssh_transport_calls_apply_plan(self, mock_model, mock_build, mock_apply):
        from conwrt.postflash import _apply_profile_post_flash
        from profile.plan import ProfilePlan
        mock_build.return_value = ProfilePlan(mode="post_install", steps=[])
        cfg = ConwrtConfig()
        result = _apply_profile_post_flash("192.168.1.1", ssh_key="key", cfg=cfg, transport="ssh")
        mock_apply.assert_called_once()
        assert result == "10.0.0.1"

    @patch("conwrt.postflash.apply_ubus", return_value="10.0.0.2")
    @patch("conwrt.postflash.build_plan")
    @patch("conwrt.postflash.load_model", return_value={"capabilities": []})
    def test_ubus_transport_calls_apply_ubus(self, mock_model, mock_build, mock_ubus):
        from conwrt.postflash import _apply_profile_post_flash
        from profile.plan import ProfilePlan
        mock_build.return_value = ProfilePlan(mode="post_install", steps=[])
        cfg = ConwrtConfig()
        result = _apply_profile_post_flash("192.168.1.1", cfg=cfg, transport="ubus")
        mock_ubus.assert_called_once()
        assert result == "10.0.0.2"

    @patch("conwrt.postflash.apply_plan", return_value="192.168.1.1")
    @patch("conwrt.postflash.build_plan")
    @patch("conwrt.postflash.load_model", return_value={"capabilities": []})
    def test_dry_run_does_not_log_applying(self, mock_model, mock_build, mock_apply):
        from conwrt.postflash import _apply_profile_post_flash
        from profile.plan import ProfilePlan
        mock_build.return_value = ProfilePlan(mode="preview", steps=[])
        cfg = ConwrtConfig()
        with patch("conwrt.postflash.log") as mock_log:
            _apply_profile_post_flash("192.168.1.1", cfg=cfg, dry_run=True, transport="ssh")
            applying_calls = [c for c in mock_log.call_args_list if "Applying profile" in str(c)]
            assert len(applying_calls) == 0

    @patch("conwrt.postflash._apply_lan_ip_post_flash", return_value="10.0.0.1")
    @patch("conwrt.postflash.apply_plan", return_value="192.168.1.1")
    @patch("conwrt.postflash.build_plan")
    @patch("conwrt.postflash.load_model", return_value={"capabilities": []})
    def test_has_static_lan_ip_calls_apply_lan_ip(self, mock_model, mock_build, mock_apply, mock_lan):
        from conwrt.postflash import _apply_profile_post_flash
        from profile.plan import ProfilePlan
        mock_build.return_value = ProfilePlan(mode="post_install", steps=[])
        cfg = ConwrtConfig(lan_ip="10.0.0.1")
        result = _apply_profile_post_flash(
            "192.168.1.1", ssh_key="key", cfg=cfg,
            interface="en0", old_client_ip="192.168.1.254",
            transport="ssh",
        )
        mock_lan.assert_called_once()
        assert result == "10.0.0.1"


# ---------------------------------------------------------------------------
# _record_configure_inventory
# ---------------------------------------------------------------------------


class TestRecordConfigureInventory:
    @patch("conwrt.postflash.fingerprint_router", return_value=None)
    def test_no_fingerprint_returns_early(self, mock_fp):
        from conwrt.postflash import _record_configure_inventory
        with patch("conwrt.postflash.log"):
            _record_configure_inventory("1.2.3.4")
        # Should not crash

    @patch("conwrt.postflash.save_fingerprint", return_value=Path("/tmp/fp.json"))
    @patch("conwrt.postflash.fingerprint_router")
    def test_basic_inventory_write(self, mock_fp, mock_save):
        from conwrt.postflash import _record_configure_inventory
        mock_fp.return_value = {
            "identity": {"board": "test-board", "model": "TestModel", "hostname": "owrt"},
            "firmware": {"version": "24.10", "kernel": "5.15", "DISTRIB_ID": "OpenWrt"},
            "network": {"macs": {"br-lan": "AA:BB:CC:DD:EE:FF", "eth0": "11:22:33:44:55:66"}},
            "security": {"ssh_fingerprint": "SHA256:abc", "ssh_key_count": 1, "wan_ssh_rules": 0},
        }
        with patch("conwrt.postflash._append_to_inventory") as mock_inv, \
             patch("conwrt.postflash.log"):
            _record_configure_inventory("1.2.3.4", password="secret", model_id="test-model")
            mock_inv.assert_called_once()

    @patch("conwrt.postflash.save_fingerprint", return_value=Path("/tmp/fp.json"))
    @patch("conwrt.postflash.fingerprint_router")
    def test_inventory_with_serial(self, mock_fp, mock_save):
        from conwrt.postflash import _record_configure_inventory
        mock_fp.return_value = {
            "identity": {"board": "b", "model": "m", "hostname": "h", "serial": "S123"},
            "firmware": {},
            "network": {"macs": {}},
            "security": {},
        }
        with patch("conwrt.postflash._append_to_inventory") as mock_inv, \
             patch("conwrt.postflash.log"):
            _record_configure_inventory("1.2.3.4", serial="S123", password="pw")
            entry = mock_inv.call_args[0][0]
            assert entry["device_serial"] == "S123"
