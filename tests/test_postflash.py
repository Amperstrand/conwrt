from __future__ import annotations

from unittest.mock import MagicMock, patch, DEFAULT

import pytest

from config import ConwrtConfig, UseCaseConfig, WireguardConfig


def _mock_result(returncode: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


@pytest.fixture(autouse=True)
def _no_sleep():
    with patch("conwrt.postflash.time.sleep"):
        yield


class TestClientIpForSubnet:
    def test_192_168_subnet(self):
        from conwrt.postflash import _client_ip_for_subnet
        assert _client_ip_for_subnet("192.168.1.1") == "192.168.1.254"

    def test_10_subnet(self):
        from conwrt.postflash import _client_ip_for_subnet
        assert _client_ip_for_subnet("10.0.0.1") == "10.0.0.254"

    def test_invalid_string(self):
        from conwrt.postflash import _client_ip_for_subnet
        assert _client_ip_for_subnet("invalid") == ""

    def test_empty_string(self):
        from conwrt.postflash import _client_ip_for_subnet
        assert _client_ip_for_subnet("") == ""

    def test_three_octets(self):
        from conwrt.postflash import _client_ip_for_subnet
        assert _client_ip_for_subnet("1.2.3") == ""


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


class TestApplyStickerCredentialsPostFlash:
    def test_no_conwrt_config_returns_early(self):
        from conwrt.postflash import _apply_sticker_credentials_post_flash
        _apply_sticker_credentials_post_flash("1.2.3.4", ssh_key="", model_id="m", cfg=None)

    def test_has_wifi_ap_returns_early(self):
        from conwrt.postflash import _apply_sticker_credentials_post_flash
        from config import WifiAPConfig
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


class TestDeployTollgatePostFlash:
    def test_no_conwrt_config_returns_early(self):
        from conwrt.postflash import _deploy_tollgate_post_flash
        _deploy_tollgate_post_flash("1.2.3.4", ssh_key="", cfg=None)

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
