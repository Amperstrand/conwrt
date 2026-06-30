"""Tests for config.py — TOML parsing, SSH key handling, WiFi config validation."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from config import (
    ConwrtConfig,
    WifiAPConfig,
    load_config,
    strip_key_comment,
    _is_inline_key,
    _parse_wifi_ap,
    _parse_wifi_sta,
    _resolve_all_keys,
    _resolve_private_from_public,
)


class TestStripKeyComment:
    def test_strips_user_comment(self):
        assert strip_key_comment("ssh-ed25519 AAAA user@host") == "ssh-ed25519 AAAA"

    def test_preserves_key_without_comment(self):
        assert strip_key_comment("ssh-ed25519 AAAA") == "ssh-ed25519 AAAA"

    def test_handles_rsa_key(self):
        result = strip_key_comment("ssh-rsa BBBB alice@example.com")
        assert result == "ssh-rsa BBBB"

    def test_handles_empty_string(self):
        assert strip_key_comment("") == ""


class TestIsInlineKey:
    def test_inline_ed25519(self):
        assert _is_inline_key("ssh-ed25519 AAAA user@host") is True

    def test_inline_rsa(self):
        assert _is_inline_key("ssh-rsa BBBB") is True

    def test_file_path(self):
        assert _is_inline_key("~/.ssh/id_ed25519.pub") is False

    def test_empty(self):
        assert _is_inline_key("") is False


class TestResolvePrivateFromPublic:
    def test_strips_pub_extension(self):
        assert _resolve_private_from_public("/home/.ssh/id_ed25519.pub") == "/home/.ssh/id_ed25519"

    def test_no_pub_extension(self):
        assert _resolve_private_from_public("/home/.ssh/key") == "/home/.ssh/key"


class TestParseWifiSta:
    def test_valid_config(self):
        cfg = _parse_wifi_sta({"ssid": "TestNet", "key": "pass123"})
        assert cfg.ssid == "TestNet"
        assert cfg.band == "2.4ghz"
        assert cfg.encryption == "psk2"

    def test_5ghz_band(self):
        cfg = _parse_wifi_sta({"ssid": "TestNet", "band": "5ghz"})
        assert cfg.band == "5ghz"

    def test_missing_ssid_raises(self):
        with pytest.raises(ValueError, match="ssid is required"):
            _parse_wifi_sta({"band": "2.4ghz"})

    def test_invalid_band_raises(self):
        with pytest.raises(ValueError, match="invalid band"):
            _parse_wifi_sta({"ssid": "TestNet", "band": "6ghz"})

    def test_invalid_encryption_raises(self):
        with pytest.raises(ValueError, match="invalid encryption"):
            _parse_wifi_sta({"ssid": "TestNet", "encryption": "wep"})

    def test_open_network(self):
        cfg = _parse_wifi_sta({"ssid": "Open", "encryption": "none"})
        assert cfg.encryption == "none"
        assert cfg.key == ""


class TestParseWifiAp:
    def test_valid_config(self):
        cfg = _parse_wifi_ap({"ssid": "MyAP", "key": "pass"})
        assert cfg.ssid == "MyAP"
        assert cfg.channel == "auto"

    def test_custom_channel(self):
        cfg = _parse_wifi_ap({"ssid": "MyAP", "channel": "36"})
        assert cfg.channel == "36"

    def test_missing_ssid_raises(self):
        with pytest.raises(ValueError, match="ssid is required"):
            _parse_wifi_ap({"band": "2.4ghz"})


class TestResolveAllKeys:
    def test_inline_keys(self):
        result = _resolve_all_keys(["ssh-ed25519 AAAA user@host"])
        assert result == ["ssh-ed25519 AAAA"]

    def test_multiple_inline_keys(self):
        result = _resolve_all_keys([
            "ssh-ed25519 AAAA user@host",
            "ssh-rsa BBBB alice@host",
        ])
        assert result == ["ssh-ed25519 AAAA", "ssh-rsa BBBB"]

    def test_empty_list(self):
        assert _resolve_all_keys([]) == []

    def test_skips_empty_strings(self):
        assert _resolve_all_keys(["", "  "]) == []


class TestLoadConfigDefaults:
    def test_missing_file_returns_defaults(self, tmp_path):
        cfg = load_config(tmp_path / "nonexistent.toml")
        assert isinstance(cfg, ConwrtConfig)
        assert cfg.password_mode == "random"
        assert cfg.wan_ssh is False
        assert cfg.use_cases == []
        assert cfg.wifi_sta is None
        assert cfg.wireguard is None

    def test_empty_file_returns_defaults(self, tmp_path):
        p = tmp_path / "config.toml"
        p.write_text("")
        cfg = load_config(p)
        assert cfg.password_mode == "random"
        assert cfg.ssh_public_key_text == ""


class TestLoadConfigToml:
    def _write(self, tmp_path: Path, content: str) -> Path:
        p = tmp_path / "config.toml"
        p.write_text(content)
        return p

    def test_password_key_only(self, tmp_path):
        p = self._write(tmp_path, '[password]\nmode = "key-only"')
        cfg = load_config(p)
        assert cfg.password_is_key_only is True
        assert cfg.password_literal is None

    def test_password_literal(self, tmp_path):
        p = self._write(tmp_path, '[password]\nmode = "mysecret"')
        cfg = load_config(p)
        assert cfg.password_literal == "mysecret"
        assert cfg.password_is_random is False

    def test_wan_ssh(self, tmp_path):
        p = self._write(tmp_path, "[network]\nwan_ssh = true")
        cfg = load_config(p)
        assert cfg.wan_ssh is True

    def test_extra_packages(self, tmp_path):
        p = self._write(tmp_path, '[asu]\nextra_packages = ["luci", "vim"]')
        cfg = load_config(p)
        assert cfg.extra_packages == ["luci", "vim"]

    def test_extra_packages_single_string(self, tmp_path):
        p = self._write(tmp_path, '[asu]\nextra_packages = "luci"')
        cfg = load_config(p)
        assert cfg.extra_packages == ["luci"]

    def test_wifi_sta(self, tmp_path):
        p = self._write(tmp_path, '[network.sta]\nssid = "Upstream"\nband = "5ghz"\nkey = "pass"')
        cfg = load_config(p)
        assert cfg.wifi_sta is not None
        assert cfg.wifi_sta.ssid == "Upstream"
        assert cfg.wifi_sta.band == "5ghz"

    def test_wifi_ap(self, tmp_path):
        p = self._write(tmp_path, '[network.ap]\nssid = "MyNet"\nchannel = "36"')
        cfg = load_config(p)
        assert cfg.wifi_ap is not None
        assert cfg.wifi_ap.ssid == "MyNet"
        assert cfg.wifi_ap.channel == "36"

    def test_use_cases(self, tmp_path):
        p = self._write(tmp_path, '[use_cases]\nenabled = ["sqm", "tether"]\n\n[use_cases.sqm]\ndownload_kbps = 100')
        cfg = load_config(p)
        assert len(cfg.use_cases) == 2
        assert cfg.use_cases[0].name == "sqm"
        assert cfg.use_cases[0].params["download_kbps"] == 100
        assert cfg.use_cases[1].name == "tether"

    def test_use_cases_single_string(self, tmp_path):
        p = self._write(tmp_path, '[use_cases]\nenabled = "sqm"')
        cfg = load_config(p)
        assert len(cfg.use_cases) == 1
        assert cfg.use_cases[0].name == "sqm"

    def test_wireguard(self, tmp_path):
        p = self._write(tmp_path, '[wireguard]\nregistration_server = "vpn-host"\nwg_interface = "wg1"')
        cfg = load_config(p)
        assert cfg.wireguard is not None
        assert cfg.wireguard.registration_server == "vpn-host"
        assert cfg.wireguard.wg_interface == "wg1"

    def test_device_section(self, tmp_path):
        p = self._write(tmp_path, '[device]\nhostname = "my-router"\nwifi_disable = true\nlan_ip_mode = "mac-hash"')
        cfg = load_config(p)
        assert cfg.hostname == "my-router"
        assert cfg.wifi_disable is True
        assert cfg.lan_ip_mode == "mac-hash"

    def test_inline_ssh_key(self, tmp_path):
        p = self._write(tmp_path, '[ssh]\nkeys = ["ssh-ed25519 AAAAB3Nz user@host"]')
        cfg = load_config(p)
        assert cfg.ssh_public_key_text == "ssh-ed25519 AAAAB3Nz"
        assert cfg.ssh_all_keys == ["ssh-ed25519 AAAAB3Nz"]

    def test_multiple_ssh_keys(self, tmp_path):
        p = self._write(tmp_path, '[ssh]\nkeys = ["ssh-ed25519 KEY1 a@b", "ssh-rsa KEY2 c@d"]')
        cfg = load_config(p)
        assert len(cfg.ssh_all_keys) == 2
        assert cfg.ssh_all_keys[0] == "ssh-ed25519 KEY1"
        assert cfg.ssh_all_keys[1] == "ssh-rsa KEY2"


class TestConwrtConfigProperties:
    def test_password_is_random(self):
        cfg = ConwrtConfig(password_mode="random")
        assert cfg.password_is_random is True
        assert cfg.password_literal is None

    def test_password_is_key_only(self):
        cfg = ConwrtConfig(password_mode="key-only")
        assert cfg.password_is_key_only is True

    def test_password_literal(self):
        cfg = ConwrtConfig(password_mode="s3cret!")
        assert cfg.password_literal == "s3cret!"

    def test_wifi_ap_property_returns_first(self):
        cfg = ConwrtConfig(wifi_aps=[WifiAPConfig(ssid="A"), WifiAPConfig(ssid="B")])
        assert cfg.wifi_ap.ssid == "A"

    def test_wifi_ap_property_returns_none_when_empty(self):
        cfg = ConwrtConfig()
        assert cfg.wifi_ap is None
