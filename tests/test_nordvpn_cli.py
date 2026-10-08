"""Hermetic tests for scripts/nordvpn.py — server selection + config rendering."""
import importlib
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

nordvpn_cli = importlib.import_module("nordvpn")

import pytest  # noqa: E402


_COUNTRIES = [
    {"id": 81, "name": "Germany", "code": "DE"},
    {"id": 1, "name": "Nowhere", "code": "NW"},
]


class TestCountryId:
    def test_lowercase_code(self):
        with patch.object(nordvpn_cli, "_get_json", return_value=_COUNTRIES):
            assert nordvpn_cli._country_id("de") == "81"

    def test_uppercase_code_regression(self):
        """The alias map used to uppercase 'de' to 'DE' and then fail the
        case-insensitive comparison — the lookup must normalize after aliasing."""
        with patch.object(nordvpn_cli, "_get_json", return_value=_COUNTRIES):
            assert nordvpn_cli._country_id("DE") == "81"

    def test_alias_germany(self):
        with patch.object(nordvpn_cli, "_get_json", return_value=_COUNTRIES):
            assert nordvpn_cli._country_id("germany") == "81"

    def test_numeric_passthrough(self):
        assert nordvpn_cli._country_id("81") == "81"

    def test_unknown_country(self):
        with patch.object(nordvpn_cli, "_get_json",
                          return_value=_COUNTRIES):
            with pytest.raises(ValueError, match="unknown NordVPN country"):
                nordvpn_cli._country_id("ZZ")


class TestServers:
    def test_lists_hostname_station_load_key(self):
        fake_servers = [{
            "hostname": "de1507.nordvpn.com", "station": "187.40.55.114", "load": 12,
            "locations": [{"country": {"code": "DE"}}],
            "technologies": [{"identifier": "wireguard_udp",
                              "metadata": [{"name": "public_key", "value": "KEY="}]}],
        }]
        with patch.object(nordvpn_cli, "_get_json",
                          side_effect=[_COUNTRIES, fake_servers]) as mock:
            rc = nordvpn_cli.cmd_servers(type("A", (), {
                "country": "de", "limit": 5, "token": "", "json": True,
            })())
        assert rc == 0
        countries_url, servers_url = (c[0][0] for c in mock.call_args_list)
        assert "servers/countries" in countries_url
        assert "country_id%5D=81" in servers_url
        assert "wireguard_udp" in servers_url

    def test_no_servers_returns_one(self):
        with patch.object(nordvpn_cli, "_get_json", return_value=[]):
            rc = nordvpn_cli.cmd_servers(type("A", (), {
                "country": "zz", "limit": 5, "token": "", "json": False,
            })())
        assert rc == 1

    def test_unknown_country_returns_one_not_raise(self):
        with patch.object(nordvpn_cli, "_get_json", return_value=_COUNTRIES):
            rc = nordvpn_cli.cmd_servers(type("A", (), {
                "country": "zz", "limit": 5, "token": "", "json": False,
            })())
        assert rc == 1

    def test_api_unreachable_returns_one(self):
        with patch.object(nordvpn_cli, "_get_json",
                          side_effect=OSError("no route to host")):
            rc = nordvpn_cli.cmd_servers(type("A", (), {
                "country": "de", "limit": 5, "token": "", "json": False,
            })())
        assert rc == 1


class TestConfigRender:
    def test_renders_conf_from_token(self, tmp_path, capsys):
        with patch.object(nordvpn_cli, "_fetch_credentials", return_value={"nordlynx_private_key": "PRIV=", "username": "u", "password": "p"}), \
             patch.object(nordvpn_cli, "_resolve_endpoint",
                          return_value=("187.40.55.102", "51820", "SRV=")):
            out = tmp_path / "nordvpn.conf"
            rc = nordvpn_cli.cmd_config(type("A", (), {
                "token": "t", "server": "DE", "country": "", "out": str(out),
            })())
        assert rc == 0
        body = out.read_text()
        assert "PrivateKey = PRIV=" in body
        assert "PublicKey = SRV=" in body
        assert "Endpoint = 187.40.55.102:51820" in body
        assert "Address = 10.5.0.2/32" in body
        assert "PersistentKeepalive = 25" in body
