import json
from unittest.mock import MagicMock, patch

import pytest

from ubus_utils import UbusAuthError, UbusCallError, UbusClient, UbusError


def _mock_response(data: dict, status: int = 200) -> MagicMock:
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=cm)
    cm.__exit__ = MagicMock(return_value=False)
    cm.read.return_value = json.dumps(data).encode()
    cm.status = status
    return cm


class TestUbusClientLogin:
    @patch("ubus_utils.urllib.request.urlopen")
    def test_login_stores_token(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({
            "result": [0, {"ubus_rpc_session": "abc123"}],
        })
        client = UbusClient("192.168.1.1")
        token = client.login("root", "password")
        assert token == "abc123"
        assert client.token == "abc123"

    @patch("ubus_utils.urllib.request.urlopen")
    def test_login_sends_correct_payload(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({
            "result": [0, {"ubus_rpc_session": "tok"}],
        })
        client = UbusClient("192.168.1.1")
        client.login("root", "")
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        payload = json.loads(req.data)
        assert payload["method"] == "call"
        assert payload["params"][1] == "session"
        assert payload["params"][2] == "login"
        assert payload["params"][3] == {"username": "root", "password": ""}

    @patch("ubus_utils.urllib.request.urlopen")
    def test_login_fails_without_token(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({
            "result": [0, {}],
        })
        client = UbusClient("192.168.1.1")
        with pytest.raises(UbusAuthError, match="no session token"):
            client.login("root", "wrong")


class TestUbusClientCall:
    @patch("ubus_utils.urllib.request.urlopen")
    def test_generic_call(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({
            "result": [0, {"model": "FooRouter"}],
        })
        client = UbusClient("192.168.1.1")
        client.token = "tok"
        result = client.call("system", "board")
        assert result == {"model": "FooRouter"}

    def test_call_without_login_raises(self):
        client = UbusClient("192.168.1.1")
        with pytest.raises(UbusError, match="not authenticated"):
            client.call("system", "board")


class TestUbusClientUci:
    @patch("ubus_utils.urllib.request.urlopen")
    def test_uci_set(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({"result": [0]})
        client = UbusClient("192.168.1.1")
        client.token = "tok"
        client.uci_set("system", "@system[0]", {"hostname": "myrouter"})
        payload = json.loads(mock_urlopen.call_args[0][0].data)
        assert payload["params"][1] == "uci"
        assert payload["params"][2] == "set"
        assert payload["params"][3] == {
            "config": "system",
            "section": "@system[0]",
            "values": {"hostname": "myrouter"},
        }

    @patch("ubus_utils.urllib.request.urlopen")
    def test_uci_commit(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({"result": [0]})
        client = UbusClient("192.168.1.1")
        client.token = "tok"
        client.uci_commit("system")
        payload = json.loads(mock_urlopen.call_args[0][0].data)
        assert payload["params"][2] == "commit"
        assert payload["params"][3] == {"config": "system"}

    @patch("ubus_utils.urllib.request.urlopen")
    def test_uci_get(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({
            "result": [0, {"values": {"hostname": "myrouter"}}],
        })
        client = UbusClient("192.168.1.1")
        client.token = "tok"
        result = client.uci_get("system", "@system[0]", "hostname")
        assert result["values"]["hostname"] == "myrouter"

    @patch("ubus_utils.urllib.request.urlopen")
    def test_uci_add(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({"result": [0, {"section": "cfg01"}]})
        client = UbusClient("192.168.1.1")
        client.token = "tok"
        result = client.uci_add("firewall", "rule", values={
            "name": "Allow-SSH",
            "target": "ACCEPT",
        })
        payload = json.loads(mock_urlopen.call_args[0][0].data)
        assert payload["params"][2] == "add"
        assert payload["params"][3]["type"] == "rule"

    @patch("ubus_utils.urllib.request.urlopen")
    def test_uci_delete(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({"result": [0]})
        client = UbusClient("192.168.1.1")
        client.token = "tok"
        client.uci_delete("firewall", "Block_iPad")
        payload = json.loads(mock_urlopen.call_args[0][0].data)
        assert payload["params"][2] == "delete"

    @patch("ubus_utils.urllib.request.urlopen")
    def test_uci_delete_option(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({"result": [0]})
        client = UbusClient("192.168.1.1")
        client.token = "tok"
        client.uci_delete("system", "@system[0]", "hostname")
        payload = json.loads(mock_urlopen.call_args[0][0].data)
        assert payload["params"][3] == {
            "config": "system",
            "section": "@system[0]",
            "option": "hostname",
        }

    @patch("ubus_utils.urllib.request.urlopen")
    def test_service_action(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({"result": [0]})
        client = UbusClient("192.168.1.1")
        client.token = "tok"
        client.service_action("firewall", "reload")
        payload = json.loads(mock_urlopen.call_args[0][0].data)
        assert payload["params"][1] == "rc"
        assert payload["params"][2] == "reload"


class TestUbusClientErrors:
    @patch("ubus_utils.urllib.request.urlopen")
    def test_ubus_error_code(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({"result": [6]})
        client = UbusClient("192.168.1.1")
        client.token = "tok"
        with pytest.raises(UbusCallError) as exc_info:
            client.call("uci", "get", {"config": "nonexistent"})
        assert exc_info.value.code == 6

    @patch("ubus_utils.urllib.request.urlopen")
    def test_http_error(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "http://192.168.1.1/ubus", 403, "Forbidden", {}, None,
        )
        client = UbusClient("192.168.1.1")
        client.token = "tok"
        with pytest.raises(UbusError, match="HTTP 403"):
            client.call("system", "board")

    @patch("ubus_utils.urllib.request.urlopen")
    def test_connection_error(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
        client = UbusClient("192.168.1.1")
        client.token = "tok"
        with pytest.raises(UbusError, match="connection failed"):
            client.call("system", "board")


class TestUbusClientDiscoverRadios:
    @patch("ubus_utils.urllib.request.urlopen")
    def test_discover_radios(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({
            "result": [0, {
                "radio0": {"config": {"band": "2g", "channel": "auto", "country": "DE"}},
                "radio1": {"config": {"band": "5g", "channel": "36"}},
            }],
        })
        client = UbusClient("192.168.1.1")
        client.token = "tok"
        radios = client.discover_radios()
        assert radios == {
            "radio0": {"band": "2g", "channel": "auto"},
            "radio1": {"band": "5g", "channel": "36"},
        }

    @patch("ubus_utils.urllib.request.urlopen")
    def test_discover_radios_calls_wireless_status(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({"result": [0, {}]})
        client = UbusClient("192.168.1.1")
        client.token = "tok"
        client.discover_radios()
        payload = json.loads(mock_urlopen.call_args[0][0].data)
        assert payload["params"][1] == "network.wireless"
        assert payload["params"][2] == "status"

    @patch("ubus_utils.urllib.request.urlopen")
    def test_discover_radios_skips_no_band(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({
            "result": [0, {
                "radio0": {"config": {"band": "2g"}},
                "radio1": {"config": {"channel": "36"}},
            }],
        })
        client = UbusClient("192.168.1.1")
        client.token = "tok"
        radios = client.discover_radios()
        assert "radio0" in radios
        assert "radio1" not in radios

    @patch("ubus_utils.urllib.request.urlopen")
    def test_find_radio_for_band_2g(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({
            "result": [0, {
                "radio0": {"config": {"band": "2g"}},
                "radio1": {"config": {"band": "5g"}},
            }],
        })
        client = UbusClient("192.168.1.1")
        client.token = "tok"
        assert client.find_radio_for_band("2g") == "radio0"

    @patch("ubus_utils.urllib.request.urlopen")
    def test_find_radio_for_band_5g(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({
            "result": [0, {
                "radio0": {"config": {"band": "2g"}},
                "radio1": {"config": {"band": "5g"}},
            }],
        })
        client = UbusClient("192.168.1.1")
        client.token = "tok"
        assert client.find_radio_for_band("5g") == "radio1"

    @patch("ubus_utils.urllib.request.urlopen")
    def test_find_radio_for_band_missing(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({
            "result": [0, {
                "radio0": {"config": {"band": "2g"}},
            }],
        })
        client = UbusClient("192.168.1.1")
        client.token = "tok"
        assert client.find_radio_for_band("6g") is None


class TestUbusClientRequestId:
    @patch("ubus_utils.urllib.request.urlopen")
    def test_request_ids_increment(self, mock_urlopen):
        mock_urlopen.return_value = _mock_response({"result": [0]})
        client = UbusClient("192.168.1.1")
        client.token = "tok"
        client.call("system", "board")
        client.call("system", "info")
        assert mock_urlopen.call_count == 2
        p1 = json.loads(mock_urlopen.call_args_list[0][0][0].data)
        p2 = json.loads(mock_urlopen.call_args_list[1][0][0].data)
        assert p1["id"] == 1
        assert p2["id"] == 2
