from unittest.mock import MagicMock, patch
from subprocess import CompletedProcess

import pytest

from auto_detect import (
    DetectedRouter,
    LLDPInfo,
    _add_evidence,
    _normalize_mac,
    _mac_prefix,
    classify_http_response,
    classify_web_ui,
    match_model_by_board,
    match_model_by_http,
    match_model_by_lldp,
    assess_readiness,
    _parse_lldp_hex_block,
    _parse_zyxel_lldp,
    _curl_get,
    _curl_head,
    _ping,
    _arp_lookup,
    probe_http_get,
    probe_http_head,
    probe_hnap,
    probe_ssh,
    _ensure_route,
    identify_router,
)


def _completed(returncode=0, stdout="", stderr=""):
    return CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class TestNormalizeMac:
    def test_uppercases(self):
        assert _normalize_mac("aa:bb:cc:dd:ee:ff") == "AA:BB:CC:DD:EE:FF"

    def test_replaces_dashes(self):
        assert _normalize_mac("AA-BB-CC-DD-EE-FF") == "AA:BB:CC:DD:EE:FF"

    def test_mixed_case_and_dashes(self):
        assert _normalize_mac("aa-bb-cc-dd-ee-ff") == "AA:BB:CC:DD:EE:FF"

    def test_already_normalized(self):
        assert _normalize_mac("AA:BB:CC:DD:EE:FF") == "AA:BB:CC:DD:EE:FF"

    def test_empty_string(self):
        assert _normalize_mac("") == ""


class TestMacPrefix:
    def test_returns_first_three_octets(self):
        assert _mac_prefix("AA:BB:CC:DD:EE:FF") == "AA:BB:CC"

    def test_handles_dashes(self):
        assert _mac_prefix("aa-bb-cc-dd-ee-ff") == "AA:BB:CC"

    def test_lowercase_input(self):
        assert _mac_prefix("aa:bb:cc:dd:ee:ff") == "AA:BB:CC"


class TestAddEvidence:
    def test_appends_formatted_message(self):
        r = DetectedRouter(ip="1.2.3.4", mac="AA:BB:CC:DD:EE:FF")
        _add_evidence(r, "probe", "found device")
        assert r.evidence == ["[probe] found device"]

    def test_appends_multiple(self):
        r = DetectedRouter(ip="1.2.3.4", mac="AA:BB:CC:DD:EE:FF")
        _add_evidence(r, "a", "first")
        _add_evidence(r, "b", "second")
        assert len(r.evidence) == 2
        assert r.evidence[0] == "[a] first"
        assert r.evidence[1] == "[b] second"


class TestClassifyHttpResponse:
    def test_uboot_firmware_update(self):
        assert classify_http_response("FIRMWARE UPDATE page", "") == "uboot"

    def test_uboot_uip(self):
        assert classify_http_response("uIP HTTP server", "") == "uboot"

    def test_openwrt_luci(self):
        assert classify_http_response("OpenWrt LuCI interface", "") == "openwrt"

    def test_glinet_stock(self):
        assert classify_http_response("GL-iNet admin panel", "") == "glinet_stock"

    def test_linksys_stock(self):
        assert classify_http_response("Linksys JNAP API", "") == "linksys_stock"

    def test_dlink_stock_hnap(self):
        assert classify_http_response("HNAP device info", "") == "dlink_stock"

    def test_dlink_stock_covr(self):
        assert classify_http_response("COVR mesh system", "") == "dlink_stock"

    def test_zyxel_stock_dispatcher(self):
        assert classify_http_response("dispatcher.cgi endpoint", "") == "zyxel_stock"

    def test_zyxel_stock_intelligent_switch(self):
        assert classify_http_response("Intelligent Switch management", "") == "zyxel_stock"

    def test_unknown_html(self):
        assert classify_http_response("<html><body>Hello</body></html>", "") == "unknown_http"

    def test_unknown_doctype(self):
        assert classify_http_response("<!DOCTYPE html><html></html>", "") == "unknown_http"

    def test_unknown_empty(self):
        assert classify_http_response("", "") == "unknown"

    def test_matches_in_headers(self):
        assert classify_http_response("", "Server: LuCI OpenWrt") == "openwrt"


class TestClassifyWebUI:
    def test_dlink_hnap(self):
        data = {"hnap": {"detected": True}, "http_get": {"body": ""}, "http_head": {"headers": ""}}
        assert classify_web_ui(data) == "dlink_hnap"

    def test_openwrt_luci(self):
        data = {"hnap": {}, "http_get": {"body": "LuCI interface"}, "http_head": {"headers": ""}}
        assert classify_web_ui(data) == "openwrt_luci"

    def test_glinet_admin(self):
        data = {"hnap": {}, "http_get": {"body": "GL-iNet admin"}, "http_head": {"headers": ""}}
        assert classify_web_ui(data) == "glinet_admin"

    def test_linksys(self):
        data = {"hnap": {}, "http_get": {"body": "Linksys router"}, "http_head": {"headers": ""}}
        assert classify_web_ui(data) == "linksys"

    def test_uboot(self):
        data = {"hnap": {}, "http_get": {"body": "FIRMWARE UPDATE"}, "http_head": {"headers": ""}}
        assert classify_web_ui(data) == "uboot"

    def test_zyxel_stock_dispatcher_with_hydra(self):
        data = {
            "hnap": {},
            "http_get": {"body": "dispatcher.cgi"},
            "http_head": {"headers": "Server: Hydra httpd"},
        }
        assert classify_web_ui(data) == "zyxel_stock"

    def test_zyxel_stock_intelligent_switch(self):
        data = {"hnap": {}, "http_get": {"body": "Intelligent Switch"}, "http_head": {"headers": ""}}
        assert classify_web_ui(data) == "zyxel_stock"

    def test_none_when_empty(self):
        data = {"hnap": {}, "http_get": {"body": ""}, "http_head": {"headers": ""}}
        assert classify_web_ui(data) == "none"

    def test_unknown_when_body_but_no_match(self):
        data = {"hnap": {}, "http_get": {"body": "random content"}, "http_head": {"headers": ""}}
        assert classify_web_ui(data) == "unknown"


class TestMatchModelByBoard:
    @patch("model_match.list_models")
    def test_exact_device_match(self, mock_list):
        mock_list.return_value = [{"id": "zyxel-gs1900-8hp-v1", "openwrt": {"device": "zyxel,gs1900-8hp"}}]
        board_json = '{"model": {"id": "zyxel,gs1900-8hp"}}'
        result = match_model_by_board(board_json)
        assert result is not None
        assert result["id"] == "zyxel-gs1900-8hp-v1"

    @patch("model_match.list_models")
    def test_substring_device_match(self, mock_list):
        mock_list.return_value = [{"id": "test", "openwrt": {"device": "vendor,big-model-name"}}]
        board_json = '{"model": {"id": "big-model-name"}}'
        result = match_model_by_board(board_json)
        assert result is not None
        assert result["id"] == "test"

    @patch("model_match.list_models")
    def test_no_match(self, mock_list):
        mock_list.return_value = [{"id": "other", "openwrt": {"device": "vendor,other"}}]
        board_json = '{"model": {"id": "vendor,unknown"}}'
        assert match_model_by_board(board_json) is None

    def test_empty_string(self):
        assert match_model_by_board("") is None

    def test_invalid_json(self):
        assert match_model_by_board("not json") is None

    @patch("model_match.list_models")
    def test_missing_model_key(self, mock_list):
        mock_list.return_value = []
        assert match_model_by_board('{"other": "data"}') is None


class TestMatchModelByHttp:
    @patch("model_match.list_models")
    def test_http_title_match(self, mock_list):
        mock_list.return_value = [{
            "id": "dlink-covr",
            "signatures": {"recovery": {"http_title": "D-Link"}},
            "vendor": "d-link",
        }]
        result = match_model_by_http("D-Link Router Page", "")
        assert len(result) == 1
        assert result[0]["id"] == "dlink-covr"

    @patch("model_match.list_models")
    def test_vendor_match_dlink(self, mock_list):
        mock_list.return_value = [{
            "id": "dlink-foo",
            "signatures": {},
            "vendor": "d-link",
        }]
        result = match_model_by_http("Welcome to D-Link", "")
        assert len(result) == 1

    @patch("model_match.list_models")
    def test_vendor_match_glinet(self, mock_list):
        mock_list.return_value = [{
            "id": "glinet-foo",
            "signatures": {},
            "vendor": "gl-inet",
        }]
        result = match_model_by_http("GL-iNet device", "")
        assert len(result) == 1

    @patch("model_match.list_models")
    def test_vendor_match_linksys(self, mock_list):
        mock_list.return_value = [{
            "id": "linksys-foo",
            "signatures": {},
            "vendor": "linksys",
        }]
        result = match_model_by_http("Linksys smart wifi", "")
        assert len(result) == 1

    @patch("model_match.list_models")
    def test_no_match(self, mock_list):
        mock_list.return_value = [{"id": "x", "signatures": {}, "vendor": "unknown-vendor"}]
        result = match_model_by_http("generic page", "")
        assert result == []


class TestMatchModelByLldp:
    @patch("model_match.list_models")
    def test_matches_description_keyword(self, mock_list):
        mock_list.return_value = [{"id": "zyxel-gs1900", "description": "ZyXEL GS1900-8HP Switch"}]
        info = LLDPInfo(system_description="GS1900-8HP Ethernet Switch")
        result = match_model_by_lldp(info)
        assert len(result) == 1
        assert result[0]["id"] == "zyxel-gs1900"

    @patch("model_match.list_models")
    def test_matches_without_hyphen(self, mock_list):
        mock_list.return_value = [{"id": "zyxel-gs1900", "description": "ZyXEL GS1900-8HP"}]
        info = LLDPInfo(system_description="GS19008HP device")
        result = match_model_by_lldp(info)
        assert len(result) == 1

    @patch("model_match.list_models")
    def test_no_match(self, mock_list):
        mock_list.return_value = [{"id": "x", "description": "Other Device"}]
        info = LLDPInfo(system_description="completely different")
        assert match_model_by_lldp(info) == []


class TestAssessReadiness:
    def test_openwrt_ready(self):
        r = DetectedRouter(ip="1.2.3.4", mac="AA:BB:CC:DD:EE:FF", firmware_state="openwrt")
        result = assess_readiness(r)
        assert result["ready"] is True

    def test_no_model_id(self):
        r = DetectedRouter(ip="1.2.3.4", mac="AA:BB:CC:DD:EE:FF", firmware_state="zyxel_stock", model_id="")
        result = assess_readiness(r)
        assert result["ready"] is False
        assert any("not identified" in i for i in result["issues"])

    @patch("router_classify.load_model", side_effect=FileNotFoundError)
    def test_model_not_found(self, mock_load):
        r = DetectedRouter(ip="1.2.3.4", mac="AA:BB:CC:DD:EE:FF", firmware_state="zyxel_stock", model_id="missing")
        result = assess_readiness(r)
        assert result["ready"] is False
        assert any("No model definition" in i for i in result["issues"])

    @patch("router_classify.load_model", return_value={"flash_methods": {}})
    def test_no_flash_methods(self, mock_load):
        r = DetectedRouter(ip="1.2.3.4", mac="AA:BB:CC:DD:EE:FF", firmware_state="zyxel_stock", model_id="test")
        result = assess_readiness(r)
        assert result["ready"] is False
        assert any("No flash methods" in i for i in result["issues"])

    @patch("router_classify.load_model", return_value={
        "flash_methods": {"oem-http": {"default_password": "1234"}},
        "stock_default_creds": {"username": "admin", "password": "1234"},
    })
    def test_zyxel_stock_with_creds(self, mock_load):
        r = DetectedRouter(
            ip="1.2.3.4", mac="AA:BB:CC:DD:EE:FF",
            firmware_state="zyxel_stock", model_id="test",
            web_ui_type="zyxel_stock",
        )
        result = assess_readiness(r)
        assert result["ready"] is True
        assert result["flash_method"] == "oem-http"

    @patch("router_classify.load_model", return_value={"flash_methods": {"sysupgrade": {}}})
    def test_ssh_available(self, mock_load):
        r = DetectedRouter(
            ip="1.2.3.4", mac="AA:BB:CC:DD:EE:FF",
            firmware_state="unknown", model_id="test",
            ssh_available=True,
        )
        result = assess_readiness(r)
        assert result["ready"] is True
        assert result["flash_method"] == "sysupgrade"

    @patch("router_classify.load_model", return_value={
        "flash_methods": {"oem-http": {}},
        "safety": {"serial_number_warning": "check serial first"},
    })
    def test_serial_warning(self, mock_load):
        r = DetectedRouter(ip="1.2.3.4", mac="AA:BB:CC:DD:EE:FF", firmware_state="zyxel_stock", model_id="test")
        result = assess_readiness(r)
        assert any("check serial" in w for w in result["warnings"])
        assert result.get("serial_check_required") is True

    @patch("router_classify.load_model", return_value={
        "flash_methods": {"oem-http": {}},
        "safety": {"serial_number_warning": "check serial"},
    })
    def test_old_firmware_version_issue(self, mock_load):
        r = DetectedRouter(
            ip="1.2.3.4", mac="AA:BB:CC:DD:EE:FF",
            firmware_state="zyxel_stock", model_id="test",
            stock_firmware_version="V2.00(AAHI.2)",
        )
        result = assess_readiness(r)
        assert any("below recommended" in i for i in result["issues"])

    @patch("router_classify.load_model", return_value={
        "flash_methods": {"oem-http": {}},
        "safety": {"serial_number_warning": "check serial"},
    })
    def test_new_firmware_version_no_issue(self, mock_load):
        r = DetectedRouter(
            ip="1.2.3.4", mac="AA:BB:CC:DD:EE:FF",
            firmware_state="zyxel_stock", model_id="test",
            stock_firmware_version="V2.90(AAHI.1)",
        )
        result = assess_readiness(r)
        assert not any("below recommended" in i for i in result["issues"])


class TestParseZyxelLldp:
    def test_subtype2_device_model(self):
        info = LLDPInfo()
        _parse_zyxel_lldp(info, 2, b"\x08GS1900-8")
        assert info.vendor_specific["zyxel_device"] == "GS1900-8"

    def test_subtype3_firmware(self):
        info = LLDPInfo()
        _parse_zyxel_lldp(info, 3, b"\x0aV2.90(AAHI.1)")
        assert info.vendor_specific["zyxel_firmware"] == "V2.90(AAHI.1)"

    def test_subtype4_serial(self):
        info = LLDPInfo()
        _parse_zyxel_lldp(info, 4, b"\x06S12345")
        assert info.vendor_specific["zyxel_serial"] == "S12345"

    def test_subtype5_management_url(self):
        info = LLDPInfo()
        _parse_zyxel_lldp(info, 5, b"\x10http://192.168.1.1")
        assert info.management_url == "http://192.168.1.1"
        assert info.vendor_specific["zyxel_mgmt_url"] == "http://192.168.1.1"

    def test_unknown_subtype(self):
        info = LLDPInfo()
        _parse_zyxel_lldp(info, 9, b"\x04data")
        assert "zyxel_sub9" in info.vendor_specific

    def test_single_byte_payload_still_sets(self):
        info = LLDPInfo()
        _parse_zyxel_lldp(info, 2, b"\x05")
        assert "zyxel_device" in info.vendor_specific


class TestParseLldpHexBlock:
    def test_too_short_returns_none(self):
        assert _parse_lldp_hex_block("") is None

    def test_wrong_eth_dst_returns_none(self):
        hex_lines = "0: 0000 0000 0000 0000 0000 0000 88cc 0100"
        assert _parse_lldp_hex_block(hex_lines) is None

    def test_valid_lldp_chassis_id(self):
        # dst=01:80:c2:00:00:0e, src=a0:c5:e0:00:01:02, ethertype=88cc
        # TLV1: type=1(len=7), header=0x0207, value: subtype=04 + MAC a0c5e0000102
        # End: 0x0000
        block = (
            "0x0000:  0180 c200 000e a0c5 e000 0102 88cc 0207 \n"
            "0x0010:  04a0 c5e0 0001 0200 00"
        )
        result = _parse_lldp_hex_block(block)
        assert result is not None
        assert result.chassis_mac == "A0:C5:E0:00:01:02"

    def test_valid_lldp_management_ip(self):
        # Chassis ID TLV (type=1, len=7) + Management Address TLV (type=8, len=12)
        # Mgmt TLV: header=0x100c, value: addr_strlen=05, subtype=01(IPv4), ip=c0a80101(192.168.1.1)
        block = (
            "0x0000:  0180 c200 000e 0000 0000 0001 88cc 0207 \n"
            "0x0010:  0400 0000 0000 0110 0c05 01c0 a801 0100 \n"
            "0x0020:  0000 0000 0000 00"
        )
        result = _parse_lldp_hex_block(block)
        assert result is not None
        assert result.management_ip == "192.168.1.1"

    def test_system_name_tlv(self):
        # Chassis ID TLV + System Name TLV (type=5, len=5, "zyxel")
        # SysName header: (5 << 9) | 5 = 0x0a05
        block = (
            "0x0000:  0180 c200 000e 0000 0000 0001 88cc 0207 \n"
            "0x0010:  0400 0000 0000 010a 057a 7978 656c 0000 \n"
            "0x0020:  00"
        )
        result = _parse_lldp_hex_block(block)
        assert result is not None
        assert result.chassis_name == "zyxel"


class TestCurlGet:
    @patch("probe_utils.subprocess.run")
    def test_success(self, mock_run):
        mock_run.return_value = _completed(0, stdout="<html>body</html>", stderr="")
        rc, body, err = _curl_get("http://1.2.3.4/")
        assert rc == 0
        assert body == "<html>body</html>"

    @patch("probe_utils.subprocess.run", side_effect=FileNotFoundError)
    def test_curl_missing(self, mock_run):
        rc, body, err = _curl_get("http://1.2.3.4/")
        assert rc == -1
        assert err == "curl failed"


class TestCurlHead:
    @patch("probe_utils.subprocess.run")
    def test_success(self, mock_run):
        mock_run.return_value = _completed(0, stdout="HTTP/1.1 200 OK\r\nServer: LuCI\r\n", stderr="")
        rc, headers, err = _curl_head("http://1.2.3.4/")
        assert rc == 0
        assert "LuCI" in headers

    @patch("probe_utils.subprocess.run", side_effect=FileNotFoundError)
    def test_curl_missing(self, mock_run):
        rc, headers, err = _curl_head("http://1.2.3.4/")
        assert rc == -1
        assert err == "curl head failed"


class TestPing:
    @patch("probe_utils.subprocess.run")
    @patch("probe_utils.detect_platform", return_value="darwin")
    def test_success_darwin(self, mock_plat, mock_run):
        mock_run.return_value = _completed(0)
        assert _ping("1.2.3.4") is True

    @patch("probe_utils.subprocess.run")
    @patch("probe_utils.detect_platform", return_value="linux")
    def test_success_linux(self, mock_plat, mock_run):
        mock_run.return_value = _completed(0)
        assert _ping("1.2.3.4") is True

    @patch("probe_utils.subprocess.run", return_value=_completed(1))
    @patch("probe_utils.detect_platform", return_value="darwin")
    def test_failure(self, mock_plat, mock_run):
        assert _ping("1.2.3.4") is False

    @patch("probe_utils.subprocess.run", side_effect=FileNotFoundError)
    @patch("probe_utils.detect_platform", return_value="darwin")
    def test_exception(self, mock_plat, mock_run):
        assert _ping("1.2.3.4") is False


class TestArpLookup:
    @patch("auto_detect.subprocess.run")
    @patch("auto_detect.detect_platform", return_value="darwin")
    def test_found(self, mock_plat, mock_run):
        mock_run.return_value = _completed(stdout="? (192.168.1.1) at AA:BB:CC:DD:EE:FF on en0")
        assert _arp_lookup("192.168.1.1") == "AA:BB:CC:DD:EE:FF"

    @patch("auto_detect.subprocess.run")
    @patch("auto_detect.detect_platform", return_value="darwin")
    def test_not_found(self, mock_plat, mock_run):
        mock_run.return_value = _completed(stdout="? (192.168.1.1) at (incomplete)")
        assert _arp_lookup("192.168.1.1") == ""

    @patch("auto_detect.subprocess.run", side_effect=FileNotFoundError("fail"))
    @patch("auto_detect.detect_platform", return_value="darwin")
    def test_exception(self, mock_plat, mock_run):
        assert _arp_lookup("1.2.3.4") == ""


class TestProbeHttpGet:
    @patch("auto_detect._curl_get", return_value=(0, "body", ""))
    def test_success(self, mock_get):
        result = probe_http_get("1.2.3.4")
        assert result["success"] is True
        assert result["body"] == "body"

    @patch("auto_detect._curl_get", return_value=(-1, "", "curl failed"))
    def test_failure(self, mock_get):
        result = probe_http_get("1.2.3.4")
        assert result["success"] is False
        assert result["error"] == "curl failed"


class TestProbeHttpHead:
    @patch("auto_detect._curl_head", return_value=(0, "Server: LuCI", ""))
    def test_success(self, mock_head):
        result = probe_http_head("1.2.3.4")
        assert result["success"] is True
        assert result["headers"] == "Server: LuCI"

    @patch("auto_detect._curl_head", return_value=(-1, "", "fail"))
    def test_failure(self, mock_head):
        result = probe_http_head("1.2.3.4")
        assert result["success"] is False


class TestProbeHnap:
    @patch("auto_detect.subprocess.run")
    def test_hnap_detected(self, mock_run):
        mock_run.return_value = _completed(0, stdout="<HNAP>GetDeviceSettings</HNAP>")
        result = probe_hnap("1.2.3.4")
        assert result["success"] is True
        assert result["detected"] is True

    @patch("auto_detect.subprocess.run")
    def test_no_hnap(self, mock_run):
        mock_run.return_value = _completed(0, stdout="<html>nothing</html>")
        result = probe_hnap("1.2.3.4")
        assert result["detected"] is False

    @patch("auto_detect.subprocess.run", side_effect=FileNotFoundError)
    def test_exception(self, mock_run):
        result = probe_hnap("1.2.3.4")
        assert result["success"] is False


class TestProbeSsh:
    @patch("auto_detect.run_ssh")
    @patch("auto_detect.socket.socket")
    def test_ssh_available_with_board(self, mock_socket_cls, mock_run_ssh):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenWrt dropbear\r\n"
        mock_socket_cls.return_value = mock_sock
        board_json = '{"model": {"id": "zyxel,gs1900-8hp"}}'
        mock_run_ssh.side_effect = [
            _completed(0, stdout=board_json),
            _completed(1, stdout=""),
        ]
        result = probe_ssh("1.2.3.4")
        assert result["available"] is True
        assert result["board_json"] == board_json

    @patch("auto_detect.socket.socket")
    def test_connection_refused(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError
        mock_socket_cls.return_value = mock_sock
        result = probe_ssh("1.2.3.4")
        assert result["available"] is False


class TestEnsureRoute:
    @patch("auto_detect.subprocess.run")
    @patch("auto_detect.detect_platform", return_value="darwin")
    @patch("auto_detect.is_root", return_value=True)
    def test_route_exists_darwin(self, mock_root, mock_plat, mock_run):
        mock_run.return_value = _completed(0, stdout="192.168.1.0/24 via 192.168.1.2")
        assert _ensure_route("192.168.1.1", "en0") is True

    @patch("auto_detect.subprocess.run")
    @patch("auto_detect.detect_platform", return_value="linux")
    def test_route_exists_linux(self, mock_plat, mock_run):
        mock_run.return_value = _completed(0, stdout="192.168.1.0/24 dev eth0")
        assert _ensure_route("192.168.1.1", "eth0") is True

    @patch("auto_detect.configure_interface_ip", return_value=True)
    @patch("auto_detect.subprocess.run")
    @patch("auto_detect.detect_platform", return_value="linux")
    def test_adds_route_linux(self, mock_plat, mock_run, mock_cfg):
        mock_run.return_value = _completed(0, stdout="")
        assert _ensure_route("192.168.1.1", "eth0") is True
        mock_cfg.assert_called_once()


class TestIdentifyRouter:
    @patch("auto_detect.match_model_by_lldp", return_value=[])
    @patch("auto_detect.match_model_by_http", return_value=[])
    @patch("auto_detect.match_models_by_oui", return_value=[])
    @patch("auto_detect.lookup_mac_vendor", return_value="ZyXEL")
    @patch("auto_detect._arp_lookup", return_value="")
    def test_basic_identification(self, mock_arp, mock_vendor, mock_oui, mock_http, mock_lldp):
        probe_data = {
            "ip": "192.168.1.1",
            "http_get": {"body": "LuCI OpenWrt", "error": ""},
            "http_head": {"headers": "Server: LuCI", "error": ""},
            "ssh": {"available": False, "info": {}, "board_json": ""},
            "hnap": {},
        }
        passive_data = {
            "arp_hosts": [{"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:FF"}],
            "dhcp_servers": [],
        }
        router = identify_router(probe_data, passive_data)
        assert router.ip == "192.168.1.1"
        assert router.mac == "AA:BB:CC:DD:EE:FF"
        assert router.vendor == "ZyXEL"
        assert router.firmware_state == "openwrt"
        assert len(router.evidence) > 0

    @patch("auto_detect.match_model_by_lldp", return_value=[])
    @patch("auto_detect.match_model_by_http", return_value=[])
    @patch("auto_detect.match_models_by_oui", return_value=[])
    @patch("auto_detect.lookup_mac_vendor", return_value="")
    @patch("auto_detect._arp_lookup", return_value="aa:bb:cc:dd:ee:ff")
    def test_fallback_arp_lookup(self, mock_arp, mock_vendor, mock_oui, mock_http, mock_lldp):
        probe_data = {
            "ip": "10.0.0.1",
            "http_get": {"body": "", "error": ""},
            "http_head": {"headers": "", "error": ""},
            "ssh": {"available": False, "info": {}, "board_json": ""},
            "hnap": {},
        }
        passive_data = {"arp_hosts": [], "dhcp_servers": []}
        router = identify_router(probe_data, passive_data)
        assert router.mac == "AA:BB:CC:DD:EE:FF"

    @patch("auto_detect.match_model_by_lldp", return_value=[])
    @patch("auto_detect.match_model_by_http", return_value=[])
    @patch("auto_detect.match_models_by_oui", return_value=[])
    @patch("auto_detect.lookup_mac_vendor", return_value="")
    @patch("auto_detect._arp_lookup", return_value="")
    def test_no_mac_uses_unknown(self, mock_arp, mock_vendor, mock_oui, mock_http, mock_lldp):
        probe_data = {
            "ip": "10.0.0.1",
            "http_get": {"body": "", "error": ""},
            "http_head": {"headers": "", "error": ""},
            "ssh": {"available": False, "info": {}, "board_json": ""},
            "hnap": {},
        }
        passive_data = {"arp_hosts": [], "dhcp_servers": []}
        router = identify_router(probe_data, passive_data)
        assert router.mac == "unknown"

    @patch("auto_detect.match_model_by_lldp", return_value=[])
    @patch("auto_detect.match_model_by_http", return_value=[])
    @patch("auto_detect.match_models_by_oui", return_value=[{"id": "test-model", "description": "Test", "flash_methods": {"sysupgrade": {}}, "vendor": "TestCorp"}])
    @patch("auto_detect.lookup_mac_vendor", return_value="")
    @patch("auto_detect._arp_lookup", return_value="")
    def test_oui_model_match(self, mock_arp, mock_vendor, mock_oui, mock_http, mock_lldp):
        probe_data = {
            "ip": "10.0.0.1",
            "http_get": {"body": "", "error": ""},
            "http_head": {"headers": "", "error": ""},
            "ssh": {"available": False, "info": {}, "board_json": ""},
            "hnap": {},
        }
        passive_data = {"arp_hosts": [{"ip": "10.0.0.1", "mac": "AA:BB:CC:DD:EE:FF"}], "dhcp_servers": []}
        router = identify_router(probe_data, passive_data)
        assert router.model_id == "test-model"
        assert router.confidence == "possible"
