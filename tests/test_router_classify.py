"""Tests for router_classify — firmware classification and readiness assessment."""

from unittest.mock import MagicMock, patch

import pytest

from router_classify import classify_http_response, classify_web_ui, assess_readiness


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_router(**overrides):
    """Create a mock router with sensible defaults for assess_readiness tests."""
    r = MagicMock()
    r.firmware_state = "unknown"
    r.model_id = ""
    r.model_name = ""
    r.stock_firmware_version = ""
    r.web_ui_type = ""
    r.ssh_available = False
    r.flash_methods = []
    r.ssh_info = {}
    r.dhcp_server = False
    r.dhcp_info = {}
    r.confidence = ""
    r.vendor = ""
    r.ip = "192.168.1.1"
    r.mac = "AA:BB:CC:DD:EE:FF"
    r.evidence = []
    r.http_response_preview = ""
    r.http_headers = ""
    r.readiness = {}
    r.lldp_info = None
    r.default_password = ""
    for k, v in overrides.items():
        setattr(r, k, v)
    return r


# ===================================================================
# classify_http_response tests
# ===================================================================

class TestClassifyHttpResponse:
    """Tests for classify_http_response(body, headers) -> str."""

    def test_openwrt_luci_body(self):
        assert classify_http_response("OpenWrt LuCI interface", "") == "openwrt"

    def test_dlink_stock_body(self):
        assert classify_http_response("HNAP device info page", "") == "dlink_stock"

    def test_zyxel_stock_body(self):
        assert classify_http_response("dispatcher.cgi endpoint", "") == "zyxel_stock"

    def test_uboot_body(self):
        assert classify_http_response("FIRMWARE UPDATE page", "") == "uboot"

    def test_glinet_stock_body(self):
        assert classify_http_response("GL-iNet admin panel", "") == "glinet_stock"

    def test_linksys_stock_body(self):
        assert classify_http_response("Linksys JNAP API endpoint", "") == "linksys_stock"

    def test_generic_html_returns_unknown_http(self):
        assert classify_http_response("<html><body>Hello</body></html>", "") == "unknown_http"

    def test_doctype_returns_unknown_http(self):
        assert classify_http_response("<!DOCTYPE html><html></html>", "") == "unknown_http"

    def test_empty_body_and_headers_returns_unknown(self):
        assert classify_http_response("", "") == "unknown"

    def test_match_in_headers_only(self):
        assert classify_http_response("", "Server: LuCI OpenWrt framework") == "openwrt"

    def test_first_pattern_wins_when_multiple_match(self):
        """body has both 'openwrt' and 'dlink' — first FIRMWARE_PATTERNS match wins."""
        body = "openwrt and dlink mentioned together"
        result = classify_http_response(body, "")
        # uboot pattern comes first in FIRMWARE_PATTERNS, then openwrt
        assert result == "openwrt"

    def test_uboot_uip_pattern(self):
        assert classify_http_response("uIP HTTP server", "") == "uboot"

    def test_covr_matches_dlink(self):
        assert classify_http_response("COVR mesh system", "") == "dlink_stock"

    def test_intelligent_switch_matches_zyxel(self):
        assert classify_http_response("Intelligent Switch management", "") == "zyxel_stock"


# ===================================================================
# classify_web_ui tests
# ===================================================================

class TestClassifyWebUI:
    """Tests for classify_web_ui(probe_data) -> str."""

    def test_hnap_detected_returns_dlink_hnap(self):
        data = {
            "hnap": {"detected": True},
            "http_get": {"body": ""},
            "http_head": {"headers": ""},
        }
        assert classify_web_ui(data) == "dlink_hnap"

    def test_luci_in_body_returns_openwrt_luci(self):
        data = {
            "hnap": {},
            "http_get": {"body": "LuCI interface"},
            "http_head": {"headers": ""},
        }
        assert classify_web_ui(data) == "openwrt_luci"

    def test_glinet_in_body_returns_glinet_admin(self):
        data = {
            "hnap": {},
            "http_get": {"body": "GL-iNet admin panel"},
            "http_head": {"headers": ""},
        }
        assert classify_web_ui(data) == "glinet_admin"

    def test_linksys_jnap_returns_linksys(self):
        data = {
            "hnap": {},
            "http_get": {"body": "Linksys JNAP API"},
            "http_head": {"headers": ""},
        }
        assert classify_web_ui(data) == "linksys"

    def test_uboot_firmware_update_returns_uboot(self):
        data = {
            "hnap": {},
            "http_get": {"body": "FIRMWARE UPDATE"},
            "http_head": {"headers": ""},
        }
        assert classify_web_ui(data) == "uboot"

    def test_dispatcher_cgi_with_hydra_server_returns_zyxel_stock(self):
        data = {
            "hnap": {},
            "http_get": {"body": "dispatcher.cgi"},
            "http_head": {"headers": "Server: Hydra httpd"},
        }
        assert classify_web_ui(data) == "zyxel_stock"

    def test_dispatcher_cgi_without_hydra_returns_unknown(self):
        data = {
            "hnap": {},
            "http_get": {"body": "dispatcher.cgi"},
            "http_head": {"headers": "Server: Apache"},
        }
        assert classify_web_ui(data) == "unknown"

    def test_intelligent_switch_returns_zyxel_stock(self):
        data = {
            "hnap": {},
            "http_get": {"body": "Intelligent Switch management"},
            "http_head": {"headers": ""},
        }
        assert classify_web_ui(data) == "zyxel_stock"

    def test_nonempty_body_no_patterns_returns_unknown(self):
        data = {
            "hnap": {},
            "http_get": {"body": "random content here"},
            "http_head": {"headers": ""},
        }
        assert classify_web_ui(data) == "unknown"

    def test_empty_body_returns_none(self):
        data = {
            "hnap": {},
            "http_get": {"body": ""},
            "http_head": {"headers": ""},
        }
        assert classify_web_ui(data) == "none"

    def test_openwrt_in_headers_not_body(self):
        data = {
            "hnap": {},
            "http_get": {"body": "some page"},
            "http_head": {"headers": "Server: OpenWrt LuCI"},
        }
        assert classify_web_ui(data) == "openwrt_luci"

    def test_hnap_takes_priority_over_openwrt(self):
        """HNAP detection should win even if body has OpenWrt."""
        data = {
            "hnap": {"detected": True},
            "http_get": {"body": "OpenWrt LuCI"},
            "http_head": {"headers": ""},
        }
        assert classify_web_ui(data) == "dlink_hnap"

    def test_whitespace_only_body_returns_none(self):
        data = {
            "hnap": {},
            "http_get": {"body": "   \n\t  "},
            "http_head": {"headers": ""},
        }
        assert classify_web_ui(data) == "none"


# ===================================================================
# assess_readiness tests
# ===================================================================

class TestAssessReadiness:
    """Tests for assess_readiness(router) -> dict."""

    def test_openwrt_firmware_ready_immediately(self):
        r = _make_router(firmware_state="openwrt")
        result = assess_readiness(r)
        assert result["ready"] is True
        assert result["issues"] == []

    def test_no_model_id_not_ready(self):
        r = _make_router(firmware_state="zyxel_stock", model_id="")
        result = assess_readiness(r)
        assert result["ready"] is False
        assert any("not identified" in i for i in result["issues"])

    @patch("router_classify.load_model", side_effect=FileNotFoundError)
    def test_model_id_but_no_model_file(self, mock_load):
        r = _make_router(firmware_state="zyxel_stock", model_id="missing-model")
        result = assess_readiness(r)
        assert result["ready"] is False
        assert any("No model definition" in i for i in result["issues"])

    @patch("router_classify.load_model", return_value={"flash_methods": {}})
    def test_model_file_with_no_flash_methods(self, mock_load):
        r = _make_router(firmware_state="zyxel_stock", model_id="test-model")
        result = assess_readiness(r)
        assert result["ready"] is False
        assert any("No flash methods" in i for i in result["issues"])

    @patch("router_classify.load_model", return_value={"flash_methods": {"sysupgrade": {}}})
    def test_ssh_available_ready_sysupgrade(self, mock_load):
        r = _make_router(
            firmware_state="unknown",
            model_id="test-model",
            ssh_available=True,
        )
        result = assess_readiness(r)
        assert result["ready"] is True
        assert result["flash_method"] == "sysupgrade"

    @patch("router_classify.load_model", return_value={
        "flash_methods": {"oem-http": {"default_password": "1234"}},
        "stock_default_creds": {"username": "admin", "password": "1234"},
    })
    def test_zyxel_web_ui_with_stock_creds_ready_oem_http(self, mock_load):
        r = _make_router(
            firmware_state="zyxel_stock",
            model_id="test-model",
            web_ui_type="zyxel_stock",
        )
        result = assess_readiness(r)
        assert result["ready"] is True
        assert result["flash_method"] == "oem-http"

    @patch("router_classify.load_model", return_value={
        "flash_methods": {"oem-http": {"default_password": "1234"}},
        "stock_default_creds": {"username": "admin", "password": "1234"},
    })
    def test_default_credentials_warning(self, mock_load):
        r = _make_router(
            firmware_state="zyxel_stock",
            model_id="test-model",
            web_ui_type="zyxel_stock",
        )
        result = assess_readiness(r)
        assert result.get("default_credentials") is True
        assert any("admin/1234" in w for w in result["warnings"])

    @patch("router_classify.load_model", return_value={
        "flash_methods": {"oem-http": {}},
        "safety": {"serial_number_warning": "check serial first"},
    })
    def test_serial_number_warning(self, mock_load):
        r = _make_router(firmware_state="zyxel_stock", model_id="test-model")
        result = assess_readiness(r)
        assert any("check serial" in w for w in result["warnings"])
        assert result.get("serial_check_required") is True

    @patch("router_classify.load_model", return_value={
        "flash_methods": {"oem-http": {}},
        "safety": {"serial_number_warning": "check serial"},
    })
    def test_firmware_version_below_recommended(self, mock_load):
        r = _make_router(
            firmware_state="zyxel_stock",
            model_id="test-model",
            stock_firmware_version="V2.00(AAHI.2)",
        )
        result = assess_readiness(r)
        assert any("below recommended" in i for i in result["issues"])

    @patch("router_classify.load_model", return_value={
        "flash_methods": {"oem-http": {}},
        "safety": {"serial_number_warning": "check serial"},
    })
    def test_firmware_version_at_recommended_no_issue(self, mock_load):
        r = _make_router(
            firmware_state="zyxel_stock",
            model_id="test-model",
            stock_firmware_version="V2.90(AAHI.1)",
        )
        result = assess_readiness(r)
        assert not any("below recommended" in i for i in result["issues"])

    @patch("router_classify.load_model", return_value={
        "flash_methods": {"oem-http": {}},
        "safety": {"serial_number_warning": "check serial"},
    })
    def test_firmware_version_major_1_below_recommended(self, mock_load):
        r = _make_router(
            firmware_state="zyxel_stock",
            model_id="test-model",
            stock_firmware_version="V1.99(BETA.1)",
        )
        result = assess_readiness(r)
        assert any("below recommended" in i for i in result["issues"])

    @patch("router_classify.load_model", return_value={
        "flash_methods": {"oem-http": {}},
    })
    def test_no_issues_has_flash_methods_ready(self, mock_load):
        r = _make_router(
            firmware_state="unknown",
            model_id="test-model",
        )
        result = assess_readiness(r)
        assert result["ready"] is True
        assert result["flash_method"] == "oem-http"

    @patch("router_classify.load_model", return_value={
        "flash_methods": {"oem-http": {}},
    })
    def test_firmware_version_without_serial_warning_no_version_check(self, mock_load):
        """If no serial_number_warning, firmware version check is skipped."""
        r = _make_router(
            firmware_state="zyxel_stock",
            model_id="test-model",
            stock_firmware_version="V1.00(OLD.1)",
        )
        result = assess_readiness(r)
        # No "below recommended" issue because serial_warning is empty
        assert not any("below recommended" in i for i in result["issues"])

    @patch("router_classify.load_model", return_value={
        "flash_methods": {"recovery-http": {}},
    })
    def test_no_ssh_no_zyxel_uses_first_flash_method(self, mock_load):
        r = _make_router(
            firmware_state="unknown",
            model_id="test-model",
            ssh_available=False,
            web_ui_type="unknown_http",
        )
        result = assess_readiness(r)
        assert result["ready"] is True
        assert result["flash_method"] == "recovery-http"

    @patch("router_classify.load_model", return_value={
        "flash_methods": {"sysupgrade": {}},
    })
    def test_ssh_preferred_over_first_flash_method(self, mock_load):
        """SSH available should pick sysupgrade over other methods."""
        r = _make_router(
            firmware_state="unknown",
            model_id="test-model",
            ssh_available=True,
            web_ui_type="",
        )
        result = assess_readiness(r)
        assert result["flash_method"] == "sysupgrade"
