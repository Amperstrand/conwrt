"""Tests for router_display.py (interactive menu and router display).

Two functions:
- _print_router(router): prints a multi-section router summary
- interactive_menu(routers): handles choice-driven user interaction

Both have many conditional branches based on router attributes.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure scripts/ on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))


# ---------------------------------------------------------------------------
# Stub router dataclass mimicking DetectedRouter (only attrs router_display reads)
# ---------------------------------------------------------------------------


@dataclass
class _StubRouter:
    ip: str = "192.168.1.1"
    mac: str = "aa:bb:cc:dd:ee:ff"
    vendor: str = ""
    model_id: str = ""
    model_name: str = ""
    firmware_state: str = ""
    confidence: str = ""
    web_ui_type: str = "none"
    ssh_available: bool = False
    ssh_info: dict = field(default_factory=dict)
    dhcp_server: bool = False
    dhcp_info: dict = field(default_factory=dict)
    http_response_preview: str = ""
    http_headers: str = ""
    evidence: list = field(default_factory=list)
    flash_methods: list = field(default_factory=list)
    stock_firmware_version: str = ""
    readiness: dict = field(default_factory=dict)
    lldp_info: object = None


@dataclass
class _StubLLDP:
    chassis_name: str = ""
    chassis_mac: str = ""


# ===========================================================================
# _print_router
# ===========================================================================


class TestPrintRouterBasics:
    def test_separator_and_ip(self, capsys):
        from router_display import _print_router
        _print_router(_StubRouter(ip="10.0.0.1"))
        out = capsys.readouterr().out
        assert "Router detected at 10.0.0.1" in out
        assert "=" * 45 in out

    def test_mac_printed(self, capsys):
        from router_display import _print_router
        _print_router(_StubRouter(mac="00:11:22:33:44:55"))
        assert "MAC:        00:11:22:33:44:55" in capsys.readouterr().out

    def test_confidence_printed(self, capsys):
        from router_display import _print_router
        _print_router(_StubRouter(confidence="high"))
        assert "Confidence: high" in capsys.readouterr().out


class TestPrintRouterVendor:
    @patch("router_display.match_models_by_oui")
    def test_vendor_with_oui_match(self, mock_match, capsys):
        from router_display import _print_router
        mock_match.return_value = ["model1"]
        _print_router(_StubRouter(vendor="D-Link", mac="1C:69:7A:00:00:01"))
        assert "Vendor:     D-Link (OUI match)" in capsys.readouterr().out

    @patch("router_display.match_models_by_oui")
    def test_vendor_without_oui_match(self, mock_match, capsys):
        from router_display import _print_router
        mock_match.return_value = []
        _print_router(_StubRouter(vendor="Unknown", mac="aa:bb:cc:dd:ee:ff"))
        out = capsys.readouterr().out
        assert "Vendor:     Unknown" in out
        assert "(OUI match)" not in out

    @patch("router_display.match_models_by_oui")
    def test_no_oui_lookup_when_mac_unknown(self, mock_match, capsys):
        """If MAC is literally 'unknown', skip OUI lookup."""
        from router_display import _print_router
        _print_router(_StubRouter(vendor="X", mac="unknown"))
        mock_match.assert_not_called()

    def test_empty_vendor_skips_oui_lookup_entirely(self, capsys):
        """When vendor is empty, no OUI lookup and no suffix."""
        from router_display import _print_router
        with patch("router_display.match_models_by_oui") as m:
            _print_router(_StubRouter(vendor="", mac="aa:bb:cc:dd:ee:ff"))
            m.assert_not_called()
        out = capsys.readouterr().out
        assert "Vendor:     " in out


class TestPrintRouterModel:
    def test_with_model_id_and_name(self, capsys):
        from router_display import _print_router
        _print_router(_StubRouter(
            model_id="m1", model_name="My Model", confidence="high",
        ))
        assert "Model:      My Model (high)" in capsys.readouterr().out

    def test_with_model_id_no_name_uses_id(self, capsys):
        from router_display import _print_router
        _print_router(_StubRouter(
            model_id="m1", model_name="", confidence="medium",
        ))
        assert "Model:      m1 (medium)" in capsys.readouterr().out

    def test_no_model_id_says_not_identified(self, capsys):
        from router_display import _print_router
        _print_router(_StubRouter(model_id="", confidence="low"))
        assert "Model:      Not identified (low)" in capsys.readouterr().out


class TestPrintRouterFirmware:
    @pytest.mark.parametrize("state,label", [
        ("uboot", "U-Boot recovery mode"),
        ("openwrt", "OpenWrt"),
        ("glinet_stock", "GL.iNet stock firmware"),
        ("linksys_stock", "Linksys stock firmware"),
        ("dlink_stock", "Stock D-Link firmware"),
        ("zyxel_stock", "ZyXEL stock firmware"),
        ("unknown_http", "Unknown web interface"),
        ("unknown", "Unknown firmware state"),
    ])
    def test_known_states_get_friendly_label(self, capsys, state, label):
        from router_display import _print_router
        _print_router(_StubRouter(firmware_state=state))
        assert f"Firmware:   {label}" in capsys.readouterr().out

    def test_unknown_state_falls_back_to_raw_value(self, capsys):
        from router_display import _print_router
        _print_router(_StubRouter(firmware_state="brand-new-state"))
        assert "Firmware:   brand-new-state" in capsys.readouterr().out

    def test_stock_firmware_version_printed(self, capsys):
        from router_display import _print_router
        _print_router(_StubRouter(
            firmware_state="zyxel_stock", stock_firmware_version="V2.90",
        ))
        assert "Stock FW:   V2.90" in capsys.readouterr().out

    def test_stock_version_skipped_when_empty(self, capsys):
        from router_display import _print_router
        _print_router(_StubRouter(stock_firmware_version=""))
        assert "Stock FW:" not in capsys.readouterr().out


class TestPrintRouterSSH:
    def test_ssh_not_available(self, capsys):
        from router_display import _print_router
        _print_router(_StubRouter(ssh_available=False))
        assert "SSH:        Not available" in capsys.readouterr().out

    def test_ssh_available_without_board(self, capsys):
        from router_display import _print_router
        _print_router(_StubRouter(ssh_available=True, ssh_info={}))
        assert "SSH:        Available" in capsys.readouterr().out

    def test_ssh_available_with_board(self, capsys):
        from router_display import _print_router
        _print_router(_StubRouter(
            ssh_available=True,
            ssh_info={"model": "dlink,covr-x1860-a1"},
        ))
        out = capsys.readouterr().out
        assert "SSH:        Available (board: dlink,covr-x1860-a1)" in out

    def test_ssh_available_with_empty_board(self, capsys):
        from router_display import _print_router
        _print_router(_StubRouter(
            ssh_available=True, ssh_info={"model": ""},
        ))
        out = capsys.readouterr().out
        # Empty board does NOT add the (board: ) suffix
        assert "SSH:        Available\n" in out


class TestPrintRouterWebUI:
    @pytest.mark.parametrize("ui_type,label", [
        ("dlink_hnap", "D-Link admin panel (HNAP API detected)"),
        ("openwrt_luci", "OpenWrt LuCI web interface"),
        ("glinet_admin", "GL.iNet admin panel"),
        ("linksys", "Linksys admin panel (JNAP API)"),
        ("uboot", "U-Boot HTTP recovery page"),
        ("zyxel_stock", "ZyXEL admin panel (dispatcher.cgi)"),
        ("unknown", "Unknown web interface"),
        ("none", "No web interface detected"),
    ])
    def test_known_web_types(self, capsys, ui_type, label):
        from router_display import _print_router
        _print_router(_StubRouter(web_ui_type=ui_type))
        assert f"Web UI:     {label}" in capsys.readouterr().out

    def test_unknown_web_type_falls_back_to_raw(self, capsys):
        from router_display import _print_router
        _print_router(_StubRouter(web_ui_type="my-custom-ui"))
        assert "Web UI:     my-custom-ui" in capsys.readouterr().out


class TestPrintRouterReadiness:
    def test_no_readiness_skips_section(self, capsys):
        from router_display import _print_router
        _print_router(_StubRouter(readiness={}))
        assert "Readiness:" not in capsys.readouterr().out

    def test_ready_status(self, capsys):
        from router_display import _print_router
        _print_router(_StubRouter(readiness={"ready": True}))
        assert "Readiness:  READY" in capsys.readouterr().out

    def test_not_ready_status(self, capsys):
        from router_display import _print_router
        _print_router(_StubRouter(readiness={"ready": False}))
        assert "Readiness:  NOT READY" in capsys.readouterr().out

    def test_issues_listed(self, capsys):
        from router_display import _print_router
        _print_router(_StubRouter(readiness={
            "ready": False,
            "issues": ["No SSH key", "WiFi down"],
        }))
        out = capsys.readouterr().out
        assert "Issue:  No SSH key" in out
        assert "Issue:  WiFi down" in out

    def test_warnings_listed(self, capsys):
        from router_display import _print_router
        _print_router(_StubRouter(readiness={
            "ready": True,
            "warnings": ["Low memory", "Old firmware"],
        }))
        out = capsys.readouterr().out
        assert "Note:   Low memory" in out
        assert "Note:   Old firmware" in out


class TestPrintRouterLLDP:
    def test_no_lldp_skips_line(self, capsys):
        from router_display import _print_router
        _print_router(_StubRouter(lldp_info=None))
        assert "LLDP:" not in capsys.readouterr().out

    def test_lldp_with_chassis_name(self, capsys):
        from router_display import _print_router
        _print_router(_StubRouter(lldp_info=_StubLLDP(
            chassis_name="switch01", chassis_mac="aa:bb:cc:dd:ee:ff",
        )))
        # chassis_name takes precedence
        assert "LLDP:       switch01" in capsys.readouterr().out

    def test_lldp_with_only_mac(self, capsys):
        from router_display import _print_router
        _print_router(_StubRouter(lldp_info=_StubLLDP(
            chassis_name="", chassis_mac="aa:bb:cc:dd:ee:ff",
        )))
        # Falls back to chassis_mac
        assert "LLDP:       aa:bb:cc:dd:ee:ff" in capsys.readouterr().out


# ===========================================================================
# interactive_menu
# ===========================================================================


class TestInteractiveMenuEmpty:
    def test_no_routers_early_return(self, capsys):
        from router_display import interactive_menu
        interactive_menu([])
        assert "No routers detected" in capsys.readouterr().out

    def test_no_routers_no_input_required(self):
        """Must NOT prompt for input when no routers."""
        from router_display import interactive_menu
        with patch("builtins.input", side_effect=AssertionError("should not prompt")):
            interactive_menu([])


class TestInteractiveMenuSingleRouter:
    @patch("builtins.input", side_effect=["q"])
    def test_quit_exits_via_sys_exit(self, _input):
        """choice 'q' -> sys.exit(0)."""
        from router_display import interactive_menu
        with pytest.raises(SystemExit) as exc:
            interactive_menu([_StubRouter()])
        assert exc.value.code == 0

    @patch("builtins.input", side_effect=["5"])
    def test_rescan_returns_normally(self, _input):
        """choice '5' returns from interactive_menu (re-scan)."""
        from router_display import interactive_menu
        # Should return without raising
        interactive_menu([_StubRouter()])

    @patch("builtins.input", side_effect=["1", "", "5"])
    def test_choice_1_prints_flash_command(self, _input, capsys):
        from router_display import interactive_menu
        interactive_menu([_StubRouter(model_id="my-model")])
        out = capsys.readouterr().out
        assert "conwrt flash" in out
        assert "--model-id my-model" in out
        assert "--request-image" in out

    @patch("builtins.input", side_effect=["1", "", "5"])
    def test_choice_1_without_model_id_omits_flag(self, _input, capsys):
        from router_display import interactive_menu
        interactive_menu([_StubRouter(model_id="")])
        out = capsys.readouterr().out
        assert "--request-image" in out
        assert "--model-id" not in out

    @patch("builtins.input", side_effect=["2", "/tmp/fw.bin", "", "5"])
    def test_choice_2_uses_image_path(self, _input, capsys):
        from router_display import interactive_menu
        interactive_menu([_StubRouter(model_id="my-model")])
        out = capsys.readouterr().out
        assert "--image /tmp/fw.bin" in out
        assert "--model-id my-model" in out

    @patch("builtins.input", side_effect=["2", "", "", "5"])
    def test_choice_2_empty_image_path_skips_command(self, _input, capsys):
        from router_display import interactive_menu
        interactive_menu([_StubRouter(model_id="my-model")])
        out = capsys.readouterr().out
        # No conwrt flash --image command should be printed
        assert "--image" not in out

    @patch("builtins.input", side_effect=["3", "", "5"])
    def test_choice_3_prints_force_uboot(self, _input, capsys):
        from router_display import interactive_menu
        interactive_menu([_StubRouter(model_id="my-model")])
        out = capsys.readouterr().out
        assert "--force-uboot" in out

    @patch("builtins.input", side_effect=["3", "", "5"])
    def test_choice_3_no_model_id_omits_flag(self, _input, capsys):
        from router_display import interactive_menu
        interactive_menu([_StubRouter(model_id="")])
        out = capsys.readouterr().out
        assert "--force-uboot" in out
        assert "--model-id" not in out

    @patch("router_display.load_model")
    @patch("builtins.input", side_effect=["3", "", "5"])
    def test_choice_3_with_model_loads_recovery_instructions(
        self, _input, mock_load, capsys,
    ):
        from router_display import interactive_menu
        mock_load.return_value = {
            "flash_methods": {
                "recovery-http": {
                    "reset_instructions": "Power off. Hold reset. Power on.",
                },
            },
        }
        interactive_menu([_StubRouter(model_id="my-model")])
        out = capsys.readouterr().out
        assert "Recovery instructions" in out
        assert "Power off" in out
        assert "Hold reset" in out
        assert "Power on" in out

    @patch("router_display.load_model")
    @patch("builtins.input", side_effect=["3", "", "5"])
    def test_choice_3_with_missing_model_swallows_error(
        self, _input, mock_load, capsys,
    ):
        from router_display import interactive_menu
        mock_load.side_effect = FileNotFoundError("model not found")
        # Must not raise
        interactive_menu([_StubRouter(model_id="missing-model")])
        out = capsys.readouterr().out
        # Still prints the basic force-uboot command
        assert "--force-uboot" in out

    @patch("router_display.load_model")
    @patch("builtins.input", side_effect=["3", "", "5"])
    def test_choice_3_model_without_reset_instructions(
        self, _input, mock_load, capsys,
    ):
        from router_display import interactive_menu
        mock_load.return_value = {
            "flash_methods": {
                "sysupgrade": {"description": "no reset_instructions here"},
            },
        }
        interactive_menu([_StubRouter(model_id="m1")])
        out = capsys.readouterr().out
        # No "Recovery instructions" section since no reset_instructions
        assert "Recovery instructions" not in out


class TestInteractiveMenuDetailedInfo:
    @patch("builtins.input", side_effect=["4", "", "5"])
    def test_choice_4_prints_all_details(self, _input, capsys):
        from router_display import interactive_menu
        router = _StubRouter(
            ip="192.168.5.1",
            mac="aa:bb:cc:dd:ee:ff",
            vendor="TestVendor",
            model_id="m1",
            model_name="My Model",
            firmware_state="openwrt",
            web_ui_type="openwrt_luci",
            ssh_available=True,
            ssh_info={"port": "22"},
            dhcp_server=True,
            dhcp_info={"lease_time": "12h"},
            confidence="high",
            flash_methods=["sysupgrade", "recovery-http"],
            evidence=["ev1", "ev2"],
        )
        interactive_menu([router])
        out = capsys.readouterr().out
        assert "DETAILED INFO: 192.168.5.1" in out
        assert "MAC:            aa:bb:cc:dd:ee:ff" in out
        assert "Vendor:         TestVendor" in out
        assert "Model ID:       m1" in out
        assert "Model name:     My Model" in out
        assert "Firmware state: openwrt" in out
        assert "Web UI type:    openwrt_luci" in out
        assert "SSH available:  True" in out
        assert "DHCP server:    True" in out
        assert "Flash methods:  sysupgrade, recovery-http" in out
        assert "SSH port: 22" in out
        assert "DHCP lease_time: 12h" in out
        assert "ev1" in out
        assert "ev2" in out

    @patch("builtins.input", side_effect=["4", "", "5"])
    def test_choice_4_no_model_id_shows_na(self, _input, capsys):
        from router_display import interactive_menu
        interactive_menu([_StubRouter(model_id="", model_name="")])
        out = capsys.readouterr().out
        assert "Model ID:       N/A" in out
        assert "Model name:     N/A" in out

    @patch("builtins.input", side_effect=["4", "", "5"])
    def test_choice_4_empty_flash_methods_shows_na(self, _input, capsys):
        from router_display import interactive_menu
        interactive_menu([_StubRouter(flash_methods=[])])
        assert "Flash methods:  N/A" in capsys.readouterr().out

    @patch("builtins.input", side_effect=["4", "", "5"])
    def test_choice_4_http_preview_truncated_to_300(self, _input, capsys):
        from router_display import interactive_menu
        big_html = "x" * 500
        interactive_menu([_StubRouter(http_response_preview=big_html)])
        out = capsys.readouterr().out
        assert "HTTP preview" in out
        # 300-char truncation
        assert "x" * 300 in out
        # Should NOT contain 301 x's (truncated)
        assert "x" * 301 not in out.split("HTTP preview")[1].split("HTTP headers")[0]

    @patch("builtins.input", side_effect=["4", "", "5"])
    def test_choice_4_no_http_preview_skipped(self, _input, capsys):
        from router_display import interactive_menu
        interactive_menu([_StubRouter(http_response_preview="")])
        assert "HTTP preview" not in capsys.readouterr().out

    @patch("builtins.input", side_effect=["4", "", "5"])
    def test_choice_4_http_headers_printed(self, _input, capsys):
        from router_display import interactive_menu
        interactive_menu([_StubRouter(http_headers="Server: foo")])
        out = capsys.readouterr().out
        assert "HTTP headers" in out
        assert "Server: foo" in out


class TestInteractiveMenuInvalidChoice:
    @patch("builtins.input", side_effect=["9", "5"])
    def test_invalid_choice_loops_until_valid(self, _input, capsys):
        from router_display import interactive_menu
        interactive_menu([_StubRouter()])
        out = capsys.readouterr().out
        assert "Invalid choice" in out


class TestInteractiveMenuMultiple:
    @patch("builtins.input", side_effect=["q"])
    def test_multiple_prompts_for_selection_first(self, _input, capsys):
        from router_display import interactive_menu
        # 'q' at the multi-router selection prompt returns normally (no sys.exit)
        interactive_menu([
            _StubRouter(ip="192.168.1.1"),
            _StubRouter(ip="192.168.1.2"),
        ])
        out = capsys.readouterr().out
        # Selection menu appears (multiple routers)
        assert "Select one" in out
        assert "[1]" in out
        assert "[2]" in out

    @patch("builtins.input", side_effect=["q"])
    def test_multiple_quit_at_selection(self, _input, capsys):
        from router_display import interactive_menu
        # 'q' at the selection prompt returns (not sys.exit)
        interactive_menu([
            _StubRouter(ip="192.168.1.1"),
            _StubRouter(ip="192.168.1.2"),
        ])
        # Should return cleanly without raising

    @patch("builtins.input", side_effect=["abc", "q"])
    def test_multiple_invalid_input_loops(self, _input, capsys):
        from router_display import interactive_menu
        interactive_menu([
            _StubRouter(ip="192.168.1.1"),
            _StubRouter(ip="192.168.1.2"),
        ])
        out = capsys.readouterr().out
        assert "Invalid selection" in out

    @patch("builtins.input", side_effect=["999", "q"])
    def test_multiple_out_of_range_loops(self, _input, capsys):
        from router_display import interactive_menu
        interactive_menu([
            _StubRouter(ip="192.168.1.1"),
            _StubRouter(ip="192.168.1.2"),
        ])
        out = capsys.readouterr().out
        assert "Invalid selection" in out

    @patch("builtins.input", side_effect=["1", "5"])
    def test_multiple_select_first_router(self, _input, capsys):
        from router_display import interactive_menu
        interactive_menu([
            _StubRouter(ip="192.168.1.1", model_id="m1"),
            _StubRouter(ip="192.168.1.2", model_id="m2"),
        ])
        out = capsys.readouterr().out
        # Action prompt should reference first router
        assert "192.168.1.1" in out

    @patch("builtins.input", side_effect=["2", "5"])
    def test_multiple_select_second_router(self, _input, capsys):
        from router_display import interactive_menu
        interactive_menu([
            _StubRouter(ip="192.168.1.1", model_id="m1"),
            _StubRouter(ip="192.168.1.2", model_id="m2"),
        ])
        out = capsys.readouterr().out
        # Action prompt mentions second router
        assert "192.168.1.2" in out

    @patch("builtins.input", side_effect=["1", "5"])
    def test_multiple_router_labels_show(self, _input, capsys):
        from router_display import interactive_menu
        interactive_menu([
            _StubRouter(ip="192.168.1.1", model_name="ModelA"),
            _StubRouter(ip="192.168.1.2", vendor="VendorB"),
        ])
        out = capsys.readouterr().out
        assert "ModelA" in out
        assert "VendorB" in out

    @patch("builtins.input", side_effect=["1", "5"])
    def test_multiple_router_fallback_to_mac(self, _input, capsys):
        from router_display import interactive_menu
        interactive_menu([
            _StubRouter(ip="192.168.1.1",
                        model_name="", vendor="",
                        mac="11:22:33:44:55:66"),
            _StubRouter(ip="192.168.1.2"),
        ])
        out = capsys.readouterr().out
        # Falls back to MAC when name and vendor are empty
        assert "11:22:33:44:55:66" in out
