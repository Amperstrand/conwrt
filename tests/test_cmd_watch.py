"""Hermetic tests for conwrt watch — detection decision logic, no network."""
import argparse
import importlib
import sys
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

watch = importlib.import_module("conwrt.cmd_watch")


def _args(**overrides):
    base = dict(
        interface="enp5s0", interval=5, timeout=1, model_id=None, image=None,
        no_upload=False, loop=False, yes=False,
    )
    base.update(overrides)
    ns = argparse.Namespace(**base)
    ns._conwrt_py = Path("/fake/scripts/conwrt.py")
    return ns


class TestPrioritize:
    def test_common_gateways_first(self):
        ips = ["10.89.4.1", "192.168.1.1", "172.16.0.1", "192.168.0.1"]
        assert watch._prioritize(ips)[:2] == ["192.168.0.1", "192.168.1.1"]

    def test_all_kept(self):
        ips = ["10.0.0.1", "192.168.99.1"]
        result = watch._prioritize(ips)
        assert sorted(result) == sorted(ips)


class TestOuiMatches:
    def test_dlink_oui(self):
        model = {"mac_oui": ["BC:22:28"]}
        assert watch._oui_matches("BC:22:28:99:1D:00", model)

    def test_wrong_oui(self):
        model = {"mac_oui": ["BC:22:28"]}
        assert not watch._oui_matches("A8:63:7D:8F:61:A8", model)

    def test_unknown_mac(self):
        assert not watch._oui_matches("", {"mac_oui": ["BC:22:28"]})
        assert not watch._oui_matches("UNKNOWN", {"mac_oui": ["BC:22:28"]})


class TestPickModel:
    MODELS = [
        {"id": "asus-lyra-map-ac2200", "description": "Lyra"},
        {"id": "dlink-covr-x1860-a1", "description": "COVR-X1860 A1 mesh WiFi",
         "openwrt": {"device": "dlink,covr-x1860-a1"}, "mac_oui": ["BC:22:28"]},
    ]

    def test_board_match_wins_for_openwrt(self):
        with patch.object(watch, "_board_match", return_value=self.MODELS[1]):
            got = watch._pick_model("192.168.1.1", "openwrt", self.MODELS, "A8:63:7D:00:00:01")
        assert got["id"] == "dlink-covr-x1860-a1"

    def test_oui_tiebreak_for_recovery(self):
        models = [
            {"id": "asus-lyra-map-ac2200", "openwrt": {"default_ip": "192.168.1.1"}},
            {"id": "dlink-covr-x1860-a1", "openwrt": {"default_ip": "192.168.1.1"},
             "mac_oui": ["BC:22:28"]},
        ]
        got = watch._pick_model("192.168.1.1", "uboot", models, "BC:22:28:99:1D:00")
        assert got["id"] == "dlink-covr-x1860-a1"

    def test_no_candidates_returns_none(self):
        assert watch._pick_model("192.168.50.1", "uboot", self.MODELS, "") is None


class TestFlashCommand:
    def test_request_image_by_default(self):
        cmd = watch._flash_command("192.168.0.1", "uboot", {"id": "dlink-covr-x1860-a1"}, _args())
        assert "--request-image" in cmd
        assert "dlink-covr-x1860-a1" in cmd

    def test_model_id_override(self):
        cmd = watch._flash_command("192.168.0.1", "uboot", None, _args(model_id="glinet-mt3000"))
        assert "glinet-mt3000" in cmd

    def test_unknown_model_non_openwrt_returns_none(self):
        assert watch._flash_command("192.168.0.1", "uboot", None, _args()) is None

    def test_dry_run_flag(self):
        cmd = watch._flash_command("192.168.1.1", "openwrt", {"id": "x"}, _args(no_upload=True))
        assert "--no-upload" in cmd


class TestConfirm:
    def test_yes_flag_skips_prompt(self):
        assert watch._confirm("flash?", True) is True

    def test_non_tty_declines(self):
        with patch.object(watch.sys.stdin, "isatty", return_value=False):
            assert watch._confirm("flash?", False) is False
