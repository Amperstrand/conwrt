from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch


from conwrt.device_inventory import (
    _print_timeline,
    _record_inventory,
    auto_detect_interface,
)
from flash.context import Timeline


def _make_ctx(**overrides):
    from flash.context import RecoveryContext, State

    defaults = dict(
        profile=SimpleNamespace(openwrt_ip="192.168.1.1", recovery_ip="192.168.1.1", name="test-model"),
        image_path="/tmp/fw.bin",
        interface="en0",
        pcap_path="",
        sha256_before="deadbeef",
        request_hash="req123",
        cache_key="cache456",
        packages=["pkg1"],
        defaults_script="echo hello",
        password_set=False,
        auth_type="key",
        wan_ssh_enabled=False,
        wireguard_pubkey="",
        timeline=Timeline(recovery_start=100.0, ssh_available=200.0),
        state=State.COMPLETE,
    )
    defaults.update(overrides)
    return RecoveryContext(**defaults)


class TestAutoDetectInterfaceMacOS:
    @patch("conwrt.device_inventory.subprocess.run")
    def test_single_active_en_interface(self, mock_run):
        def _mock_run(cmd, **kwargs):
            r = MagicMock()
            if cmd[0] == "ifconfig" and cmd[1] == "bridge0":
                r.stdout = ""
                r.returncode = 0
                return r
            iface = cmd[1]
            if iface == "en1":
                r.stdout = "en1: flags=8863<UP,BROADCAST> mtu 1500\n\tstatus: active\n\tbase 1000baseT duplex\n"
                r.returncode = 0
            else:
                r.returncode = 1
            return r

        mock_run.side_effect = _mock_run
        result = auto_detect_interface()
        assert result == "en1"

    @patch("conwrt.device_inventory.subprocess.run")
    def test_no_active_interface_returns_none(self, mock_run):
        def _mock_run(cmd, **kwargs):
            r = MagicMock()
            if cmd[0] == "ifconfig" and cmd[1] == "bridge0":
                r.stdout = ""
                r.returncode = 0
                return r
            r.returncode = 1
            return r

        mock_run.side_effect = _mock_run
        result = auto_detect_interface()
        assert result is None

    @patch("conwrt.device_inventory.subprocess.run")
    def test_skips_bridge_member(self, mock_run):
        def _mock_run(cmd, **kwargs):
            r = MagicMock()
            if cmd[0] == "ifconfig" and cmd[1] == "bridge0":
                r.stdout = "\tmember: en1\n"
                r.returncode = 0
                return r
            iface = cmd[1]
            if iface == "en1":
                r.stdout = "en1: flags=8863<UP,BROADCAST> mtu 1500\n\tstatus: active\n\tbase 1000baseT duplex\n"
                r.returncode = 0
            else:
                r.returncode = 1
            return r

        mock_run.side_effect = _mock_run
        result = auto_detect_interface()
        assert result is None

    @patch("conwrt.device_inventory.subprocess.run")
    def test_skips_thunderbolt_mtu_16000(self, mock_run):
        def _mock_run(cmd, **kwargs):
            r = MagicMock()
            if cmd[0] == "ifconfig" and cmd[1] == "bridge0":
                r.stdout = ""
                r.returncode = 0
                return r
            iface = cmd[1]
            if iface == "en1":
                r.stdout = "en1: flags=8863<UP,BROADCAST> mtu 16000\n\tstatus: active\n\tbase 1000baseT duplex\n"
                r.returncode = 0
            else:
                r.returncode = 1
            return r

        mock_run.side_effect = _mock_run
        result = auto_detect_interface()
        assert result is None

    @patch("conwrt.device_inventory.subprocess.run")
    def test_multiple_active_returns_first(self, mock_run):
        def _mock_run(cmd, **kwargs):
            r = MagicMock()
            if cmd[0] == "ifconfig" and cmd[1] == "bridge0":
                r.stdout = ""
                r.returncode = 0
                return r
            iface = cmd[1]
            if iface in ("en1", "en2"):
                r.stdout = f"{iface}: flags=8863<UP,BROADCAST> mtu 1500\n\tstatus: active\n\tbase 1000baseT duplex\n"
                r.returncode = 0
            else:
                r.returncode = 1
            return r

        mock_run.side_effect = _mock_run
        result = auto_detect_interface()
        assert result == "en1"

    @patch("conwrt.device_inventory.subprocess.run")
    def test_skips_wifi_missing_base_duplex(self, mock_run):
        def _mock_run(cmd, **kwargs):
            r = MagicMock()
            if cmd[0] == "ifconfig" and cmd[1] == "bridge0":
                r.stdout = ""
                r.returncode = 0
                return r
            iface = cmd[1]
            if iface == "en1":
                r.stdout = "en1: flags=8863<UP,BROADCAST> mtu 1500\n\tstatus: active\n"
                r.returncode = 0
            else:
                r.returncode = 1
            return r

        mock_run.side_effect = _mock_run
        result = auto_detect_interface()
        assert result is None


class TestPrintTimeline:
    @patch("conwrt.device_inventory.log")
    @patch("conwrt.device_inventory.ts", return_value=100.0)
    @patch("conwrt.device_inventory.ts_str", side_effect=lambda t: f"T{t}")
    def test_prints_all_timeline_events(self, mock_ts_str, mock_ts, mock_log):
        tl = Timeline(
            recovery_start=100.0,
            power_off=105.0,
            link_up=110.0,
            uboot_http_first=115.0,
            upload_start=120.0,
            upload_complete=125.0,
            flash_triggered=126.0,
            flash_complete=130.0,
            first_openwrt_packet=140.0,
            ssh_available=150.0,
        )
        ctx = _make_ctx(timeline=tl)
        _print_timeline(ctx)
        logged = " ".join(str(c) for c in mock_log.call_args_list)
        assert "TOTAL TIME:        50s (0m 50s)" in logged
        assert "SHA-256" in logged

    @patch("conwrt.device_inventory.log")
    @patch("conwrt.device_inventory.ts", return_value=100.0)
    @patch("conwrt.device_inventory.ts_str", side_effect=lambda t: f"T{t}")
    def test_handles_none_events(self, mock_ts_str, mock_ts, mock_log):
        tl = Timeline(recovery_start=100.0)
        ctx = _make_ctx(timeline=tl)
        _print_timeline(ctx)
        for c in mock_log.call_args_list:
            logged_text = str(c)
            if "Power off" in logged_text or "Link up" in logged_text:
                assert "N/A" in logged_text

    @patch("conwrt.device_inventory.os.path.isfile", return_value=True)
    @patch("conwrt.device_inventory.os.path.getsize", return_value=10240)
    @patch("conwrt.device_inventory.log")
    @patch("conwrt.device_inventory.ts", return_value=100.0)
    @patch("conwrt.device_inventory.ts_str", side_effect=lambda t: f"T{t}")
    def test_prints_pcap_info_when_exists(self, mock_ts_str, mock_ts, mock_log, mock_getsize, mock_isfile):
        tl = Timeline(recovery_start=100.0)
        ctx = _make_ctx(timeline=tl, pcap_path="/tmp/capture.pcap")
        _print_timeline(ctx)
        pcap_logged = any("Pcap" in str(c) for c in mock_log.call_args_list)
        assert pcap_logged


class TestRecordInventory:
    @patch("conwrt.device_inventory._append_to_inventory")
    @patch("conwrt.device_inventory.save_fingerprint", return_value=Path("/tmp/fp.json"))
    @patch("conwrt.device_inventory.load_model", return_value={"openwrt": {"target": "mediatek/filogic"}})
    @patch("conwrt.device_inventory._load_config")
    @patch("conwrt.device_inventory.fingerprint_router")
    @patch("conwrt.device_inventory.log")
    def test_records_basic_inventory(self, mock_log, mock_fp, mock_cfg, mock_model, mock_save, mock_append):
        mock_fp.return_value = {
            "identity": {"hostname": "test-router", "board": "test-board", "serial": "SN001", "model": "M1", "vendor": "TestVendor"},
            "firmware": {"version": "1.0", "kernel": "5.15", "DISTRIB_ID": "OpenWrt"},
            "network": {"macs": {"eth0": "aa:bb:cc:dd:ee:ff", "lo": "00:00:00:00:00:00"}},
            "security": {"ssh_fingerprint": "SHA256:abc", "ssh_key_count": 2, "wan_ssh_rules": 1, "packages_installed": 42},
            "diagnostics": {},
            "modem": {"model": "Quectel", "firmware": "V1.0", "imei": "12345", "iccid": "89123"},
        }
        mock_cfg.return_value = MagicMock(ssh_all_keys=["key1", "key2"])
        ctx = _make_ctx(
            timeline=Timeline(recovery_start=100.0, ssh_available=200.0, power_off=110.0, link_up=120.0),
        )
        _record_inventory(ctx)
        mock_append.assert_called_once()
        entry = mock_append.call_args[0][0]
        assert entry["device_serial"] == "SN001"
        assert entry["hostname"] == "test-router"
        assert entry["openwrt_target"] == "mediatek/filogic"
        assert entry["sha256_firmware"] == "deadbeef"
        assert entry["modem"]["model"] == "Quectel"
        assert "mac_eth0" not in entry["mac_addresses"]
        assert entry["mac_addresses"] == {"eth0": "aa:bb:cc:dd:ee:ff"}
        assert entry["timeline"]["total_seconds"] == 100

    @patch("conwrt.device_inventory.fingerprint_router", return_value=None)
    @patch("conwrt.device_inventory.log")
    def test_returns_early_on_no_fingerprint(self, mock_log, mock_fp):
        ctx = _make_ctx()
        _record_inventory(ctx)
        no_fp_calls = [c for c in mock_log.call_args_list if "Could not fingerprint" in str(c)]
        assert len(no_fp_calls) >= 1

    @patch("conwrt.device_inventory._append_to_inventory", side_effect=IOError("disk full"))
    @patch("conwrt.device_inventory.save_fingerprint", return_value=Path("/tmp/fp.json"))
    @patch("conwrt.device_inventory.load_model", return_value={})
    @patch("conwrt.device_inventory._load_config", return_value=MagicMock(ssh_all_keys=[]))
    @patch("conwrt.device_inventory.fingerprint_router")
    @patch("conwrt.device_inventory.log")
    def test_handles_inventory_write_failure(self, mock_log, mock_fp, mock_cfg, mock_model, mock_save, mock_append):
        mock_fp.return_value = {
            "identity": {"hostname": "h", "board": "b", "serial": "s"},
            "firmware": {},
            "network": {"macs": {}},
            "security": {},
            "diagnostics": {},
        }
        ctx = _make_ctx()
        _record_inventory(ctx)
        fail_calls = [c for c in mock_log.call_args_list if "Failed to write inventory" in str(c)]
        assert len(fail_calls) >= 1
