"""E2E tests for eSIM provisioning on OpenWrt routers with eUICC cards.

Requires hardware: CONWRT_DEVICE_IP env var must be set.
Tests use the Speedtest Travel (BetterRoaming) profile as a zero-cost
test fixture — no credentials consumed for enable/disable cycles.

Test markers:
  @pytest.mark.hardware    — requires CONWRT_DEVICE_IP
  @pytest.mark.power_cycle — additionally requires the router to be in MBIM mode
  @pytest.mark.one_shot    — consumes a matching-id (run deliberately)

Speedtest profile test data:
  ICCID:     8944476500021393355
  Provider:  Speedtest Travel (BetterRoaming)
  APN:       truphone.com
  Carrier:   Truphone/1Global
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time

import pytest

SPEEDTEST_ICCID = "8944476500021393355"
SPEEDTEST_APN = "truphone.com"
NADANADA_ICCID = "89353082711108402322"
SILENTLINK_ICCID = "8948010010098742686"

pytestmark = pytest.mark.hardware


def _ssh(ip: str, cmd: str) -> str:
    r = subprocess.run(
        ["ssh", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=accept-new",
         f"root@{ip}", cmd],
        capture_output=True, text=True, timeout=120
    )
    return r.stdout + r.stderr


def _at(ip: str, cmd: str) -> str:
    return _ssh(ip, f'P=$(modem-at probe 2>/dev/null); modem-at run $P "{cmd}" 2>/dev/null')


def _lpac(ip: str, args: str) -> str:
    return _ssh(ip,
        f'LPAC_APDU=mbim LPAC_HTTP=curl LPAC_APDU_MBIM_UIM_SLOT=2 '
        f'/usr/bin/lpac {args} 2>&1 | grep -v WARNING')


def _in_mbim_mode(ip: str) -> bool:
    return "cdc-wdm0" in _ssh(ip, "ls /dev/cdc-wdm0 2>/dev/null && echo cdc-wdm0")


# === Phase 3 tests: MBIM mode (requires prior power-cycle into MBIM) ===

@pytest.mark.power_cycle
class TestMBIMMode:
    def test_cdc_wdm0_present(self, device_ip):
        assert _in_mbim_mode(device_ip), "cdc-wdm0 not present — not in MBIM mode"

    def test_ttyusb_ports_available(self, device_ip):
        result = _ssh(device_ip, "ls /dev/ttyUSB* 2>/dev/null | wc -l")
        assert int(result.strip()) >= 1, "no ttyUSB ports"

    def test_lpac_deployed(self, device_ip):
        result = _ssh(device_ip, "/usr/bin/lpac version 2>&1")
        assert "2.3.0" in result, f"lpac not deployed or wrong version: {result[:100]}"

    def test_kernel_module_loaded(self, device_ip):
        result = _ssh(device_ip, "lsmod | grep cdc_mbim")
        assert "cdc_mbim" in result, "cdc_mbim kernel module not loaded"


# === Phase 5 tests: MBIM gate (read-only, safe) ===

@pytest.mark.power_cycle
class TestMBIMGate:
    def test_chip_info_returns_eid(self, device_ip):
        result = _lpac(device_ip, "chip info")
        assert '"eidValue"' in result, f"chip info failed: {result[:200]}"
        eid = re.search(r'"eidValue":"([0-9a-fA-F]{32})"', result)
        assert eid, "no 32-hex EID found in chip info"

    def test_profile_list_returns_profiles(self, device_ip):
        result = _lpac(device_ip, "profile list")
        assert '"code":0' in result, f"profile list failed: {result[:200]}"
        profiles = json.loads(result.split("\n")[-1])["payload"]["data"]
        assert len(profiles) >= 2, f"expected ≥2 profiles, got {len(profiles)}"

    def test_speedtest_profile_present(self, device_ip):
        result = _lpac(device_ip, "profile list")
        assert SPEEDTEST_ICCID in result, "Speedtest profile not on card"


# === Phase 5 write tests: enable/disable cycle (zero-cost) ===

@pytest.mark.power_cycle
class TestSpeedtestCycle:
    @pytest.fixture(autouse=True)
    def restore_profile(self, device_ip):
        yield
        _lpac(device_ip, f"profile enable {SILENTLINK_ICCID}")

    def test_enable_speedtest_disables_others(self, device_ip):
        result = _lpac(device_ip, f"profile enable {SPEEDTEST_ICCID}")
        assert '"code":0' in result, f"enable failed: {result[:200]}"

    def test_state_flip_confirmed(self, device_ip):
        result = _lpac(device_ip, "profile list")
        profiles = json.loads(result.split("\n")[-1])["payload"]["data"]
        speedtest = next(p for p in profiles if p["iccid"] == SPEEDTEST_ICCID)
        assert speedtest["profileState"] == "enabled", "Speedtest not enabled after enable"

    def test_state_restored(self, device_ip):
        result = _lpac(device_ip, "profile list")
        profiles = json.loads(result.split("\n")[-1])["payload"]["data"]
        silentlink = next(p for p in profiles if p["iccid"] == SILENTLINK_ICCID)
        speedtest = next(p for p in profiles if p["iccid"] == SPEEDTEST_ICCID)
        assert silentlink["profileState"] == "enabled", "silent.link not re-enabled"
        assert speedtest["profileState"] == "disabled", "Speedtest not disabled after restore"


# === Phase 6 one-shot test: download (consumes matching-id) ===

@pytest.mark.power_cycle
@pytest.mark.one_shot
class TestProfileDownload:
    def test_download_profile(self, device_ip):
        """Downloads a profile via SM-DP+. CONSUMES the matching-id — run deliberately."""
        matching_id = os.environ.get("CONWRT_ESIM_TEST_MATCHING_ID", "")
        smdp = os.environ.get("CONWRT_ESIM_TEST_SMDP", "smdp.io")
        if not matching_id:
            pytest.skip("CONWRT_ESIM_TEST_MATCHING_ID not set — refusing to consume a credential")
        result = _lpac(device_ip, f"profile download -s {smdp} -m {matching_id}")
        assert '"code":0' in result, f"download failed: {result[:500]}"


# === Phase 7 tests: ECM mode verification ===

class TestECMDataVerification:
    def test_internet_reachable(self, device_ip):
        result = _ssh(device_ip, "ping -c 2 -W 5 8.8.8.8 2>&1")
        assert "round-trip" in result or "time=" in result, f"no internet: {result[:200]}"

    def test_https_works(self, device_ip):
        result = _ssh(device_ip, "wget -q -O- -T 15 https://api.ipify.org 2>&1")
        assert re.search(r'\d+\.\d+\.\d+\.\d+', result), "no public IP returned"

    def test_active_profile_is_silentlink(self, device_ip):
        result = _at(device_ip, "AT+QCCID")
        assert SILENTLINK_ICCID in result, f"wrong ICCID active: {result[:100]}"


# === Speedtest network exploration tests (enable → scan → probe → restore) ===

@pytest.mark.power_cycle
class TestSpeedtestNetwork:
    def test_01_enable_speedtest(self, device_ip):
        result = _lpac(device_ip, f"profile enable {SPEEDTEST_ICCID}")
        assert '"code":0' in result

    def test_02_cfun_reset_for_new_profile(self, device_ip):
        result = _at(device_ip, "AT+CFUN=1,1")
        time.sleep(60)  # modem re-detection window

    def test_03_iccid_switched(self, device_ip):
        result = _at(device_ip, "AT+QCCID")
        assert SPEEDTEST_ICCID in result, "Speedtest ICCID not active after CFUN"

    def test_04_registration_status(self, device_ip):
        result = _at(device_ip, "AT+CEREG?")
        # Speedtest may register or may not (no active data plan)
        # We just record the status — don't assert specific value
        print(f"  CEREG: {result.strip()}")

    def test_05_network_scan(self, device_ip):
        """Scan available networks (30+ second operation)."""
        result = _ssh(device_ip, '''
            P=$(modem-at probe)
            exec 8<>/dev/$P
            stty -F /dev/$P 115200 raw -echo min 0 time 60
            printf 'AT+COPS=?\r' >&8
            sleep 35
            dd bs=1 count=3000 <&8 2>/dev/null
        ''')
        print(f"  Network scan: {result.strip()[:300]}")
        # Don't assert — Speedtest may not be allowed to scan

    def test_06_set_speedtest_apn(self, device_ip):
        result = _at(device_ip, f'AT+CGDCONT=1,"IPV4V6","{SPEEDTEST_APN}"')
        # Record result, don't fail — may reject APN change without data

    def test_07_restore_silentlink(self, device_ip):
        result = _lpac(device_ip, f"profile enable {SILENTLINK_ICCID}")
        assert '"code":0' in result
        _at(device_ip, "AT+CFUN=1,1")
        time.sleep(60)

    def test_08_silentlink_restored(self, device_ip):
        result = _at(device_ip, "AT+QCCID")
        assert SILENTLINK_ICCID in result, "silent.link not restored"
