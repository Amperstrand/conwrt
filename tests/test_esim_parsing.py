"""Unit tests for eSIM parsing and state machine logic (CI-safe, no hardware)."""
import pytest

from conwrt.esim import (
    parse_qeng,
    parse_cops,
    parse_qccid,
    parse_cereg,
    parse_profile_list,
    earfcn_to_band,
    signal_quality,
)

QENG_LTE_SAMPLE = (
    'AT+QENG="servingcell"\r\n'
    '+QENG: "servingcell","NOCONN","LTE","FDD",242,02,1D9DD1F,129,1650,3,5,5,AF7,-99,-10,-69,13,0,-,28\r\n'
    "OK"
)

QENG_5G_SAMPLE = (
    '+QENG: "servingcell","CONN","NR5G","TDD",242,02,1D9DD1F,129,633984,3,5,5,AF7,-95,-8,-65,18,0,-,28'
)

COPS_SAMPLE = 'AT+COPS?\r\n+COPS: 0,0,"Telia N IMSIM",13\r\nOK'
COPS_MANUAL_SAMPLE = '+COPS: 1,0,"Telenor",7'

QCCID_SAMPLE = 'AT+QCCID\r\n+QCCID: 8948010010098742686\r\nOK'

CEREG_SAMPLE = '+CEREG: 0,5'
CEREG_DENIED_SAMPLE = '+CEREG: 2,3'

PROFILE_LIST_SAMPLE = '''{"type":"lpa","payload":{"code":0,"message":"success","data":[
  {"iccid":"89353082711108402322","profileState":"enabled","serviceProviderName":"nadanada","profileNickname":"nadanada-production"},
  {"iccid":"8944476500021393355","profileState":"disabled","serviceProviderName":"Speedtest Travel","profileNickname":"speedtest-dryrun"},
  {"iccid":"8948010010098742686","profileState":"enabled","serviceProviderName":"IMSIM","profileNickname":"silentlink-production"}
]}}'''


class TestParseQENG:
    def test_lte_serving_cell(self):
        result = parse_qeng(QENG_LTE_SAMPLE)
        assert result is not None
        assert result["state"] == "NOCONN"
        assert result["tech"] == "LTE"
        assert result["duplex"] == "FDD"
        assert result["mcc"] == 242
        assert result["mnc"] == 2
        assert result["earfcn"] == 1650
        assert result["band"] == "B3 (1800MHz)"
        assert result["rsrp"] == -99
        assert result["rsrq"] == -10
        assert result["rssi"] == -69
        assert result["sinr"] == 13
        assert result["quality"] == "fair"

    def test_5g_serving_cell(self):
        result = parse_qeng(QENG_5G_SAMPLE)
        assert result is not None
        assert result["tech"] == "NR5G"
        assert result["duplex"] == "TDD"
        assert result["mcc"] == 242

    def test_no_match(self):
        assert parse_qeng("garbage") is None
        assert parse_qeng("") is None
        assert parse_qeng("ERROR") is None


class TestParseCOPS:
    def test_automatic(self):
        result = parse_cops(COPS_SAMPLE)
        assert result is not None
        assert result["mode"] == "automatic"
        assert result["operator"] == "Telia N IMSIM"

    def test_manual(self):
        result = parse_cops(COPS_MANUAL_SAMPLE)
        assert result is not None
        assert result["mode"] == "manual"
        assert result["operator"] == "Telenor"

    def test_no_match(self):
        assert parse_cops("OK") is None


class TestParseQCCID:
    def test_valid(self):
        assert parse_qccid(QCCID_SAMPLE) == "8948010010098742686"

    def test_no_match(self):
        assert parse_qccid("ERROR") is None
        assert parse_qccid("") is None


class TestParseCEREG:
    def test_registered_roaming(self):
        result = parse_cereg(CEREG_SAMPLE)
        assert result["status"] == "registered_roaming"

    def test_denied(self):
        result = parse_cereg(CEREG_DENIED_SAMPLE)
        assert result["status"] == "denied"

    def test_unknown(self):
        assert parse_cereg("garbage")["status"] == "unknown"


class TestParseProfileList:
    def test_three_profiles(self):
        profiles = parse_profile_list(PROFILE_LIST_SAMPLE)
        assert len(profiles) == 3
        assert profiles[0]["iccid"] == "89353082711108402322"
        assert profiles[0]["profileState"] == "enabled"
        assert profiles[2]["profileNickname"] == "silentlink-production"

    def test_invalid_json(self):
        assert parse_profile_list("not json") == []

    def test_empty(self):
        assert parse_profile_list('{"payload":{"data":[]}}') == []


class TestBandLookup:
    @pytest.mark.parametrize("earfcn,expected", [
        (0, "B1 (2100MHz)"),
        (599, "B1 (2100MHz)"),
        (600, "B2 (1900MHz)"),
        (1650, "B3 (1800MHz)"),
        (1950, "B4 (AWS)"),
        (2400, "B5 (850MHz)"),
        (2650, "B6 (800MHz)"),
        (3000, "B7 (2600MHz)"),
        (3450, "B8 (900MHz)"),
        (5000, "B20 (800MHz)"),
        (6200, "B28 (700MHz)"),
        (9999, "band?(9999)"),
    ])
    def test_band_mapping(self, earfcn, expected):
        assert earfcn_to_band(earfcn) == expected


class TestSignalQuality:
    @pytest.mark.parametrize("rsrp,expected", [
        (-70, "excellent"),
        (-80, "excellent"),
        (-81, "good"),
        (-90, "good"),
        (-91, "fair"),
        (-100, "fair"),
        (-101, "poor"),
        (-110, "poor"),
        (-111, "very poor"),
        (-130, "very poor"),
    ])
    def test_quality_thresholds(self, rsrp, expected):
        assert signal_quality(rsrp) == expected
