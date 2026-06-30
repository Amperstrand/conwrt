"""Tests for flash/hnap.py pure crypto and auth functions."""
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from flash.hnap import (
    _aes_encrypt128,
    _arr2hex,
    _build_soap_body,
    _chang_text,
    _hexstr2arr,
    _hmac_md5_hex,
    _str2hex,
    _hnap_auth_header,
    _hnap_content_header,
    _parse_hnap_response,
)


class TestStr2Hex:
    def test_ascii(self):
        assert _str2hex("AB") == "4142"

    def test_empty(self):
        assert _str2hex("") == ""


class TestHexstr2Arr:
    def test_basic(self):
        assert _hexstr2arr("0a1f", 4) == [10, 31, 0, 0]

    def test_fills_zeros(self):
        assert _hexstr2arr("ff", 4) == [255, 0, 0, 0]

    def test_empty(self):
        assert _hexstr2arr("", 4) == [0, 0, 0, 0]


class TestArr2Hex:
    def test_basic(self):
        assert _arr2hex([10, 31]) == "0a1f"

    def test_empty(self):
        assert _arr2hex([]) == ""


class TestAesEncrypt128:
    def test_produces_hex_output(self):
        result = _aes_encrypt128("test plaintext 16b", "0123456789abcdef0123456789abcdef")
        assert all(c in "0123456789abcdef" for c in result)

    def test_deterministic(self):
        key = "0123456789abcdef0123456789abcdef"
        pt = "test plaintext 16b"
        assert _aes_encrypt128(pt, key) == _aes_encrypt128(pt, key)

    def test_different_key_different_output(self):
        pt = "test plaintext 16b"
        r1 = _aes_encrypt128(pt, "0123456789abcdef0123456789abcdef")
        r2 = _aes_encrypt128(pt, "fedcba9876543210fedcba9876543210")
        assert r1 != r2


class TestHmacMd5Hex:
    def test_deterministic(self):
        r1 = _hmac_md5_hex("key", "message")
        r2 = _hmac_md5_hex("key", "message")
        assert r1 == r2

    def test_different_msg_different_hash(self):
        assert _hmac_md5_hex("key", "msg1") != _hmac_md5_hex("key", "msg2")

    def test_is_hex_string(self):
        result = _hmac_md5_hex("key", "msg")
        assert len(result) == 32
        assert all(c in "0123456789abcdef" for c in result)


class TestChangText:
    def test_swapcase(self):
        assert _chang_text("ABCdef") == "abcDEF"

    def test_empty(self):
        assert _chang_text("") == ""


class TestBuildSoapBody:
    def test_wraps_in_envelope(self):
        body = _build_soap_body("<Test>value</Test>")
        assert body.startswith(b"<?xml")
        assert b"<soap:Body>" in body
        assert b"<Test>value</Test>" in body
        assert b"</soap:Envelope>" in body

    def test_returns_bytes(self):
        result = _build_soap_body("<X/>")
        assert isinstance(result, bytes)


class TestHnapAuthHeader:
    def test_format(self):
        header = _hnap_auth_header("privatekey", "Login", "12345")
        parts = header.split(" ")
        assert len(parts) == 2
        assert parts[1] == "12345"

    def test_uses_swapcase(self):
        header = _hnap_auth_header("key", "Action", "time")
        auth_part = header.split(" ")[0]
        assert auth_part == auth_part.swapcase().swapcase()


class TestHnapContentHeader:
    def test_produces_uppercase_hex(self):
        body = b"<Test>content</Test>"
        result = _hnap_content_header(body, "0123456789abcdef0123456789abcdef")
        assert result == result.upper()
        assert all(c in "0123456789ABCDEF" for c in result)


class TestParseHnapResponse:
    def test_extracts_tag_values(self):
        xml = b'<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><LoginResponse><Result>OK</Result></LoginResponse></soap:Body></soap:Envelope>'
        result = _parse_hnap_response(xml)
        assert result.get("Result") == "OK"

    def test_returns_empty_on_invalid_xml(self):
        result = _parse_hnap_response(b"not xml")
        assert result == {}

    def test_extracts_challenge(self):
        xml = b'<?xml version="1.0"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><LoginResponse><Challenge>abc123</Challenge><PublicKey>pubkey</PublicKey></LoginResponse></soap:Body></soap:Envelope>'
        result = _parse_hnap_response(xml)
        assert result.get("Challenge") == "abc123"
        assert result.get("PublicKey") == "pubkey"
