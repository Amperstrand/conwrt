"""Flow-layer tests for the D-Link HNAP recovery path (#794 top-priority pair).

The protocol primitives (AES/HMAC/SOAP/headers) are pinned by
test_hnap_protocol.py; this suite pins the ORCHESTRATION the #91-class
recovery actually rides on: the 3-step challenge-response login, its
cookie fallbacks, the retry ladder, and the upload+validation sequence
with its deliberately-trigger-not-verify semantics. The wire is faked
at the _hnap_post/urlopen seams (unit tests never touch the wire).
"""
from __future__ import annotations

import importlib.util
import io
import sys
import urllib.error
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

spec = importlib.util.spec_from_file_location("hnap", Path(__file__).resolve().parents[1] / "scripts" / "flash" / "hnap.py")
hnap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hnap)

HNAP_NS = "http://purenetworks.com/HNAP1/"


def soap(inner: str) -> bytes:
    return hnap._build_soap_body(inner).replace(b"<Login ", b'<Login xmlns="%s">' % HNAP_NS.encode())


def login_challenge_body(*, cookie_xml: str = "COOKIE123", public_key: str = "PUBKEY01",
                         challenge: str = "CHALLENGE01") -> bytes:
    return (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<LoginResponse xmlns="{HNAP_NS}">'
        f"<LoginResult>OK</LoginResult>"
        f"<Challenge>{challenge}</Challenge>"
        f"<PublicKey>{public_key}</PublicKey>"
        f"<Cookie>{cookie_xml}</Cookie>"
        f"</LoginResponse>"
    ).encode()


def login_final_body(result: str = "SUCCESS") -> bytes:
    return (
        f'<LoginResponse xmlns="{HNAP_NS}">'
        f"<LoginResult>{result}</LoginResult></LoginResponse>"
    ).encode()


class FakePost:
    """Scripted _hnap_post: returns queued (status, body, headers) per call,
    records every request for assertions."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[dict] = []

    def __call__(self, base_url, body, soap_action, **kw):
        self.calls.append({"url": base_url, "soap_action": soap_action, "kw": kw})
        status, resp_body, resp_headers = self.responses.pop(0)
        return status, resp_body, resp_headers


@pytest.fixture()
def profile(tmp_path):
    image = tmp_path / "fw.bin"
    image.write_bytes(b"\xA5" * 2048)
    return SimpleNamespace(recovery_ip="192.168.0.1", default_password="dlinkpass",
                           _image=image)


class TestLogin:
    def test_happy_path_with_xml_cookie(self, monkeypatch):
        fake = FakePost([(200, login_challenge_body(), {}),
                         (200, login_final_body(), {})])
        monkeypatch.setattr(hnap, "_hnap_post", fake)
        key, cookie = hnap._hnap_login("http://x/HNAP1/", f"{HNAP_NS}Login", "pw")
        assert cookie == "uid=COOKIE123"
        # independent reference for the key derivation
        import hashlib
        want = hmac_new("PUBKEY01pw", "CHALLENGE01").upper()
        assert key == want
        # challenge-request uses the withoutloginkey literal; final uses the key
        assert fake.calls[0]["kw"].get("private_key") == "withoutloginkey"
        assert fake.calls[1]["kw"].get("private_key") == key

    def test_cookie_fallback_to_set_cookie_header(self, monkeypatch):
        fake = FakePost([(200, login_challenge_body(cookie_xml=""), {}),
                         (200, login_final_body(), {})])
        fake.responses[0] = (200, login_challenge_body(cookie_xml=""),
                             {"set-cookie": "uid=HDR456; path=/; HttpOnly"})
        monkeypatch.setattr(hnap, "_hnap_post", fake)
        _, cookie = hnap._hnap_login("http://x/HNAP1/", f"{HNAP_NS}Login", "pw")
        assert cookie == "uid=HDR456"

    def test_cookie_fallback_to_any_header(self, monkeypatch):
        fake = FakePost([(200, login_challenge_body(cookie_xml=""),
                          {"x-junk": "something; uid=ANY789"}),
                         (200, login_final_body(), {})])
        monkeypatch.setattr(hnap, "_hnap_post", fake)
        _, cookie = hnap._hnap_login("http://x/HNAP1/", f"{HNAP_NS}Login", "pw")
        assert cookie == "uid=ANY789"

    @pytest.mark.parametrize("challenge,pub", [("", "P"), ("C", "")])
    def test_missing_challenge_material(self, monkeypatch, challenge, pub):
        fake = FakePost([(200, login_challenge_body(challenge=challenge,
                                                     public_key=pub), {})])
        monkeypatch.setattr(hnap, "_hnap_post", fake)
        assert hnap._hnap_login("http://x/HNAP1/", f"{HNAP_NS}Login", "pw") is None

    def test_non_200_login_request(self, monkeypatch):
        monkeypatch.setattr(hnap, "_hnap_post", FakePost([(401, b"", {})]))
        assert hnap._hnap_login("http://x/HNAP1/", f"{HNAP_NS}Login", "pw") is None

    def test_login_result_rejected(self, monkeypatch):
        fake = FakePost([(200, login_challenge_body(), {}),
                         (200, login_final_body(result="FAILED"), {})])
        monkeypatch.setattr(hnap, "_hnap_post", fake)
        assert hnap._hnap_login("http://x/HNAP1/", f"{HNAP_NS}Login", "pw") is None


def hmac_new(key: str, msg: str) -> str:
    import hashlib, hmac as _h
    return _h.new(key.encode(), msg.encode(), hashlib.md5).hexdigest()


class TestFlashOrchestration:
    def make_login_ok(self, monkeypatch):
        fake = FakePost([(200, login_challenge_body(), {}),
                         (200, login_final_body(), {}),
                         # the validation POST (step 5) goes through _hnap_post
                         (200, b'<GetFirmwareValidationResponse xmlns="%s">'
                               b"<IsValid>true</IsValid><CountDown>300</CountDown>"
                               b"</GetFirmwareValidationResponse>" % HNAP_NS.encode(), {})])
        monkeypatch.setattr(hnap, "_hnap_post", fake)
        return fake

    def make_urlopen(self, monkeypatch, *, status=200, body=b"<ok/>"):
        uploads = []

        class FakeResp(io.BytesIO):
            pass

        def fake_urlopen(req, timeout=None):
            uploads.append(req)
            if isinstance(status, Exception):
                raise status
            return io.BytesIO(body)

        monkeypatch.setattr(hnap.urllib.request, "urlopen", fake_urlopen)
        return uploads

    def test_no_password_short_circuits(self, profile, monkeypatch):
        profile.default_password = ""
        called = []
        monkeypatch.setattr(hnap, "_hnap_post", lambda *a, **k: called.append(1))
        ok, msg = hnap._flash_via_dlink_hnap(str(profile._image), profile)
        assert not ok and "default_password" in msg
        assert not called

    def test_auth_rejected_twice_fails(self, profile, monkeypatch):
        monkeypatch.setattr(hnap, "_hnap_post",
                            FakePost([(200, login_challenge_body(), {}),
                                      (200, login_final_body("FAILED"), {}),
                                      (200, login_challenge_body(), {}),
                                      (200, login_final_body("FAILED"), {})]))
        monkeypatch.setattr(hnap.time, "sleep", lambda s: None)
        ok, msg = hnap._flash_via_dlink_hnap(str(profile._image), profile)
        assert not ok and "auth rejected" in msg

    def test_network_error_then_success(self, profile, monkeypatch):
        fake = FakePost([
            urllib.error.URLError("refused"),           # attempt 1: network
            (200, login_challenge_body(), {}),          # attempt 2: full login
            (200, login_final_body(), {}),
            (200, b'<GetFirmwareValidationResponse xmlns="%s">'
                  b"<IsValid>true</IsValid><CountDown>60</CountDown>"
                  b"</GetFirmwareValidationResponse>" % HNAP_NS.encode(), {}),
        ])
        def raising_post(*a, **k):
            item = fake.responses.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        monkeypatch.setattr(hnap, "_hnap_post", raising_post)
        sleeps = []
        monkeypatch.setattr(hnap.time, "sleep", lambda s: sleeps.append(s))
        uploads = self.make_urlopen(monkeypatch)
        ok, _ = hnap._flash_via_dlink_hnap(str(profile._image), profile)
        assert ok
        assert sleeps == [5], "exactly one backoff between login attempts"
        assert len(uploads) == 1, "exactly one firmware upload POST"

    def test_success_matrix_upload_shape(self, profile, monkeypatch):
        fake = self.make_login_ok(monkeypatch)
        uploads = self.make_urlopen(monkeypatch)
        ok, msg = hnap._flash_via_dlink_hnap(str(profile._image), profile)
        assert ok, msg
        (req,) = uploads
        # multipart carries the image bytes and the FWFile field
        assert b"\xA5" * 2048 in req.data
        assert b'name="FWFile"' in req.data
        assert b'filename="fw.bin"' in req.data
        ctype = req.headers["Content-type"]
        assert ctype.startswith("multipart/form-data; boundary=----ConwrtBoundary")
        assert req.headers["Soapaction"] == f'"{HNAP_NS}FirmwareUpload"'
        # urllib normalizes header keys (HNAP_AUTH -> Hnap_auth)
        assert "Hnap_auth" in req.headers and "Hnap_content" in req.headers
        assert req.headers["Cookie"] == "uid=COOKIE123"
        # login took exactly 2 posts + validation took the 3rd
        assert [c["soap_action"] for c in fake.calls] == \
            [f"{HNAP_NS}Login", f"{HNAP_NS}Login", f"{HNAP_NS}GetFirmwareValidation"]

    def test_upload_http_error_fails(self, profile, monkeypatch):
        self.make_login_ok(monkeypatch)
        err = urllib.error.HTTPError("url", 500, "boom", hdrs=None, fp=io.BytesIO(b"server died"))
        self.make_urlopen(monkeypatch, status=err)
        ok, msg = hnap._flash_via_dlink_hnap(str(profile._image), profile)
        assert not ok and "HTTP 500" in msg and "server died" in msg

    def test_upload_urlerror_fails(self, profile, monkeypatch):
        self.make_login_ok(monkeypatch)
        self.make_urlopen(monkeypatch,
                          status=urllib.error.URLError("no route to host"))
        ok, msg = hnap._flash_via_dlink_hnap(str(profile._image), profile)
        assert not ok and "connection failed" in msg

    def test_validation_rejection_is_trigger_not_verify(self, profile, monkeypatch):
        """CURRENT-SEMANTICS PIN: a rejected image STILL returns True — the
        HNAP path's job is to TRIGGER upload+validation, not to verify the
        flash (the dual-image 15-20 min boot is the real verdict window;
        #91-class 'accepted-but-no-boot' is handled by the runbook's
        pcap/25-min rules, not this return value)."""
        fake = FakePost([(200, login_challenge_body(), {}),
                         (200, login_final_body(), {}),
                         (200, b'<GetFirmwareValidationResponse xmlns="%s">'
                               b"<IsValid>false</IsValid>"
                               b"</GetFirmwareValidationResponse>" % HNAP_NS.encode(), {})])
        monkeypatch.setattr(hnap, "_hnap_post", fake)
        self.make_urlopen(monkeypatch)
        ok, msg = hnap._flash_via_dlink_hnap(str(profile._image), profile)
        assert ok, "trigger-not-verify: upload happened; the verdict is downstream"
        assert "triggered" in msg

    def test_validation_non_200_is_non_fatal(self, profile, monkeypatch):
        fake = FakePost([(200, login_challenge_body(), {}),
                         (200, login_final_body(), {}),
                         (0, b"", {})])
        monkeypatch.setattr(hnap, "_hnap_post", fake)
        self.make_urlopen(monkeypatch)
        ok, _ = hnap._flash_via_dlink_hnap(str(profile._image), profile)
        assert ok
