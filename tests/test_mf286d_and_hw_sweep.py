"""mf286d_flash_campaign + hardware_sweep tests (#763 P3).

mf286d: the ZTE goform primitives (the AD-gated factory-mode chain),
the Goform client against a loopback rehearsal mock, and wait_http's
polling contract — the campaign's own MockDevice is exercised as
designed (rehearsal on 127.0.0.1).

hardware_sweep: the outside-in classifier's ladder (v6 → banner →
auth → files), each layer's verdict row, and the cut-experiment
driver's step sequence — switch_ssh stubbed at the module seam, the
labgrid power calls stubbed, Place faked.
"""
from __future__ import annotations

import http.client
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import mf286d_flash_campaign as mf  # noqa: E402
import hardware_sweep as hs  # noqa: E402


class TestZtePrimitives:
    def test_sha256_upper_b64_shape(self):
        # sha256 of the base64 of the password, UPPER hex — the ZTE
        # goform LOGIN field contract
        h = mf.sha256_upper_b64("password")
        assert h == h.upper() and len(h) == 64

    def test_ad_token_derivation(self):
        # AD = md5(md5(WA+CR) + RD) — the factory-mode gate token
        t = mf.ad_token("WA", "CR", "RD")
        import hashlib
        inner = hashlib.md5(b"WACR").hexdigest()
        want = hashlib.md5(inner.encode() + b"RD").hexdigest()
        assert t == want

    def test_ad_token_depends_on_all_three(self):
        assert mf.ad_token("A", "B", "C") != mf.ad_token("X", "B", "C")
        assert mf.ad_token("A", "B", "C") != mf.ad_token("A", "X", "C")
        assert mf.ad_token("A", "B", "C") != mf.ad_token("A", "B", "X")


class TestGoformClient:
    def test_login_and_factory_via_mock(self):
        # the goform field SHAPES are the contract (the ZTE endpoints
        # are unreachable from CI); HTTPConnection is patched
        captured = {}

        class FakeConn:
            def __init__(self, host, timeout=None):
                self.host, self.timeout = host, timeout
                self.requests = []

            def request(self, method, path, body=None, headers=None):
                captured.setdefault("calls", []).append((method, path, body, headers))

            def getresponse(self):
                return SimpleNamespace(status=200, read=lambda: b"ok")

            def close(self):
                pass

        orig = mf.http.client.HTTPConnection
        mf.http.client.HTTPConnection = FakeConn
        try:
            g = mf.Goform("1.2.3.4", timeout=2)
            out = g.login("pw")
            assert out == "ok"
            method, path, body, headers = captured["calls"][0]
            assert method == "POST"
            assert path == "/goform/goform_set_cmd_process"
            assert "goformId=LOGIN" in body
            assert f"password={mf.sha256_upper_b64('pw')}" in body

            g.factory_open("ADTOKEN")
            method, path, body, headers = captured["calls"][1]
            assert path == "/goform/goform_process"
            assert "goformId=SwitchFactoryMode" in body
            assert "SwitchCMD=Open" in body
            assert "AD=ADTOKEN" in body
        finally:
            mf.http.client.HTTPConnection = orig


class TestWaitHttp:
    def test_waits_for_200(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"hi")

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), H)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            assert mf.wait_http(f"127.0.0.1:{port}", timeout=5) is True
        finally:
            srv.shutdown()

    def test_unreachable_times_out(self):
        # port 9 (discard) closed on loopback — the poll loop must
        # exhaust, not raise
        t0 = time.monotonic()
        assert mf.wait_http("127.0.0.1:9", timeout=2, want_codes=(200,)) is False
        assert time.monotonic() - t0 >= 1.5


# --- hardware_sweep ---------------------------------------------------------

def _place():
    return SimpleNamespace(name="ap-lan6", vlan="1006",
                           linklocal="fe80::dead:beef")


@pytest.fixture()
def sweep(monkeypatch, tmp_path):
    replies: list[str] = []
    calls = []

    def fake_switch_ssh(switch_host, cmd, timeout=60):
        calls.append(cmd)
        return 0, replies.pop(0) if replies else ""

    powers = []

    def fake_power(place, state, labgrid_host="ai-legion", **kw):
        powers.append((place, state))
        return 0, "ok"

    monkeypatch.setattr(hs, "switch_ssh", fake_switch_ssh)
    monkeypatch.setattr(hs, "labgrid_power", fake_power)
    monkeypatch.setattr(hs, "RESULTS", tmp_path / "hw-sweep.jsonl")
    monkeypatch.setattr(hs.time, "sleep", lambda s: None)
    return SimpleNamespace(replies=replies, calls=calls, powers=powers)


class TestClassifyUnit:
    def test_network_dead(self, sweep):
        sweep.replies.append("V6-FAIL\n")
        row = hs.classify_unit(_place(), "switch")
        assert row["outcome"] == "network-dead"

    def test_no_dropbear(self, sweep):
        sweep.replies.extend(["V6-OK\n", "SSH-2.0-something-else\n"])
        row = hs.classify_unit(_place(), "switch")
        assert row["outcome"] == "no-dropbear"
        assert row["v6"] == "alive"

    def test_auth_dead_carries_detail(self, sweep):
        sweep.replies.extend(["V6-OK\n", "SSH-2.0-dropbear\n", "Remote closed\n"])
        row = hs.classify_unit(_place(), "switch")
        assert row["outcome"] == "auth-dead"
        assert "Remote closed" in row["detail"]

    def test_managed_full_ladder(self, sweep):
        sweep.replies.extend([
            "V6-OK\n",
            "SSH-2.0-dropbear-2022\n",
            "AUTH-OK\n",
            ("OK /etc/shadow\nOK /etc/config/network\n"
             "OK /etc/config/dropbear\nOK /etc/dropbear/authorized_keys\n"
             "DISTRIB_RELEASE='24.10.2'\n"),
        ])
        row = hs.classify_unit(_place(), "switch")
        assert row["outcome"] == "managed"
        assert row["auth"] == "key-works"
        assert row["release"] == "24.10.2"
        assert row["missing_files"] == []

    def test_partial_on_missing_files(self, sweep):
        sweep.replies.extend([
            "V6-OK\n",
            "SSH-2.0-dropbear\n",
            "AUTH-OK\n",
            ("OK /etc/shadow\nMISSING /etc/config/dropbear\n"
             "jffs2: 24 unchecked, 15 orphan xattrs\n"
             "DISTRIB_RELEASE='24.10.8'\n"),
        ])
        row = hs.classify_unit(_place(), "switch")
        assert row["outcome"] == "partial"
        assert row["missing_files"] == ["MISSING /etc/config/dropbear"]
        assert len(row["jffs2_debris"]) == 1  # the debris line is captured
