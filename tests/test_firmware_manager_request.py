"""Tests for firmware-manager's ASU request flow + cache presentation
(#794 lane 3). Network seams stubbed at module level (_http_post_json,
_http_get_json, urlopen for downloads); hashes, classification, and
metadata are exercised for real. No wire.
"""
from __future__ import annotations

import hashlib
import io
import json
import urllib.error
from pathlib import Path
from types import SimpleNamespace

import importlib
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

fm = importlib.import_module("firmware-manager")


IMG_BYTES = b"IMAGEDATA-0123456789"
IMG_SHA = hashlib.sha256(IMG_BYTES).hexdigest()


class _FakeResp:
    """Streaming-shaped: read(n) yields the NEXT chunk, b'' at EOF."""

    def __init__(self, body: bytes):
        self._body = body
        self._pos = 0

    def read(self, n=-1):
        if self._pos >= len(self._body):
            return b""
        chunk = self._body[self._pos:] if n < 0 else self._body[self._pos:self._pos + n]
        self._pos += len(chunk)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _stub_network(monkeypatch, tmp_path, *, build_reply=None, poll_replies=None,
                  download_body=IMG_BYTES):
    """Stub every network seam; returns call logs."""
    posts, gets, downloads = [], [], []
    poll_iter = iter(poll_replies or [{"status": "done"}])

    def fake_post(url, data, timeout=30):
        posts.append((url, data))
        if isinstance(build_reply, Exception):
            raise build_reply
        return build_reply or {"request_hash": "hash123"}

    def fake_get(url, timeout=15):
        gets.append(url)
        r = next(poll_iter)
        if isinstance(r, Exception):
            raise r
        return r

    def fake_urlopen(req, timeout=120):
        downloads.append(req.full_url)
        return _FakeResp(download_body)

    monkeypatch.setattr(fm, "_http_post_json", fake_post)
    monkeypatch.setattr(fm, "_http_get_json", fake_get)
    monkeypatch.setattr(fm.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(fm, "IMAGES_DIR", tmp_path / "images")
    monkeypatch.setattr(fm.time, "sleep", lambda s: None)
    return posts, gets, downloads


def _args(**kw):
    base = dict(profile="virtual-x86-64", version="24.10.0", target=None,
                packages=None, ssh_key=None, password=None, wan_ssh=False,
                tofb=False, model_capabilities=None, dry_run=False,
                netconsole=None)
    base.update(kw)
    return SimpleNamespace(**base)


def _stub_plan(monkeypatch):
    plan = SimpleNamespace(
        asu_defaults_script=lambda: "# defaults\n",
        all_packages=lambda: [],
        all_packages_remove=lambda: [],
        ssh_key_cleaned=None, ssh_key_source="none")
    monkeypatch.setattr(fm, "build_plan", lambda *a, **kw: plan)
    monkeypatch.setattr(fm, "_load_config",
                        lambda: SimpleNamespace(ssh_public_key_path=None,
                                                ssh_all_keys=[], extra_packages=[],
                                                wan_ssh=False, tofb=False,
                                                disable_lan_dhcp=True))
    return plan


class TestCmdRequest:
    def test_happy_path_downloads_verifies_and_writes_metadata(self, monkeypatch, tmp_path, capsys):
        _stub_plan(monkeypatch)
        posts, gets, downloads = _stub_network(
            monkeypatch, tmp_path,
            build_reply={"request_hash": "rq1"},
            poll_replies=[{"status": "pending"}, {"status": "done", "bin_dir": "bd",
                                                  "images": [{"name": "fw-sysupgrade.bin",
                                                              "sha256": IMG_SHA, "size": len(IMG_BYTES)}],
                                                  "version": "24.10.0", "target": "x86/64",
                                                  "profile": "virtual"}])
        rc = fm.cmd_request(_args())
        assert rc == 0, capsys.readouterr().out
        # request submitted once, polled twice, downloaded once
        assert len(posts) == 1 and len(gets) == 2 and downloads[0].endswith("fw-sysupgrade.bin")
        out = Path(capsys.readouterr().out.strip().splitlines()[-1])
        assert out.exists()
        meta = json.loads((out / "build.metadata.json").read_text())
        assert meta["images"][0]["verified"] is True
        assert meta["images"][0]["type"] == "sysupgrade"
        assert meta["images"][0]["sha256"] == IMG_SHA
        assert (out / "fw-sysupgrade.bin").read_bytes() == IMG_BYTES

    def test_cache_hit_skips_network(self, monkeypatch, tmp_path, capsys):
        _stub_plan(monkeypatch)
        # run the happy path once to populate the cache, then re-request
        posts, gets, _ = _stub_network(monkeypatch, tmp_path,
                      build_reply={"request_hash": "rq1"},
                      poll_replies=[{"status": "done", "bin_dir": "bd",
                                     "images": [{"name": "fw.bin", "sha256": IMG_SHA,
                                                 "size": len(IMG_BYTES)}]}])
        fm.cmd_request(_args())
        rc2 = fm.cmd_request(_args())
        out = capsys.readouterr().out
        assert rc2 == 0
        assert len(posts) == 1, "second request must not hit ASU (cache)"

    def test_sha_mismatch_deletes_and_fails(self, monkeypatch, tmp_path, capsys):
        _stub_plan(monkeypatch)
        _stub_network(monkeypatch, tmp_path,
                      build_reply={"request_hash": "rq1"},
                      poll_replies=[{"status": "done", "bin_dir": "bd",
                                     "images": [{"name": "fw.bin",
                                                 "sha256": "0" * 64,  # wrong digest
                                                 "size": len(IMG_BYTES)}]}])
        rc = fm.cmd_request(_args())
        assert rc == 1
        leaked = list((tmp_path / "images").rglob("fw.bin"))
        assert not leaked, "mismatched image must be deleted, not left behind"

    def test_build_failure_status_fails(self, monkeypatch, tmp_path):
        _stub_plan(monkeypatch)
        _stub_network(monkeypatch, tmp_path,
                      build_reply={"request_hash": "rq1"},
                      poll_replies=[{"status": "failed", "message": "bad target"}])
        assert fm.cmd_request(_args()) == 1

    def test_no_request_hash_fails(self, monkeypatch, tmp_path):
        _stub_plan(monkeypatch)
        _stub_network(monkeypatch, tmp_path, build_reply={})
        assert fm.cmd_request(_args()) == 1

    def test_asu_http_error_fails_cleanly(self, monkeypatch, tmp_path):
        _stub_plan(monkeypatch)
        _stub_network(monkeypatch, tmp_path,
                      build_reply=urllib.error.HTTPError("u", 500, "boom", {}, None))
        assert fm.cmd_request(_args()) == 1

    def test_dry_run_prints_plan_and_cache_key_no_network(self, monkeypatch, tmp_path, capsys):
        _stub_plan(monkeypatch)
        posts, gets, _ = _stub_network(monkeypatch, tmp_path)
        monkeypatch.setattr(fm, "print_plan", lambda p: print("PLAN-PRINTED"))
        rc = fm.cmd_request(_args(dry_run=True))
        assert rc == 0
        out = capsys.readouterr().out
        assert "PLAN-PRINTED" in out and "cache_key=" in out
        assert not posts and not gets

    def test_netconsole_block_reaches_asu_request(self, monkeypatch, tmp_path):
        _stub_plan(monkeypatch)
        posts, _, _ = _stub_network(
            monkeypatch, tmp_path,
            build_reply={"request_hash": "rq1"},
            poll_replies=[{"status": "done", "bin_dir": "bd",
                           "images": [{"name": "fw.bin", "sha256": IMG_SHA,
                                       "size": len(IMG_BYTES)}]}])
        fm.cmd_request(_args(netconsole="192.168.77.9:6666"))
        body = json.dumps(posts[0][1])
        assert "netconsole" in body and "192.168.77.9:6666" in body


class TestImageClassification:
    @pytest.mark.parametrize("name,expected", [
        ("fw-sysupgrade.bin", "sysupgrade"),
        ("fw-factory.img", "factory"),
        ("fw-recovery.bin", "recovery"),
        ("fw-mystery.bin", "unknown"),
    ])
    def test_by_filename(self, monkeypatch, tmp_path, name, expected):
        _stub_plan(monkeypatch)
        _stub_network(monkeypatch, tmp_path,
                      build_reply={"request_hash": "rq1"},
                      poll_replies=[{"status": "done", "bin_dir": "bd",
                                     "images": [{"name": name, "sha256": IMG_SHA,
                                                 "size": len(IMG_BYTES)}]}])
        fm.cmd_request(_args())
        # find the metadata written under the temp images dir
        meta = next((tmp_path / "images").rglob("build.metadata.json"))
        assert json.loads(meta.read_text())["images"][0]["type"] == expected
