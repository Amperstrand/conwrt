"""Tests for scripts/flash/chromium_upload.py (pure parts only — no browser,
no device; the driver itself is bench-verified hardware flow)."""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from flash.chromium_upload import (
    build_local_form,
    classify_outcome,
    resolve_chromium_executable,
)


def _make_exe(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"#!/bin/sh\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class TestResolveChromium:
    def test_prefers_newest_version_across_layouts(self, tmp_path):
        # old-style full chromium and newer headless shell both present
        _make_exe(tmp_path / "chromium-1200/chrome-linux/chrome")
        _make_exe(tmp_path / "chromium_headless_shell-1234/chrome-headless-shell-linux64/chrome-headless-shell")
        got = resolve_chromium_executable(tmp_path)
        assert got is not None
        assert "1234" in got

    def test_numeric_not_lexicographic(self, tmp_path):
        # 999 > 1000 lexicographically but not numerically
        _make_exe(tmp_path / "chromium-999/chrome-linux/chrome")
        _make_exe(tmp_path / "chromium-1000/chrome-linux/chrome")
        got = resolve_chromium_executable(tmp_path)
        assert got is not None
        assert "1000" in got

    def test_mac_layout(self, tmp_path):
        _make_exe(tmp_path / "chromium-1187/chrome-mac/Chromium.app/Contents/MacOS/Chromium")
        got = resolve_chromium_executable(tmp_path)
        assert got is not None
        assert got.endswith("Chromium")

    def test_skips_non_executables(self, tmp_path):
        marker = tmp_path / "chromium-1234/chrome-linux/chrome"
        marker.parent.mkdir(parents=True)
        marker.write_bytes(b"not executable")
        assert resolve_chromium_executable(tmp_path) is None

    def test_empty_cache_returns_none(self, tmp_path):
        assert resolve_chromium_executable(tmp_path) is None


class TestBuildLocalForm:
    def test_form_targets_endpoint_with_multipart(self):
        html = build_local_form("http://192.168.0.1:80/upload", "firmware")
        assert 'action="http://192.168.0.1:80/upload"' in html
        assert 'method="post"' in html
        assert 'enctype="multipart/form-data"' in html
        assert 'name="firmware"' in html
        assert 'type="file"' in html

    def test_field_name_is_parameterized(self):
        assert 'name="image2"' in build_local_form("http://x/u", "image2")


class TestClassifyOutcome:
    def test_real_response_body_is_accepted(self):
        accepted, verdict = classify_outcome("Upgrade successfully!")
        assert accepted, verdict

    @pytest.mark.parametrize("tail", [
        "click: pending-navigation timeout (known behavior)",
        "post-upload wait: Page.content: Unable to retrieve content because the page is navigating",
    ])
    def test_hang_endings_are_pending_not_accepted(self, tail):
        # 2026-10-19 live evidence: an idle-dead recovery server hangs the
        # TCP connection exactly like an accepted POST — only the recovery
        # server vanishing (ARP) proves consumption.
        accepted, verdict = classify_outcome(tail)
        assert not accepted
        assert "PENDING" in verdict

    def test_window_dead(self):
        accepted, verdict = classify_outcome("net::ERR_CONNECTION_REFUSED")
        assert not accepted
        assert "WINDOW DEAD" in verdict

    def test_unrecognized_demands_pcap(self):
        accepted, verdict = classify_outcome("something novel happened")
        assert not accepted
        assert "pcap" in verdict


def test_env_override_cache(monkeypatch, tmp_path):
    _make_exe(tmp_path / "chromium-777/chrome-linux/chrome")
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", str(tmp_path))
    got = resolve_chromium_executable()
    assert got is not None
    assert "777" in got
    assert os.path.isabs(got)
