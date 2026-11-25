"""Tests for the toolchain-pin guard itself (#763 P2 tail).

sdk_rust_version guards rust-pin drift; these tests pin the guard:
feed parsing, manifest validation, every failure class of
check_failures, the update/print modes, main() dispatch, and the
script's own --self-test discipline (so it cannot silently rot out
of the fast tier). All network seams stubbed — no wire.
"""
from __future__ import annotations

import io
import json
import sys
import urllib.error
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import sdk_rust_version as guard  # noqa: E402

MANIFEST = Path(guard.MANIFEST)

GOOD_BODY = "include $(TOPDIR)/rules.mk\nPKG_VERSION:=1.96.0\nPKG_HASH:=deadbeef\n"


class _FakeResponse:
    """urlopen result the guard consumes via `with` (context protocol)."""

    def __init__(self, body: bytes):
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _manifest_dict() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _write(tmp_path: Path, data: dict, name: str = "m.json") -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return p


class TestFetchFeedRust:
    def test_parses_pkg_version(self, monkeypatch):
        monkeypatch.setattr(
            guard.urllib.request, "urlopen",
            lambda url, timeout=None: _FakeResponse(GOOD_BODY.encode()))
        assert guard.fetch_feed_rust("25.12") == "1.96.0"

    def test_missing_pkg_version_is_none(self, monkeypatch):
        monkeypatch.setattr(
            guard.urllib.request, "urlopen",
            lambda url, timeout=None: _FakeResponse(b"PKG_HASH:=deadbeef\n"))
        assert guard.fetch_feed_rust("25.12") is None

    def test_non_semver_is_none(self, monkeypatch):
        body = GOOD_BODY.replace("1.96.0", "1.96")
        monkeypatch.setattr(
            guard.urllib.request, "urlopen",
            lambda url, timeout=None: _FakeResponse(body.encode()))
        assert guard.fetch_feed_rust("25.12") is None

    def test_network_error_is_none(self, monkeypatch):
        def boom(url, timeout=None):
            raise urllib.error.URLError("no route")
        monkeypatch.setattr(guard.urllib.request, "urlopen", boom)
        assert guard.fetch_feed_rust("25.12") is None


class TestLoadManifest:
    def test_real_manifest_loads(self):
        m = guard.load_manifest(MANIFEST)
        assert isinstance(m["openwrt_sdk"]["rust_per_release"], dict)

    def test_bad_json_raises(self, tmp_path):
        p = tmp_path / "bad.json"
        p.write_text("{not json", encoding="utf-8")
        with pytest.raises(guard.AuditError, match="not valid JSON"):
            guard.load_manifest(p)

    def test_unreadable_raises(self, tmp_path):
        with pytest.raises(guard.AuditError, match="cannot read"):
            guard.load_manifest(tmp_path / "missing.json")

    @pytest.mark.parametrize("drop", ["rust_per_release", "releases"])
    def test_missing_keys_raise(self, tmp_path, drop):
        data = _manifest_dict()
        data["openwrt_sdk"].pop(drop)
        with pytest.raises(guard.AuditError, match=drop):
            guard.load_manifest(_write(tmp_path, data))


class TestPinsAndEras:
    def test_comment_keys_skipped(self):
        pins = guard.series_pins(_manifest_dict())
        assert not any(k.startswith("_") for k in pins)
        assert pins  # and the real pins survive

    def test_era_series_covers_every_pinned_era(self):
        eras = guard.era_series_list(_manifest_dict())
        pins = guard.series_pins(_manifest_dict())
        assert set(eras) <= set(pins)  # the invariant check_failures enforces


class TestCheckFailures:
    def _stub(self, pins):
        return lambda series: pins.get(series)

    def test_clean_manifest_no_failures(self):
        pins = guard.series_pins(_manifest_dict())
        assert guard.check_failures(_manifest_dict(), self._stub(pins)) == []

    def test_drift_detected(self, tmp_path):
        data = _manifest_dict()
        series, pinned = next(iter(guard.series_pins(data).items()))
        data["openwrt_sdk"]["rust_per_release"][series] = "9.9.9"
        stub = self._stub({series: pinned})
        failures = guard.check_failures(data, stub)
        assert any(f"DRIFT rust pin {series}" in f for f in failures)

    def test_unreachable_branch_is_drift(self):
        failures = guard.check_failures(_manifest_dict(), lambda s: None)
        assert any("unreachable" in f for f in failures)
        # and never a silent pass: one failure per pin
        assert len(failures) == len(guard.series_pins(_manifest_dict()))

    def test_era_without_pin_detected(self, tmp_path):
        data = _manifest_dict()
        series = data["openwrt_sdk"]["releases"]["apk"]["series"]
        data["openwrt_sdk"]["rust_per_release"].pop(series)
        pins = guard.series_pins(_manifest_dict())
        failures = guard.check_failures(data, self._stub(pins))
        assert any(f"no entry for '{series}'" in f for f in failures)


class TestRunModes:
    def test_run_check_exit_codes(self, tmp_path, capsys):
        pins = guard.series_pins(_manifest_dict())
        ok = guard.run_check(MANIFEST, self_stub := (lambda s: pins.get(s)))
        assert ok == 0
        assert "match the live packages feed" in capsys.readouterr().out
        bad = guard.run_check(MANIFEST, lambda s: None)
        assert bad == 1
        assert "drifted" in capsys.readouterr().err

    def test_run_update_repairs_and_preserves_comments(self, tmp_path):
        data = _manifest_dict()
        real_pins = guard.series_pins(data)  # every series answers the stub
        series, pinned = next(iter(real_pins.items()))
        data["openwrt_sdk"]["rust_per_release"][series] = "0.0.1"
        path = _write(tmp_path, data)
        rc = guard.run_update(path, lambda s: real_pins.get(s))
        assert rc == 0, "post-update check must pass once every pin matches"
        after = json.loads(path.read_text(encoding="utf-8"))
        assert after["openwrt_sdk"]["rust_per_release"][series] == pinned
        # unreachable series pins were left untouched (NOTE path)
        assert after["openwrt_sdk"]["rust_per_release"]  # still whole

    def test_run_print(self, capsys):
        assert guard.run_print("25.12", lambda s: "1.96.0") == 0
        assert capsys.readouterr().out.strip() == "1.96.0"
        assert guard.run_print("25.12", lambda s: None) == 1

    def test_self_test_passes_on_real_manifest(self, capsys):
        # the guard's own seeded-drift discipline, pinned in the fast tier
        assert guard.run_self_test(MANIFEST) == 0
        out = capsys.readouterr().out
        assert "self-test PASS" in out

    def test_main_self_test_flag(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv",
                            ["sdk_rust_version.py", "--self-test"])
        assert guard.main() == 0
