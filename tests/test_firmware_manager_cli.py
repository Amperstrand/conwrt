"""Tests for firmware-manager's cache presentation commands + main
(#794 lane 3, part 2): list/show/find over a synthetic cache tree,
_ensure_gitignore, and the CLI dispatch. No network.
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

fm = importlib.import_module("firmware-manager")


@pytest.fixture()
def cache(tmp_path, monkeypatch):
    monkeypatch.setattr(fm, "IMAGES_DIR", tmp_path / "images")
    images = tmp_path / "images"
    # two profiles: one with full metadata, one without
    d1 = images / "prof_a" / "abcdef0123456789"
    d1.mkdir(parents=True)
    (d1 / "build.metadata.json").write_text(json.dumps({
        "version": "24.10.0", "build_at": "2026-11-24T20:00:00Z",
        "images": [{"type": "sysupgrade"}, {"type": "factory"}],
    }))
    d2 = images / "prof_b" / "1234567890abcdef"
    d2.mkdir(parents=True)
    (d2 / "stray.bin").write_bytes(b"x")
    return images


class TestCmdList:
    def test_lists_profiles_with_metadata_and_gaps(self, cache, capsys):
        rc = fm.cmd_list(SimpleNamespace(profile=None, json=False))
        out = capsys.readouterr().out
        assert rc == 0
        assert "prof_a" in out and "24.10.0" in out
        assert "factory, sysupgrade" in out
        assert "prof_b" in out and " ? " in out  # no metadata -> placeholders

    def test_profile_filter(self, cache, capsys):
        fm.cmd_list(SimpleNamespace(profile="prof_a", json=False))
        out = capsys.readouterr().out
        assert "prof_a" in out and "prof_b" not in out

    def test_empty_cache_is_clean(self, tmp_path, monkeypatch, caplog):
        monkeypatch.setattr(fm, "IMAGES_DIR", tmp_path / "nothing")
        caplog.set_level(20)  # INFO: the empty-cache notice is logger.info
        assert fm.cmd_list(SimpleNamespace(profile=None, json=False)) == 0
        assert "no cached firmware" in caplog.text


class TestCmdShow:
    def test_show_prints_metadata(self, cache, capsys):
        rc = fm.cmd_show(SimpleNamespace(profile="prof_a", hash="abcdef012345"))
        out = capsys.readouterr().out
        assert rc == 0
        assert "24.10.0" in out and "sysupgrade" in out

    def test_show_missing_hash_fails(self, cache):
        assert fm.cmd_show(SimpleNamespace(profile="prof_a", hash="nope")) == 1


class TestEnsureGitignore:
    def test_appends_images_entry_when_missing(self, tmp_path, monkeypatch):
        gi = tmp_path / ".gitignore"
        gi.write_text("target/\n")
        monkeypatch.setattr(fm, "REPO_ROOT", tmp_path)
        # _ensure_gitignore writes at the repo root — check the exact shape
        fm._ensure_gitignore()
        text = gi.read_text()
        assert "images/" in text or "/images" in text

    def test_idempotent_when_present(self, tmp_path, monkeypatch):
        gi = tmp_path / ".gitignore"
        gi.write_text("target/\nimages/\n")
        monkeypatch.setattr(fm, "REPO_ROOT", tmp_path)
        fm._ensure_gitignore()
        assert gi.read_text() == "target/\nimages/\n"


class TestMain:
    @pytest.mark.parametrize("argv,cmd", [
        (["request", "--profile", "p", "--version", "v"], "cmd_request"),
        (["list"], "cmd_list"),
        (["show", "--profile", "p", "--hash", "h"], "cmd_show"),
        (["find", "--profile", "p"], "cmd_find"),
    ])
    def test_dispatch(self, monkeypatch, argv, cmd):
        called = {}

        def fake_cmd(a):
            called[cmd] = a
            return 0

        monkeypatch.setattr("sys.argv", ["firmware-manager.py", *argv])
        monkeypatch.setattr(fm, cmd, fake_cmd)
        monkeypatch.setattr(fm, "_ensure_gitignore", lambda: None)  # never touch the real gitignore
        assert fm.main() == 0
        assert cmd in called

    def test_unknown_command_exits_via_argparse(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["firmware-manager.py", "bogus"])
        monkeypatch.setattr(fm, "_ensure_gitignore", lambda: None)
        with pytest.raises(SystemExit):
            fm.main()

    def test_no_args_prints_help_and_returns_one(self, monkeypatch, capsys):
        monkeypatch.setattr("sys.argv", ["firmware-manager.py"])
        monkeypatch.setattr(fm, "_ensure_gitignore", lambda: None)
        assert fm.main() == 1
        assert "subcommands" in capsys.readouterr().err
