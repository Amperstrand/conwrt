"""cmd_find + cache-hygiene tests for firmware-manager.py (#794).

The 79%-coverage gap was cmd_find (the newest-entry cache lookup the
flash flows consume) and _ensure_gitignore. All driven with a fake
IMAGES_DIR — no network, no builds.
"""
from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

fm = importlib.import_module("firmware-manager")


def make_entry(base: Path, profile: str, cache_key: str, *,
               enqueued: str, images: list[dict], write_files: bool = True) -> Path:
    d = base / profile / cache_key
    d.mkdir(parents=True)
    meta = {"enqueued_at": enqueued, "images": images}
    (d / "build.metadata.json").write_text(json.dumps(meta))
    if write_files:
        for img in images:
            (d / img["name"]).write_bytes(b"firmware")
    return d


def find_args(profile: str, image_type: str | None = None) -> argparse.Namespace:
    return argparse.Namespace(profile=profile, type=image_type)


@pytest.fixture()
def cache(tmp_path, monkeypatch):
    monkeypatch.setattr(fm, "IMAGES_DIR", tmp_path)
    return tmp_path


class TestCmdFind:
    def test_newest_entry_wins(self, cache, capsys):
        make_entry(cache, "p", "old", enqueued="2026-01-01T00:00:00",
                   images=[{"name": "old.bin", "type": "sysupgrade"}])
        make_entry(cache, "p", "new", enqueued="2026-06-01T00:00:00",
                   images=[{"name": "new.bin", "type": "sysupgrade"}])
        assert fm.cmd_find(find_args("p")) == 0
        assert "new.bin" in capsys.readouterr().out

    def test_type_filter_selects_matching_image(self, cache, capsys):
        make_entry(cache, "p", "k1", enqueued="2026-01-01",
                   images=[{"name": "a.bin", "type": "factory"},
                           {"name": "b.bin", "type": "sysupgrade"}])
        assert fm.cmd_find(find_args("p", image_type="sysupgrade")) == 0
        out = capsys.readouterr().out
        assert "b.bin" in out and "a.bin" not in out

    def test_entries_without_matching_type_are_skipped(self, cache):
        make_entry(cache, "p", "k1", enqueued="2026-01-01",
                   images=[{"name": "a.bin", "type": "factory"}])
        assert fm.cmd_find(find_args("p", image_type="sysupgrade")) == 1

    def test_missing_profile_dir(self, cache):
        assert fm.cmd_find(find_args("nope")) == 1

    def test_entries_without_metadata_skipped(self, cache):
        (cache / "p" / "bare").mkdir(parents=True)
        assert fm.cmd_find(find_args("p")) == 1

    def test_falls_back_to_hash_dir_when_files_missing(self, cache, capsys):
        make_entry(cache, "p", "k1", enqueued="2026-01-01",
                   images=[{"name": "gone.bin", "type": "sysupgrade"}],
                   write_files=False)
        assert fm.cmd_find(find_args("p")) == 0
        assert str(cache / "p" / "k1") in capsys.readouterr().out

    def test_metadata_without_hash_dir(self, cache, monkeypatch):
        # metadata readable but directory vanished -> rc 1 path
        make_entry(cache, "p", "k1", enqueued="2026-01-01",
                   images=[{"name": "x.bin", "type": "sysupgrade"}])
        real_read = fm._read_metadata

        def shim(profile, key):
            return real_read(profile, key) if key == "gone" else None
        monkeypatch.setattr(fm, "_read_metadata", shim)
        # no entries with readable metadata at all
        assert fm.cmd_find(find_args("p")) == 1

    def test_stray_file_in_profile_dir_ignored(self, cache):
        make_entry(cache, "p", "k1", enqueued="2026-01-01",
                   images=[{"name": "x.bin", "type": "sysupgrade"}])
        (cache / "p" / "stray.txt").write_text("not a dir")
        assert fm.cmd_find(find_args("p")) == 0


class TestEnsureGitignore:
    def test_absent_gitignore_is_noop(self, tmp_path, monkeypatch):
        # CURRENT-SEMANTICS PIN: a missing .gitignore is left alone —
        # creation is the repo's job, the helper only appends to what
        # exists (guard: never fabricate a repo file).
        gi = tmp_path / ".gitignore"
        monkeypatch.setattr(fm, "REPO_ROOT", tmp_path)
        monkeypatch.setattr(fm, "IMAGES_DIR", tmp_path / "images")
        fm._ensure_gitignore()
        assert not gi.exists()

    def test_idempotent_when_present(self, tmp_path, monkeypatch):
        gi = tmp_path / ".gitignore"
        gi.write_text("images/\n")
        monkeypatch.setattr(fm, "REPO_ROOT", tmp_path)
        monkeypatch.setattr(fm, "IMAGES_DIR", tmp_path / "images")
        fm._ensure_gitignore()
        assert gi.read_text() == "images/\n"

    def test_appends_once_when_missing_from_existing(self, tmp_path, monkeypatch):
        gi = tmp_path / ".gitignore"
        gi.write_text("*.pyc\n")  # no trailing newline path too
        monkeypatch.setattr(fm, "REPO_ROOT", tmp_path)
        monkeypatch.setattr(fm, "IMAGES_DIR", tmp_path / "images")
        fm._ensure_gitignore()
        fm._ensure_gitignore()
        text = gi.read_text()
        assert text.count("images/") == 1
        assert text.endswith("images/\n")
