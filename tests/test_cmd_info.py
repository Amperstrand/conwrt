from __future__ import annotations

import json
from argparse import Namespace
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from conwrt.cmd_info import cmd_list, cmd_cache, _cache_list, _cache_clean


def _args(**overrides):
    defaults = {
        "cache_command": "list",
        "model_id": "",
        "keep_latest": False,
        "yes": True,
    }
    defaults.update(overrides)
    return Namespace(**defaults)


class TestCmdListEmpty:
    @patch("conwrt.cmd_info.list_models", return_value=[])
    def test_returns_1_when_no_models(self, mock_list, capsys):
        result = cmd_list(Namespace())
        assert result == 1
        captured = capsys.readouterr()
        assert "No models found" in captured.err


class TestCmdListWithModels:
    @patch(
        "conwrt.cmd_info.list_models",
        return_value=[
            {
                "id": "test-device-v1",
                "vendor": "TestCorp",
                "openwrt": {"target": "testarch/testsub"},
                "flash_methods": {"sysupgrade": {}},
                "description": "A test device",
            }
        ],
    )
    def test_returns_0_and_prints_table(self, mock_list, capsys):
        result = cmd_list(Namespace())
        assert result == 0
        captured = capsys.readouterr()
        assert "test-device-v1" in captured.out
        assert "TestCorp" in captured.out
        assert "sysupgrade" in captured.out

    @patch(
        "conwrt.cmd_info.list_models",
        return_value=[
            {
                "id": "bare-model",
                "vendor": "V",
                "openwrt": {},
                "description": "",
            }
        ],
    )
    def test_handles_missing_flash_methods(self, mock_list, capsys):
        result = cmd_list(Namespace())
        assert result == 0
        captured = capsys.readouterr()
        assert "bare-model" in captured.out
        assert "none" in captured.out


class TestCmdCacheDispatch:
    def test_dispatches_list(self):
        with patch("conwrt.cmd_info._cache_list", return_value=0) as mock:
            result = cmd_cache(_args(cache_command="list"))
            assert result == 0
            mock.assert_called_once()

    def test_dispatches_clean(self):
        with patch("conwrt.cmd_info._cache_clean", return_value=0) as mock:
            result = cmd_cache(_args(cache_command="clean"))
            assert result == 0
            mock.assert_called_once()

    def test_returns_1_for_unknown_command(self, capsys):
        result = cmd_cache(_args(cache_command="unknown"))
        assert result == 1
        captured = capsys.readouterr()
        assert "Usage" in captured.err


class TestCacheListNoDir:
    def test_returns_1_when_no_images_dir(self, tmp_path, capsys):
        missing = tmp_path / "nonexistent"
        result = _cache_list(missing)
        assert result == 1
        captured = capsys.readouterr()
        assert "No images/ directory" in captured.err


class TestCacheListEmpty:
    def test_returns_0_when_no_entries(self, tmp_path, capsys):
        images = tmp_path / "images"
        images.mkdir()
        result = _cache_list(images)
        assert result == 0
        captured = capsys.readouterr()
        assert "No cached firmware" in captured.out


class TestCacheListWithEntries:
    def test_prints_table_with_metadata(self, tmp_path, capsys):
        images = tmp_path / "images"
        model_dir = images / "test-device"
        hash_dir = model_dir / "abc123def456"
        hash_dir.mkdir(parents=True)

        metadata = {"version": "24.10.2", "version_code": "r12345+1"}
        (hash_dir / "test.metadata.json").write_text(json.dumps(metadata))

        bin_file = hash_dir / "test-sysupgrade.bin"
        bin_file.write_bytes(b"\x00" * 2048)

        result = _cache_list(images)
        assert result == 0
        captured = capsys.readouterr()
        assert "test-device" in captured.out
        assert "sysupgrade" in captured.out
        assert "24.10.2" in captured.out


class TestCacheListBadMetadata:
    def test_handles_corrupt_json_gracefully(self, tmp_path, capsys):
        images = tmp_path / "images"
        model_dir = images / "broken-device"
        hash_dir = model_dir / "deadbeef0000"
        hash_dir.mkdir(parents=True)

        (hash_dir / "broken.metadata.json").write_text("{bad json")
        bin_file = hash_dir / "firmware.bin"
        bin_file.write_bytes(b"\x00" * 512)

        result = _cache_list(images)
        assert result == 0
        captured = capsys.readouterr()
        assert "broken-device" in captured.out


class TestCacheCleanNoDir:
    def test_returns_1_when_no_images_dir(self, tmp_path, capsys):
        missing = tmp_path / "nonexistent"
        result = _cache_clean(missing, _args())
        assert result == 1
        captured = capsys.readouterr()
        assert "No images/ directory" in captured.err


class TestCacheCleanNoMatchingModel:
    def test_returns_0_when_no_matching_model(self, tmp_path, capsys):
        images = tmp_path / "images"
        model_dir = images / "other-device"
        hash_dir = model_dir / "abc123"
        hash_dir.mkdir(parents=True)
        (hash_dir / "file.bin").write_bytes(b"\x00" * 100)

        result = _cache_clean(images, _args(model_id="nonexistent"))
        assert result == 0
        captured = capsys.readouterr()
        assert "No cached images found for model" in captured.out


class TestCacheCleanWithYes:
    def test_removes_all_builds_when_yes(self, tmp_path, capsys):
        images = tmp_path / "images"
        model_dir = images / "test-device"
        h1 = model_dir / "hash1"
        h2 = model_dir / "hash2"
        h1.mkdir(parents=True)
        h2.mkdir(parents=True)
        (h1 / "fw.bin").write_bytes(b"\x00" * 1024)
        (h2 / "fw.bin").write_bytes(b"\x00" * 1024)

        result = _cache_clean(images, _args(yes=True))
        assert result == 0
        assert not h1.exists()
        assert not h2.exists()
        captured = capsys.readouterr()
        assert "Removed 2 cached build(s)" in captured.out


class TestCacheCleanKeepLatest:
    def test_keeps_latest_and_removes_older(self, tmp_path, capsys):
        images = tmp_path / "images"
        model_dir = images / "test-device"
        old = model_dir / "old_hash"
        new = model_dir / "new_hash"
        old.mkdir(parents=True)
        new.mkdir(parents=True)
        (old / "fw.bin").write_bytes(b"\x00" * 512)
        (new / "fw.bin").write_bytes(b"\x00" * 512)

        result = _cache_clean(images, _args(keep_latest=True, yes=True))
        assert result == 0
        assert not old.exists()
        assert new.exists()
        captured = capsys.readouterr()
        assert "Removed 1 cached build(s)" in captured.out


class TestCacheCleanPromptCancel:
    def test_cancels_when_user_says_no(self, tmp_path, capsys):
        images = tmp_path / "images"
        model_dir = images / "test-device"
        h = model_dir / "hash1"
        h.mkdir(parents=True)
        (h / "fw.bin").write_bytes(b"\x00" * 256)

        with patch("builtins.input", return_value="n"):
            result = _cache_clean(images, _args(yes=False))

        assert result == 0
        assert h.exists()
        captured = capsys.readouterr()
        assert "Cancelled" in captured.out


class TestCacheCleanPromptEOF:
    def test_cancels_on_eof(self, tmp_path, capsys):
        images = tmp_path / "images"
        model_dir = images / "test-device"
        h = model_dir / "hash1"
        h.mkdir(parents=True)
        (h / "fw.bin").write_bytes(b"\x00" * 256)

        with patch("builtins.input", side_effect=EOFError):
            result = _cache_clean(images, _args(yes=False))

        assert result == 0
        assert h.exists()


class TestCacheCleanHyphenModel:
    def test_matches_hyphen_variant_of_model_id(self, tmp_path, capsys):
        images = tmp_path / "images"
        model_dir = images / "test_device"
        h = model_dir / "hash1"
        h.mkdir(parents=True)
        (h / "fw.bin").write_bytes(b"\x00" * 256)

        result = _cache_clean(images, _args(model_id="test-device", yes=True))
        assert result == 0
        assert not h.exists()
