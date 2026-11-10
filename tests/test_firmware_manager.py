"""Tests for firmware-manager.py pure functions.

Loaded via importlib since the hyphenated filename is not importable by name.
"""
import importlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

fm = importlib.import_module("firmware-manager")


class TestComputeCacheKey:
    def test_deterministic(self):
        key1 = fm._compute_cache_key("openwrt", "24.10", "mediatek/filogic", "device", ["pkg1", "pkg2"], "script")
        key2 = fm._compute_cache_key("openwrt", "24.10", "mediatek/filogic", "device", ["pkg1", "pkg2"], "script")
        assert key1 == key2

    def test_different_packages_different_key(self):
        key1 = fm._compute_cache_key("openwrt", "24.10", "target", "device", ["pkg1"], None)
        key2 = fm._compute_cache_key("openwrt", "24.10", "target", "device", ["pkg2"], None)
        assert key1 != key2

    def test_package_order_irrelevant(self):
        key1 = fm._compute_cache_key("openwrt", "24.10", "target", "device", ["pkg1", "pkg2"], None)
        key2 = fm._compute_cache_key("openwrt", "24.10", "target", "device", ["pkg2", "pkg1"], None)
        assert key1 == key2

    def test_different_script_different_key(self):
        key1 = fm._compute_cache_key("openwrt", "24.10", "target", "device", None, "echo hello")
        key2 = fm._compute_cache_key("openwrt", "24.10", "target", "device", None, "echo world")
        assert key1 != key2

    def test_none_packages_and_script(self):
        key = fm._compute_cache_key("openwrt", "24.10", "target", "device", None, None)
        assert len(key) == 64

    def test_is_sha256_hex(self):
        key = fm._compute_cache_key("openwrt", "24.10", "target", "device", [], "")
        assert all(c in "0123456789abcdef" for c in key)
        assert len(key) == 64

    def test_different_target_different_key(self):
        key1 = fm._compute_cache_key("openwrt", "24.10", "target1", "device", None, None)
        key2 = fm._compute_cache_key("openwrt", "24.10", "target2", "device", None, None)
        assert key1 != key2


class TestMetadataPath:
    def test_builds_correct_path(self):
        p = fm._metadata_path("myprofile", "abc123")
        assert str(p).endswith("myprofile/abc123/build.metadata.json")

    def test_under_images_dir(self):
        p = fm._metadata_path("profile", "hash")
        assert "images" in str(p)


class TestReadMetadata:
    def test_returns_none_when_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(fm, "IMAGES_DIR", tmp_path)
        result = fm._read_metadata("profile", "nohash")
        assert result is None

    def test_reads_build_metadata(self, tmp_path, monkeypatch):
        monkeypatch.setattr(fm, "IMAGES_DIR", tmp_path)
        meta = {"request_hash": "abc", "images": [{"name": "firmware.bin"}]}
        meta_dir = tmp_path / "profile" / "abc"
        meta_dir.mkdir(parents=True)
        (meta_dir / "build.metadata.json").write_text(json.dumps(meta))
        result = fm._read_metadata("profile", "abc")
        assert result is not None
        assert result["request_hash"] == "abc"

    def test_reads_legacy_metadata(self, tmp_path, monkeypatch):
        monkeypatch.setattr(fm, "IMAGES_DIR", tmp_path)
        meta = {"request_hash": "old"}
        meta_dir = tmp_path / "profile" / "old"
        meta_dir.mkdir(parents=True)
        (meta_dir / "old.metadata.json").write_text(json.dumps(meta))
        result = fm._read_metadata("profile", "old")
        assert result is not None
        assert result["request_hash"] == "old"

    def test_returns_none_on_invalid_json(self, tmp_path, monkeypatch):
        monkeypatch.setattr(fm, "IMAGES_DIR", tmp_path)
        meta_dir = tmp_path / "profile" / "bad"
        meta_dir.mkdir(parents=True)
        (meta_dir / "build.metadata.json").write_text("not json{{{")
        result = fm._read_metadata("profile", "bad")
        assert result is None


class TestFindCachedFirmware:
    def test_returns_none_when_no_metadata(self, tmp_path, monkeypatch):
        monkeypatch.setattr(fm, "IMAGES_DIR", tmp_path)
        result = fm._find_cached_firmware("profile", "nohash")
        assert result is None

    def test_returns_none_when_images_not_verified(self, tmp_path, monkeypatch):
        monkeypatch.setattr(fm, "IMAGES_DIR", tmp_path)
        meta = {"images": [{"name": "fw.bin", "verified": False}]}
        meta_dir = tmp_path / "profile" / "abc"
        meta_dir.mkdir(parents=True)
        (meta_dir / "build.metadata.json").write_text(json.dumps(meta))
        result = fm._find_cached_firmware("profile", "abc")
        assert result is None

    def test_returns_dir_when_verified(self, tmp_path, monkeypatch):
        monkeypatch.setattr(fm, "IMAGES_DIR", tmp_path)
        meta = {"images": [{"name": "fw.bin", "verified": True}]}
        meta_dir = tmp_path / "profile" / "abc"
        meta_dir.mkdir(parents=True)
        (meta_dir / "build.metadata.json").write_text(json.dumps(meta))
        (meta_dir / "fw.bin").write_bytes(b"\x00" * 100)
        result = fm._find_cached_firmware("profile", "abc")
        assert result is not None
        assert result.name == "abc"
