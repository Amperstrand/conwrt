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


class TestResolveAsuVersion:
    def _set_latest(self, monkeypatch, latest):
        monkeypatch.setattr(fm, "_latest_versions_cache", latest)

    def test_concrete_version_passthrough(self, monkeypatch):
        self._set_latest(monkeypatch, ["25.12.5", "24.10.8"])
        assert fm.resolve_asu_version("25.12.5") == "25.12.5"
        assert fm.resolve_asu_version("24.10.2") == "24.10.2"

    def test_snapshot_alias(self, monkeypatch):
        self._set_latest(monkeypatch, ["25.12.5", "24.10.8"])
        assert fm.resolve_asu_version("SNAPSHOT") == "SNAPSHOT"
        assert fm.resolve_asu_version("snapshot") == "SNAPSHOT"

    def test_rc_and_snapshot_suffix_passthrough(self, monkeypatch):
        self._set_latest(monkeypatch, ["25.12.5"])
        assert fm.resolve_asu_version("24.10.2-rc1") == "24.10.2-rc1"
        assert fm.resolve_asu_version("21.02-SNAPSHOT") == "21.02-SNAPSHOT"

    def test_branch_track_resolves_to_newest(self, monkeypatch):
        self._set_latest(monkeypatch, ["25.12.5", "24.10.8"])
        assert fm.resolve_asu_version("25") == "25.12.5"
        assert fm.resolve_asu_version("24") == "24.10.8"
        assert fm.resolve_asu_version("24.10") == "24.10.8"
        assert fm.resolve_asu_version("25.12") == "25.12.5"

    def test_unknown_track_uses_pinned_fallback(self, monkeypatch):
        self._set_latest(monkeypatch, [])
        assert fm.resolve_asu_version("25") == "25.12.5"
        assert fm.resolve_asu_version("24") == "24.10.8"

    def test_unknown_track_no_fallback_passthrough(self, monkeypatch):
        self._set_latest(monkeypatch, ["25.12.5"])
        assert fm.resolve_asu_version("23") == "23"

    def test_empty_version_passthrough(self, monkeypatch):
        self._set_latest(monkeypatch, ["25.12.5"])
        assert fm.resolve_asu_version("") == ""

    def test_model_versions_resolve(self, monkeypatch):
        """Every models/*.json version must survive resolution to a concrete ASU version."""
        self._set_latest(monkeypatch, ["25.12.5", "24.10.8"])
        for version in ["24", "25", "snapshot", "2022-02-16"]:
            resolved = fm.resolve_asu_version(version)
            assert resolved == "SNAPSHOT" or len(resolved.split("-")[0].split(".")) >= 3 or resolved == version


class TestAsuProfileFromRegistry:
    """The ASU profile name is a per-device FACT (openwrt.profile), never
    derivable by separator-swapping the model id — and the swap is NOT
    invertible ('glinet-mt3000' id vs 'glinet_gl-mt3000' profile).
    Whatever spelling the caller passes, the outbound request carries
    the registry's canonical name (#487/#506 lineage)."""

    def _request_body_for(self, monkeypatch, tmp_path, profile_arg, target=None):
        import argparse
        import urllib.error

        captured = {}

        def fake_post(url, body, timeout=30):
            captured.update(body)
            raise urllib.error.HTTPError(url, 400, "stopped-by-test", None, None)

        monkeypatch.setattr(fm, "_http_post_json", fake_post)
        monkeypatch.setattr(fm, "IMAGES_DIR", tmp_path / "images")
        monkeypatch.setenv("CONWRT_CONFIG", str(tmp_path / "no-such-config.toml"))

        ns = argparse.Namespace(
            profile=profile_arg, version="24", target=target, packages=None,
            ssh_key=None, password=None, wan_ssh=False, tofb=False,
            dry_run=False,
        )
        rc = fm.cmd_request(ns)
        assert rc == 1, "the stubbed 400 must stop the request path"
        return captured

    def test_mangled_underscore_spelling_gets_registry_profile(self, monkeypatch, tmp_path):
        body = self._request_body_for(monkeypatch, tmp_path, "dlink_covr_x1860_a1")
        assert body["profile"] == "dlink_covr-x1860-a1"
        assert body["target"] == "ramips/mt7621"

    def test_explicit_target_still_gets_registry_profile(self, monkeypatch, tmp_path):
        body = self._request_body_for(
            monkeypatch, tmp_path, "dlink_covr_x1860_a1", target="ramips/mt7621")
        assert body["profile"] == "dlink_covr-x1860-a1"

    def test_plain_model_id_and_profile_form_both_resolve(self, monkeypatch, tmp_path):
        """The swap is NOT invertible: the registry must accept the id,
        the underscored id, and the profile form itself."""
        for arg in ("glinet-mt3000", "glinet_mt3000", "glinet_gl-mt3000"):
            body = self._request_body_for(monkeypatch, tmp_path, arg)
            assert body["profile"] == "glinet_gl-mt3000", f"arg {arg}: {body}"
            assert body["target"] == "mediatek/filogic", f"arg {arg}: {body}"

    def test_every_model_json_carries_an_asu_profile(self):
        """The registry is the ASU naming authority — every model must
        carry openwrt.profile or the request falls back to the caller's
        spelling (the #487 hole)."""
        models_dir = ROOT / "models"
        missing = [
            p.stem for p in sorted(models_dir.glob("*.json"))
            if not json.loads(p.read_text()).get("openwrt", {}).get("profile")
        ]
        assert not missing, f"models missing openwrt.profile: {missing}"
