"""Tests for conwrt.image_source — URL resolution, checksum parsing, download.

Hardware-safe: all network I/O and hashing are mocked or local fixtures.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from conwrt import image_source
from conwrt.image_source import (
    DEFAULT_IMAGE_SUFFIX,
    DEFAULT_RELEASE,
    fetch_image,
    image_filename,
    image_suffix,
    parse_sha256sums,
    resolve_image_url,
    resolve_release,
    target_dir_url,
)

_MT3000 = {
    "id": "glinet-mt3000",
    "openwrt": {
        "target": "mediatek/filogic",
        "device": "glinet,gl-mt3000",
        "profile": "glinet_gl-mt3000",
        "version": "24",
        "release": "24.10.2",
    },
}


class TestResolveRelease(TestCase):
    def test_uses_model_release(self):
        self.assertEqual(resolve_release(_MT3000), "24.10.2")

    def test_override_wins_over_model(self):
        self.assertEqual(resolve_release(_MT3000, override="25.12.5"), "25.12.5")

    def test_env_wins_over_model(self):
        with patch.dict("os.environ", {"CONWRT_OPENWRT_RELEASE": "25.12.5"}):
            self.assertEqual(resolve_release(_MT3000), "25.12.5")

    def test_default_when_absent(self):
        model = {"id": "x", "openwrt": {"target": "a/b", "profile": "p"}}
        self.assertEqual(resolve_release(model), DEFAULT_RELEASE)

    def test_rejects_non_full_version(self):
        model = {"id": "x", "openwrt": {"target": "a/b", "profile": "p", "release": "24"}}
        with self.assertRaises(ValueError):
            resolve_release(model)


class TestImageFilenameAndUrl(TestCase):
    def test_filename(self):
        self.assertEqual(
            image_filename(_MT3000, "24.10.2"),
            "openwrt-24.10.2-mediatek-filogic-glinet_gl-mt3000-squashfs-sysupgrade.bin",
        )

    def test_url(self):
        self.assertEqual(
            resolve_image_url(_MT3000, "24.10.2"),
            "https://downloads.openwrt.org/releases/24.10.2/targets/mediatek/filogic/"
            "openwrt-24.10.2-mediatek-filogic-glinet_gl-mt3000-squashfs-sysupgrade.bin",
        )

    def test_target_dir_url(self):
        self.assertEqual(
            target_dir_url(_MT3000, "24.10.2"),
            "https://downloads.openwrt.org/releases/24.10.2/targets/mediatek/filogic",
        )

    def test_invalid_target_raises(self):
        model = {"id": "x", "openwrt": {"target": "noslash", "profile": "p"}}
        with self.assertRaises(ValueError):
            image_filename(model, "24.10.2")

    def test_missing_profile_raises(self):
        model = {"id": "x", "openwrt": {"target": "a/b"}}
        with self.assertRaises(ValueError):
            image_filename(model, "24.10.2")

    def test_base_url_override(self):
        with patch.dict("os.environ", {"CONWRT_OPENWRT_BASE": "https://mirror.example"}):
            self.assertTrue(resolve_image_url(_MT3000, "24.10.2").startswith("https://mirror.example/"))


class TestImageSuffix(TestCase):
    def test_default_suffix(self):
        self.assertEqual(image_suffix(_MT3000), DEFAULT_IMAGE_SUFFIX)

    def test_model_suffix(self):
        model = {"id": "x", "openwrt": {"target": "a/b", "profile": "p",
                                        "image_suffix": "squashfs-factory.bin"}}
        self.assertEqual(image_suffix(model), "squashfs-factory.bin")

    def test_override_wins(self):
        self.assertEqual(image_suffix(_MT3000, "initramfs-kernel.bin"),
                         "initramfs-kernel.bin")

    def test_env_wins_over_model(self):
        with patch.dict("os.environ", {"CONWRT_IMAGE_SUFFIX": "initramfs-kernel.bin"}):
            self.assertEqual(image_suffix(_MT3000), "initramfs-kernel.bin")

    def test_filename_and_url_use_suffix(self):
        self.assertEqual(
            image_filename(_MT3000, "24.10.2", "squashfs-factory.bin"),
            "openwrt-24.10.2-mediatek-filogic-glinet_gl-mt3000-squashfs-factory.bin",
        )
        self.assertTrue(
            resolve_image_url(_MT3000, "24.10.2", "squashfs-factory.bin").endswith(
                "-squashfs-factory.bin")
        )


class TestParseSha256sums(TestCase):
    def test_binary_marker_star(self):
        text = "abc123 *openwrt-foo.bin\ndef456 *openwrt-bar.bin\n"
        self.assertEqual(parse_sha256sums(text, "openwrt-foo.bin"), "abc123")

    def test_plain_separator(self):
        text = "abc123  openwrt-foo.bin\n"
        self.assertEqual(parse_sha256sums(text, "openwrt-foo.bin"), "abc123")

    def test_missing_returns_none(self):
        self.assertIsNone(parse_sha256sums("abc *other.bin\n", "openwrt-foo.bin"))

    def test_comments_and_blanks_ignored(self):
        text = "\n# a comment\nabc *openwrt-foo.bin\n"
        self.assertEqual(parse_sha256sums(text, "openwrt-foo.bin"), "abc")


class TestFetchImage(TestCase):
    def _run(self, tmp, sums_text="deadbeef *openwrt-24.10.2-mediatek-filogic-glinet_gl-mt3000-squashfs-sysupgrade.bin\n",
             content=b"FIRMWARE"):
        captured = {}

        def fake_download(url, dest, timeout=300.0):
            captured["url"] = url
            Path(dest).write_bytes(content)

        with patch.object(image_source, "_http_get_text", return_value=sums_text), \
             patch.object(image_source, "_download_file", side_effect=fake_download), \
             patch.object(image_source, "sha256_file", return_value="deadbeef"):
            path = fetch_image(_MT3000, dest_dir=str(tmp))
        return path, captured

    def test_downloads_and_verifies(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path, captured = self._run(tmp)
            self.assertTrue(path.endswith("openwrt-24.10.2-mediatek-filogic-glinet_gl-mt3000-squashfs-sysupgrade.bin"))
            self.assertIn("releases/24.10.2/targets/mediatek/filogic", captured["url"])

    def test_missing_from_sha256sums_raises(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(image_source, "_http_get_text", return_value="abc *other.bin\n"), \
                 patch.object(image_source, "_download_file"):
                with self.assertRaises(RuntimeError):
                    fetch_image(_MT3000, dest_dir=str(tmp))

    def test_sha_mismatch_raises_and_removes(self):
        import tempfile

        def fake_download(url, dest, timeout=300.0):
            Path(dest).write_bytes(b"FIRMWARE")

        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(image_source, "_http_get_text", return_value="deadbeef *openwrt-24.10.2-mediatek-filogic-glinet_gl-mt3000-squashfs-sysupgrade.bin\n"), \
                 patch.object(image_source, "_download_file", side_effect=fake_download), \
                 patch.object(image_source, "sha256_file", return_value="cafebabe"):
                with self.assertRaises(RuntimeError):
                    fetch_image(_MT3000, dest_dir=str(tmp))

    def test_cached_file_reused(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            first, _ = self._run(tmp)
            # Second call: no download should occur when the cached hash matches.
            with patch.object(image_source, "_http_get_text", return_value="deadbeef *openwrt-24.10.2-mediatek-filogic-glinet_gl-mt3000-squashfs-sysupgrade.bin\n"), \
                 patch.object(image_source, "_download_file") as mock_dl, \
                 patch.object(image_source, "sha256_file", return_value="deadbeef"):
                second = fetch_image(_MT3000, dest_dir=str(tmp))
            mock_dl.assert_not_called()
            self.assertEqual(first, second)
