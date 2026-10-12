"""Tests for `conwrt image` — vanilla image sourcing subcommand."""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from conwrt.cmd_image import cmd_image


def _args(**overrides):
    defaults = dict(model_id="glinet-mt3000", release=None, dest=None, force=False,
                    image_suffix=None)
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


class TestCmdImage(TestCase):
    @patch("conwrt.cmd_image.fetch_image", return_value="/tmp/images/openwrt.bin")
    def test_success_prints_path(self, mock_fetch):
        rc = cmd_image(_args())
        self.assertEqual(rc, 0)
        mock_fetch.assert_called_once()
        self.assertEqual(mock_fetch.call_args[0][0], "glinet-mt3000")

    @patch("conwrt.cmd_image.fetch_image", return_value="/tmp/x.bin")
    def test_release_passed(self, mock_fetch):
        cmd_image(_args(release="25.12.5"))
        self.assertEqual(mock_fetch.call_args.kwargs.get("release"), "25.12.5")

    @patch("conwrt.cmd_image.fetch_image", return_value="/tmp/x.bin")
    def test_suffix_passed(self, mock_fetch):
        cmd_image(_args(image_suffix="squashfs-factory.bin"))
        self.assertEqual(mock_fetch.call_args.kwargs.get("suffix"), "squashfs-factory.bin")

    @patch("conwrt.cmd_image.fetch_image", side_effect=RuntimeError("boom"))
    def test_fetch_failure_returns_1(self, mock_fetch):
        self.assertEqual(cmd_image(_args()), 1)

    @patch("conwrt.cmd_image.resolve_release", side_effect=ValueError("bad release"))
    def test_bad_release_returns_1(self, mock_resolve):
        self.assertEqual(cmd_image(_args()), 1)
