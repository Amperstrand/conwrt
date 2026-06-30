"""Tests for conwrt.extreme_helpers — extracted pure utility functions."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from conwrt.extreme_helpers import (
    _parse_key_value_lines,
    _sanitize_filename_part,
    _ssh_with_password,
    _scp_with_password,
    _generate_zyxel_password,
)


class TestParseKeyValueLines(TestCase):
    def test_simple_key_value(self):
        self.assertEqual(_parse_key_value_lines("KEY=VALUE"), {"KEY": "VALUE"})

    def test_multiple_lines(self):
        result = _parse_key_value_lines("A=1\nB=2\nC=3")
        self.assertEqual(result, {"A": "1", "B": "2", "C": "3"})

    def test_value_contains_equals(self):
        self.assertEqual(_parse_key_value_lines("KEY=VAL=UE"), {"KEY": "VAL=UE"})

    def test_empty_lines_skipped(self):
        result = _parse_key_value_lines("A=1\n\nB=2\n")
        self.assertEqual(result, {"A": "1", "B": "2"})

    def test_lines_without_equals_skipped(self):
        result = _parse_key_value_lines("A=1\nNOEQUALS\nB=2")
        self.assertEqual(result, {"A": "1", "B": "2"})

    def test_whitespace_stripped(self):
        result = _parse_key_value_lines("  A = 1 \n B = 2 ")
        self.assertEqual(result, {"A": "1", "B": "2"})

    def test_empty_string(self):
        self.assertEqual(_parse_key_value_lines(""), {})


class TestSanitizeFilenamePart(TestCase):
    def test_simple_string(self):
        self.assertEqual(_sanitize_filename_part("hello"), "hello")

    def test_spaces_replaced(self):
        self.assertEqual(_sanitize_filename_part("hello world"), "hello-world")

    def test_special_chars_replaced(self):
        self.assertEqual(_sanitize_filename_part("foo/bar:baz"), "foo-bar-baz")

    def test_dashes_trimmed(self):
        self.assertEqual(_sanitize_filename_part("---foo---"), "foo")

    def test_empty_string_returns_unknown(self):
        self.assertEqual(_sanitize_filename_part(""), "unknown")

    def test_whitespace_only_returns_unknown(self):
        self.assertEqual(_sanitize_filename_part("  "), "unknown")


class TestSshWithPassword(TestCase):
    @patch("conwrt.extreme_helpers.shutil.which", return_value="/usr/local/bin/sshpass")
    @patch("conwrt.extreme_helpers.subprocess.run")
    def test_successful_ssh(self, mock_run, mock_which):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="ok", stderr=""
        )
        result = _ssh_with_password("1.2.3.4", "admin", "secret", "ls")
        self.assertEqual(result.returncode, 0)
        cmd = mock_run.call_args[0][0]
        self.assertIn("/usr/local/bin/sshpass", cmd)
        self.assertIn("-p", cmd)
        self.assertIn("secret", cmd)
        self.assertIn("admin@1.2.3.4", cmd)
        self.assertIn("ls", cmd)

    @patch("conwrt.extreme_helpers.shutil.which", return_value=None)
    def test_sshpass_not_found(self, mock_which):
        result = _ssh_with_password("1.2.3.4", "admin", "secret", "ls")
        self.assertEqual(result.returncode, 127)

    @patch("conwrt.extreme_helpers.shutil.which", return_value="/usr/local/bin/sshpass")
    @patch("conwrt.extreme_helpers.subprocess.run")
    def test_extra_ssh_options_passed_through(self, mock_run, mock_which):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        _ssh_with_password("1.2.3.4", "admin", "pw", "cmd",
                           extra_ssh_options=["-o", "KexAlgorithms=+diffie-hellman-group1-sha1"])
        cmd = mock_run.call_args[0][0]
        self.assertIn("-o", cmd)
        self.assertIn("KexAlgorithms=+diffie-hellman-group1-sha1", cmd)


class TestScpWithPassword(TestCase):
    @patch("conwrt.extreme_helpers.shutil.which", return_value="/usr/local/bin/sshpass")
    @patch("conwrt.extreme_helpers.subprocess.run")
    def test_successful_scp(self, mock_run, mock_which):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        result = _scp_with_password("1.2.3.4", "admin", "secret", "/tmp/remote", "/tmp/local")
        self.assertEqual(result.returncode, 0)
        cmd = mock_run.call_args[0][0]
        # Verify scp -O flag present
        self.assertIn("scp", cmd)
        o_idx = cmd.index("scp")
        self.assertEqual(cmd[o_idx + 1], "-O")
        # Verify remote path format user@ip:remote_src
        self.assertIn("admin@1.2.3.4:/tmp/remote", cmd)

    @patch("conwrt.extreme_helpers.shutil.which", return_value=None)
    def test_sshpass_not_found(self, mock_which):
        result = _scp_with_password("1.2.3.4", "admin", "secret", "/tmp/remote", "/tmp/local")
        self.assertEqual(result.returncode, 127)

    @patch("conwrt.extreme_helpers.shutil.which", return_value="/usr/local/bin/sshpass")
    @patch("conwrt.extreme_helpers.subprocess.run")
    def test_extra_ssh_options_passed_through(self, mock_run, mock_which):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        _scp_with_password("1.2.3.4", "admin", "pw", "/tmp/r", "/tmp/l",
                           extra_ssh_options=["-o", "KexAlgorithms=+diffie-hellman-group1-sha1"])
        cmd = mock_run.call_args[0][0]
        self.assertIn("KexAlgorithms=+diffie-hellman-group1-sha1", cmd)


class TestGenerateZyxelPassword(TestCase):
    @patch("conwrt.extreme_helpers.shutil.which", return_value="/usr/local/bin/zyxel_pwgen")
    @patch("conwrt.extreme_helpers.subprocess.run")
    def test_takes_last_line(self, mock_run, mock_which):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="line1\nline2\nthe_password\n", stderr=""
        )
        result = _generate_zyxel_password("ABC123")
        self.assertEqual(result, "the_password")

    @patch("conwrt.extreme_helpers.shutil.which", return_value=None)
    def test_tool_not_found(self, mock_which):
        self.assertIsNone(_generate_zyxel_password("ABC123"))

    @patch("conwrt.extreme_helpers.shutil.which", return_value="/usr/local/bin/zyxel_pwgen")
    @patch("conwrt.extreme_helpers.subprocess.run")
    def test_subprocess_fails(self, mock_run, mock_which):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="error"
        )
        self.assertIsNone(_generate_zyxel_password("ABC123"))

    @patch("conwrt.extreme_helpers.shutil.which", return_value="/usr/local/bin/zyxel_pwgen")
    @patch("conwrt.extreme_helpers.subprocess.run", side_effect=OSError("nope"))
    def test_oserror_returns_none(self, mock_run, mock_which):
        self.assertIsNone(_generate_zyxel_password("ABC123"))
