"""Tests for tollgate ipk resolution and deployment."""
from __future__ import annotations

import hashlib
import os
from unittest.mock import MagicMock, patch

import pytest

from use_cases.tollgate import (
    deploy_tollgate_post_flash,
    resolve_ipk_auto,
    resolve_ipk_nostr,
)


# =====================================================================
# resolve_ipk_nostr
# =====================================================================


class TestResolveIpkNostr:
    def test_success(self, tmp_path):
        dummy_content = b"dummy ipk content for testing"
        dummy_sha = hashlib.sha256(dummy_content).hexdigest()

        with patch("nostr_fetch.query_releases") as mock_query, \
             patch("use_cases.tollgate.urlretrieve") as mock_retrieve:
            mock_query.return_value = [{
                "url": "https://example.com/tollgate.ipk",
                "x": dummy_sha,
                "version": "v0.4.0",
                "created_at": 1700000000,
            }]

            def fake_retrieve(url, path):
                with open(path, "wb") as f:
                    f.write(dummy_content)

            mock_retrieve.side_effect = fake_retrieve

            result = resolve_ipk_nostr(
                arch="aarch64_cortex-a53", dest=str(tmp_path),
            )

            expected = str(tmp_path / "tollgate.ipk")
            assert result == expected
            assert os.path.exists(result)

    def test_no_releases(self, tmp_path):
        with patch("nostr_fetch.query_releases") as mock_query:
            mock_query.return_value = []

            with pytest.raises(RuntimeError, match="No nostr releases found"):
                resolve_ipk_nostr(arch="aarch64_cortex-a53", dest=str(tmp_path))

    def test_sha256_mismatch(self, tmp_path):
        with patch("nostr_fetch.query_releases") as mock_query, \
             patch("use_cases.tollgate.urlretrieve") as mock_retrieve:
            mock_query.return_value = [{
                "url": "https://example.com/tollgate.ipk",
                "x": "0000000000000000000000000000000000000000000000000000000000000000",
                "version": "v0.4.0",
                "created_at": 1700000000,
            }]

            def fake_retrieve(url, path):
                with open(path, "wb") as f:
                    f.write(b"content that will not match the fake hash")

            mock_retrieve.side_effect = fake_retrieve

            with pytest.raises(RuntimeError, match="SHA-256 mismatch"):
                resolve_ipk_nostr(arch="aarch64_cortex-a53", dest=str(tmp_path))

            # File must be deleted on mismatch
            ipk = str(tmp_path / "tollgate.ipk")
            assert not os.path.exists(ipk)

    def test_version_not_found(self, tmp_path):
        with patch("nostr_fetch.query_releases") as mock_query:
            mock_query.return_value = [
                {"url": "https://a.ipk", "x": "a1", "version": "v0.3.0", "created_at": 100},
                {"url": "https://b.ipk", "x": "b2", "version": "v0.4.0", "created_at": 200},
            ]

            with pytest.raises(RuntimeError, match="not found"):
                resolve_ipk_nostr(
                    arch="aarch64_cortex-a53",
                    version="v0.99.0",
                    dest=str(tmp_path),
                )


# =====================================================================
# resolve_ipk_auto
# =====================================================================


class TestResolveIpkAuto:
    @patch("use_cases.tollgate.resolve_ipk_gh")
    @patch("use_cases.tollgate.resolve_ipk_nostr")
    def test_nostr_first(self, mock_nostr, mock_gh):
        mock_nostr.return_value = "/tmp/tollgate.ipk"

        result = resolve_ipk_auto(arch="aarch64_cortex-a53")

        assert result == "/tmp/tollgate.ipk"
        mock_nostr.assert_called_once()
        mock_gh.assert_not_called()

    @patch("use_cases.tollgate.resolve_ipk_gh")
    @patch("use_cases.tollgate.resolve_ipk_nostr")
    def test_fallback_to_gh(self, mock_nostr, mock_gh):
        mock_nostr.side_effect = RuntimeError("nostr down")
        mock_gh.return_value = "/tmp/tollgate.gh.ipk"

        result = resolve_ipk_auto(arch="aarch64_cortex-a53")

        assert result == "/tmp/tollgate.gh.ipk"
        mock_gh.assert_called_once()

    @patch("use_cases.tollgate.resolve_ipk_gh")
    @patch("use_cases.tollgate.resolve_ipk_nostr")
    def test_github_source(self, mock_nostr, mock_gh):
        mock_gh.return_value = "/tmp/tollgate.gh.ipk"

        result = resolve_ipk_auto(arch="aarch64_cortex-a53", source="github")

        assert result == "/tmp/tollgate.gh.ipk"
        mock_gh.assert_called_once()
        mock_nostr.assert_not_called()

    @patch("use_cases.tollgate.resolve_ipk_gh")
    @patch("use_cases.tollgate.resolve_ipk_nostr")
    def test_nostr_source_no_fallback(self, mock_nostr, mock_gh):
        mock_nostr.side_effect = RuntimeError("nostr down")

        with pytest.raises(RuntimeError, match="nostr down"):
            resolve_ipk_auto(arch="aarch64_cortex-a53", source="nostr")

        mock_gh.assert_not_called()


# =====================================================================
# deploy_tollgate_post_flash
# =====================================================================


class TestDeployTollgatePostFlash:
    @patch("subprocess.run")
    @patch("ssh_utils.ssh_cmd")
    @patch("use_cases.tollgate.resolve_ipk_auto")
    def test_success(self, mock_resolve, mock_ssh_cmd, mock_run):
        mock_resolve.return_value = "/tmp/tollgate.ipk"
        mock_ssh_cmd.return_value = ["ssh", "root@1.2.3.4", "opkg install"]
        mock_run.side_effect = [
            MagicMock(returncode=0, stderr=""),   # SCP
            MagicMock(returncode=0, stderr=""),   # install
        ]

        result = deploy_tollgate_post_flash(
            ip="1.2.3.4",
            arch="aarch64_cortex-a53",
        )

        assert result is True

    @patch("subprocess.run")
    @patch("ssh_utils.ssh_cmd")
    @patch("use_cases.tollgate.resolve_ipk_auto")
    def test_detect_arch(self, mock_resolve, mock_ssh_cmd, mock_run):
        mock_ssh_cmd.return_value = ["ssh", "root@1.2.3.4", "detect"]
        mock_resolve.return_value = "/tmp/tollgate.ipk"
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="aarch64_cortex-a53\n", stderr=""),  # detect
            MagicMock(returncode=0, stderr=""),   # SCP
            MagicMock(returncode=0, stderr=""),   # install
        ]

        result = deploy_tollgate_post_flash(ip="1.2.3.4", arch="")

        assert result is True
        mock_resolve.assert_called_once_with(
            arch="aarch64_cortex-a53",
            channel="stable",
            version="latest",
            source="auto",
        )

    @patch("subprocess.run")
    @patch("ssh_utils.ssh_cmd")
    @patch("use_cases.tollgate.resolve_ipk_auto")
    def test_scp_failure(self, mock_resolve, mock_ssh_cmd, mock_run):
        mock_resolve.return_value = "/tmp/tollgate.ipk"
        mock_run.return_value = MagicMock(returncode=1, stderr="SCP failed")

        result = deploy_tollgate_post_flash(
            ip="1.2.3.4",
            arch="aarch64_cortex-a53",
        )

        assert result is False

    @patch("subprocess.run")
    @patch("ssh_utils.ssh_cmd")
    @patch("use_cases.tollgate.resolve_ipk_auto")
    def test_install_failure(self, mock_resolve, mock_ssh_cmd, mock_run):
        mock_resolve.return_value = "/tmp/tollgate.ipk"
        mock_ssh_cmd.return_value = ["ssh", "root@1.2.3.4", "opkg install"]
        mock_run.side_effect = [
            MagicMock(returncode=0, stderr=""),                # SCP succeeds
            MagicMock(returncode=1, stderr="Install failed"),  # install fails
        ]

        result = deploy_tollgate_post_flash(
            ip="1.2.3.4",
            arch="aarch64_cortex-a53",
        )

        assert result is False
