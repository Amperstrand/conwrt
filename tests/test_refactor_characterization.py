"""Characterization tests pinning behavior across the conservative refactor.

These tests lock in the observable behavior of helpers that are being
de-duplicated or relocated (SSH wrappers, SSH-pubkey parsing, file hashing,
the local check_ssh probe). They must stay green at every phase so the
consolidations are provably behavior-preserving.
"""
from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def _load_firmware_manager():
    spec = importlib.util.spec_from_file_location(
        "firmware_manager", ROOT / "scripts" / "firmware-manager.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


# ── conwrt.check_ssh probe ───────────────────────────────────────────────

def test_check_ssh_true_when_sentinel_in_stdout() -> None:
    import conwrt
    with patch("conwrt.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="SSH_OK\n", stderr="")
        assert conwrt.check_ssh("192.168.1.1") is True
    # The probe command is the SSH_OK echo (distinct from flash.detect.check_ssh).
    argv = mock_run.call_args.args[0]
    assert argv[0] == "ssh"
    assert "echo SSH_OK" in argv


def test_check_ssh_false_when_sentinel_absent() -> None:
    import conwrt
    with patch("conwrt.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="nope", stderr="")
        assert conwrt.check_ssh("192.168.1.1") is False


def test_check_ssh_false_on_exception() -> None:
    import conwrt
    with patch("conwrt.subprocess.run", side_effect=OSError("boom")):
        assert conwrt.check_ssh("192.168.1.1") is False


# ── ssh_utils.run_ssh wrapper ──────────────────────────────────────────────

def test_ssh_run_builds_expected_argv() -> None:
    with patch("ssh_utils.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        from ssh_utils import run_ssh
        run_ssh("10.0.0.2", "uci show network", key="/tmp/id", timeout=15)
    argv = mock_run.call_args.args[0]
    assert argv[0] == "ssh"
    assert "root@10.0.0.2" in argv
    assert "uci show network" in argv
    assert "-i" in argv and "/tmp/id" in argv
    assert mock_run.call_args.kwargs["timeout"] == 15


def test_ssh_run_without_key_omits_identity_flag() -> None:
    with patch("ssh_utils.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        from ssh_utils import run_ssh
        run_ssh("10.0.0.2", "echo hi")
    argv = mock_run.call_args.args[0]
    assert "-i" not in argv


# ── SHA-256 file hashing (3 implementations must agree) ──────────────────

def test_sha256_file_implementations_agree(tmp_path: Path) -> None:
    from flash.context import sha256_file
    fm = _load_firmware_manager()

    payload = b"conwrt-refactor-characterization\x00\x01\x02" * 4096
    f = tmp_path / "blob.bin"
    f.write_bytes(payload)

    expected = hashlib.sha256(payload).hexdigest()
    assert sha256_file(str(f)) == expected
    assert fm._sha256_file(f) == expected


# ── SSH public-key comment stripping ─────────────────────────────────────

def test_strip_key_comment_drops_trailing_comment() -> None:
    from config import _strip_key_comment
    assert _strip_key_comment("ssh-ed25519 AAAAC3Nz user@host") == "ssh-ed25519 AAAAC3Nz"


def test_strip_key_comment_keeps_bare_key() -> None:
    from config import _strip_key_comment
    assert _strip_key_comment("ssh-ed25519 AAAAC3Nz") == "ssh-ed25519 AAAAC3Nz"


def test_strip_key_comment_single_token_unchanged() -> None:
    from config import _strip_key_comment
    assert _strip_key_comment("  weirdtoken  ") == "weirdtoken"


def test_public_strip_key_comment_alias_is_canonical() -> None:
    from config import _strip_key_comment, strip_key_comment
    assert strip_key_comment is _strip_key_comment


def test_read_ssh_pubkey_strips_comment_and_returns_name(tmp_path: Path) -> None:
    from config import read_ssh_pubkey
    key_file = tmp_path / "id_ed25519.pub"
    key_file.write_text("ssh-ed25519 AAAAC3NzaABCDEF operator@laptop\n")
    cleaned, source = read_ssh_pubkey(str(key_file))
    assert cleaned == "ssh-ed25519 AAAAC3NzaABCDEF"
    assert source == "id_ed25519.pub"
