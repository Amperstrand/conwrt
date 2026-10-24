"""Tests for conwrt.device_credentials + the configure-flow blank-password gate."""
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from conwrt import device_credentials as dc  # noqa: E402


def test_generate_charset_and_length():
    pw = dc.generate()
    assert len(pw) == 16
    assert pw.isalnum()
    assert dc.generate() != dc.generate()


def test_record_creates_0600_and_appends(tmp_path):
    path = tmp_path / "creds.jsonl"
    p1 = dc.record("pw-one", mac="aa:bb:cc:dd:ee:01", model="m", ip="1.2.3.4",
                   source="t", path=path)
    assert p1 == path
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600
    p2 = dc.record("pw-two", mac="aa:bb:cc:dd:ee:02", source="t", path=path)
    assert p2 == path
    lines = [json.loads(l) for l in path.read_text().splitlines()]
    assert [l["root_password"] for l in lines] == ["pw-one", "pw-two"]
    assert lines[0]["mac"] == "aa:bb:cc:dd:ee:01"


def test_record_tightens_loose_permissions(tmp_path):
    path = tmp_path / "creds.jsonl"
    path.write_text(" {}\n")
    path.chmod(0o644)
    dc.record("x", path=path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_record_env_override(tmp_path, monkeypatch):
    target = tmp_path / "env.jsonl"
    monkeypatch.setenv("CONWRT_CREDENTIALS_FILE", str(target))
    assert dc.credentials_path() == target
    dc.record("env-pw", source="t")
    assert "env-pw" in target.read_text()


def test_blank_detection():
    assert dc.is_blank("")
    assert dc.is_blank("\n")
    assert dc.is_blank("   ")
    assert not dc.is_blank("$6$rounds$salt$hash")
    assert not dc.is_blank("!"), "locked accounts are not blank-open"


def test_probe_and_set_commands():
    assert "shadow" in dc.blank_password_probe()
    assert "root" in dc.blank_password_probe()
    cmd = dc.set_password_cmd("abc123XYZ")
    assert cmd == "printf '%s\\n%s\\n' 'abc123XYZ' 'abc123XYZ' | passwd root"
    assert "address" in dc.mac_probe()


class _Resp:
    def __init__(self, out: str):
        self.stdout = out


def test_ensure_sets_records_and_verifies(monkeypatch, tmp_path):
    monkeypatch.setenv("CONWRT_CREDENTIALS_FILE", str(tmp_path / "c.jsonl"))
    import conwrt.commands_configure as cc

    calls = []
    replies = [
        _Resp(""),            # initial blank probe
        _Resp("2\n"),        # authorized_keys count (key present -> safe to harden)
        _Resp("password changed"),  # passwd set
        _Resp("$6$hash"),     # post-set verification (non-blank)
        _Resp("aa:bb:cc:00:11:22\n"),  # mac probe
    ]

    def fake_ssh(ip, cmd, key=None):
        calls.append(cmd)
        return replies.pop(0)

    monkeypatch.setattr(cc, "run_ssh", fake_ssh)
    logs = []
    cc._ensure_root_password("1.2.3.4", ssh_key=None, provided=None,
                             model_id="m1", log_fn=logs.append)
    assert any("passwd root" in c for c in calls)
    entry = json.loads((tmp_path / "c.jsonl").read_text().splitlines()[0])
    assert entry["mac"] == "aa:bb:cc:00:11:22"
    assert entry["source"] == "configure"
    assert entry["root_password"].isalnum()
    assert any("BLANK" in l for l in logs)


def test_ensure_skips_when_not_blank(monkeypatch, tmp_path):
    credfile = tmp_path / "c.jsonl"
    monkeypatch.setenv("CONWRT_CREDENTIALS_FILE", str(credfile))
    import conwrt.commands_configure as cc

    monkeypatch.setattr(cc, "run_ssh", lambda ip, cmd, key=None: _Resp("$6$hash"))
    cc._ensure_root_password("1.2.3.4", ssh_key=None, provided=None,
                             model_id="m", log_fn=lambda *_: None)
    assert not credfile.exists()


def test_ensure_records_explicit_password_when_set(monkeypatch, tmp_path):
    credfile = tmp_path / "c.jsonl"
    monkeypatch.setenv("CONWRT_CREDENTIALS_FILE", str(credfile))
    import conwrt.commands_configure as cc

    replies = [_Resp("$6$hash"), _Resp("aa:bb:cc:00:11:99\n")]
    monkeypatch.setattr(cc, "run_ssh",
                        lambda ip, cmd, key=None: replies.pop(0))
    cc._ensure_root_password("1.2.3.4", ssh_key=None, provided="op-chosen-pw",
                             model_id="m", log_fn=lambda *_: None)
    entry = json.loads(credfile.read_text().splitlines()[0])
    assert entry["root_password"] == "op-chosen-pw"
    assert entry["source"] == "configure-explicit"


def test_ensure_warns_when_set_fails(monkeypatch, tmp_path):
    monkeypatch.setenv("CONWRT_CREDENTIALS_FILE", str(tmp_path / "c.jsonl"))
    import conwrt.commands_configure as cc

    replies = [_Resp(""), _Resp("2\n"), _Resp(""), _Resp("")]
    monkeypatch.setattr(cc, "run_ssh", lambda ip, cmd, key=None: replies.pop(0))
    logs = []
    ok = cc._ensure_root_password("1.2.3.4", ssh_key=None, provided=None,
                                  model_id="m", log_fn=logs.append)
    assert not ok
    assert any("failed to set" in l for l in logs)
    assert not (tmp_path / "c.jsonl").exists()


def test_ensure_refuses_without_any_key(monkeypatch, tmp_path):
    """Bench pre-adoption state: blank password is the only door -> refuse to harden."""
    monkeypatch.setenv("CONWRT_CREDENTIALS_FILE", str(tmp_path / "c.jsonl"))
    import conwrt.commands_configure as cc

    replies = [_Resp(""), _Resp("0\n")]  # blank password, zero keys installed
    monkeypatch.setattr(cc, "run_ssh", lambda ip, cmd, key=None: replies.pop(0))
    logs = []
    ok = cc._ensure_root_password("1.2.3.4", ssh_key=None, provided=None,
                                  model_id="m", log_fn=logs.append)
    assert not ok
    assert any("pre-adoption" in l for l in logs)
    assert not (tmp_path / "c.jsonl").exists()


def test_ensure_proceeds_when_connected_with_key(monkeypatch, tmp_path):
    """Key in use (even with zero keys installed) -> safe to harden."""
    monkeypatch.setenv("CONWRT_CREDENTIALS_FILE", str(tmp_path / "c.jsonl"))
    import conwrt.commands_configure as cc

    replies = [_Resp(""), _Resp("0\n"), _Resp("ok"), _Resp("$6$h"), _Resp("aa:bb\n")]
    monkeypatch.setattr(cc, "run_ssh", lambda ip, cmd, key=None: replies.pop(0))
    ok = cc._ensure_root_password("1.2.3.4", ssh_key="/k", provided=None,
                                  model_id="m", log_fn=lambda *_: None)
    assert ok
    assert (tmp_path / "c.jsonl").exists()
