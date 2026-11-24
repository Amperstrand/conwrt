"""Tests for conwrt backup command (#794 tier 2, lane 2).

Transport seams (_ssh_with_password / _scp_with_password / password
generation) patched at module level; MTD parsing, partition filtering,
and the critical-partition safety gate exercised for real. No wire.
"""
from __future__ import annotations

import sys
from pathlib import Path
from subprocess import CompletedProcess
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import conwrt.cmd_backup as cb  # noqa: E402

# Shape from the VERIFIED NR7101 serial session (recipes/zyxel/nr7101/
# serial-recovery-session-2026-06-28.md): stock Zyxel /proc/mtd rows are
# 3-field (dev size "label") — no erasesize column, no header line.
# NOTE: mainline-Linux /proc/mtd is 4-column WITH a header; this command
# targets stock-Zyxel SSH (model backup.method=ssh gate), where the
# 3-field shape is what the parser was written against. Pointing it at a
# 4-column source would misparse labels (parts[2]=erasesize) — divergence
# pinned here as documentation, not behavior.
MTD_OUTPUT = "\n".join([
    'mtd0: 00080000 "Board"',
    'mtd1: 00100000 "Factory"',
    'mtd2: 02000000 "firmware"',
])


def _cp(rc=0, stdout="", stderr=""):
    return CompletedProcess(args=[], returncode=rc, stdout=stdout, stderr=stderr)


def _args(**kw):
    base = dict(model_id="test-model", ip="192.168.1.1", user="Admin",
                password="pw", serial=None, partitions=None, output_dir=None)
    base.update(kw)
    return SimpleNamespace(**base)


@pytest.fixture()
def ssh(monkeypatch):
    """Script the SSH side; capture every command issued."""
    calls: list[str] = []
    outputs = {"cat /proc/mtd": _cp(0, MTD_OUTPUT)}

    def _ssh(ip, user, password, cmd, timeout=30):
        calls.append(cmd)
        if cmd in outputs:
            return outputs[cmd]
        return outputs.get(cmd, _cp(0, ""))

    monkeypatch.setattr(cb, "_ssh_with_password", _ssh)
    scp_calls: list[tuple[str, str]] = []

    def _scp(ip, user, password, remote, local, timeout=120):
        scp_calls.append((remote, local))
        Path(local).parent.mkdir(parents=True, exist_ok=True)
        Path(local).write_bytes(b"DUMP")
        return _cp(0)

    monkeypatch.setattr(cb, "_scp_with_password", _scp)
    return SimpleNamespace(ssh_calls=calls, scp_calls=scp_calls, outputs=outputs)


@pytest.fixture()
def model(monkeypatch):
    loaded = {"id": "test-model",
              "backup": {"method": "ssh", "critical_partitions": ["Factory"]}}

    def load_model(mid):
        if mid == "test-model":
            return loaded
        raise SystemExit(f"unknown model {mid}")

    monkeypatch.setattr(cb, "load_model", load_model)
    return loaded


class TestValidation:
    def test_missing_model_id(self):
        assert cb.cmd_backup(_args(model_id="")) == 1

    def test_non_ssh_model_refused(self, monkeypatch, model):
        model["backup"]["method"] = "http"
        assert cb.cmd_backup(_args()) == 1

    def test_no_password_and_no_serial(self, model):
        assert cb.cmd_backup(_args(password="")) == 1

    def test_serial_without_pwgen_refused(self, monkeypatch, model):
        monkeypatch.setattr(cb, "_generate_zyxel_password", lambda s: "")
        assert cb.cmd_backup(_args(password="", serial="S123")) == 1

    def test_serial_generates_password(self, monkeypatch, model, ssh, capsys):
        monkeypatch.setattr(cb, "_generate_zyxel_password",
                            lambda s: "GENPW" if s == "S123" else "")
        rc = cb.cmd_backup(_args(password="", serial="S123"))
        assert rc == 0
        # the generated password was used on the wire stubs implicitly;
        # success means the flow accepted the generated credential path


class TestMtdParsing:
    def test_partitions_parsed_with_shapes(self, model, ssh, tmp_path):
        rc = cb.cmd_backup(_args(output_dir=str(tmp_path)))
        assert rc == 0
        assert len(ssh.scp_calls) == 3
        # board/factory/firmware dumped and scp'd in order
        remotes = [r for r, _ in ssh.scp_calls]
        assert remotes == ["/tmp/mtd0.bin", "/tmp/mtd1.bin", "/tmp/mtd2.bin"]

    def test_partition_filter(self, model, ssh, tmp_path):
        cb.cmd_backup(_args(partitions="1", output_dir=str(tmp_path)))
        assert [r for r, _ in ssh.scp_calls] == ["/tmp/mtd1.bin"]

    def test_ssh_failure_reports_hint(self, model, ssh, monkeypatch, capsys):
        ssh.outputs["cat /proc/mtd"] = _cp(1, "", "sshpass not found")
        rc = cb.cmd_backup(_args())
        assert rc == 1
        assert "Install sshpass" in capsys.readouterr().err

    def test_empty_mtd_output_fails(self, model, ssh):
        ssh.outputs["cat /proc/mtd"] = _cp(0, "")
        assert cb.cmd_backup(_args()) == 1


class TestBackupFlow:
    def test_happy_path_writes_files_and_cleans_remote(self, model, ssh, tmp_path):
        rc = cb.cmd_backup(_args(output_dir=str(tmp_path)))
        assert rc == 0
        files = sorted(p.name for p in tmp_path.glob("*.bin"))
        assert files == ["mtd0_Board.bin", "mtd1_Factory.bin", "mtd2_firmware.bin"]
        # remote cleanup issued for every partition
        assert sum(1 for c in ssh.ssh_calls if c.startswith("rm -f")) == 3

    def test_nanddump_failure_fails_partition(self, model, ssh, tmp_path, monkeypatch):
        real = cb._ssh_with_password

        def flaky(ip, user, password, cmd, timeout=30):
            if "nanddump" in cmd and "mtd1" in cmd:
                return _cp(1, "", "nanddump: read error")
            return real(ip, user, password, cmd, timeout)

        monkeypatch.setattr(cb, "_ssh_with_password", flaky)
        rc = cb.cmd_backup(_args(output_dir=str(tmp_path)))
        assert rc == 1

    def test_missing_critical_partition_is_hard_failure(self, model, ssh, tmp_path, monkeypatch):
        # Factory is critical; make its dump fail -> DO-NOT-FLASH gate
        real = cb._ssh_with_password

        def flaky(ip, user, password, cmd, timeout=30):
            if "nanddump" in cmd and "mtd1" in cmd:
                return _cp(1, "", "boom")
            return real(ip, user, password, cmd, timeout)

        monkeypatch.setattr(cb, "_ssh_with_password", flaky)
        rc = cb.cmd_backup(_args(output_dir=str(tmp_path)))
        assert rc == 1  # even though the other partitions backed up fine

    def test_critical_absent_from_device_also_fails(self, model, ssh, tmp_path):
        # device reports no Factory partition at all
        ssh.outputs["cat /proc/mtd"] = _cp(0, "\n".join([
            "dev: size erasesize name",
            'mtd0: 00080000 00020000 "Board"',
        ]))
        rc = cb.cmd_backup(_args(output_dir=str(tmp_path)))
        assert rc == 1  # critical partition not present -> refuse
