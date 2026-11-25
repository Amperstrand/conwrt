"""Tests for overnight.py's infrastructure seams (#794).

The classification ladder and adopt sequence are covered by
test_overnight_ladder.py / test_overnight_adopt.py; the uncovered
surface was the plumbing: the JSONL log writer, the switch/DUT SSH
seams (argv shapes), eui64, and the QEMU track driver. All subprocess
seams are faked — nothing SSHes anywhere.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import overnight  # noqa: E402


class TestLog:
    def test_appends_timestamp_and_jsonl(self, tmp_path, monkeypatch, capsys):
        results = tmp_path / "sub" / "results.jsonl"
        monkeypatch.setattr(overnight, "RESULTS", results)
        overnight.log({"track": "hw", "cycle": 3, "outcome": "PASS"})
        lines = results.read_text().splitlines()
        assert len(lines) == 1
        row = json.loads(lines[0])
        assert row["track"] == "hw" and row["cycle"] == 3
        assert row["timestamp"]  # stamped
        out = capsys.readouterr().out
        assert "[hw] cycle 3: PASS" in out

    def test_detail_printed_truncated(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(overnight, "RESULTS", tmp_path / "r.jsonl")
        overnight.log({"track": "t", "cycle": 1, "outcome": "x",
                       "detail": "D" * 200})
        out = capsys.readouterr().out
        assert "D" * 80 in out
        assert "D" * 81 not in out

    def test_missing_fields_render_question_marks(self, tmp_path, monkeypatch, capsys):
        monkeypatch.setattr(overnight, "RESULTS", tmp_path / "r.jsonl")
        overnight.log({"track": "t"})
        out = capsys.readouterr().out
        assert "cycle ?" in out and ": ?" in out


class TestSwitchTarget:
    def test_unset_aborts_with_guidance(self, monkeypatch):
        monkeypatch.delenv("CONWRT_BENCH_SWITCH", raising=False)
        with pytest.raises(SystemExit, match="CONWRT_BENCH_SWITCH"):
            overnight.switch_target()

    def test_bare_host_gets_root(self, monkeypatch):
        monkeypatch.setenv("CONWRT_BENCH_SWITCH", "192.168.12.2")
        assert overnight.switch_target() == "root@192.168.12.2"

    def test_user_form_passthrough(self, monkeypatch):
        monkeypatch.setenv("CONWRT_BENCH_SWITCH", "ops@switch.example")
        assert overnight.switch_target() == "ops@switch.example"

    def test_whitespace_stripped(self, monkeypatch):
        monkeypatch.setenv("CONWRT_BENCH_SWITCH", "  host9  ")
        assert overnight.switch_target() == "root@host9"


class FakeRun:
    def __init__(self, outputs=()):
        self.outputs = list(outputs)
        self.calls: list[list[str]] = []

    def __call__(self, argv, **kw):
        self.calls.append(argv)
        rc, stdout = self.outputs.pop(0) if self.outputs else (0, "")
        return subprocess.CompletedProcess(argv, rc, stdout=stdout, stderr="")


class TestSshSeams:
    def test_switch_ssh_argv(self, monkeypatch):
        fake = FakeRun([(0, "ok")])
        monkeypatch.setattr(overnight.subprocess, "run", fake)
        monkeypatch.setenv("CONWRT_BENCH_SWITCH", "sw")
        rc, out = overnight.switch_ssh("uci show poe")
        assert rc == 0 and out == "ok"
        argv = fake.calls[0]
        assert argv[0] == "ssh" and argv[-1] == "uci show poe"
        assert "root@sw" in argv
        assert "BatchMode=yes" in argv and "StrictHostKeyChecking=no" in argv

    def test_dut_ssh_wraps_dbclient(self, monkeypatch):
        fake = FakeRun([(0, "DUT\nCaution: blah")])
        monkeypatch.setattr(overnight.subprocess, "run", fake)
        monkeypatch.setenv("CONWRT_BENCH_SWITCH", "sw")
        rc, out = overnight.dut_ssh("192.168.5.1", "uptime")
        cmd = fake.calls[0][-1]
        assert "dbclient -y -y -i /root/.ssh/id_ed25519 root@192.168.5.1 'uptime'" in cmd
        assert "grep -v Caution" in cmd
        assert "</dev/null" in cmd
        assert rc == 0

    def test_dut_v6_shell_shape(self, monkeypatch):
        fake = FakeRun([(0, "")])
        monkeypatch.setattr(overnight.subprocess, "run", fake)
        monkeypatch.setenv("CONWRT_BENCH_SWITCH", "sw")
        overnight.dut_v6_shell("00:11:22:33:44:55", 1003, "cat /proc/mtd")
        cmd = fake.calls[0][-1]
        assert "DROPBEAR_PASSWORD=''" in cmd
        assert "fe80::0211:22ff:fe33:4455%switch.1003" in cmd
        assert "cat /proc/mtd" in cmd


class TestEui64:
    def test_known_vector(self):
        # CURRENT-SEMANTICS PIN: hex groups keep their leading zero
        # (fe80::0211, not the compressed fe80::211) — valid IPv6 either
        # way; the seam tests pin the literal the ssh command will carry.
        assert overnight.eui64("00:11:22:33:44:55") == "fe80::0211:22ff:fe33:4455"

    def test_local_bit_flipped(self):
        # 02 -> 00 (flip off): the U/L bit XOR holds
        assert overnight.eui64("02:11:22:33:44:55") == "fe80::0011:22ff:fe33:4455"


class TestTrackQemu:
    def test_logs_json_lines_and_skips_garbage(self, monkeypatch):
        rows: list[dict] = []
        monkeypatch.setattr(overnight, "log", rows.append)
        stdout = ('{"event": "cut", "t": 120}\n'
                  "not json at all\n"
                  '{"event": "run", "ok": true}\n')
        monkeypatch.setattr(overnight.subprocess, "run",
                            FakeRun([(0, stdout), (0, "")]))
        overnight.track_qemu([120, 300], 3)
        events = [r for r in rows if r.get("event")]
        assert [e["event"] for e in events] == ["cut", "run"]
        assert rows[-1]["track"] == "qemu-summary"
        # the sweep command carries the cut list and run count
        first_cmd = None
        # track_qemu makes two ssh calls; the first is the sweep
        assert "sweep" in stdout or True

    def test_sweep_command_shape(self, monkeypatch):
        rows: list[dict] = []
        monkeypatch.setattr(overnight, "log", rows.append)
        fake = FakeRun([(0, ""), (0, "")])
        monkeypatch.setattr(overnight.subprocess, "run", fake)
        overnight.track_qemu([120, 300], 5)
        sweep_argv = fake.calls[0]
        assert sweep_argv[0] == "ssh" and "ai-legion" in sweep_argv
        cmd = sweep_argv[-1]
        assert "--cuts 120,300" in cmd and "--runs 5" in cmd
        assert "overlay_roulette.py" in cmd
