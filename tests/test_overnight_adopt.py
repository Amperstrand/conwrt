"""overnight.adopt_unit — switch-key adoption tests (hardware-safe).

#291 twin of the bench_adopt fix: the adoption payload runs on a
factory-fresh DUT where /root/.ssh/id_ed25519.pub does not exist, so the
key must be read SWITCH-side and embedded in the payload.
"""

from __future__ import annotations

import subprocess

import pytest

import overnight

SWITCH_KEY = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJb4PBnGmVcWqX0OZ8pT"
              "+3QMq7dH2iWc1Rk0vKqZf1kQ root@switch")


def fake_switch_ssh(monkeypatch: pytest.MonkeyPatch, switch_has_key: bool):
    """Patch overnight.switch_ssh; capture every switch-side command."""
    calls: list[str] = []

    def switch_ssh(cmd: str, timeout: int = 60) -> tuple[int, str]:
        calls.append(cmd)
        if cmd == "cat /root/.ssh/id_ed25519.pub":
            return (0, SWITCH_KEY + "\n") if switch_has_key else (1, "")
        if "KEYS-OK" in cmd:
            return (0, "KEYS-OK")
        if "ADOPT-OK" in cmd:
            return (0, "ADOPT-OK")
        return (0, "")

    monkeypatch.setattr(overnight, "switch_ssh", switch_ssh)
    return calls


class TestAdoptUnitSwitchKey:
    def test_healthy_flow_embeds_switch_key(self, monkeypatch) -> None:
        calls = fake_switch_ssh(monkeypatch, switch_has_key=True)
        assert overnight.adopt_unit("192.168.104.51", "b4:2d:56:25:79:b1", 1004)
        assert calls[0] == "cat /root/.ssh/id_ed25519.pub", \
            "the switch's pubkey must be fetched switch-side first"
        keys_cmd = next(c for c in calls if "KEYS-OK" in c)
        assert "cat /root/.ssh/id_ed25519.pub >>" not in keys_cmd, \
            "payload runs on a factory DUT where that file does not exist"
        assert SWITCH_KEY in keys_cmd, "switch key content must be embedded"
        assert "grep -q" in keys_cmd, "dedup on the key prefix for idempotence"

    def test_missing_switch_key_refuses_adoption(self, monkeypatch, capsys) -> None:
        calls = fake_switch_ssh(monkeypatch, switch_has_key=False)
        assert overnight.adopt_unit("192.168.104.51", "b4:2d:56:25:79:b1", 1004) is False
        assert "refusing to adopt" in capsys.readouterr().out
        assert not any("KEYS-OK" in c for c in calls), \
            "must not push anything to the DUT without the switch key"

    def test_payload_installs_key_exactly_once_on_factory_stub(
            self, monkeypatch, tmp_path) -> None:
        calls = fake_switch_ssh(monkeypatch, switch_has_key=True)
        overnight.adopt_unit("192.168.104.51", "b4:2d:56:25:79:b1", 1004)
        keys_cmd = next(c for c in calls if "KEYS-OK" in c)
        # remote command = from 'mkdir' to the KEYS-OK echo (marker-extract:
        # the line carries several quotes — DROPBEAR_PASSWORD='', the remote
        # command, and embedded "key" quoting)
        remote = keys_cmd[keys_cmd.index("mkdir -p"):
                          keys_cmd.rindex("KEYS-OK") + len("KEYS-OK")]
        dut_etc = tmp_path / "factory-dut" / "etc" / "dropbear"
        remote = remote.replace("/etc/dropbear", str(dut_etc))
        for _ in range(2):  # idempotent across two adoption attempts
            subprocess.run(["/bin/sh", "-c", remote], check=True, capture_output=True)
        installed = (dut_etc / "authorized_keys").read_text()
        assert installed.count(SWITCH_KEY) == 1, \
            "switch key must land exactly once, not duplicate across runs"
