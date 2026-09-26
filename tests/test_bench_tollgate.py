"""bench_tollgate — unit tests (hardware-safe; no network, no devices)."""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _SCRIPTS / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, mod)
    spec.loader.exec_module(mod)
    return mod


bt = _load("bench_tollgate")


PLACE = bt.Place("ap-lan4", "192.168.104.51")


class TestPlaceDerivation:
    def test_mnemonic_vlan(self) -> None:
        assert PLACE.vlan == 1004
        assert bt.Place("ap-lan7", "x").vlan == 1007

    def test_port(self) -> None:
        assert PLACE.port == "lan4"


class TestFlashSequence:
    def test_sysupgrade_is_dash_n_never_force(self) -> None:
        cmds = [" ".join(c) for c in bt.flash_sequence(PLACE, Path("img.fit"))]
        upgrade = [c for c in cmds if "sysupgrade" in c]
        assert upgrade and all("-n" in c for c in upgrade)
        assert not any("-F" in c or " --force" in c for c in cmds)

    def test_upload_uses_legacy_scp_protocol(self) -> None:
        scp = [" ".join(c) for c in bt.flash_sequence(PLACE, Path("img.fit"))
               if c[0] == "scp"][0]
        assert " -O " in scp


class TestGates:
    def test_flash_refuses_without_i_know(self, tmp_path: Path) -> None:
        img = tmp_path / "img.fit"
        img.write_bytes(b"x")
        rc = bt.main(["--place", "ap-lan4", "--dut-ip", "192.168.104.51",
                     "--coordinator", "coord.invalid:20408", "--switch", "switch.invalid",
                      "flash-baseline", "--image", str(img)])
        assert rc == 2

    def test_install_refuses_without_i_know(self, tmp_path: Path) -> None:
        ipk = tmp_path / "t.ipk"
        ipk.write_bytes(b"x")
        rc = bt.main(["--place", "ap-lan4", "--dut-ip", "192.168.104.51",
                     "--coordinator", "coord.invalid:20408", "--switch", "switch.invalid",
                      "install-ipk", "--ipk", str(ipk)])
        assert rc == 2

    def test_sha_mismatch_aborts_before_hardware(self, tmp_path: Path) -> None:
        img = tmp_path / "img.fit"
        img.write_bytes(b"x")
        rc = bt.main(["--place", "ap-lan4", "--dut-ip", "192.168.104.51",
                     "--coordinator", "coord.invalid:20408", "--switch", "switch.invalid",
                      "flash-baseline", "--image", str(img), "--i-know",
                      "--sha256", "0" * 64, "--tftproot", "/tmp/t"])
        assert rc == 1


class TestLifeline:
    def test_targets_place_vlan(self) -> None:
        cmd = " ".join(bt.lifeline_command(PLACE, bt.Config("c", "s"), Path("/tmp/t")))
        assert "switch.1004" in cmd
        assert "id 1004" in cmd
        assert "LIFELINE-ARMED" in cmd


def test_plan_lists_every_stage_without_hardware(capsys: pytest.CaptureFixture[str]) -> None:
    rc = bt.main(["--place", "ap-lan4", "--dut-ip", "192.168.104.51",
                     "--coordinator", "coord.invalid:20408", "--switch", "switch.invalid", "plan"])
    assert rc == 0
    out = capsys.readouterr().out
    for stage in ("power_cycle", "lifeline", "flash", "wait", "install", "logs"):
        assert stage in out


class TestLifelineSurvivalAndRequirement:
    def test_lifeline_daemonizes_instead_of_nohup_foreground(self) -> None:
        """nohup --no-daemon dies with the arming SSH session on BusyBox —
        the lifeline must self-daemonize and prove itself via pgrep."""
        cmd = " ".join(bt.lifeline_command(PLACE, bt.Config("c", "s"), Path("/tmp/t")))
        assert "nohup" not in cmd and "--no-daemon" not in cmd
        assert "pgrep" in cmd, "LIFELINE-ARMED must be earned, not echoed"

    def test_arm_lifeline_gates_on_marker_content(self, monkeypatch) -> None:
        class FakeProc:
            returncode = 0
            stdout = "LIFELINE-BROKEN\n"
            stderr = ""
        monkeypatch.setattr(bt.subprocess, "run", lambda *a, **k: FakeProc())
        assert bt.arm_lifeline(PLACE, bt.Config("c", "s"), Path("/tmp/t")) is False

    def test_flash_refuses_without_tftproot(self, tmp_path: Path) -> None:
        img = tmp_path / "img.fit"
        img.write_bytes(b"x")
        rc = bt.main(["--place", "ap-lan4", "--dut-ip", "192.168.104.51",
                      "--coordinator", "c.invalid:1", "--switch", "s.invalid",
                      "flash-baseline", "--image", str(img), "--i-know"])
        assert rc == 2


class TestSysupgradeRejection:
    def test_synchronous_sysupgrade_failure_aborts(self, tmp_path: Path,
                                                    monkeypatch) -> None:
        """sysupgrade exiting nonzero with the DUT still reachable is a
        validation rejection — the tool must abort, not poll a phantom."""
        img = tmp_path / "img.fit"
        img.write_bytes(b"image-bytes")

        class FakeProc:
            returncode = 1
            stdout = "Image check failed. Invalid image.\n"
            stderr = ""

        calls: list = []

        def fake_run(cmd, **k):
            calls.append(cmd if isinstance(cmd, str) else " ".join(cmd))
            joined = cmd if isinstance(cmd, str) else " ".join(cmd)
            if "pgrep" in joined:
                return FakeProc()  # lifeline arming: marker missing -> BROKEN path
            if "power" in joined or "acquire" in joined:
                return FakeProc()
            if "sysupgrade" in joined:
                return FakeProc()
            if joined.endswith("echo up") or " echo up" in joined:
                return types.SimpleNamespace(returncode=0, stdout="up\n", stderr="")
            return FakeProc()

        monkeypatch.setattr(bt.subprocess, "run", fake_run)
        monkeypatch.setattr(bt.time, "sleep", lambda s: None)

        class ArmTrue:
            def __call__(self, *a, **k):
                return True

        monkeypatch.setattr(bt, "arm_lifeline", ArmTrue())
        monkeypatch.setattr(bt, "wait_for_dut", lambda *a, **k: True)
        rc = bt.main(["--place", "ap-lan4", "--dut-ip", "192.168.104.51",
                      "--coordinator", "c.invalid:1", "--switch", "s.invalid",
                      "flash-baseline", "--image", str(img),
                      "--tftproot", "/tmp/t", "--i-know"])
        assert rc == 1, "a rejected sysupgrade with a reachable DUT must fail"
