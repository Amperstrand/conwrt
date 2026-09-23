"""bench_tollgate — unit tests (hardware-safe; no network, no devices)."""

from __future__ import annotations

import importlib.util
import sys
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
                      "--sha256", "0" * 64])
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
