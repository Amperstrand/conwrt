"""conwrt_tui + maas_qemu_test + test_blankdl_fence (#763 P3, final trio).

conwrt_tui: the rendering helpers' ANSI shapes, run_conwrt /
run_conwrt_capture subprocess wrappers (returncode contract, launch
failure -> 1/None without raising), and one menu action end-to-end
against a stubbed model loader.

maas_qemu_test: the pre-flight checks (KVM path, bridge STP + port
enslavement via fake /sys trees) and the QEMU command shape (KVM vs
no-KVM, bridge netdev, PXE boot order, headless flags).

test_blankdl_fence: the fence regression script itself, pinned in
the fast tier as a subprocess run (loopback-only UDP; the 2026-11-08
off-by-one guard).
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import conwrt_tui as tui  # noqa: E402
import maas_qemu_test as mq  # noqa: E402


class TestTuiHelpers:
    def test_dim_wraps_with_reset(self):
        out = tui.dim("x")
        assert out.startswith(tui.Color.DIM)
        assert out.endswith(tui.Color.RESET)

    def test_header_prints_ruler(self, capsys):
        tui.header("Devices")
        out = capsys.readouterr().out
        assert "Devices" in out
        assert "=======" in out  # the under-ruler matches the text length
        assert tui.Color.CYAN in out

    def test_success_warning_error_colors(self, capsys):
        tui.success("s"); tui.warning("w"); tui.error("e")
        out = capsys.readouterr().out
        assert tui.Color.GREEN in out
        assert tui.Color.YELLOW in out
        assert tui.Color.RED in out

    def test_pause_swallows_eof(self, monkeypatch):
        # non-interactive contexts (EOF) must not raise
        monkeypatch.setattr("builtins.input", lambda *a: (_ for _ in ()).throw(EOFError))
        tui.pause()

    def test_pause_swallows_interrupt(self, monkeypatch):
        monkeypatch.setattr("builtins.input",
                            lambda *a: (_ for _ in ()).throw(KeyboardInterrupt))
        tui.pause()


class TestRunConwrt:
    def test_returncode_passthrough(self, monkeypatch, capsys):
        fake = subprocess.CompletedProcess(args=[], returncode=3,
                                            stdout="", stderr="")
        monkeypatch.setattr(tui.subprocess, "run", lambda *a, **kw: fake)
        assert tui.run_conwrt(["list"]) == 3
        assert "exited with code 3" in capsys.readouterr().out

    def test_launch_failure_returns_1_not_raise(self, monkeypatch):
        def boom(*a, **kw):
            raise FileNotFoundError("no conwrt.py")
        monkeypatch.setattr(tui.subprocess, "run", boom)
        assert tui.run_conwrt(["list"]) == 1

    def test_capture_none_on_launch_failure(self, monkeypatch):
        def boom(*a, **kw):
            raise FileNotFoundError("no")
        monkeypatch.setattr(tui.subprocess, "run", boom)
        assert tui.run_conwrt_capture(["list"]) is None

    def test_capture_returns_completed(self, monkeypatch):
        fake = subprocess.CompletedProcess(args=[], returncode=0,
                                            stdout="out", stderr="")
        monkeypatch.setattr(tui.subprocess, "run", lambda *a, **kw: fake)
        assert tui.run_conwrt_capture(["list"]) is fake


class TestActionBrowseDevices:
    def test_renders_model_rows(self, monkeypatch, capsys):
        import model_loader
        fake_models = [
            {"id": "a-model", "vendor": "VendA", "description": "model A",
             "openwrt": {"target": "ath79/generic"},
             "flash_methods": {"sysupgrade": {"description": "d"}}},
            {"id": "b-model", "vendor": "VendB", "description": "model B",
             "openwrt": {"target": "ipq40xx/generic"}, "flash_methods": {}},
        ]
        monkeypatch.setattr(model_loader, "list_models", lambda: fake_models)
        monkeypatch.setattr(tui, "pause", lambda: None)
        tui.action_browse_devices()
        out = capsys.readouterr().out
        assert "a-model" in out and "VendA" in out
        assert "b-model" in out


# --- maas_qemu_test ---------------------------------------------------------

class _KvmFakePath:
    """Path replacement scoped to the module under test — patching
    pathlib.Path itself would break pytest's own machinery."""

    present = True

    def __init__(self, p):
        self.p = str(p)

    def exists(self):
        return self.p == "/dev/kvm" and _KvmFakePath.present


class TestCheckKvm:
    def test_true_when_dev_kvm(self, monkeypatch):
        _KvmFakePath.present = True
        monkeypatch.setattr(mq, "Path", _KvmFakePath)
        assert mq.check_kvm() is True

    def test_false_when_missing(self, monkeypatch):
        _KvmFakePath.present = False
        monkeypatch.setattr(mq, "Path", _KvmFakePath)
        assert mq.check_kvm() is False


class TestCheckBridge:
    def _fake_sys(self, tmp_path, bridge, stp=None, ports=("eth9",)):
        # the patched Path maps the ABSOLUTE /sys/class/net/<bridge>
        # request into this tree (re-root via lstrip)
        b = tmp_path / "sys" / "class" / "net" / bridge
        b.mkdir(parents=True)
        (b / "bridge").mkdir()
        if stp is not None:
            (b / "bridge" / "stp_state").write_text(stp)
        brif = b / "brif"
        brif.mkdir()
        for p in ports:
            (brif / p).touch()
        return tmp_path

    def _patch_sys(self, monkeypatch, tmp_path):
        base = tmp_path

        def fake_path(p):
            return base / str(p).lstrip("/")

        monkeypatch.setattr(mq, "Path", fake_path)

    def test_missing_bridge(self, tmp_path, monkeypatch):
        self._fake_sys(tmp_path, "br0")  # some OTHER bridge exists
        self._patch_sys(monkeypatch, tmp_path)
        ok, why = mq.check_bridge("br-missing")
        assert not ok and "does not exist" in why

    def test_stp_enabled_rejected_with_fix_hint(self, tmp_path, monkeypatch):
        self._fake_sys(tmp_path, "br0", stp="1")
        self._patch_sys(monkeypatch, tmp_path)
        ok, why = mq.check_bridge("br0")
        assert not ok and "STP enabled" in why and "stp_state 0" in why

    def test_no_ports_rejected(self, tmp_path, monkeypatch):
        self._fake_sys(tmp_path, "br0", stp="0", ports=())
        self._patch_sys(monkeypatch, tmp_path)
        ok, why = mq.check_bridge("br0")
        assert not ok and "no ports" in why

    def test_ready_bridge(self, tmp_path, monkeypatch):
        self._fake_sys(tmp_path, "br0", stp="0", ports=("eth9", "eth10"))
        self._patch_sys(monkeypatch, tmp_path)
        ok, why = mq.check_bridge("br0")
        assert ok and "2 ports" in why


class TestBuildQemuCmd:
    def test_kvm_shape(self):
        cmd = mq.build_qemu_cmd("br-maas", kvm=True, memory_mb=2048, cpus=2)
        assert cmd[0] == "qemu-system-x86_64"
        assert "-enable-kvm" in cmd and "host" in cmd
        assert "-smp" in cmd and "2" in cmd
        assert f"bridge,br=br-maas,id=net0" in cmd
        assert "-boot" in cmd and "n" in cmd  # PXE boot order

    def test_no_kvm_still_buildable(self, capsys):
        cmd = mq.build_qemu_cmd("br-maas", kvm=False, memory_mb=1024, cpus=1)
        assert "-enable-kvm" not in cmd
        assert "-cpu" not in cmd
        assert "WARNING" in capsys.readouterr().out


class TestSshChecks:
    def test_check_ssh_to_maas(self, monkeypatch):
        monkeypatch.setattr(
            mq.subprocess, "run",
            lambda cmd, **kw: SimpleNamespace(returncode=0))
        assert mq.check_ssh_to_maas("10.9.9.9") is True

    def test_query_maas_machines_parses_count(self, monkeypatch):
        monkeypatch.setattr(
            mq.subprocess, "run",
            lambda cmd, **kw: SimpleNamespace(returncode=0, stdout="login\n4\n"))
        assert mq.query_maas_machines() == 4

    def test_query_maas_machines_garbage_is_zero(self, monkeypatch):
        monkeypatch.setattr(
            mq.subprocess, "run",
            lambda cmd, **kw: SimpleNamespace(returncode=1, stdout="junk"))
        assert mq.query_maas_machines() == 0


# --- test_blankdl_fence -----------------------------------------------------

class TestBlankdlFenceSelfTest:
    def test_fence_serves_every_geometry(self):
        """The 2026-11-08 off-by-one regression script, pinned in the fast
        tier: byte-exact serving across image geometries incl. the
        duplicate-ACK resend path. Loopback UDP only."""
        proc = subprocess.run(
            [sys.executable, str(REPO / "scripts" / "test_blankdl_fence.py")],
            capture_output=True, text=True, timeout=120, cwd=str(REPO))
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "ALL PASS" in proc.stdout
        assert "FAIL" not in proc.stdout
