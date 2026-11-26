"""Tests for `conwrt overlay` — the CLI reachability unit (#828 item 3).

The overlay tarball was previously only reachable via a hand-run
`python -c` one-liner; this pins the subcommand: the tarball shape, the
identity resolution through the ONE decision place (flag > config),
the netmask pair from #838, and the error classes.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tarfile
import argparse
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from conwrt import cmd_overlay  # noqa: E402


def _args(**kw) -> argparse.Namespace:
    base = dict(out=None, lan_ip=None, authorized_keys=None,
                keep_dhcp=False, print_command=False)
    base.update(kw)
    return argparse.Namespace(**base)


def _no_config(monkeypatch):
    import profile.overlay as ov
    monkeypatch.setattr(ov, "resolve_overlay_identity",
                        lambda *a, **k: (None, None))


class TestCmdOverlay:
    def test_prints_tarball_path(self, monkeypatch, tmp_path, capsys):
        _no_config(monkeypatch)
        assert cmd_overlay.cmd_overlay(_args()) == 0
        out = capsys.readouterr().out.strip()
        assert out.endswith(".tar.gz") and os.path.isfile(out)
        os.unlink(out)

    def test_out_path_respected(self, monkeypatch, tmp_path):
        _no_config(monkeypatch)
        target = tmp_path / "my.tar.gz"
        assert cmd_overlay.cmd_overlay(_args(out=str(target))) == 0
        assert target.is_file()

    def test_identity_flags_reach_tarball(self, monkeypatch, tmp_path, capsys):
        # patch at cmd_overlay's bound-name site (module-level import)
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFlagKeyForTesting flag@cli"
        monkeypatch.setattr(cmd_overlay, "resolve_overlay_identity",
                            lambda ip, keys, cfg=None: ("192.168.5.1", key))
        assert cmd_overlay.cmd_overlay(_args(lan_ip="192.168.5.1")) == 0
        path = capsys.readouterr().out.strip()
        try:
            with tarfile.open(path, "r:gz") as tar:
                names = tar.getnames()
                assert "etc/config/dhcp" in names
                assert "etc/dropbear/authorized_keys" in names
                frag = tar.extractfile(
                    "etc/uci-defaults/99-conwrt-lan-ip").read().decode()
                # the #838 netmask pair rides along
                assert "ipaddr='192.168.5.1'" in frag
                assert "netmask='255.255.255.0'" in frag
                assert "uci commit network" in frag
                keys = tar.extractfile(
                    "etc/dropbear/authorized_keys").read().decode()
                assert key in keys
        finally:
            os.unlink(path)

    def test_keep_dhcp_omits_dhcp_config(self, monkeypatch, capsys):
        _no_config(monkeypatch)
        assert cmd_overlay.cmd_overlay(_args(keep_dhcp=True)) == 0
        path = capsys.readouterr().out.strip()
        try:
            with tarfile.open(path, "r:gz") as tar:
                assert "etc/config/dhcp" not in tar.getnames()
        finally:
            os.unlink(path)

    def test_print_command_emits_pasteable_lines(self, monkeypatch, capsys):
        _no_config(monkeypatch)
        assert cmd_overlay.cmd_overlay(_args(print_command=True)) == 0
        captured = capsys.readouterr()
        assert captured.out.strip().endswith(".tar.gz")
        err = captured.err
        assert "scp -O" in err and "root@192.168.1.1:/tmp/" in err
        assert "sysupgrade -n -f /tmp/conwrt-overlay" in err
        os.unlink(captured.out.strip())

    def test_key_path_argument(self, monkeypatch, tmp_path, capsys):
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFromAFile test@path"
        kf = tmp_path / "id.pub"
        kf.write_text(key + "\n")
        monkeypatch.setattr(
            cmd_overlay, "resolve_overlay_identity",
            lambda ip, keys, cfg=None: (ip, keys))
        assert cmd_overlay.cmd_overlay(_args(authorized_keys=str(kf))) == 0
        path = capsys.readouterr().out.strip()
        try:
            with tarfile.open(path, "r:gz") as tar:
                assert key in tar.extractfile(
                    "etc/dropbear/authorized_keys").read().decode()
        finally:
            os.unlink(path)

    def test_bad_key_argument_aborts(self, monkeypatch):
        with pytest.raises(SystemExit, match="neither key text"):
            cmd_overlay.cmd_overlay(_args(authorized_keys="/nonexistent/pub"))

    def test_cli_dispatch_end_to_end(self, tmp_path):
        """Full argv path: python -m conwrt overlay ... (uses the shim + map)."""
        r = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1]
                                 / "scripts" / "conwrt.py"),
             "overlay", "--out", str(tmp_path / "o.tar.gz")],
            capture_output=True, text=True, timeout=60,
            env={**os.environ, "PYTHONPATH": str(
                Path(__file__).resolve().parents[1] / "scripts")})
        assert r.returncode == 0, r.stderr[-300:]
        assert (tmp_path / "o.tar.gz").is_file()
