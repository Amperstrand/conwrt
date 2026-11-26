"""Identity-reachability tests for the flash-path overlay (#828).

The #780 overlay features (lan_ip, authorized_keys) were only reachable
via the hand-run python one-liner; the automated flash paths called
build_overlay_tarball(disable_dhcp=True) and nothing else. These tests
pin the fix: all flash-path overlays now carry identity resolved by the
ONE decision place (profile.overlay.resolve_overlay_identity) with
flag > config precedence.
"""
from __future__ import annotations

import os
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from profile.overlay import (  # noqa: E402
    build_overlay_tarball,
    resolve_overlay_identity,
)


def _cfg(**kw):
    base = {"lan_ip": "", "lan_ip_mode": "mac-hash",
            "ssh_public_key_text": "", "ssh_public_key_path": ""}
    base.update(kw)
    return types.SimpleNamespace(**base)


class TestResolveOverlayIdentity:
    def test_flags_win_over_config(self):
        cfg = _cfg(lan_ip="10.0.0.99", lan_ip_mode="static",
                   ssh_public_key_text="ssh-ed25519 CONFIG")
        ip, keys = resolve_overlay_identity(
            "192.168.5.1", "ssh-ed25519 FLAG", cfg=cfg)
        assert ip == "192.168.5.1" and keys == "ssh-ed25519 FLAG"

    def test_static_config_lan_ip_used_when_mode_static(self):
        cfg = _cfg(lan_ip="10.0.0.99", lan_ip_mode="static")
        ip, _ = resolve_overlay_identity(cfg=cfg)
        assert ip == "10.0.0.99"

    def test_mac_hash_mode_is_never_baked(self):
        # THE deliberate gap: mac-hash derivation is device-side; a
        # static pin from config would freeze a wrong identity class
        cfg = _cfg(lan_ip="10.0.0.99", lan_ip_mode="mac-hash")
        ip, _ = resolve_overlay_identity(cfg=cfg)
        assert ip is None

    def test_keys_from_config_text_then_path(self, tmp_path):
        key_file = tmp_path / "id.pub"
        key_file.write_text("ssh-ed25519 FROMFILE\n")
        _, keys = resolve_overlay_identity(
            cfg=_cfg(ssh_public_key_path=str(key_file)))
        assert keys == "ssh-ed25519 FROMFILE"
        _, keys = resolve_overlay_identity(
            cfg=_cfg(ssh_public_key_text="ssh-ed25519 TEXT"))
        assert keys == "ssh-ed25519 TEXT"

    def test_explicit_key_path_argument_is_read(self, tmp_path):
        kf = tmp_path / "op.pub"
        kf.write_text("ssh-ed25519 EXPLICIT\n")
        _, keys = resolve_overlay_identity(authorized_keys=str(kf), cfg=_cfg())
        assert keys == "ssh-ed25519 EXPLICIT"

    def test_invalid_explicit_ip_raises(self):
        with pytest.raises(ValueError, match="IPv4"):
            resolve_overlay_identity("not-an-ip", cfg=_cfg())

    def test_no_config_no_flags_all_none(self, monkeypatch):
        # no config file resolvable -> (None, None), never a crash
        import profile.overlay as ov
        monkeypatch.setattr(ov.os.path, "expanduser", lambda p: "/nonexistent")
        ip, keys = resolve_overlay_identity()
        assert ip is None and keys is None


class TestFlashPathCarriesIdentity:
    """The three automated flash paths attach identity to the overlay."""

    def _capture_overlay(self, monkeypatch, target_module, **call_kw):
        captured = {}

        def fake_build(**kw):
            captured.update(kw)
            path = "/tmp/fake-overlay.tar.gz"
            Path(path).write_bytes(b"")
            return path

        monkeypatch.setattr(f"{target_module}.build_overlay_tarball", fake_build)
        return captured

    def test_flash_utils_sysupgrade_overlay_carries_identity(self, monkeypatch):
        import conwrt.flash_utils as fu
        captured = {}
        real_build = None
        from profile.overlay import build_overlay_tarball as _real

        def fake_build(**kw):
            captured.update(kw)
            return "/tmp/fake.tar.gz"

        # patch at the profile.overlay import site inside the function
        import profile.overlay as ov
        monkeypatch.setattr(ov, "build_overlay_tarball", fake_build)
        monkeypatch.setattr(fu, "_scp_upload", lambda *a, **k: (True, "/tmp/fw.bin"))
        monkeypatch.setattr(fu, "ssh_cmd", lambda *a, **k: ["ssh", "cmd"])
        import subprocess as _sp
        monkeypatch.setattr(_sp, "run",
                            lambda *a, **k: _sp.CompletedProcess([], 0,
                                stdout="Commencing", stderr=""))
        monkeypatch.setattr(fu, "detect_platform", lambda: "openwrt")
        ok = fu._flash_via_sysupgrade("1.2.3.4", "/fw.bin",
                                      lan_ip="192.168.5.1",
                                      authorized_keys="ssh-ed25519 X")
        assert ok
        assert captured.get("disable_dhcp") is True
        assert captured.get("lan_ip") == "192.168.5.1"
        assert captured.get("authorized_keys") == "ssh-ed25519 X"

    def test_flash_utils_defaults_when_no_identity(self, monkeypatch, tmp_path):
        import conwrt.flash_utils as fu
        captured = {}
        import profile.overlay as ov

        def fake_build(**kw):
            captured.update(kw)
            return "/tmp/fake.tar.gz"

        monkeypatch.setattr(ov, "build_overlay_tarball", fake_build)
        monkeypatch.setattr(ov, "resolve_overlay_identity",
                            lambda *a, **k: (None, None))
        monkeypatch.setattr(fu, "_scp_upload", lambda *a, **k: (True, "/tmp/fw.bin"))
        monkeypatch.setattr(fu, "ssh_cmd", lambda *a, **k: ["ssh", "cmd"])
        import subprocess as _sp
        monkeypatch.setattr(_sp, "run",
                            lambda *a, **k: _sp.CompletedProcess([], 0,
                                stdout="Commencing", stderr=""))
        monkeypatch.setattr(fu, "detect_platform", lambda: "openwrt")
        assert fu._flash_via_sysupgrade("1.2.3.4", "/fw.bin")
        assert captured.get("lan_ip") is None
        assert captured.get("authorized_keys") is None
        assert captured.get("disable_dhcp") is True

    def test_extreme_path_calls_resolver(self, monkeypatch):
        # source-level contract: the extreme sysupgrade handler resolves
        # identity and forwards it (deep-driving the full handler needs
        # its state machine; the wiring pin suffices for reachability)
        src = Path("scripts/conwrt/extreme.py").read_text()
        assert "resolve_overlay_identity" in src
        assert "lan_ip=ident_ip" in src and "authorized_keys=ident_keys" in src

    def test_oem_handlers_path_calls_resolver(self):
        src = Path("scripts/flash/oem_handlers.py").read_text()
        assert "resolve_overlay_identity" in src
        assert "lan_ip=ident_ip" in src and "authorized_keys=ident_keys" in src

    def test_overlay_tarball_still_default_off_without_args(self):
        path = build_overlay_tarball(disable_dhcp=True)
        try:
            import tarfile
            with tarfile.open(path, "r:gz") as tar:
                names = tar.getnames()
                assert "etc/config/dhcp" in names
                assert "etc/uci-defaults/99-conwrt-lan-ip" not in names
                assert "etc/dropbear/authorized_keys" not in names
        finally:
            os.unlink(path)
