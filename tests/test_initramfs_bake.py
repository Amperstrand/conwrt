"""Offline tests for initramfs_bake (#784 cut 1).

The overlay is the profile pipeline's own output verified end-to-end
against a stubbed config — no SDK, no bench, no wire.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

import importlib
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

bake_mod = importlib.import_module("conwrt.initramfs_bake")


@pytest.fixture()
def stub_config(monkeypatch, tmp_path):
    key = tmp_path / "id_ed25519.pub"
    key.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyForBaking\n")

    from config import ConwrtConfig
    cfg = ConwrtConfig(
        lan_ip_mode="static", lan_ip="192.168.105.31",
        ssh_public_key_path=str(key), ssh_all_keys=[str(key)],
        ssh_public_key_text=key.read_text(),
        hostname_pattern="static", hostname="nr-stage1")
    monkeypatch.setattr(bake_mod, "load_config", lambda: cfg)
    # force the static IP through the builder path the same way the
    # firmware-manager flow does
    return cfg, key


class TestBake:
    def test_overlay_layout_and_fragment(self, tmp_path, stub_config):
        out = tmp_path / "overlay"
        files_root = bake_mod.bake("zyxel-nr7101", out)
        frag = files_root / "etc" / "uci-defaults" / "99-conwrt-identity"
        assert frag.exists()
        text = frag.read_text()
        # the identity triple: DHCP off + key + the static IP path
        assert "dhcp" in text.lower()
        assert "dropbear" in text or "authorized_keys" in text
        assert (out / "README-build.md").exists()
        assert "PROFILE=" in (out / "README-build.md").read_text()
        assert "ramips" in (out / "README-build.md").read_text()

    def test_refuses_empty_fragment(self, tmp_path, stub_config, monkeypatch):
        # an empty identity fragment would bake a no-op overlay — a
        # stage-1 boot indistinguishable from stock. Refuse.
        monkeypatch.setattr(
            bake_mod, "build_plan",
            lambda *a, **kw: SimpleNamespace(asu_defaults_script=lambda: ""))
        with pytest.raises(ValueError, match="empty identity fragment"):
            bake_mod.bake("zyxel-nr7101", tmp_path / "o2")

    def test_unknown_model_raises(self, tmp_path, stub_config):
        with pytest.raises(ValueError, match="unknown model"):
            bake_mod.bake("not-a-model", tmp_path / "o3")

    def test_bake_is_idempotent(self, tmp_path, stub_config):
        out = tmp_path / "overlay"
        first = bake_mod.bake("zyxel-nr7101", out)
        frag1 = (first / "etc" / "uci-defaults" / "99-conwrt-identity").read_text()
        second = bake_mod.bake("zyxel-nr7101", out)
        frag2 = (second / "etc" / "uci-defaults" / "99-conwrt-identity").read_text()
        assert frag1 == frag2
        # no duplicate files littered
        assert len(list((out / "files" / "etc" / "uci-defaults").iterdir())) == 1

    def test_dhcp_always_disabled_in_stage1(self, tmp_path, stub_config, monkeypatch):
        seen = {}

        def fake_build_plan(cfg, **kw):
            seen.update(kw)
            return SimpleNamespace(
                asu_defaults_script=lambda: "(\ntrue\n) || exit 1")

        monkeypatch.setattr(bake_mod, "build_plan", fake_build_plan)
        bake_mod.bake("zyxel-nr7101", tmp_path / "o4")
        # the rogue-DHCP discipline is not optional at stage 1
        assert seen.get("disable_dhcp") is True

    def test_cli_wiring(self, tmp_path, stub_config, capsys):
        rc = bake_mod.main(["--model-id", "zyxel-nr7101",
                            "--out", str(tmp_path / "o5")])
        assert rc == 0
        out = Path(capsys.readouterr().out.strip())
        assert (out / "etc" / "uci-defaults" / "99-conwrt-identity").exists()

    def test_cli_unknown_model_fails_cleanly(self, tmp_path, stub_config, capsys):
        rc = bake_mod.main(["--model-id", "nope", "--out", str(tmp_path / "o6")])
        assert rc == 1
        assert "unknown model" in capsys.readouterr().err

    def test_cli_lan_ip_lands_in_fragment(self, tmp_path, stub_config, monkeypatch):
        # Regression (2026-11-25): --lan-ip was silently dropped — bake()
        # mutated cfg AFTER build_plan, so the static-LAN block never
        # rendered. Pin that the CLI override reaches the fragment even
        # when the config carries no static IP of its own.
        from config import ConwrtConfig
        key = stub_config[1]
        cfg = ConwrtConfig(
            lan_ip_mode="", lan_ip="",
            ssh_public_key_path=str(key), ssh_all_keys=[str(key)],
            ssh_public_key_text=key.read_text(),
            hostname_pattern="static", hostname="nr-stage1")
        monkeypatch.setattr(bake_mod, "load_config", lambda: cfg)

        out = tmp_path / "o-lanip"
        files_root = bake_mod.bake("zyxel-nr7101", out, lan_ip="192.168.7.1")
        text = (files_root / "etc" / "uci-defaults" / "99-conwrt-identity").read_text()
        assert "network.lan.ipaddr" in text
        assert "192.168.7.1" in text

    def test_cli_lan_ip_validated(self, tmp_path, stub_config, monkeypatch):
        # same injection/typo guard as the overlay path (PR #780)
        from config import ConwrtConfig
        key = stub_config[1]
        cfg = ConwrtConfig(
            lan_ip_mode="", lan_ip="",
            ssh_public_key_path=str(key), ssh_all_keys=[str(key)],
            ssh_public_key_text=key.read_text(),
            hostname_pattern="static", hostname="nr-stage1")
        monkeypatch.setattr(bake_mod, "load_config", lambda: cfg)

        with pytest.raises(ValueError, match="IPv4 literal"):
            bake_mod.bake("zyxel-nr7101", tmp_path / "o-bad", lan_ip="192.168.1")
