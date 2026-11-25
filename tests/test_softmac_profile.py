"""#242: device_profile exposes signatures.recovery.recovery_soft_mac."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from flash.device_profile import build_profile_from_model


def test_profile_exposes_recovery_soft_mac():
    # x1860 carries recovery_mac_prefix only — the field stays EMPTY until
    # #240's bench observation lands (deliberate: population is bench-gated)
    p = build_profile_from_model("dlink-covr-x1860-a1")
    assert getattr(p, "recovery_soft_mac", None) == ""

    # GL.iNet class: no constant recovery MAC at all
    p2 = build_profile_from_model("glinet-gl-ar300m-lite")
    assert getattr(p2, "recovery_soft_mac", None) == ""


def test_profile_reads_soft_mac_when_present(tmp_path, monkeypatch):
    import flash.device_profile as dp
    fake = {
        "id": "fake-softmac", "vendor": "V", "description": "d",
        "openwrt": {"target": "t", "profile": "p", "default_ip": "192.168.0.1"},
        "flash_methods": {"recovery-http": {
            "recovery_ip": "192.168.0.1", "client_ip": "192.168.0.10"}},
        "signatures": {"recovery": {
            "recovery_soft_mac": "3e:85:be:87:55:42"}},
    }
    monkeypatch.setattr(dp, "load_model", lambda mid: fake)
    p = build_profile_from_model("fake-softmac")
    assert p.recovery_soft_mac == "3e:85:be:87:55:42"
