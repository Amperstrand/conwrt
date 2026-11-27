"""esim-preflight tests (#835): the stage-gated checklist driver.

All host interactions stubbed at the module seam (_run). The gates'
verdict logic, the EUI-64 door derivation, the INFO-gate semantics
(None = not-yet-attested, not failed), and the JSON contract are
pinned; one live-ish path (zycast --validate) runs the REAL cargo
validator against the REAL header fixture.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from conwrt import esim_preflight as fp  # noqa: E402


@pytest.fixture()
def stub_run(monkeypatch):
    canned: dict[str, tuple[int, str]] = {}
    calls: list[list[str]] = []

    def fake_run(cmd, timeout=20):
        calls.append(cmd)
        for key, val in canned.items():
            if key in " ".join(cmd):
                return val
        return 0, ""

    monkeypatch.setattr(fp, "_run", fake_run)
    return types.SimpleNamespace(canned=canned, calls=calls)


class TestDeriveV6:
    def test_known_units(self):
        # 78c5 (the E11 unit) and a6e4 (the campaign's other unit)
        assert fp.derive_v6("78:c5:7d:13:91:9c") == "fe80::7ac5:7dff:fe13:919c"
        assert fp.derive_v6("a6:e4:..") == ""  # malformed -> empty, no raise

    def test_strips_dashes(self):
        assert fp.derive_v6("78-c5-7d-13-91-9c") == "fe80::7ac5:7dff:fe13:919c"


class TestFlashStage:
    def _args(self, **kw):
        base = dict(stage="flash", image=None, expect_model="7101",
                    specimen_mac=None, staging_iface="enp2s0.999",
                    poe_verified=False, unit=None, preset=None,
                    card_diff_path=None, modem_stable=False,
                    activation_code=None, json=False)
        base.update(kw)
        return types.SimpleNamespace(**base)

    def test_missing_image_fails_first_gate(self, stub_run):
        rep = fp.stage_flash(self._args())
        assert rep.gates[0].ok is False
        assert not rep.passed

    def test_validate_gate_green_on_real_fixture(self, stub_run, tmp_path):
        # the REAL zycast --validate path against the REAL header
        # fixture — the #847 gate chain, exercised from the checklist
        img = tmp_path / "img.bin"
        img.write_bytes(b"0RDH" + b"\x00" * 508)
        stub_run.canned["sha256sum"] = (0, "b4b6c10a " + "x" * 40)
        stub_run.canned["zycast"] = (0, "validate: all gates passed "
                                        "(magic, model, attested , pacing, "
                                        "flash-mutex) — nothing sent")
        rep = fp.stage_flash(self._args(image=str(img)))
        by_name = {g.name: g for g in rep.gates}
        assert by_name["image present + sha pinned"].ok is True
        assert by_name["zycast --validate passes (magic/model/pacing)"].ok is True

    def test_validate_refusal_fails_the_gate(self, stub_run, tmp_path):
        (tmp_path / "img.bin").write_bytes(b"\x1f\x8bgarbage")
        stub_run.canned["sha256sum"] = (0, "x" * 64)
        stub_run.canned["zycast"] = (1, "zycast: refusing to send: payload "
                                        "does not carry a ZyXEL RAS magic")
        rep = fp.stage_flash(self._args(image=str(tmp_path / "img.bin")))
        by_name = {g.name: g for g in rep.gates}
        assert by_name["zycast --validate passes (magic/model/pacing)"].ok is False

    def test_specimen_mac_neighbor_evidence(self, stub_run):
        stub_run.canned["ip neigh"] = (0, "192.168.1.1 lladdr "
                                          "78:c5:7d:13:91:9c REACHABLE")
        rep = fp.stage_flash(self._args(specimen_mac="78:C5:7D:13:91:9C"))
        by_name = {g.name: g for g in rep.gates}
        assert by_name["specimen MAC read LIVE matches the record"].ok is True

    def test_specimen_absent_red(self, stub_run):
        stub_run.canned["ip neigh"] = (0, "192.168.1.1 lladdr "
                                          "aa:bb:cc:dd:ee:01 REACHABLE")
        rep = fp.stage_flash(self._args(specimen_mac="78:c5:7d:13:91:9c"))
        assert rep.gates[2].ok is False

    def test_poe_gate_is_info_until_attested(self, stub_run, tmp_path):
        stub_run.canned["zycast"] = (0, "validate: all gates passed")
        stub_run.canned["sha256sum"] = (0, "x" * 64)
        rep = fp.stage_flash(self._args(image=str(tmp_path / "i.bin"),
                                        specimen_mac=None))
        poe = rep.gates[-1]
        assert poe.ok is None  # INFO, not fail
        rep2 = fp.stage_flash(self._args(image=str(tmp_path / "i.bin"),
                                         poe_verified=True))
        assert rep2.gates[-1].ok is True


class TestConfigureStage:
    def _args(self, **kw):
        base = dict(stage="configure", image=None, expect_model="7101",
                    specimen_mac="78:c5:7d:13:91:9c",
                    staging_iface="enp2s0.999", poe_verified=False,
                    unit=None, preset=None, card_diff_path=None,
                    modem_stable=False, activation_code=None, json=False)
        base.update(kw)
        return types.SimpleNamespace(**base)

    def test_v6_door_derived_and_alive(self, stub_run):
        stub_run.canned["ping -c2"] = (0, "2 received")
        rep = fp.stage_configure(self._args())
        assert rep.gates[0].ok is True
        assert "fe80::7ac5:7dff:fe13:919c" in rep.gates[0].detail

    def test_board_identity_gate(self, stub_run):
        stub_run.canned["ping -c2"] = (0, "alive")
        stub_run.canned["ssh"] = (0, "zyxel,nr7101\n78:c5:7d:13:91:9c")
        rep = fp.stage_configure(self._args())
        assert rep.gates[1].ok is True

    def test_wrong_board_refuses(self, stub_run):
        stub_run.canned["ssh"] = (0, "zyxel,some-other\naa:bb:cc:dd:ee:01")
        rep = fp.stage_configure(self._args())
        assert rep.gates[1].ok is False

    def test_preset_render_gate(self, stub_run):
        stub_run.canned["profile"] = (0, "PLAN: 7 steps")
        rep = fp.stage_configure(self._args(preset="ddns"))
        assert rep.gates[2].ok is True


class TestEsimStage:
    def _args(self, **kw):
        base = dict(stage="esim", image=None, expect_model="7101",
                    specimen_mac=None, staging_iface="enp2s0.999",
                    poe_verified=False, unit=None, preset=None,
                    card_diff_path=None, modem_stable=False,
                    activation_code=None, json=False)
        base.update(kw)
        return types.SimpleNamespace(**base)

    def test_gate0_is_info_until_diff_recorded(self, stub_run):
        rep = fp.stage_esim(self._args())
        assert rep.gates[0].ok is None  # INFO: not failed, not passed

    def test_gate0_passes_with_diff_path(self, stub_run):
        rep = fp.stage_esim(self._args(card_diff_path="/tmp/card-before.txt"))
        assert rep.gates[0].ok is True

    def test_transport_gate_checks_lpac_pcscd(self, stub_run):
        stub_run.canned["lpac"] = (0, "/usr/bin/lpac\n999 pcscd")
        rep = fp.stage_esim(self._args())
        assert rep.gates[2].ok is True

    def test_all_unattested_still_not_passed(self, stub_run):
        # INFO gates keep the stage un-passed until attested — the
        # operator (or agent) must actively confirm each one
        rep = fp.stage_esim(self._args())
        assert rep.passed is False

    def test_info_only_gates_are_pending_not_blocked(self, stub_run):
        # The wrong-verdict class (found in the live dress rehearsal):
        # a stage whose only misses are INFO gates (ok=None) must NOT
        # report BLOCKED — it is PENDING, waiting on attestation.
        rep = fp.StageReport(stage="configure", gates=[
            fp.Gate(name="green", ok=True),
            fp.Gate(name="info", ok=None),
        ])
        assert rep.passed is False
        assert rep.blocked is False  # no red gate — PENDING, not BLOCKED

    def test_blocked_requires_a_red_gate(self, stub_run):
        rep = fp.StageReport(stage="configure", gates=[
            fp.Gate(name="green", ok=True),
            fp.Gate(name="info", ok=None),
            fp.Gate(name="red", ok=False),
        ])
        assert rep.blocked is True
        assert rep.passed is False


class TestCliContract:
    def test_json_output_shape(self, stub_run, monkeypatch, capsys):
        stub_run.canned["ping -c2"] = (0, "alive")
        stub_run.canned["ssh"] = (0, "zyxel,nr7101\n78:c5:7d:13:91:9c")
        stub_run.canned["profile"] = (0, "PLAN: 7 steps")
        args = types.SimpleNamespace(
            stage="configure", image=None, expect_model="7101",
            specimen_mac="78:c5:7d:13:91:9c", staging_iface="enp2s0.999",
            poe_verified=False, unit=None, preset="ddns",
            card_diff_path=None, modem_stable=False,
            activation_code=None, json=True)
        rc = fp.cmd_esim_preflight(args)
        out = json.loads(capsys.readouterr().out)
        assert out["stage"] == "configure"
        assert isinstance(out["gates"], list) and out["gates"]
        assert "passed" in out and rc == 0

    def test_text_output_marks(self, stub_run, capsys):
        args = types.SimpleNamespace(
            stage="esim", image=None, expect_model="7101",
            specimen_mac=None, staging_iface="enp2s0.999",
            poe_verified=False, unit=None, preset=None,
            card_diff_path=None, modem_stable=False,
            activation_code=None, json=False)
        rc = fp.cmd_esim_preflight(args)
        out = capsys.readouterr().out
        assert "GATE 0" in out and "expect:" in out and "BLOCKED" in out
        assert rc == 1

    def test_pending_exit_code_and_verdict(self, stub_run, capsys):
        # all-green gates + one INFO -> PENDING (verdict text + rc 2),
        # never BLOCKED
        args = types.SimpleNamespace(
            stage="configure", image=None, expect_model="7101",
            specimen_mac="78:c5:7d:13:91:9c", staging_iface="enp2s0.999",
            poe_verified=False, unit=None, preset=None,
            card_diff_path=None, modem_stable=False,
            activation_code=None, json=False)
        stub_run.canned["ping -c2"] = (0, "alive")
        stub_run.canned["ssh"] = (0, "zyxel,nr7101\n78:c5:7d:13:91:9c")
        rc = fp.cmd_esim_preflight(args)
        out = capsys.readouterr().out
        assert "PENDING" in out and "BLOCKED" not in out
        assert rc == 2
