"""Unit tests for the SIM-mode renderer/validator (no hardware)."""
from __future__ import annotations

import ast
import copy
import json
from pathlib import Path

import pytest

from conwrt import sim_modes

REMOTE = "remote_android_sap"
LOCAL = ("local_esim_silentlink", "local_physical_ice")
READER = "ssh:user@helper:bt:AA:BB:CC:DD:EE:FF"
PIN = "4444"


def _model():
    return sim_modes.load_model()


def test_validate_model_ok():
    assert sim_modes.validate_model(_model()) == []


@pytest.mark.parametrize("mode_id", sim_modes.MODE_IDS)
def test_every_mode_renders(mode_id):
    plan = sim_modes.render_mode(_model(), mode_id, environ={})
    assert plan["mode"] == mode_id
    assert plan["carrier_profile"]
    assert plan["commands"]
    assert plan["commit"] == "uci commit network"
    assert plan["restart"] == "/etc/init.d/wwand restart"


@pytest.mark.parametrize("mode_id", LOCAL)
def test_local_modes_delete_remote_fields(mode_id):
    plan = sim_modes.render_mode(_model(), mode_id, environ={})
    assert plan["uci"]["network.wwmodem_auto.rsim_reader"] is None
    assert plan["uci"]["network.wwmodem_auto.pincode"] is None
    assert "uci -q delete network.wwmodem_auto.rsim_reader" in plan["commands"]
    assert "uci -q delete network.wwmodem_auto.pincode" in plan["commands"]
    assert plan["ready"] is True


def test_local_mode_can_set_a_pin_from_env():
    plan = sim_modes.render_mode(
        _model(), "local_physical_ice",
        environ={sim_modes.ENV_PIN: PIN}, show_secrets=True)
    assert plan["uci"]["network.wwmodem_auto.pincode"] == PIN
    assert any(PIN in command for command in plan["commands"])


def test_local_pin_is_redacted_by_default():
    """A PIN-protected local card must not print its PIN without --show-secrets."""
    plan = sim_modes.render_mode(
        _model(), "local_physical_ice", environ={sim_modes.ENV_PIN: PIN})
    assert plan["uci"]["network.wwmodem_auto.pincode"] == sim_modes.REDACTED
    assert plan["redacted"] is True
    assert not any(PIN in command for command in plan["commands"])
    assert any(sim_modes.ENV_PIN in command for command in plan["commands"])


def test_remote_without_pin_deletes_stale_value():
    """No PIN env means delete a pincode left by an earlier mode."""
    plan = sim_modes.render_mode(_model(), REMOTE, reader=READER, environ={})
    assert plan["ready"] is True
    assert plan["uci"]["network.wwmodem_auto.pincode"] is None
    assert "uci -q delete network.wwmodem_auto.pincode" in plan["commands"]


def test_remote_without_reader_is_not_ready():
    plan = sim_modes.render_mode(_model(), REMOTE, environ={})
    assert plan["ready"] is False
    assert plan["missing_secrets"] == ["rsim_reader"]
    assert any(sim_modes.ENV_READER in command for command in plan["commands"])
    assert any("not set" in warning for warning in plan["warnings"])


def test_remote_redacts_reader_and_pin_by_default():
    plan = sim_modes.render_mode(
        _model(), REMOTE, reader=READER, environ={sim_modes.ENV_PIN: PIN})
    assert plan["ready"] is True
    assert plan["uci"]["network.wwmodem_auto.rsim_reader"] == sim_modes.REDACTED
    assert plan["uci"]["network.wwmodem_auto.pincode"] == sim_modes.REDACTED
    assert not any("AA:BB" in command for command in plan["commands"])
    assert not any(PIN in command for command in plan["commands"])
    assert any(sim_modes.ENV_READER in command for command in plan["commands"])


def test_remote_show_secrets_emits_values():
    plan = sim_modes.render_mode(
        _model(), REMOTE, reader=READER,
        environ={sim_modes.ENV_PIN: PIN}, show_secrets=True)
    assert plan["uci"]["network.wwmodem_auto.rsim_reader"] == READER
    assert plan["uci"]["network.wwmodem_auto.pincode"] == PIN
    assert any("AA:BB" in command for command in plan["commands"])
    assert any(PIN in command for command in plan["commands"])


def test_remote_reader_from_environment():
    plan = sim_modes.render_mode(
        _model(), REMOTE, environ={sim_modes.ENV_READER: READER}, show_secrets=True)
    assert plan["uci"]["network.wwmodem_auto.rsim_reader"] == READER


def test_apn_and_pdp_overrides():
    plan = sim_modes.render_mode(
        _model(), "local_physical_ice",
        apn="example.apn", pdp_type="ipv4v6", environ={})
    assert plan["apn"] == "example.apn"
    assert plan["pdp_type"] == "ipv4v6"
    assert any("example.apn" in command for command in plan["commands"])


def test_unknown_mode_is_rejected():
    with pytest.raises(sim_modes.SimModeError):
        sim_modes.render_mode(_model(), "no-such-mode", environ={})


def test_validate_rejects_real_identifiers():
    model = copy.deepcopy(_model())
    model["cellular"]["sim_modes"][REMOTE]["uci"][
        "network.wwmodem_auto.rsim_reader"] = "ssh:user@helper:bt:12:34:56:78:9A:BC"
    errors = sim_modes.validate_model(model)
    assert any("MAC address" in error for error in errors)


def test_validate_rejects_cfun_in_uci():
    model = copy.deepcopy(_model())
    model["cellular"]["sim_modes"]["local_physical_ice"]["uci"][
        "network.wwan0.apn"] = "AT+CFUN=1,1"
    errors = sim_modes.validate_model(model)
    assert any("CFUN" in error for error in errors)


def test_validate_rejects_local_reader():
    model = copy.deepcopy(_model())
    model["cellular"]["sim_modes"]["local_physical_ice"]["uci"][
        "network.wwmodem_auto.rsim_reader"] = "ssh:user@helper:bt:<phone>"
    errors = sim_modes.validate_model(model)
    assert any("must delete rsim_reader" in error for error in errors)


def test_json_plan_is_serializable_and_redacted():
    plan = sim_modes.render_mode(
        _model(), REMOTE, reader=READER,
        environ={sim_modes.ENV_PIN: PIN})
    blob = json.dumps(plan)
    assert "AA:BB" not in blob
    assert PIN not in blob
    assert sim_modes.REDACTED in blob


def test_legacy_esim_has_no_cfun_reset_call():
    source = (Path(sim_modes.__file__).parent / "esim.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name) or node.func.id != "_at_run":
            continue
        for arg in node.args[1:2]:
            if isinstance(arg, ast.Constant) and "CFUN" in str(arg.value):
                offenders.append(arg.value)
    assert offenders == []
