"""CLI tests for `conwrt flow`."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from conwrt.cmd_flow import cmd_flow


def _args(**kw):
    base = dict(flow_command="list", flow=None, model_id=None, version=None,
                ip="192.168.1.1", overrides=None)
    base.update(kw)
    return SimpleNamespace(**base)


def test_flow_list_includes_net4sats(capsys):
    rc = cmd_flow(_args(flow_command="list"))
    out = capsys.readouterr().out
    assert rc == 0
    assert "net4sats" in out


def test_flow_script_renders_with_overrides(capsys):
    rc = cmd_flow(_args(
        flow_command="script", flow="net4sats",
        model_id="dlink-covr-x1860-a1", version="24.10.7",
        overrides=["upstream_ssid=Acme", "upstream_key=s3cr3t"],
    ))
    out = capsys.readouterr().out
    assert rc == 0
    assert "OpenWrt 24.10.7" in out
    assert "uci set wireless.sta1.ssid='Acme'" in out
    assert "uci set wireless.sta1.key='s3cr3t'" in out


def test_flow_script_rejects_missing_required_params(capsys):
    with pytest.raises(SystemExit):
        cmd_flow(_args(
            flow_command="script", flow="net4sats",
            model_id="dlink-covr-x1860-a1", version="24.10.7", overrides=[],
        ))


def test_flow_instructions_renders_markdown(capsys):
    rc = cmd_flow(_args(
        flow_command="instructions", flow="net4sats",
        model_id="glinet-mt3000", version="25.12.0",
        overrides=["upstream_ssid=Acme", "upstream_key=s3cr3t"],
    ))
    out = capsys.readouterr().out
    assert rc == 0
    assert out.startswith("# net4sats on")
    assert "aarch64_cortex-a53" in out
    assert "apk" in out


def test_flow_unknown_flow_exits(capsys):
    with pytest.raises(SystemExit):
        cmd_flow(_args(flow_command="script", flow="nope", model_id="glinet-mt3000", overrides=["x=1"]))


def test_flow_script_with_set_password_injects_password_step(capsys):
    rc = cmd_flow(_args(
        flow_command="script", flow="net4sats", model_id="dlink-covr-x1860-a1", version="24.10.7",
        overrides=["upstream_ssid=A", "upstream_key=B"], set_password=True,
    ))
    out = capsys.readouterr().out
    assert rc == 0
    assert "chpasswd" in out
    assert "root password: $PW" in out
