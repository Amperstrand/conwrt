"""Tests for `conwrt lan-migrate` (host-side orchestration, mocked)."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch


from conwrt import cmd_lan_migrate as M


def _args(**kw):
    base = dict(model_id="dlink-covr-x1860-a1", ip="192.168.1.1",
                interface="en6", rollback_secs=60)
    base.update(kw)
    return SimpleNamespace(**base)


@patch("subprocess.run")
def test_idempotent_when_already_on_target(mock_run):
    mock_run.return_value = SimpleNamespace(returncode=0, stdout="10.89.4.1\n", stderr="")
    rc = M.cmd_lan_migrate(_args(ip="10.89.4.1"))
    assert rc == 0


@patch.object(M, "_port_open")
@patch.object(M, "_ssh")
@patch.object(M, "_run")
def test_migrate_applies_verifies_and_cancels_rollback(mock_run, mock_ssh, mock_port):
    cur = SimpleNamespace(returncode=0, stdout="192.168.1.1\n", stderr="")
    mock_run.side_effect = [cur, SimpleNamespace(returncode=0, stdout="", stderr="")]
    mock_ssh.side_effect = [
        cur,
        SimpleNamespace(returncode=0, stdout="", stderr=""),
        SimpleNamespace(returncode=0, stdout="10.89.4.1\n", stderr=""),
        SimpleNamespace(returncode=0, stdout="", stderr=""),
    ]
    mock_port.return_value = True
    rc = M.cmd_lan_migrate(_args())
    assert rc == 0
    applied = mock_ssh.call_args_list[1].args[1]
    assert "network.lan.ipaddr='10.89.4.1'" in applied
    assert "lanrevert.sh" in applied
    assert "/tmp/lanrevert.cancel" in applied
    cancel = mock_ssh.call_args_list[2].args[1]
    assert "touch /tmp/lanrevert.cancel" in cancel


@patch.object(M, _port_open_name := "_port_open", return_value=False)
@patch.object(M, "_ssh")
@patch.object(M, "_run")
def test_migrate_rolls_back_when_new_ip_never_comes_up(mock_run, mock_ssh, mock_port):
    cur = SimpleNamespace(returncode=0, stdout="192.168.1.1\n", stderr="")
    mock_run.side_effect = [cur, SimpleNamespace(returncode=0, stdout="", stderr=""),
                            SimpleNamespace(returncode=0, stdout="", stderr="")]
    mock_ssh.side_effect = [cur, SimpleNamespace(returncode=0, stdout="", stderr="")]
    rc = M.cmd_lan_migrate(_args(rollback_secs=10))
    assert rc == 1


@patch("conwrt.cmd_lan_migrate.load_model")
def test_migrate_fails_when_model_has_no_lan_subnet(mock_load):
    mock_load.return_value = {"id": "test", "openwrt": {"target": "ramips/mt7621", "version": "24.10.7"}, "lan_subnet": ""}
    rc = M.cmd_lan_migrate(_args())
    assert rc == 1
