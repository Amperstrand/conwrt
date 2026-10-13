"""manual_step() — labgrid ManualPowerDriver/ManualSwitchDriver semantics
for desk rigs (docs/DEVICE-TRANSITIONS.md P1)."""
import sys
from unittest import mock

import pytest

from flash.context import manual_step


def test_event_confirm_announces_and_proceeds(capsys):
    assert manual_step("unplug the power", voice=False, confirm="event") is True
    out = capsys.readouterr().out
    assert "unplug the power" in out


def test_enter_confirm_refuses_without_tty(capsys):
    assert sys.stdin.isatty() is False  # pytest pipes stdin
    assert manual_step("hold reset", voice=False, confirm="enter") is False
    out = capsys.readouterr().out
    assert "REFUSED" in out


def test_enter_confirm_assume_confirmed_skips_blocking():
    assert manual_step("hold reset", voice=False, confirm="enter",
                       assume_confirmed=True) is True


def test_enter_confirm_reads_input_on_tty():
    with mock.patch("flash.context.sys.stdin") as fake_stdin, \
         mock.patch("builtins.input", return_value="") as fake_input:
        fake_stdin.isatty.return_value = True
        assert manual_step("hold reset", voice=False, confirm="enter") is True
        fake_input.assert_called_once()


def test_unknown_confirm_mode_rejected():
    with pytest.raises(ValueError):
        manual_step("x", voice=False, confirm="carrier-pigeon")


def test_recovery_context_manual_routes_through_manual_step():
    from unittest import mock
    from flash.context import RecoveryContext, say

    ctx = RecoveryContext.__new__(RecoveryContext)
    ctx._say_fn = say
    with mock.patch("flash.context.manual_step", return_value=True) as ms:
        assert ctx.manual("unplug the power") is True
    ms.assert_called_once_with("unplug the power", voice=True, confirm="event")
