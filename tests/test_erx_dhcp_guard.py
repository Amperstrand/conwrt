"""erx_dhcp_guard — fail-closed tests (hardware-safe; canned ssh only).

#285: when SSH to the ERX fails (auth/routing/timeout or an unreadable uci
state) the guard must fail LOUDLY. The old ssh() returned '' and validate()
printed "PASS: 0 host entries" — green on red for the mandatory
pre-restart gate.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest

import erx_dhcp_guard as guard

HEALTHY_UCI = """dhcp.lan=dhcp
dhcp.lan.interface='lan'
dhcp.@host[0]=host
dhcp.@host[0].mac='aa:bb:cc:dd:ee:01'
dhcp.@host[0].ip='192.168.13.10'
dhcp.@host[0].name='ap-one'
dhcp.@host[1]=host
dhcp.@host[1].mac='aa:bb:cc:dd:ee:02'
dhcp.@host[1].ip='192.168.13.11'
dhcp.@host[1].name='ap-two'
"""

DUP_MAC_UCI = HEALTHY_UCI.replace("aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:01")

HEALTHY_CHECK = {
    "pgrep dnsmasq": "1234",
    "nslookup": "Server: 127.0.0.1\nAddress: 142.250.0.1",
    "dhcp.leases": "3",
    "logread": "0",
}


def fake_ssh(monkeypatch: pytest.MonkeyPatch,
             responses: dict[str, tuple[int, str, str]],
             default: tuple[int, str, str] = (0, "", "")) -> None:
    """Patch subprocess.run; responses maps a needle in the remote command
    to (rc, stdout, stderr)."""

    def fake_run(cmd, capture_output=True, text=True, timeout=None, **kw):
        remote = cmd[-1]
        for needle, result in responses.items():
            if needle in remote:
                return SimpleNamespace(returncode=result[0],
                                       stdout=result[1], stderr=result[2])
        return SimpleNamespace(returncode=default[0], stdout=default[1],
                               stderr=default[2])

    monkeypatch.setattr(guard.subprocess, "run", fake_run)


class TestValidateFailsClosed:
    def test_auth_failure_never_passes(self, monkeypatch, capsys) -> None:
        # The exact #285 finding: ssh rc=255 -> '' -> "PASS: 0 host entries"
        fake_ssh(monkeypatch, {}, default=(255, "",
                   "root@192.168.13.1: Permission denied (publickey)."))
        rc = guard.cmd_validate()
        out = capsys.readouterr().out
        assert rc == 1
        assert "cannot inspect" in out
        assert "UNSAFE" in out
        assert "PASS" not in out

    def test_unreachable_erx_never_passes(self, monkeypatch, capsys) -> None:
        fake_ssh(monkeypatch, {}, default=(255, "",
                   "ssh: connect to host 192.168.13.1 port 22: No route to host"))
        assert guard.cmd_validate() == 1
        assert "cannot inspect" in capsys.readouterr().out

    def test_ssh_timeout_fails_closed(self, monkeypatch, capsys) -> None:
        import subprocess

        def boom(*a, **k):
            raise subprocess.TimeoutExpired(cmd="ssh", timeout=15)

        monkeypatch.setattr(guard.subprocess, "run", boom)
        rc = guard.cmd_validate()
        assert rc == 1
        assert "timed out" in capsys.readouterr().out

    def test_empty_uci_read_fails_closed(self, monkeypatch, capsys) -> None:
        # rc 0 but no dhcp config at all: the audit could not inspect
        fake_ssh(monkeypatch, {"uci show dhcp": (0, "", "")})
        rc = guard.cmd_validate()
        assert rc == 1
        assert "cannot inspect" in capsys.readouterr().out

    def test_channel_dies_after_uci_still_fails(self, monkeypatch, capsys) -> None:
        # uci reads fine, the generated-config grep loses the channel:
        # validate must still refuse to bless the config
        fake_ssh(monkeypatch, {
            "uci show dhcp": (0, HEALTHY_UCI, ""),
            "grep dhcp-host": (255, "", "Connection reset by peer"),
        })
        assert guard.cmd_validate() == 1
        assert "cannot inspect" in capsys.readouterr().out

    def test_healthy_config_still_passes(self, monkeypatch, capsys) -> None:
        fake_ssh(monkeypatch, {
            "uci show dhcp": (0, HEALTHY_UCI, ""),
            "grep dhcp-host": (0,
                               "dhcp-host=aa:bb:cc:dd:ee:01,192.168.13.10,ap-one\n"
                               "dhcp-host=aa:bb:cc:dd:ee:02,192.168.13.11,ap-two", ""),
        })
        rc = guard.cmd_validate()
        out = capsys.readouterr().out
        assert rc == 0
        assert "PASS: 2 host entries" in out

    def test_duplicate_mac_still_detected(self, monkeypatch, capsys) -> None:
        fake_ssh(monkeypatch, {"uci show dhcp": (0, DUP_MAC_UCI, "")})
        rc = guard.cmd_validate()
        out = capsys.readouterr().out
        assert rc == 1
        assert "DUPLICATE MAC" in out

    def test_generated_duplicate_still_detected(self, monkeypatch, capsys) -> None:
        fake_ssh(monkeypatch, {
            "uci show dhcp": (0, HEALTHY_UCI, ""),
            "grep dhcp-host": (0, "dhcp-host=aa:bb:cc:dd:ee:01,192.168.13.10\n"
                                 "dhcp-host=aa:bb:cc:dd:ee:01,192.168.13.10", ""),
        })
        assert guard.cmd_validate() == 1
        assert "GENERATED CONFIG duplicate" in capsys.readouterr().out


class TestCheckFailsClosed:
    def test_unreachable_erx_is_unhealthy(self, monkeypatch, capsys) -> None:
        fake_ssh(monkeypatch, {}, default=(255, "",
                   "ssh: connect to host 192.168.13.1 port 22: Connection refused"))
        rc = guard.cmd_check()
        out = capsys.readouterr().out
        assert rc == 1
        assert "UNHEALTHY" in out
        assert "cannot reach" in out

    def test_healthy_check_still_passes(self, monkeypatch, capsys) -> None:
        fake_ssh(monkeypatch, {
            "pgrep dnsmasq": (0, HEALTHY_CHECK["pgrep dnsmasq"], ""),
            "nslookup": (0, HEALTHY_CHECK["nslookup"], ""),
            "dhcp.leases": (0, HEALTHY_CHECK["dhcp.leases"], ""),
            "logread": (0, HEALTHY_CHECK["logread"], ""),
        })
        rc = guard.cmd_check()
        assert rc == 0
        assert "HEALTHY" in capsys.readouterr().out

    def test_dnsmasq_down_is_unhealthy_not_crash(self, monkeypatch, capsys) -> None:
        # pgrep rc=1 with no output is a remote *result*, not a channel
        # failure: "NOT RUNNING" must stay reachable (rc 1, no traceback)
        fake_ssh(monkeypatch, {
            "pgrep dnsmasq": (1, "", ""),
            "nslookup": (0, "Server: 127.0.0.1\nAddress: 142.250.0.1", ""),
            "dhcp.leases": (0, "3", ""),
            "logread": (0, "0", ""),
        })
        rc = guard.cmd_check()
        out = capsys.readouterr().out
        assert rc == 1
        assert "dnsmasq NOT RUNNING" in out


class TestAuditFailsClosed:
    def test_audit_propagates_validate_refusal(self, monkeypatch, capsys) -> None:
        fake_ssh(monkeypatch, {}, default=(255, "", "Permission denied"))
        assert guard.cmd_audit() == 1
        assert "cannot inspect" in capsys.readouterr().out


class TestSshChannel:
    def test_rc255_raises_inspect_error(self, monkeypatch) -> None:
        fake_ssh(monkeypatch, {}, default=(255, "", "No route to host"))
        with pytest.raises(guard.InspectError, match="rc=255"):
            guard.ssh("uci show dhcp")

    def test_remote_nonzero_rc_is_a_result_not_a_failure(self, monkeypatch) -> None:
        fake_ssh(monkeypatch, {}, default=(1, "", ""))
        assert guard.ssh("pgrep dnsmasq") == ""
