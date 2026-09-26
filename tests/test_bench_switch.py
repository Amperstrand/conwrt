"""bench_switch + serial_transport — unit tests (hardware-safe, no network)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _SCRIPTS / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, mod)
    spec.loader.exec_module(mod)
    return mod


bs = _load("bench_switch")
st = _load("serial_transport")


# ------------------------------------------------------- serial linting

class TestSerialLinter:
    def test_rejects_variable_in_single_quotes(self) -> None:
        with pytest.raises(st.SerialLinterError, match="will not expand"):
            st.lint_script(["uci set network.dut1002.device='switch.100$N'"])

    def test_accepts_literal_lines(self) -> None:
        st.lint_script(["uci set network.dut1002.device='switch.1002'",
                        "echo done"])

    def test_allows_command_substitution_outside_quotes(self) -> None:
        st.lint_script(["P=`uci -q get poe.@port[0].name`"])

    def test_rejects_overlong_line(self) -> None:
        with pytest.raises(st.SerialLinterError, match="exceeds"):
            st.lint_script(["echo '" + "x" * 250 + "'"])

    def test_skips_comments_and_blanks(self) -> None:
        st.lint_script(["# comment", "", "  ", "true"])


# ------------------------------------------------------- deploy generator

PUBKEY = "ssh-ed25519 AAAAC3test test@host"


class TestDeployLines:
    def test_all_values_literal(self) -> None:
        lines = bs.deploy_lines(bs.BenchProfile(), PUBKEY)
        st.lint_script(lines)

    def test_vlan1_is_list_form_uplink_only(self) -> None:
        lines = bs.deploy_lines(bs.BenchProfile(), None)
        assert "uci add_list network.vlan1.ports='lan1:u*'" in lines
        assert not any(ln.startswith("uci add_list network.vlan1.ports='lan8") for ln in lines)

    def test_from_scratch_prerequisites(self) -> None:
        lines = bs.deploy_lines(bs.BenchProfile(), None)
        assert "uci set network.@device[0].name='switch'" in lines
        assert "uci -q delete network.lan_vlan" in lines
        assert "uci -q delete network.lan.ipaddr" in lines
        assert "uci set network.vlan1.local='1'" in lines
        assert "uci set network.vlan1005.local='1'" in lines
        assert "uci -q set dhcp.lan.ignore='1'" in lines
        assert "uci add_list firewall.@zone[0].network=dut1005" in lines
        assert "uci -q del_list firewall.@zone[0].network=dut1005" in lines

    def test_dut_vlans_mnemonic_addresses(self) -> None:
        lines = bs.deploy_lines(bs.BenchProfile(), None)
        assert "uci set network.dut1002.device='switch.1002'" in lines
        assert "uci set network.dut1008.device='switch.1008'" in lines
        assert "uci set network.dut1003.ipaddr='192.168.103.1'" in lines
        assert "uci add_list network.vlan1007.ports='lan7:u*'" in lines

    def test_deadman_is_first(self) -> None:
        assert bs.deploy_lines(bs.BenchProfile(), None)[0].startswith("nohup sh -c")

    def test_pubkey_installed_idempotently(self) -> None:
        lines = bs.deploy_lines(bs.BenchProfile(), PUBKEY)
        assert any("grep -q" in ln and "|| {" in ln for ln in lines)
        key_chunks = [ln for ln in lines if "conwrt-key" in ln and "echo -n" in ln]
        assert key_chunks, "key must be installed in chunks"
        joined = "".join(ln.split("'")[1] for ln in key_chunks)
        assert PUBKEY in joined

    def test_custom_profile(self) -> None:
        prof = bs.BenchProfile(mgmt_ip="192.168.99.2", mgmt_gateway="192.168.99.1",
                               dut_ports=("lan2", "lan3"))
        lines = bs.deploy_lines(prof, None)
        assert "uci add_list network.lan.ipaddr='192.168.99.2/24'" in lines
        assert "uci set network.dut1003.ipaddr='192.168.103.1'" in lines
        assert not any("dut1004" in ln for ln in lines)


def test_deadman_cancel() -> None:
    assert "killall sleep" in bs.deadman_cancel_lines()[0]


def test_vlan_name() -> None:
    assert bs.vlan_name(bs.BenchProfile(), "lan7") == "vlan1007"


class TestDeployReadbackGate:
    def test_reverts_stale_staging_before_staging(self) -> None:
        lines = bs.deploy_lines(bs.BenchProfile(), None)
        joined = "\n".join(lines)
        assert "uci revert network" in joined and "uci revert poe" in joined, \
            "aborted-run staging debris must be reverted before staging"
        assert joined.index("uci revert network") < joined.index("uci set network.lan.proto")

    def test_commit_is_gated_on_value_readbacks(self) -> None:
        lines = bs.deploy_lines(bs.BenchProfile(), None)
        gate_idx = next(i for i, l in enumerate(lines) if l.startswith("RB=1"))
        commit_idx = next(i for i, l in enumerate(lines) if "uci commit network" in l)
        readback_idx = next(i for i, l in enumerate(lines) if "---READBACK---" in l)
        assert gate_idx < commit_idx, "the readback gate must precede any commit"
        assert gate_idx < readback_idx < commit_idx
        mgmt = bs.BenchProfile().mgmt_ip
        assert any(f'= "{mgmt}/24" ]' in l for l in lines[gate_idx:readback_idx]), \
            "the management address must be read back before commit"

    def test_mismatch_reverts_and_cancels_deadman(self) -> None:
        lines = bs.deploy_lines(bs.BenchProfile(), None)
        else_idx = next(i for i, l in enumerate(lines) if l.startswith("else"))
        tail = "\n".join(lines[else_idx:])
        assert "uci revert network" in tail and "killall sleep" in tail
        assert "READBACK-MISMATCH" in tail


class TestSshStdinDeploy:
    def test_deploy_script_travels_via_stdin_not_wrapped_sh_c(self,
                                                              monkeypatch) -> None:
        captured: dict = {}

        def fake_ssh(host, cmd, timeout=60, stdin_data=None):
            captured.update(host=host, cmd=cmd, stdin=stdin_data)
            return 0, "DEPLOY-COMMITTED"

        monkeypatch.setattr(bs, "ssh", fake_ssh)
        rc = bs.cmd_deploy("10.9.9.9", None, bs.BenchProfile(), None)
        assert rc == 0
        assert captured["cmd"] == "sh -s", "script must be fed via stdin"
        assert captured["stdin"] and "nohup sh -c 'sleep 600 && reboot'" in captured["stdin"], \
            "the deadman's single quotes must survive untouched"
