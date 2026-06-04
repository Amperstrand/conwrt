"""Tests for render_shell — the SSH shell renderer for structured UCI operations.

These tests verify that render_shell produces output equivalent to what conwrt
currently generates via raw f-strings. This is the migration contract: if these
tests pass, the op-based approach produces identical shell output.
"""
from __future__ import annotations

from profile.ops import (
    BlankLine,
    Comment,
    Op,
    ServiceAction,
    ShellCommand,
    UciAdd,
    UciAddList,
    UciCommit,
    UciDelete,
    UciSet,
    render_shell,
)


class TestRenderUciSet:
    def test_single_value(self):
        ops: list[Op] = [
            UciSet(config="system", section="@system[0]", values={"hostname": "my-router"}),
        ]
        assert render_shell(ops) == "uci set system.@system[0].hostname='my-router'"

    def test_multiple_values(self):
        ops: list[Op] = [
            UciSet(config="firewall", section="Block_iPad", values={
                "enabled": "1",
                "target": "REJECT",
            }),
        ]
        lines = render_shell(ops).split("\n")
        assert "uci set firewall.Block_iPad.enabled='1'" in lines
        assert "uci set firewall.Block_iPad.target='REJECT'" in lines

    def test_list_value_produces_add_list(self):
        ops: list[Op] = [
            UciSet(config="dhcp", section="@dnsmasq[0]", values={
                "server": ["/youtube.com/", "/googlevideo.com/"],
            }),
        ]
        lines = render_shell(ops).split("\n")
        assert "uci add_list dhcp.@dnsmasq[0].server='/youtube.com/'" in lines
        assert "uci add_list dhcp.@dnsmasq[0].server='/googlevideo.com/'" in lines

    def test_empty_values_produces_nothing(self):
        ops: list[Op] = [UciSet(config="system", section="lan")]
        assert render_shell(ops) == ""

    def test_value_with_single_quote_escaped(self):
        ops: list[Op] = [
            UciSet(config="system", section="@system[0]", values={"hostname": "it's a router"}),
        ]
        assert "it'\\''s a router" in render_shell(ops)


class TestRenderUciAdd:
    def test_anonymous_section_with_values(self):
        ops: list[Op] = [
            UciAdd(config="firewall", type="rule", values={
                "name": "Block-iPad",
                "target": "REJECT",
                "src": "lan",
            }),
        ]
        lines = render_shell(ops).split("\n")
        assert "uci add firewall rule" in lines
        assert "uci set firewall.@rule[-1].name='Block-iPad'" in lines
        assert "uci set firewall.@rule[-1].target='REJECT'" in lines
        assert "uci set firewall.@rule[-1].src='lan'" in lines

    def test_named_section(self):
        ops: list[Op] = [
            UciAdd(config="dhcp", type="ipset", name="youtube",
                   values={"name": "youtube_set"}),
        ]
        lines = render_shell(ops).split("\n")
        assert "uci add dhcp ipset" in lines
        assert "uci set dhcp.@ipset[-1].name='youtube'" in lines
        assert "uci set dhcp.@ipset[-1].name='youtube_set'" in lines

    def test_empty_values_only_creates_section(self):
        ops: list[Op] = [UciAdd(config="firewall", type="rule")]
        assert render_shell(ops) == "uci add firewall rule"


class TestRenderUciDelete:
    def test_delete_section(self):
        ops: list[Op] = [UciDelete(config="wireless", section="@wifi-iface[1]")]
        assert render_shell(ops) == "uci delete wireless.@wifi-iface[1]"

    def test_delete_option(self):
        ops: list[Op] = [
            UciDelete(config="wireless", section="@wifi-iface[0]", option="disabled"),
        ]
        assert render_shell(ops) == "uci delete wireless.@wifi-iface[0].disabled"


class TestRenderUciAddList:
    def test_basic(self):
        ops: list[Op] = [
            UciAddList(config="dhcp", section="@dnsmasq[0]", option="server", value="/x/"),
        ]
        assert render_shell(ops) == "uci add_list dhcp.@dnsmasq[0].server='/x/'"


class TestRenderUciCommit:
    def test_basic(self):
        ops: list[Op] = [UciCommit(config="firewall")]
        assert render_shell(ops) == "uci commit firewall"


class TestRenderServiceAction:
    def test_reload(self):
        ops: list[Op] = [ServiceAction(name="firewall", action="reload")]
        assert render_shell(ops) == "/etc/init.d/firewall reload"

    def test_restart(self):
        ops: list[Op] = [ServiceAction(name="dnsmasq", action="restart")]
        assert render_shell(ops) == "/etc/init.d/dnsmasq restart"


class TestRenderShellCommand:
    def test_basic(self):
        ops: list[Op] = [ShellCommand(command="sync; sync; reboot")]
        assert render_shell(ops) == "sync; sync; reboot"


class TestRenderComment:
    def test_basic(self):
        ops: list[Op] = [Comment(text="AdGuard Home")]
        assert render_shell(ops) == "# AdGuard Home"

    def test_with_section_markers(self):
        ops: list[Op] = [Comment(text="--- WireGuard VPN client ---")]
        assert render_shell(ops) == "# --- WireGuard VPN client ---"


class TestRenderBlankLine:
    def test_basic(self):
        ops: list[Op] = [UciCommit(config="network"), BlankLine(), UciSet(config="dhcp", section="@dnsmasq[0]", values={"noresolv": "1"})]
        lines = render_shell(ops).split("\n")
        assert lines[0] == "uci commit network"
        assert lines[1] == ""
        assert lines[2] == "uci set dhcp.@dnsmasq[0].noresolv='1'"


class TestCommentBlankLineCompound:
    def test_comment_blank_ops_interleaved(self):
        ops: list[Op] = [
            Comment(text="AdGuard Home"),
            UciSet(config="adguardhome", section="adguardhome", values={"enabled": "1"}),
            UciCommit(config="adguardhome"),
            BlankLine(),
            Comment(text="DNS forwarding"),
            UciSet(config="dhcp", section="@dnsmasq[0]", values={"noresolv": "1"}),
            UciCommit(config="dhcp"),
        ]
        script = render_shell(ops)
        assert script.startswith("# AdGuard Home\n")
        assert "\n\n" in script  # blank line between groups
        assert "# DNS forwarding" in script


class TestRenderCompoundScript:
    def test_full_firewall_rule(self):
        """Simulates a real-world sequence: add rule, set values, commit, reload."""
        ops: list[Op] = [
            UciAdd(config="firewall", type="rule", name="Block_iPad", values={
                "src": "lan",
                "dest": "wan",
                "src_mac": "AA:BB:CC:DD:EE:FF",
                "proto": "all",
                "target": "REJECT",
            }),
            UciCommit(config="firewall"),
            ServiceAction(name="firewall", action="reload"),
        ]
        script = render_shell(ops)
        assert "uci add firewall rule" in script
        assert "uci set firewall.@rule[-1].name='Block_iPad'" in script
        assert "uci set firewall.@rule[-1].src_mac='AA:BB:CC:DD:EE:FF'" in script
        assert "uci commit firewall" in script
        assert "/etc/init.d/firewall reload" in script

    def test_empty_ops_list(self):
        assert render_shell([]) == ""

    def test_order_preserved(self):
        ops: list[Op] = [
            UciSet(config="system", section="@system[0]", values={"hostname": "a"}),
            UciSet(config="system", section="@system[0]", values={"timezone": "UTC"}),
            UciCommit(config="system"),
        ]
        lines = render_shell(ops).split("\n")
        assert lines[0] == "uci set system.@system[0].hostname='a'"
        assert lines[1] == "uci set system.@system[0].timezone='UTC'"
        assert lines[2] == "uci commit system"
