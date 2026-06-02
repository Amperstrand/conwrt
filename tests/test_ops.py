"""Tests for structured UCI operation types (profile/ops.py)."""
from __future__ import annotations

from profile.ops import (
    Op,
    ServiceAction,
    ShellCommand,
    UciAdd,
    UciAddList,
    UciCommit,
    UciDelete,
    UciSet,
)


class TestUciSet:
    def test_basic(self):
        op = UciSet(config="system", section="@system[0]", values={"hostname": "my-router"})
        assert op.config == "system"
        assert op.section == "@system[0]"
        assert op.values == {"hostname": "my-router"}

    def test_multiple_values(self):
        op = UciSet(config="firewall", section="Block_iPad", values={
            "enabled": "1",
            "target": "REJECT",
            "src_mac": "AA:BB:CC:DD:EE:FF",
        })
        assert len(op.values) == 3

    def test_list_value(self):
        op = UciSet(config="dhcp", section="@dnsmasq[0]", values={
            "server": ["/youtube.com/", "/googlevideo.com/"],
        })
        assert isinstance(op.values["server"], list)
        assert len(op.values["server"]) == 2

    def test_default_values_empty(self):
        op = UciSet(config="network", section="lan")
        assert op.values == {}


class TestUciAdd:
    def test_anonymous_section(self):
        op = UciAdd(config="firewall", type="rule", values={"name": "Block-iPad", "target": "REJECT"})
        assert op.name == ""
        assert op.values["name"] == "Block-iPad"

    def test_named_section(self):
        op = UciAdd(config="dhcp", type="ipset", name="youtube",
                     values={"name": "youtube_set"})
        assert op.name == "youtube"


class TestUciDelete:
    def test_delete_section(self):
        op = UciDelete(config="firewall", section="Block_iPad")
        assert op.option == ""

    def test_delete_option(self):
        op = UciDelete(config="wireless", section="@wifi-iface[0]", option="disabled")
        assert op.option == "disabled"


class TestUciAddList:
    def test_basic(self):
        op = UciAddList(config="dhcp", section="@dnsmasq[0]", option="server", value="/youtube.com/")
        assert op.value == "/youtube.com/"


class TestUciCommit:
    def test_basic(self):
        op = UciCommit(config="firewall")
        assert op.config == "firewall"


class TestServiceAction:
    def test_reload(self):
        op = ServiceAction(name="firewall", action="reload")
        assert op.action == "reload"

    def test_restart(self):
        op = ServiceAction(name="dnsmasq", action="restart")
        assert op.name == "dnsmasq"


class TestShellCommand:
    def test_basic(self):
        op = ShellCommand(command="sync; sync; reboot")
        assert op.command == "sync; sync; reboot"


class TestOpUnion:
    """Verify Op type accepts all operation types."""

    def test_all_types_are_op(self):
        ops: list[Op] = [
            UciSet(config="system", section="@system[0]", values={"hostname": "test"}),
            UciAdd(config="firewall", type="rule"),
            UciDelete(config="wireless", section="@wifi-iface[0]", option="disabled"),
            UciAddList(config="dhcp", section="@dnsmasq[0]", option="server", value="/x/"),
            UciCommit(config="system"),
            ServiceAction(name="firewall", action="reload"),
            ShellCommand(command="echo hello"),
        ]
        assert len(ops) == 7
        # Verify isinstance works for each
        assert isinstance(ops[0], UciSet)
        assert isinstance(ops[1], UciAdd)
        assert isinstance(ops[2], UciDelete)
        assert isinstance(ops[3], UciAddList)
        assert isinstance(ops[4], UciCommit)
        assert isinstance(ops[5], ServiceAction)
        assert isinstance(ops[6], ShellCommand)
