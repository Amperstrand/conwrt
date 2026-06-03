from profile.ops import (
    RpcCall,
    ShellCommand,
    UciAdd,
    UciAddList,
    UciCommit,
    UciDelete,
    UciSet,
    ServiceAction,
    render_ubus,
)


class TestRenderUciSet:
    def test_single_value(self):
        ops = [UciSet(config="system", section="@system[0]", values={"hostname": "foo"})]
        calls = render_ubus(ops)
        assert len(calls) == 1
        c = calls[0]
        assert c.object_name == "uci"
        assert c.method == "set"
        assert c.params == {
            "config": "system",
            "section": "@system[0]",
            "values": {"hostname": "foo"},
        }

    def test_multiple_values(self):
        ops = [UciSet(config="dropbear", section="@dropbear[0]", values={
            "PasswordAuth": "off",
            "Port": "22",
        })]
        calls = render_ubus(ops)
        assert len(calls) == 1
        assert calls[0].params["values"] == {"PasswordAuth": "off", "Port": "22"}


class TestRenderUciAdd:
    def test_anonymous_section(self):
        ops = [UciAdd(config="firewall", type="rule", values={
            "name": "Allow-SSH",
            "target": "ACCEPT",
        })]
        calls = render_ubus(ops)
        assert len(calls) == 1
        c = calls[0]
        assert c.method == "add"
        assert c.params["type"] == "rule"
        assert "name" not in c.params

    def test_named_section(self):
        ops = [UciAdd(config="firewall", type="rule", name="my_rule")]
        calls = render_ubus(ops)
        assert calls[0].params["name"] == "my_rule"


class TestRenderUciDelete:
    def test_delete_section(self):
        ops = [UciDelete(config="firewall", section="Block_iPad")]
        calls = render_ubus(ops)
        assert calls[0].method == "delete"
        assert "option" not in calls[0].params

    def test_delete_option(self):
        ops = [UciDelete(config="system", section="@system[0]", option="hostname")]
        calls = render_ubus(ops)
        assert calls[0].params["option"] == "hostname"


class TestRenderUciAddList:
    def test_add_list_becomes_set_with_array(self):
        ops = [UciAddList(config="firewall", section="wan", option="network", value="usbwan")]
        calls = render_ubus(ops)
        assert len(calls) == 1
        c = calls[0]
        assert c.method == "set"
        assert c.params["values"] == {"network": ["usbwan"]}


class TestRenderUciCommit:
    def test_commit(self):
        ops = [UciCommit(config="system")]
        calls = render_ubus(ops)
        assert calls[0].params == {"config": "system"}


class TestRenderServiceAction:
    def test_restart(self):
        ops = [ServiceAction(name="firewall", action="restart")]
        calls = render_ubus(ops)
        assert calls[0].object_name == "rc"
        assert calls[0].method == "restart"
        assert calls[0].params == {"name": "firewall"}

    def test_enable(self):
        ops = [ServiceAction(name="sqm", action="enable")]
        calls = render_ubus(ops)
        assert calls[0].method == "enable"


class TestRenderShellCommand:
    def test_shell_command_marked_fallback(self):
        ops = [ShellCommand(command="mkdir -p /etc/config")]
        calls = render_ubus(ops)
        assert len(calls) == 1
        c = calls[0]
        assert c.object_name == "exec"
        assert c.params["command"] == "mkdir -p /etc/config"
        assert c.params["fallback"] is True


class TestRenderMixedOps:
    def test_full_sequence(self):
        ops = [
            UciSet(config="system", section="@system[0]", values={"hostname": "r1"}),
            UciCommit(config="system"),
            ShellCommand(command="echo done"),
        ]
        calls = render_ubus(ops)
        assert len(calls) == 3
        assert calls[0].method == "set"
        assert calls[1].method == "commit"
        assert calls[2].object_name == "exec"

    def test_empty_ops(self):
        assert render_ubus([]) == []
