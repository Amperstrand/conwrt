"""Tests for the tollgate flow (distinct from net4sats) and the password step."""
from __future__ import annotations

from flows import Flow, Step, get as get_flow, registry as flow_registry
from flows.render import render_flow_shell
from model_loader import load_model


def test_tollgate_and_net4sats_both_registered():
    flows = flow_registry()
    assert "tollgate" in flows
    assert "net4sats" in flows


def test_tollgate_is_net4sats_minus_portal_with_generic_branding():
    tollgate = get_flow("tollgate")
    net4sats = get_flow("net4sats")
    assert [s.title for s in tollgate.steps][:3] == [s.title for s in net4sats.steps][:3]
    assert not any(s.package == "configurationwizzard" for s in tollgate.steps)
    assert any(s.package == "configurationwizzard" for s in net4sats.steps)
    assert tollgate.steps[-1].use_case_params["gateway_name"] == "TollGate"
    assert net4sats.steps[-1].use_case_params["gateway_name"] == "net4sats"


def test_password_step_renders_chpasswd():
    flow = Flow(name="pw", description="", steps=[Step(kind="password", title="Set a random root password")])
    script = render_flow_shell(flow, load_model("dlink-covr-x1860-a1"), {}, version="24.10.7")
    assert "chpasswd" in script
    assert "root password: $PW" in script
    assert "ssh root@$IP sh <<'CONWRT_EOF'" in script


def test_tollgate_flow_renders_without_portal():
    tollgate = get_flow("tollgate")
    script = render_flow_shell(tollgate, load_model("glinet-mt3000"),
                               {"upstream_ssid": "A", "upstream_key": "B"}, version="24.10.7")
    assert "gatewayname='TollGate'" in script
    assert "configurationwizzard" not in script


def test_set_password_step_renders_chpasswd_with_value():
    flow = Flow(name="sp", description="",
                steps=[Step(kind="set_password", title="Set root password", password="s3cr3t")])
    script = render_flow_shell(flow, load_model("dlink-covr-x1860-a1"), {}, version="24.10.7")
    assert "echo 'root:s3cr3t' | chpasswd" in script


def test_hostname_step_renders_uci_and_proc():
    flow = Flow(name="hn", description="",
                steps=[Step(kind="hostname", title="Set hostname", hostname="net4sats")])
    script = render_flow_shell(flow, load_model("dlink-covr-x1860-a1"), {}, version="24.10.7")
    assert "uci set system.@system[0].hostname='net4sats'" in script
    assert "echo 'net4sats' > /proc/sys/kernel/hostname" in script


def test_wan_ssh_step_opens_firewall_port_22():
    flow = Flow(name="ws", description="", steps=[Step(kind="wan_ssh", title="WAN SSH")])
    script = render_flow_shell(flow, load_model("dlink-covr-x1860-a1"), {}, version="24.10.7")
    assert "firewall.wan_ssh" in script
    assert "firewall.wan_ssh.dest_port='22'" in script
    assert "/etc/init.d/firewall restart" in script
