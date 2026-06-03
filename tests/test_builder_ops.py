from config import ConwrtConfig, UseCaseConfig
from profile import build_plan
from profile.ops import ShellCommand, UciAdd, UciCommit, UciSet, render_shell
from profile.plan import StepKind


class TestBuilderInlineOps:
    def test_dhcp_disable_step_has_ops(self):
        cfg = ConwrtConfig()
        plan = build_plan(cfg, mode="post_install", disable_dhcp=True)
        steps = [s for s in plan.steps if s.kind == StepKind.DHCP_DISABLE]
        assert len(steps) == 1
        step = steps[0]
        assert len(step.ops) == 2
        assert isinstance(step.ops[0], UciSet)
        assert step.ops[0].config == "dhcp"
        assert step.ops[0].values == {"ignore": "1"}
        assert isinstance(step.ops[1], UciCommit)

    def test_static_hostname_step_has_ops(self):
        cfg = ConwrtConfig(hostname="my-router")
        plan = build_plan(cfg, mode="post_install")
        steps = [s for s in plan.steps if s.kind == StepKind.HOSTNAME]
        assert len(steps) == 1
        step = steps[0]
        assert len(step.ops) == 2
        assert isinstance(step.ops[0], UciSet)
        assert step.ops[0].values["hostname"] == "my-router"
        assert isinstance(step.ops[1], UciCommit)

    def test_mac_hash_hostname_step_has_ops(self):
        cfg = ConwrtConfig(hostname_pattern="model_mac")
        plan = build_plan(cfg, mode="post_install", model_id="asus-lyra-map-ac2200")
        steps = [s for s in plan.steps if s.kind == StepKind.HOSTNAME]
        assert len(steps) == 1
        step = steps[0]
        assert all(isinstance(op, ShellCommand) for op in step.ops)
        rendered = render_shell(step.ops)
        assert "uci set system.@system[0].hostname" in rendered
        assert "uci commit system" in rendered

    def test_ssh_key_step_has_ops(self):
        cfg = ConwrtConfig()
        plan = build_plan(cfg, mode="post_install", ssh_key_path=None)
        steps = [s for s in plan.steps if s.kind == StepKind.SSH_KEY]
        assert len(steps) == 0

    def test_password_step_has_ops(self):
        cfg = ConwrtConfig()
        plan = build_plan(cfg, mode="post_install", password="secret")
        steps = [s for s in plan.steps if s.kind == StepKind.PASSWORD]
        assert len(steps) == 1
        step = steps[0]
        assert len(step.ops) == 1
        assert isinstance(step.ops[0], ShellCommand)
        assert "passwd root" in step.ops[0].command

    def test_wan_ssh_step_has_ops(self):
        cfg = ConwrtConfig()
        plan = build_plan(cfg, mode="post_install", wan_ssh=True)
        steps = [s for s in plan.steps if s.kind == StepKind.WAN_SSH]
        assert len(steps) == 1
        step = steps[0]
        assert len(step.ops) == 4
        assert isinstance(step.ops[0], UciAdd)
        assert step.ops[0].config == "firewall"
        assert step.ops[0].type == "rule"
        assert isinstance(step.ops[1], UciCommit)
        assert isinstance(step.ops[2], UciSet)
        assert step.ops[2].config == "dropbear"
        assert isinstance(step.ops[3], UciCommit)

    def test_cellular_step_has_ops(self):
        cfg = ConwrtConfig()
        plan = build_plan(cfg, mode="post_install", model_capabilities=["cellular"])
        steps = [s for s in plan.steps if s.kind == StepKind.CELLULAR]
        assert len(steps) == 1
        step = steps[0]
        assert len(step.ops) == 2
        assert isinstance(step.ops[0], UciSet)
        assert step.ops[0].values["proto"] == "qmi"
        assert isinstance(step.ops[1], UciCommit)

    def test_lan_ip_step_has_ops(self):
        cfg = ConwrtConfig(lan_ip="192.168.50.1")
        plan = build_plan(cfg, mode="post_install")
        steps = [s for s in plan.steps if s.kind == StepKind.LAN_IP]
        assert len(steps) == 1
        step = steps[0]
        assert len(step.ops) == 1
        assert isinstance(step.ops[0], UciSet)
        assert step.ops[0].values["ipaddr"] == "192.168.50.1"

    def test_mac_hash_ip_step_has_ops(self):
        cfg = ConwrtConfig(lan_ip_mode="mac-hash")
        plan = build_plan(cfg, mode="post_install", model_id="asus-lyra-map-ac2200")
        steps = [s for s in plan.steps if s.kind == StepKind.LAN_IP_MAC_HASH]
        assert len(steps) == 1
        step = steps[0]
        assert all(isinstance(op, ShellCommand) for op in step.ops)
        rendered = render_shell(step.ops)
        assert "md5sum" in rendered
        assert "uci set network.lan.ipaddr" in rendered


class TestBuilderUseCaseOps:
    def test_use_case_step_has_ops(self):
        cfg = ConwrtConfig(
            use_cases=[UseCaseConfig(name="sqm", params={"download_kbps": 50000, "upload_kbps": 10000})],
        )
        plan = build_plan(cfg, mode="post_install")
        uc_steps = [s for s in plan.steps if s.kind == StepKind.USE_CASE and s.use_case_name == "sqm"]
        assert len(uc_steps) == 1
        step = uc_steps[0]
        assert len(step.ops) > 0

    def test_use_case_ops_render_to_shell(self):
        cfg = ConwrtConfig(
            use_cases=[UseCaseConfig(name="ssh-hardening")],
        )
        plan = build_plan(cfg, mode="post_install")
        uc_steps = [s for s in plan.steps if s.kind == StepKind.USE_CASE and s.use_case_name == "ssh-hardening"]
        assert len(uc_steps) == 1
        rendered = render_shell(uc_steps[0].ops)
        assert "uci set dropbear" in rendered
        assert "uci commit dropbear" in rendered

    def test_tether_use_case_has_ops(self):
        cfg = ConwrtConfig(
            use_cases=[UseCaseConfig(name="tether-android-adb")],
        )
        plan = build_plan(cfg, mode="asu_build", model_capabilities=["usb"])
        uc_steps = [s for s in plan.steps if s.kind == StepKind.USE_CASE and s.use_case_name == "tether-android-adb"]
        assert len(uc_steps) == 1
        assert len(uc_steps[0].ops) > 0

    def test_unknown_use_case_has_empty_ops(self):
        cfg = ConwrtConfig(
            use_cases=[UseCaseConfig(name="nonexistent")],
        )
        plan = build_plan(cfg, mode="post_install")
        uc_steps = [s for s in plan.steps if s.kind == StepKind.USE_CASE]
        assert len(uc_steps) == 1
        assert uc_steps[0].ops == []
        assert "unknown" in uc_steps[0].skipped_reason
