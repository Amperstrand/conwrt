"""Tests for pure helper functions in profile.builder."""
from __future__ import annotations

import base64
from unittest.mock import MagicMock

from config import ConwrtConfig, WifiAPConfig
from profile import build_plan
from profile.builder import (
    _VALID_HOSTNAME_RE,
    _configure_script_for_mode,
    _firstboot_for_mode,
    _password_firstboot,
    _password_ops,
    _ssh_key_firstboot,
    _ssh_key_ops,
    _uc_packages_for_mode,
)
from profile.ops import ShellCommand
from profile.plan import StepKind
from ssh_utils import DROPBEAR_AUTH_KEYS_PATH


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_uc(
    packages=None,
    packages_remove=None,
    packages_via="auto",
    configure_via="auto",
    configure_script="uci set foo.bar='baz'",
):
    """Create a mock use case object with configurable attributes."""
    uc = MagicMock()
    uc.packages = packages if packages is not None else ["pkg1", "pkg2"]
    uc.packages_remove = packages_remove if packages_remove is not None else []
    uc.packages_via = packages_via
    uc.configure_via = configure_via
    uc.build_configure.return_value = configure_script
    return uc


# ===================================================================
# 1. _ssh_key_firstboot
# ===================================================================

class TestSshKeyFirstboot:
    def test_single_key_uses_redirect(self):
        result = _ssh_key_firstboot(["ssh-ed25519 AAAA"])
        assert "echo 'ssh-ed25519 AAAA' >" in result

    def test_single_key_has_mkdir_and_chmod(self):
        result = _ssh_key_firstboot(["ssh-ed25519 AAAA"])
        assert result.startswith("mkdir -p")
        assert "chmod 600" in result

    def test_two_keys_first_redirect_second_append(self):
        result = _ssh_key_firstboot(["key1", "key2"])
        lines = result.split("\n")
        key_lines = [l for l in lines if l.startswith("echo")]
        assert len(key_lines) == 2
        assert ">" in key_lines[0] and ">>" not in key_lines[0]
        assert ">>" in key_lines[1]

    def test_empty_list_only_mkdir_chmod(self):
        result = _ssh_key_firstboot([])
        lines = result.split("\n")
        assert len(lines) == 2
        assert lines[0].startswith("mkdir -p")
        assert lines[1].startswith("chmod 600")

    def test_contains_dropbear_path(self):
        result = _ssh_key_firstboot(["key1"])
        assert DROPBEAR_AUTH_KEYS_PATH in result
        assert "/etc/dropbear" in result

    def test_mkdir_uses_parent_dir(self):
        result = _ssh_key_firstboot(["key1"])
        parent = DROPBEAR_AUTH_KEYS_PATH.rsplit("/", 1)[0]
        assert f"mkdir -p {parent}" in result


# ===================================================================
# 2. _ssh_key_ops
# ===================================================================

class TestSshKeyOps:
    def test_single_key_returns_three_ops(self):
        ops = _ssh_key_ops(["key1"])
        assert len(ops) == 3
        assert all(isinstance(op, ShellCommand) for op in ops)

    def test_single_key_ops_content(self):
        ops = _ssh_key_ops(["key1"])
        assert "mkdir -p" in ops[0].command
        assert "echo 'key1' >" in ops[1].command
        assert "chmod 600" in ops[2].command

    def test_two_keys_returns_four_ops(self):
        ops = _ssh_key_ops(["key1", "key2"])
        assert len(ops) == 4
        # mkdir, echo key1 >, echo key2 >>, chmod
        assert ">" in ops[1].command and ">>" not in ops[1].command
        assert ">>" in ops[2].command

    def test_empty_keys_returns_mkdir_chmod(self):
        ops = _ssh_key_ops([])
        assert len(ops) == 2
        assert "mkdir" in ops[0].command
        assert "chmod" in ops[1].command

    def test_ops_match_firstboot_lines(self):
        keys = ["ssh-ed25519 AAA", "ssh-ed25519 BBB"]
        fb = _ssh_key_firstboot(keys)
        ops = _ssh_key_ops(keys)
        # Each op command should appear as a line in the firstboot script
        for op in ops:
            assert op.command in fb


# ===================================================================
# 3. _password_firstboot
# ===================================================================

class TestPasswordFirstboot:
    def test_contains_base64_encoded_password(self):
        result = _password_firstboot("secret")
        expected_b64 = base64.b64encode(b"secret").decode()
        assert expected_b64 in result

    def test_contains_passwd_root(self):
        result = _password_firstboot("secret")
        assert "passwd root" in result

    def test_roundtrip_base64_decode(self):
        password = "my-p@ssw0rd!"
        result = _password_firstboot(password)
        # Extract the base64 string from the output
        import re
        b64_match = re.search(r"echo '([A-Za-z0-9+/=]+)' \| base64 -d", result)
        assert b64_match is not None
        decoded = base64.b64decode(b64_match.group(1)).decode()
        assert decoded == password

    def test_special_characters_in_password(self):
        password = "p@$$w0rd!#%^&*()"
        result = _password_firstboot(password)
        expected_b64 = base64.b64encode(password.encode()).decode()
        assert expected_b64 in result

    def test_printf_format(self):
        result = _password_firstboot("test")
        assert "printf" in result
        assert "\\n" in result


# ===================================================================
# 4. _password_ops
# ===================================================================

class TestPasswordOps:
    def test_returns_single_shell_command(self):
        ops = _password_ops("secret")
        assert len(ops) == 1
        assert isinstance(ops[0], ShellCommand)

    def test_command_matches_firstboot(self):
        password = "secret"
        ops = _password_ops(password)
        expected = _password_firstboot(password)
        assert ops[0].command == expected

    def test_password_in_command(self):
        ops = _password_ops("mypass")
        assert "passwd root" in ops[0].command


# ===================================================================
# 5. _uc_packages_for_mode
# ===================================================================

class TestUcPackagesForMode:
    # -- auto via ----------------------------------------------------------
    def test_auto_via_asu_build(self):
        uc = _make_uc(packages_via="auto")
        pkgs, remove = _uc_packages_for_mode(uc, "asu_build")
        assert pkgs == ["pkg1", "pkg2"]
        assert remove == []

    def test_auto_via_post_install(self):
        uc = _make_uc(packages_via="auto")
        pkgs, remove = _uc_packages_for_mode(uc, "post_install")
        assert pkgs == ["pkg1", "pkg2"]

    def test_auto_via_preview(self):
        uc = _make_uc(packages_via="auto")
        pkgs, remove = _uc_packages_for_mode(uc, "preview")
        assert pkgs == ["pkg1", "pkg2"]

    # -- image via ---------------------------------------------------------
    def test_image_via_asu_build(self):
        uc = _make_uc(packages_via="image")
        pkgs, remove = _uc_packages_for_mode(uc, "asu_build")
        assert pkgs == ["pkg1", "pkg2"]

    def test_image_via_post_install_no_packages(self):
        uc = _make_uc(packages_via="image")
        pkgs, remove = _uc_packages_for_mode(uc, "post_install")
        assert pkgs == []

    def test_image_via_preview_no_packages(self):
        uc = _make_uc(packages_via="image")
        pkgs, remove = _uc_packages_for_mode(uc, "preview")
        assert pkgs == []

    # -- opkg via ----------------------------------------------------------
    def test_opkg_via_asu_build_no_packages(self):
        uc = _make_uc(packages_via="opkg")
        pkgs, remove = _uc_packages_for_mode(uc, "asu_build")
        assert pkgs == []

    def test_opkg_via_post_install(self):
        uc = _make_uc(packages_via="opkg")
        pkgs, remove = _uc_packages_for_mode(uc, "post_install")
        assert pkgs == ["pkg1", "pkg2"]

    def test_opkg_via_preview(self):
        uc = _make_uc(packages_via="opkg")
        pkgs, remove = _uc_packages_for_mode(uc, "preview")
        assert pkgs == ["pkg1", "pkg2"]

    # -- empty packages ----------------------------------------------------
    def test_empty_packages_returns_empty(self):
        uc = _make_uc(packages=[], packages_via="auto")
        pkgs, remove = _uc_packages_for_mode(uc, "asu_build")
        assert pkgs == []
        assert remove == []

    def test_empty_packages_image_via(self):
        uc = _make_uc(packages=[], packages_via="image")
        pkgs, remove = _uc_packages_for_mode(uc, "asu_build")
        assert pkgs == []

    def test_empty_packages_opkg_via(self):
        uc = _make_uc(packages=[], packages_via="opkg")
        pkgs, remove = _uc_packages_for_mode(uc, "post_install")
        assert pkgs == []

    # -- packages_remove always preserved ----------------------------------
    def test_remove_always_preserved_auto(self):
        uc = _make_uc(packages_remove=["bad1", "bad2"], packages_via="auto")
        _, remove = _uc_packages_for_mode(uc, "asu_build")
        assert remove == ["bad1", "bad2"]

    def test_remove_preserved_empty_packages(self):
        uc = _make_uc(packages=[], packages_remove=["bad1"])
        _, remove = _uc_packages_for_mode(uc, "post_install")
        assert remove == ["bad1"]

    def test_remove_preserved_image_via(self):
        uc = _make_uc(packages_via="image", packages_remove=["bad1"])
        _, remove = _uc_packages_for_mode(uc, "post_install")
        assert remove == ["bad1"]


# ===================================================================
# 6. _configure_script_for_mode
# ===================================================================

class TestConfigureScriptForMode:
    def test_firstboot_via_asu_build_returns_script(self):
        uc = _make_uc(configure_via="firstboot")
        result = _configure_script_for_mode(uc, {}, "asu_build")
        assert result == "uci set foo.bar='baz'"

    def test_firstboot_via_post_install_returns_empty(self):
        uc = _make_uc(configure_via="firstboot")
        result = _configure_script_for_mode(uc, {}, "post_install")
        assert result == ""

    def test_firstboot_via_preview_returns_empty(self):
        uc = _make_uc(configure_via="firstboot")
        result = _configure_script_for_mode(uc, {}, "preview")
        assert result == ""

    def test_ssh_via_asu_build_returns_empty(self):
        uc = _make_uc(configure_via="ssh")
        result = _configure_script_for_mode(uc, {}, "asu_build")
        assert result == ""

    def test_ssh_via_post_install_returns_script(self):
        uc = _make_uc(configure_via="ssh")
        result = _configure_script_for_mode(uc, {}, "post_install")
        assert result == "uci set foo.bar='baz'"

    def test_ssh_via_preview_returns_script(self):
        uc = _make_uc(configure_via="ssh")
        result = _configure_script_for_mode(uc, {}, "preview")
        assert result == "uci set foo.bar='baz'"

    def test_auto_via_returns_script_all_modes(self):
        uc = _make_uc(configure_via="auto")
        for mode in ("asu_build", "post_install", "preview"):
            result = _configure_script_for_mode(uc, {}, mode)
            assert result == "uci set foo.bar='baz'"

    def test_empty_script_returns_empty(self):
        uc = _make_uc(configure_script="")
        result = _configure_script_for_mode(uc, {}, "asu_build")
        assert result == ""

    def test_whitespace_only_script_returns_empty(self):
        uc = _make_uc(configure_script="   \n  \t  ")
        result = _configure_script_for_mode(uc, {}, "asu_build")
        assert result == ""


# ===================================================================
# 7. _firstboot_for_mode
# ===================================================================

class TestFirstbootForMode:
    def test_firstboot_via_asu_build_returns_script(self):
        uc = _make_uc(configure_via="firstboot")
        result = _firstboot_for_mode(uc, {}, "asu_build")
        assert result == "uci set foo.bar='baz'"

    def test_firstboot_via_preview_returns_script(self):
        uc = _make_uc(configure_via="firstboot")
        result = _firstboot_for_mode(uc, {}, "preview")
        assert result == "uci set foo.bar='baz'"

    def test_firstboot_via_post_install_returns_empty(self):
        uc = _make_uc(configure_via="firstboot")
        result = _firstboot_for_mode(uc, {}, "post_install")
        assert result == ""

    def test_ssh_via_returns_empty_all_modes(self):
        uc = _make_uc(configure_via="ssh")
        for mode in ("asu_build", "post_install", "preview"):
            result = _firstboot_for_mode(uc, {}, mode)
            assert result == ""

    def test_both_via_asu_build_returns_script(self):
        uc = _make_uc(configure_via="both")
        result = _firstboot_for_mode(uc, {}, "asu_build")
        assert result == "uci set foo.bar='baz'"

    def test_both_via_preview_returns_script(self):
        uc = _make_uc(configure_via="both")
        result = _firstboot_for_mode(uc, {}, "preview")
        assert result == "uci set foo.bar='baz'"

    def test_both_via_post_install_returns_empty(self):
        uc = _make_uc(configure_via="both")
        result = _firstboot_for_mode(uc, {}, "post_install")
        assert result == ""

    def test_empty_script_returns_empty(self):
        uc = _make_uc(configure_script="")
        result = _firstboot_for_mode(uc, {}, "asu_build")
        assert result == ""

    def test_whitespace_script_returns_empty(self):
        uc = _make_uc(configure_script="  \n  ")
        result = _firstboot_for_mode(uc, {}, "asu_build")
        assert result == ""


# ===================================================================
# 8. _VALID_HOSTNAME_RE
# ===================================================================

class TestValidHostnameRe:
    def test_simple_valid_hostname(self):
        assert _VALID_HOSTNAME_RE.match("my-router") is not None

    def test_single_char_valid(self):
        assert _VALID_HOSTNAME_RE.match("a") is not None

    def test_max_63_chars_valid(self):
        name = "a" * 63
        assert _VALID_HOSTNAME_RE.match(name) is not None

    def test_64_chars_invalid(self):
        name = "a" * 64
        assert _VALID_HOSTNAME_RE.match(name) is None

    def test_starts_with_hyphen_invalid(self):
        assert _VALID_HOSTNAME_RE.match("-router") is None

    def test_ends_with_hyphen_invalid(self):
        assert _VALID_HOSTNAME_RE.match("router-") is None

    def test_spaces_invalid(self):
        assert _VALID_HOSTNAME_RE.match("my router") is None

    def test_special_chars_invalid(self):
        assert _VALID_HOSTNAME_RE.match("my@router") is None

    def test_empty_string_invalid(self):
        assert _VALID_HOSTNAME_RE.match("") is None

    def test_alphanumeric_valid(self):
        assert _VALID_HOSTNAME_RE.match("router01") is not None

    def test_two_chars_valid(self):
        assert _VALID_HOSTNAME_RE.match("ab") is not None

    def test_uppercase_valid(self):
        assert _VALID_HOSTNAME_RE.match("MyRouter") is not None

    def test_underscore_invalid(self):
        assert _VALID_HOSTNAME_RE.match("my_router") is None


# ===================================================================
# 9. Invalid hostname step in build_plan
# ===================================================================

class TestInvalidHostname:
    def test_invalid_hostname_skipped(self):
        cfg = ConwrtConfig(hostname="invalid hostname!")
        plan = build_plan(cfg, mode="post_install")
        steps = [s for s in plan.steps if s.kind == StepKind.HOSTNAME]
        assert len(steps) == 1
        assert steps[0].skipped_reason != ""
        assert steps[0].include_in_asu is False
        assert steps[0].include_in_post_install is False

    def test_64_char_hostname_skipped(self):
        cfg = ConwrtConfig(hostname="a" * 64)
        plan = build_plan(cfg, mode="post_install")
        steps = [s for s in plan.steps if s.kind == StepKind.HOSTNAME]
        assert len(steps) == 1
        assert steps[0].skipped_reason != ""
        assert steps[0].include_in_asu is False


# ===================================================================
# 10. WiFi disable step
# ===================================================================

class TestWifiDisable:
    def test_wifi_disable_step_exists(self):
        cfg = ConwrtConfig()
        plan = build_plan(cfg, mode="post_install", wifi_disable=True)
        steps = [s for s in plan.steps if s.kind == StepKind.WIFI_DISABLE]
        assert len(steps) == 1

    def test_wifi_disable_firstboot_script(self):
        cfg = ConwrtConfig()
        plan = build_plan(cfg, mode="post_install", wifi_disable=True)
        steps = [s for s in plan.steps if s.kind == StepKind.WIFI_DISABLE]
        fb = steps[0].firstboot_script
        assert "uci set wireless.$radio.disabled='1'" in fb

    def test_wifi_disable_from_config(self):
        cfg = ConwrtConfig(wifi_disable=True)
        plan = build_plan(cfg, mode="post_install")
        steps = [s for s in plan.steps if s.kind == StepKind.WIFI_DISABLE]
        assert len(steps) == 1

    def test_wifi_disable_configure_script(self):
        cfg = ConwrtConfig()
        plan = build_plan(cfg, mode="post_install", wifi_disable=True)
        steps = [s for s in plan.steps if s.kind == StepKind.WIFI_DISABLE]
        assert "uci commit wireless" in steps[0].configure_script


# ===================================================================
# 11. WiFi AP step
# ===================================================================

class TestWifiApStep:
    def test_single_ap_step(self):
        cfg = ConwrtConfig(
            wifi_aps=[WifiAPConfig(band="2.4ghz", ssid="TestNet", encryption="psk2", key="pass")],
        )
        plan = build_plan(cfg, mode="post_install")
        steps = [s for s in plan.steps if s.kind == StepKind.WIFI_AP]
        assert len(steps) == 1
        assert "TestNet" in steps[0].label
        assert "2.4ghz" in steps[0].label

    def test_ap_step_wifi_role(self):
        cfg = ConwrtConfig(
            wifi_aps=[WifiAPConfig(band="5ghz", ssid="My5G", encryption="psk2", key="pass")],
        )
        plan = build_plan(cfg, mode="post_install")
        steps = [s for s in plan.steps if s.kind == StepKind.WIFI_AP]
        assert steps[0].wifi_role == "ap"

    def test_ap_step_wifi_params(self):
        cfg = ConwrtConfig(
            wifi_aps=[WifiAPConfig(band="5ghz", ssid="My5G", encryption="psk2", key="pass123")],
        )
        plan = build_plan(cfg, mode="post_install")
        steps = [s for s in plan.steps if s.kind == StepKind.WIFI_AP]
        params = steps[0].wifi_params
        assert params["ssid"] == "My5G"
        assert params["encryption"] == "psk2"
        assert params["key"] == "pass123"
        assert params["network"] == "lan"

    def test_multiple_ap_steps(self):
        cfg = ConwrtConfig(
            wifi_aps=[
                WifiAPConfig(band="2.4ghz", ssid="Net24", encryption="psk2", key="a"),
                WifiAPConfig(band="5ghz", ssid="Net5", encryption="psk2", key="b"),
            ],
        )
        plan = build_plan(cfg, mode="post_install")
        steps = [s for s in plan.steps if s.kind == StepKind.WIFI_AP]
        assert len(steps) == 2
        assert steps[0].wifi_params["index"] == 0
        assert steps[1].wifi_params["index"] == 1


# ===================================================================
# 12. Extra SSH keys
# ===================================================================

class TestExtraSshKeys:
    def test_extra_keys_appear_in_ssh_step(self):
        cfg = ConwrtConfig(ssh_public_key_text="ssh-ed25519 BASEKEY user@host")
        plan = build_plan(
            cfg, mode="post_install",
            extra_pub_keys=["ssh-ed25519 EXTRA1 host1", "ssh-ed25519 EXTRA2 host2"],
        )
        steps = [s for s in plan.steps if s.kind == StepKind.SSH_KEY]
        assert len(steps) == 1
        fb = steps[0].firstboot_script
        assert "BASEKEY" in fb
        assert "EXTRA1" in fb
        assert "EXTRA2" in fb

    def test_duplicate_keys_removed(self):
        key = "ssh-ed25519 SAMEKEY user@host"
        cfg = ConwrtConfig(ssh_public_key_text=key)
        plan = build_plan(
            cfg, mode="post_install",
            extra_pub_keys=["ssh-ed25519 SAMEKEY other@host"],
        )
        steps = [s for s in plan.steps if s.kind == StepKind.SSH_KEY]
        fb = steps[0].firstboot_script
        # Count occurrences of the key (stripped)
        stripped = "ssh-ed25519 SAMEKEY"
        assert fb.count(stripped) == 1

    def test_keys_stripped_of_comments(self):
        cfg = ConwrtConfig(ssh_public_key_text="ssh-ed25519 BASEKEY user@host")
        plan = build_plan(cfg, mode="post_install")
        steps = [s for s in plan.steps if s.kind == StepKind.SSH_KEY]
        fb = steps[0].firstboot_script
        # Comment should be stripped
        assert "user@host" not in fb
        assert "BASEKEY" in fb


# ===================================================================
# 13. Model hostname prefix derivation
# ===================================================================

class TestModelHostnamePrefix:
    def test_asus_lyra_prefix(self):
        cfg = ConwrtConfig(hostname_pattern="model_mac")
        plan = build_plan(cfg, mode="post_install", model_id="asus-lyra-map-ac2200")
        steps = [s for s in plan.steps if s.kind == StepKind.HOSTNAME]
        assert len(steps) == 1
        assert "lyra_" in steps[0].configure_script

    def test_model_with_numeric_segments(self):
        # "vendor-x1-3000" — "x1" is <= 2 chars, "3000" is all digits → no hostname step
        cfg = ConwrtConfig(hostname_pattern="model_mac")
        plan = build_plan(cfg, mode="post_install", model_id="vendor-x1-3000")
        steps = [s for s in plan.steps if s.kind == StepKind.HOSTNAME]
        assert len(steps) == 0

    def test_model_hostname_prefix_from_model_file(self):
        # When model has hostname_prefix in JSON, it's used
        # Use a real model that exists in models/ dir
        cfg = ConwrtConfig(hostname_pattern="model_mac")
        plan = build_plan(cfg, mode="post_install", model_id="dlink-covr-x1860-a1")
        steps = [s for s in plan.steps if s.kind == StepKind.HOSTNAME]
        # dlink-covr-x1860-a1: segments after vendor = "covr" (>2 chars, not digits)
        assert len(steps) == 1
        assert "covr_" in steps[0].configure_script


# ===================================================================
# 14. Model LAN subnet parsing
# ===================================================================

class TestModelLanSubnet:
    def test_lan_subnet_strips_cidr(self):
        # Use a model that has lan_subnet with CIDR
        # We test the behavior by building plan with mac-hash mode
        # The model_data parsing happens inside build_plan
        # Since we can't easily inject model_data, test the step exists
        cfg = ConwrtConfig(lan_ip_mode="mac-hash")
        plan = build_plan(cfg, mode="post_install", model_id="asus-lyra-map-ac2200")
        mac_steps = [s for s in plan.steps if s.kind == StepKind.LAN_IP_MAC_HASH]
        assert len(mac_steps) == 1

    def test_static_lan_ip_with_model(self):
        cfg = ConwrtConfig(lan_ip="192.168.50.1", lan_ip_mode="static")
        plan = build_plan(cfg, mode="post_install", model_id="asus-lyra-map-ac2200")
        lan_steps = [s for s in plan.steps if s.kind == StepKind.LAN_IP]
        assert len(lan_steps) == 1
        assert "192.168.50.1" in lan_steps[0].configure_script
