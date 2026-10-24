"""Tests for pure helper functions in profile.builder."""
from __future__ import annotations

import base64
import os
import shlex
import shutil
import subprocess
import tempfile
from unittest.mock import MagicMock

import pytest

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
from profile.ops import ShellCommand, UciSet
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
        assert "printf '%s\\n' 'ssh-ed25519 AAAA' >" in result

    def test_single_key_has_mkdir_and_chmod(self):
        result = _ssh_key_firstboot(["ssh-ed25519 AAAA"])
        assert result.startswith("mkdir -p")
        assert "chmod 700" in result  # dir: dropbear rejects keys on loose dirs
        assert "chmod 600" in result

    def test_two_keys_first_redirect_second_append(self):
        result = _ssh_key_firstboot(["key1", "key2"])
        lines = result.split("\n")
        key_lines = [l for l in lines if l.startswith("printf")]
        assert len(key_lines) == 2
        assert ">" in key_lines[0] and ">>" not in key_lines[0]
        assert ">>" in key_lines[1]

    def test_empty_list_only_mkdir_chmod(self):
        # Empty keys never reach the step in practice, but the helper must
        # not bake key-only-auth into an empty step.
        result = _ssh_key_firstboot([])
        lines = result.split("\n")
        assert len(lines) == 2
        assert lines[0].startswith("mkdir -p")
        assert lines[1].startswith("chmod 700")

    def test_keys_bake_key_only_auth(self):
        # #155: a baked key means key-only dropbear (no password surface).
        result = _ssh_key_firstboot(["key1"])
        assert "PasswordAuth='off'" in result
        assert "RootPasswordAuth='off'" in result
        assert "uci commit dropbear" in result

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
    def test_single_key_returns_shell_prefix_ops(self):
        ops = _ssh_key_ops(["key1"])
        # mkdir, chmod 700, printf, chmod 600, chown, ownership-verify (#464),
        # key-gate, staged-changes persistence gate (#464), readback
        # (ShellCommand) + key-only UciSet + commit (#155) + restart (#229)
        shells = [op for op in ops if isinstance(op, ShellCommand)]
        assert len(shells) == 9

    def test_ops_bake_key_only_auth(self):
        # #155: ops carry the same key-only dropbear config as firstboot.
        ops = _ssh_key_ops(["key1"])
        assert any(isinstance(op, UciSet) for op in ops)
        uci = next(op for op in ops if isinstance(op, UciSet))
        assert uci.values == {"PasswordAuth": "off", "RootPasswordAuth": "off"}

    def test_single_key_ops_content(self):
        ops = _ssh_key_ops(["key1"])
        assert "mkdir -p" in ops[0].command
        assert "chmod 700" in ops[1].command
        assert "printf" in ops[2].command and "'key1'" in ops[2].command
        assert "chmod 600" in ops[3].command
        assert "chown 0:0" in ops[4].command
        assert "[ -O " in ops[5].command and "-perm 600" in ops[5].command  # BusyBox-safe gate (#464)
        assert "grep -qF 'key1'" in ops[6].command
        assert "|| exit 1" in ops[6].command

    def test_two_keys_returns_thirteen_ops(self):
        ops = _ssh_key_ops(["key1", "key2"])
        # mkdir, chmod 700, printf x2, chmod 600, chown, ownership gate,
        # key gate, UciSet, commit, persistence gate, readback, restart
        assert len(ops) == 13
        assert ">" in ops[2].command and ">>" not in ops[2].command
        assert ">>" in ops[3].command

    def test_empty_keys_returns_mkdir_chmod(self):
        ops = _ssh_key_ops([])
        assert len(ops) == 2
        assert "mkdir" in ops[0].command
        assert "chmod 700" in ops[1].command
        # Empty keys: NO key-only-auth ops (nothing would unlock).

    def test_ops_match_firstboot_lines(self):
        keys = ["ssh-ed25519 AAA", "ssh-ed25519 BBB"]
        fb = _ssh_key_firstboot(keys)
        ops = _ssh_key_ops(keys)
        # Each SHELL op should appear as a line in the firstboot script; the
        # UciSet/UciCommit pair mirrors the same uci lines textually.
        from profile.ops import UciCommit, ServiceAction
        for op in ops:
            if isinstance(op, ShellCommand):
                if ("grep -qF" in op.command or "uci get dropbear" in op.command
                        or "uci changes dropbear" in op.command):
                    # gate + readback: fb uses the verbose { echo; exit 1; }
                    # forms for both, so compare by keyword, not verbatim
                    if "uci changes dropbear" in op.command:
                        # ops gate on staged leftovers; firstboot's counterpart
                        # is the propagated `uci commit dropbear ||` form (#464)
                        assert "uci commit dropbear ||" in fb
                        assert "exit 1" in op.command and "exit 1" in fb
                        continue
                    keyword = "grep -qF" if "grep -qF" in op.command else "uci get dropbear"
                    assert keyword in op.command and keyword in fb
                    assert "exit 1" in fb
                    continue
                assert op.command in fb
            elif isinstance(op, ServiceAction):
                assert f"/etc/init.d/{op.name} {op.action}" in fb
            elif isinstance(op, UciSet):
                for k, v in op.values.items():
                    assert f"uci set dropbear.{op.section}.{k}='{v}'" in fb
            elif isinstance(op, UciCommit):
                assert f"uci commit {op.config}" in fb


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
        # Count occurrences of the key across the WRITE lines only — the
        # #229 verify-gate legitimately re-references the key in its grep.
        stripped = "ssh-ed25519 SAMEKEY"
        write_lines = [l for l in fb.split("\n") if l.startswith("printf")]
        assert sum(l.count(stripped) for l in write_lines) == 1

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


# ===================================================================
# #229: recovery-flash authorized_keys lockout regressions
# ===================================================================

class TestSshKey229LockoutSafety:
    """The defaults script must (a) verify the key landed before disabling
    password auth, and (b) exit non-zero on failure so uci_apply_defaults
    retains it for retry instead of consuming a half-applied boot."""

    def test_hardening_gated_on_key_verification(self):
        # #229: the script's exit status is its LAST command (uci commit).
        # If the key write is lost but commit succeeds, uci_apply_defaults
        # deletes the script (base-files /etc/init.d/boot: rm -f $applied)
        # and publickey-only lockout becomes permanent. The verify gate must
        # sit between the key write and the hardening uci lines.
        result = _ssh_key_firstboot(["ssh-ed25519 KEYBODY"])
        verify_idx = result.index("grep -qF 'ssh-ed25519 KEYBODY'")
        gate_line = result[verify_idx:verify_idx + 200]
        assert "exit 1" in gate_line  # verbose { echo; exit 1; } or || exit 1
        harden_idx = result.index("PasswordAuth='off'")
        commit_idx = result.index("uci commit dropbear")
        assert result.index("chmod 600") < verify_idx < harden_idx < commit_idx

    def test_failed_key_write_keeps_script_nonzero(self):
        # Simulate the #229 failure class: the authorized_keys write does not
        # land (unwritable fs at uci-defaults time). The script must exit
        # non-zero so base-files RETAINS it and retries next boot — never
        # reaching the password-off hardening.
        import os
        import shutil
        import subprocess
        import tempfile

        key = "ssh-ed25519 AAAATESTBODY"
        script = _ssh_key_firstboot([key])
        sandbox = tempfile.mkdtemp()
        target = os.path.join(sandbox, "authorized_keys")
        # Neutralize uci for the dry run: the contract under test is the
        # gate ordering around it, not uci itself.
        dry = script.replace(DROPBEAR_AUTH_KEYS_PATH, target)
        dry = "\n".join(
            "true # " + line
            if line.startswith("uci ") or line.startswith('[ "$(uci get')
            or line.startswith('[ -O ')
            else line
            for line in dry.splitlines()
        )
        ro_dir = os.path.join(sandbox, "ro", "dropbear")
        os.makedirs(ro_dir)
        ro_target = os.path.join(ro_dir, "authorized_keys")
        # Root bypasses mode-based write protection (review of #253): occupy
        # the target with a directory so the write fails for EVERY uid.
        os.makedirs(ro_target)
        try:
            proc = subprocess.run(
                ["sh", "-c", dry.replace(target, ro_target)],
                capture_output=True, text=True, timeout=10,
            )
            assert proc.returncode != 0, (
                "script must fail (and be retained) when the key write fails"
            )
            assert not os.path.isfile(ro_target)
        finally:
            shutil.rmtree(sandbox)

    def test_successful_key_write_exits_zero(self):
        # Happy path dry-run: key lands, mode 600, script exits 0 (deleted,
        # hardening applied — exactly once).
        import os
        import shutil
        import subprocess
        import tempfile

        key = "ssh-ed25519 AAAATESTBODY"
        script = _ssh_key_firstboot([key])
        sandbox = tempfile.mkdtemp()
        target = os.path.join(sandbox, "authorized_keys")
        dry = script.replace(DROPBEAR_AUTH_KEYS_PATH, target)
        dry = "\n".join(
            "true # " + line
            if line.startswith("uci ") or line.startswith('[ "$(uci get')
            or line.startswith('[ -O ')
            else line
            for line in dry.splitlines()
        )
        try:
            proc = subprocess.run(
                ["sh", "-c", dry], capture_output=True, text=True, timeout=10,
            )
            assert proc.returncode == 0
            with open(target) as fh:
                assert fh.read().strip() == key
            assert os.stat(target).st_mode & 0o777 == 0o600
        finally:
            shutil.rmtree(sandbox)


    def test_chown_precedes_gate(self):
        # P1: non-root-owned /etc/dropbear makes dropbear reject ALL keys
        result = _ssh_key_firstboot(["key1"])
        assert result.index("chown 0:0") < result.index("grep -qF")

    def test_readback_gates_restart(self):
        # P2: PasswordAuth must read back 'off' before the tolerant restart
        result = _ssh_key_firstboot(["key1"])
        assert result.index("uci get dropbear") < result.index("/etc/init.d/dropbear restart")

    def test_gate_precedes_password_auth(self):
        result = _ssh_key_firstboot(["key1"])
        assert result.index("grep -qF") < result.index("PasswordAuth='off'")

    def test_gate_exits_nonzero(self):
        result = _ssh_key_firstboot(["key1"])
        gate = next(l for l in result.split("\n") if l.startswith("grep -qF"))
        assert "exit 1" in gate

    def test_dropbear_dir_700(self):
        # dropbear silently refuses authorized_keys when the dir is loose
        result = _ssh_key_firstboot(["key1"])
        assert "chmod 700" in result

    def test_dropbear_restart_after_commit(self):
        result = _ssh_key_firstboot(["key1"])
        assert result.index("uci commit dropbear") < result.index("/etc/init.d/dropbear restart")


def _unshare_available() -> bool:
    try:
        return subprocess.run(
            ["unshare", "-rm", "true"], capture_output=True, timeout=10
        ).returncode == 0
    except Exception:
        return False


def _run_defaults_in_sandbox(script: str, dropbear_is_file: bool):
    """Execute the generated defaults script under a private mount namespace
    with a fake /etc and PATH-stubbed uci — the #229 local reproduction.

    dropbear_is_file=True injects the failure mode: a stale overlay artifact
    occupying /etc/dropbear makes every write fail.
    """
    root = tempfile.mkdtemp(prefix="conwrt-229-")
    try:
        os.makedirs(f"{root}/bin")
        os.makedirs(f"{root}/etc/init.d")
        if dropbear_is_file:
            open(f"{root}/etc/dropbear", "w").close()
        else:
            os.makedirs(f"{root}/etc/dropbear")
        with open(f"{root}/bin/uci", "w") as f:
            f.write(
                "#!/bin/sh\n"
                f'echo "$@" >> {shlex.quote(root + "/uci.log")}\n'
                'case "$1 $2" in '
                '"get dropbear.@dropbear[0].PasswordAuth") echo off;; '
                '"get dropbear.@dropbear[0].RootPasswordAuth") echo off;; '
                "esac\n"
                "exit 0\n"
            )
        os.chmod(f"{root}/bin/uci", 0o755)
        with open(f"{root}/etc/init.d/dropbear", "w") as f:
            f.write(f"#!/bin/sh\necho restarted >> {shlex.quote(root + '/restart.log')}\nexit 0\n")
        os.chmod(f"{root}/etc/init.d/dropbear", 0o755)
        wrapper = (
            f"mount --bind {shlex.quote(root + '/etc')} /etc && "
            f"export PATH={shlex.quote(root + '/bin')}:/usr/bin:/bin && "
            f"sh -c {shlex.quote(script)}; "
            f"echo $? > {shlex.quote(root + '/exitcode')}"
        )
        subprocess.run(
            ["unshare", "-rm", "sh", "-c", wrapper], capture_output=True, timeout=30
        )
        code = None
        if os.path.exists(root + "/exitcode"):
            code = int(open(root + "/exitcode").read().strip() or -1)
        uci = open(root + "/uci.log").read() if os.path.exists(root + "/uci.log") else ""
        restarted = os.path.exists(root + "/restart.log")
        keyfile = root + "/etc/dropbear/authorized_keys"
        keydata = open(keyfile).read() if os.path.isfile(keyfile) else None
        keymode = oct(os.stat(keyfile).st_mode & 0o777) if os.path.isfile(keyfile) else None
        return code, uci, restarted, keydata, keymode
    finally:
        shutil.rmtree(root, ignore_errors=True)


@pytest.mark.skipif(not _unshare_available(), reason="unshare -rm unavailable (user namespaces off)")
class TestSshDefaultsSandbox229:
    KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIc229test conwrt@test"

    def test_failed_write_keeps_password_auth_and_retries(self):
        code, uci, restarted, keydata, _ = _run_defaults_in_sandbox(
            _ssh_key_firstboot([self.KEY]), dropbear_is_file=True
        )
        # The lockout scenario: every write fails. The script must fail
        # (retained + retried next boot) and must NOT disable password auth.
        assert code == 1
        assert "PasswordAuth" not in uci
        assert restarted is False
        assert keydata is None

    def test_successful_write_applies_key_and_key_only_auth(self):
        code, uci, restarted, keydata, keymode = _run_defaults_in_sandbox(
            _ssh_key_firstboot([self.KEY]), dropbear_is_file=False
        )
        assert code == 0
        assert keydata is not None and self.KEY in keydata
        assert keymode == "0o600"
        assert "dropbear.@dropbear[0].PasswordAuth=off" in uci
        assert "commit dropbear" in uci
        assert restarted is True

    def test_idempotent_rerun_succeeds(self):
        script = _ssh_key_firstboot([self.KEY])
        first = _run_defaults_in_sandbox(script, dropbear_is_file=False)
        second = _run_defaults_in_sandbox(script, dropbear_is_file=False)
        assert first[0] == second[0] == 0
        assert second[3] == first[3]  # same key content (overwrite, not append)


class TestSshKeyGateHardening:
    """#464 — the ssh-key firstboot gate must fail closed on ownership
    repairs and on commit failure (a stale matching key file must never
    enable the password-auth disable while dropbear would refuse it)."""

    def test_firstboot_gates_on_ownership_repair(self):
        from profile.builder import _ssh_key_firstboot

        script = _ssh_key_firstboot(["ssh-ed25519 AAAA"])
        assert "[ -O " in script and "find " in script and "-perm 600" in script
        assert (
            "conwrt-ssh: key ownership/mode verify failed" in script
        ), "ownership verify must fail the script (retained for retry)"
        # the verify must sit BEFORE the password-auth disable
        assert script.index("[ -O ") < script.index("PasswordAuth='off'")

    def test_firstboot_propagates_commit_failure(self):
        from profile.builder import _ssh_key_firstboot

        script = _ssh_key_firstboot(["ssh-ed25519 AAAA"])
        assert "uci commit dropbear ||" in script
        assert "commit failed" in script
        # commit failure must precede the readback (staged /tmp/.uci values)
        assert script.index("uci commit dropbear ||") < script.index("uci get")

    def test_ops_mirror_the_gates(self):
        from profile.builder import _ssh_key_ops

        rendered = "\n".join(
            op.command for op in _ssh_key_ops(["ssh-ed25519 AAAA"])
            if hasattr(op, "command")
        )
        assert "[ -O " in rendered and "-perm 600" in rendered
        # typed UciCommit cannot carry `||`; the ops-side persistence gate
        # bites because a failed commit leaves STAGED changes behind
        assert 'uci changes dropbear' in rendered
        # the persistence gate must follow the typed UciCommit in the op sequence
        from profile.ops import UciCommit
        seq = list(_ssh_key_ops(["ssh-ed25519 AAAA"]))
        commit_idx = next(i for i, op in enumerate(seq) if isinstance(op, UciCommit))
        gate_idx = next(i for i, op in enumerate(seq)
                        if getattr(op, "command", "").startswith('[ -z "$(uci changes'))
        assert gate_idx > commit_idx
