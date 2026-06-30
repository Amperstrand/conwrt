"""Tests for conwrt/cmd_nor_recovery.py — NOR recovery setup command.

All SSH, SCP, subprocess, and network calls are mocked.
No real hardware interaction.
"""
from __future__ import annotations

import argparse
import subprocess
from unittest.mock import patch


from conwrt.cmd_nor_recovery import cmd_setup_nor_recovery


def _args(model_id="glinet-gl-ar300m-nand", ip=None, dry_run=False,
          i_want_a_brick=False, skip_uboot=False, no_voice=False):
    return argparse.Namespace(
        model_id=model_id, ip=ip, dry_run=dry_run,
        i_want_a_brick=i_want_a_brick, skip_uboot=skip_uboot, no_voice=no_voice,
    )


def _model(**overrides):
    base = {
        "id": "glinet-gl-ar300m-nand",
        "vendor": "GL.iNet",
        "description": "GL-AR300M (NAND)",
        "openwrt": {"device": "glinet,gl-ar300m-nand", "default_ip": "192.168.1.1"},
        "nor_recovery": {
            "uboot_upgrade": {
                "url": "https://example.com/uboot.bin",
                "sha256": "a" * 64,
                "flash_command": "mtd -r write /tmp/uboot-recovery.bin /dev/mtd0",
                "version": "2022-02-16",
            },
            "nor_firmware": {
                "url": "https://example.com/nor.bin",
                "sha256": "b" * 64,
                "mtd_partition": "nor_firmware",
                "description": "NOR recovery firmware",
            },
            "boot_env": {"boot_dev": "on"},
            "boot_method": {"recommended": "bootcount"},
            "recovery_hostname": "ar300-nor-recovery",
            "bootargs_fix": "console=ttyS0,115200 rootfstype=squashfs,jffs2 noinitrd",
            "boot_local": "nor",
            "requires_kmod_mtd_rw": True,
            "mtd_rw_module_param": "i_want_a_brick=1",
            "post_setup_verification": {
                "nand_boot": "Switch LEFT, power cycle",
                "nor_boot": "Bootcount method",
            },
        },
    }
    for k, v in overrides.items():
        base[k] = v
    return base


def _cp(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr,
    )


PATCH_TARGETS = {
    "load_model": "conwrt.cmd_nor_recovery.load_model",
    "detect_key": "conwrt.cmd_nor_recovery._detect_ssh_key_path",
    "ssh_cmd": "conwrt.cmd_nor_recovery.ssh_cmd",
    "check_ssh": "conwrt.cmd_nor_recovery.check_ssh",
    "run_ssh": "conwrt.cmd_nor_recovery.run_ssh",
    "sha256_file": "conwrt.cmd_nor_recovery.sha256_file",
    "poll_until": "conwrt.cmd_nor_recovery.poll_until",
    "say": "conwrt.cmd_nor_recovery.say",
    "log": "conwrt.cmd_nor_recovery.log",
    "sleep": "conwrt.cmd_nor_recovery.time.sleep",
    "makedirs": "conwrt.cmd_nor_recovery.os.makedirs",
    "urlretrieve": "conwrt.cmd_nor_recovery.urllib.request.urlretrieve",
    "subprocess_run": "conwrt.cmd_nor_recovery.subprocess.run",
}


class Patches:
    """Context manager that applies all standard patches."""

    def __init__(self, **overrides):
        self._overrides = overrides
        self._mocks = {}
        self._patches = {}

    def __enter__(self):
        defaults = {
            "load_model": _model(),
            "detect_key": "/fake/key",
            "ssh_cmd": ["ssh", "-i", "/fake/key", "root@192.168.1.1", "CMD"],
            "check_ssh": True,
            "run_ssh": _cp(0, "ok", ""),
            "sha256_file": "a" * 64,
            "poll_until": True,
            "say": None,
            "log": None,
            "sleep": None,
            "makedirs": None,
            "urlretrieve": None,
            "subprocess_run": None,
        }
        for k, v in self._overrides.items():
            defaults[k] = v

        for name, target in PATCH_TARGETS.items():
            val = defaults[name]
            if val is None:
                p = patch(target)
            elif callable(val) and not isinstance(val, (str, list, bool, int, dict,
                                                         subprocess.CompletedProcess)):
                # Functions/lambdas → side_effect (called each time)
                p = patch(target, side_effect=val)
            else:
                p = patch(target, return_value=val)
            self._mocks[name] = p.start()
            self._patches[name] = p
        return self

    def __exit__(self, *args):
        for p in self._patches.values():
            p.stop()

    def __getitem__(self, name):
        return self._mocks[name]

    @property
    def mocks(self):
        return self._mocks


def _ssh_and_board_side_effects(board_name="glinet,gl-ar300m-nand", extra=None):
    """Build subprocess.run side_effects: SSH check + board check + optional extras."""
    seq = [
        _cp(0, "SSH_OK", ""),
        _cp(0, board_name, ""),
    ]
    if extra:
        seq.extend(extra)
    return seq


def _full_live_run_ssh(nor_hash="b" * 64):
    """Return a run_ssh side_effect function for a full happy-path live run."""
    def side(ip, cmd, **kw):
        if "insmod" in cmd and "mtd-rw" in cmd:
            return _cp(0, "ok", "")
        if "opkg" in cmd:
            return _cp(0, "ok", "")
        if "sha256sum" in cmd:
            return _cp(0, f"{nor_hash}  /tmp/nor-firmware.bin", "")
        if "mtd write" in cmd:
            return _cp(0, "", "")
        if "fw_setenv" in cmd:
            return _cp(0, "", "")
        if "fw_printenv bootargs" in cmd:
            return _cp(0, "bootargs=console=ttyS0,115200", "")
        if "fw_printenv boot_local" in cmd:
            return _cp(0, "boot_local=nor", "")
        if "fw_printenv boot_dev" in cmd:
            return _cp(0, "boot_dev=on", "")
        if "fw_printenv bootcount" in cmd:
            return _cp(0, "bootcount=3", "")
        if "bootcount" in cmd:
            return _cp(0, "bootcount=3", "")
        return _cp(0, "", "")
    return side


# ---------------------------------------------------------------------------
# 1. Input validation / early exits (15 tests)
# ---------------------------------------------------------------------------

class TestModelNotFound:
    @patch("conwrt.cmd_nor_recovery.load_model", side_effect=FileNotFoundError)
    @patch("conwrt.cmd_nor_recovery.log")
    def test_returns_1(self, mock_log, mock_load):
        assert cmd_setup_nor_recovery(_args()) == 1

    @patch("conwrt.cmd_nor_recovery.load_model", side_effect=FileNotFoundError)
    @patch("conwrt.cmd_nor_recovery.log")
    def test_stderr_mentions_model_id(self, mock_log, mock_load, capsys):
        cmd_setup_nor_recovery(_args(model_id="no-such-model"))
        assert "no-such-model" in capsys.readouterr().err

    @patch("conwrt.cmd_nor_recovery.load_model", side_effect=FileNotFoundError)
    @patch("conwrt.cmd_nor_recovery.log")
    def test_stderr_mentions_list_command(self, mock_log, mock_load, capsys):
        cmd_setup_nor_recovery(_args())
        assert "conwrt list" in capsys.readouterr().err


class TestNoNorRecoverySection:
    @patch("conwrt.cmd_nor_recovery.load_model", return_value={"id": "x", "openwrt": {}})
    @patch("conwrt.cmd_nor_recovery.log")
    def test_returns_1(self, mock_log, mock_load):
        assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 1

    @patch("conwrt.cmd_nor_recovery.load_model", return_value={"id": "x", "openwrt": {}})
    @patch("conwrt.cmd_nor_recovery.log")
    def test_stderr_mentions_nor_recovery(self, mock_log, mock_load, capsys):
        cmd_setup_nor_recovery(_args(i_want_a_brick=True))
        assert "nor_recovery" in capsys.readouterr().err


class TestSafetyGate:
    @patch("conwrt.cmd_nor_recovery.load_model", return_value=_model())
    @patch("conwrt.cmd_nor_recovery.log")
    def test_returns_1_without_flags(self, mock_log, mock_load):
        assert cmd_setup_nor_recovery(_args()) == 1

    @patch("conwrt.cmd_nor_recovery.load_model", return_value=_model())
    @patch("conwrt.cmd_nor_recovery.log")
    def test_stderr_mentions_brick(self, mock_log, mock_load, capsys):
        cmd_setup_nor_recovery(_args())
        err = capsys.readouterr().err
        assert "i-want-a-brick" in err

    @patch("conwrt.cmd_nor_recovery.load_model", return_value=_model())
    @patch("conwrt.cmd_nor_recovery.log")
    def test_stderr_mentions_dry_run(self, mock_log, mock_load, capsys):
        cmd_setup_nor_recovery(_args())
        assert "dry-run" in capsys.readouterr().err

    def test_brick_flag_passes(self):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=_full_live_run_ssh(),
            sha256_file="a" * 64,
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""),  # SCP uboot
                subprocess.TimeoutExpired("ssh", 120),  # uboot flash
                _cp(0, "", ""),  # SCP nor
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 0

    def test_dry_run_passes(self):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            sha256_file="a" * 64,
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            assert cmd_setup_nor_recovery(_args(dry_run=True)) == 0

    def test_both_flags_pass(self):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            sha256_file="a" * 64,
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            assert cmd_setup_nor_recovery(_args(dry_run=True, i_want_a_brick=True)) == 0


class TestIPResolution:
    def test_args_ip_overrides_default(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            cmd_setup_nor_recovery(_args(dry_run=True, ip="10.0.0.1"))
            ips = [c[0][0] for c in p["ssh_cmd"].call_args_list]
            assert "10.0.0.1" in ips

    def test_falls_back_to_model_default_ip(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            cmd_setup_nor_recovery(_args(dry_run=True))
            ips = [c[0][0] for c in p["ssh_cmd"].call_args_list]
            assert "192.168.1.1" in ips

    def test_falls_back_to_default_ip_constant(self):
        m = _model()
        del m["openwrt"]["default_ip"]
        with Patches(load_model=m, subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            cmd_setup_nor_recovery(_args(dry_run=True))
            assert p["ssh_cmd"].call_count > 0


class TestEmptyNorRecoveryDict:
    def test_empty_dict_is_falsy_returns_1(self):
        m = {"id": "x", "openwrt": {"default_ip": "192.168.1.1"}, "nor_recovery": {}}
        with Patches(load_model=m):
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 1


class TestNoVoiceSuppression:
    def test_no_voice_suppresses_say(self):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=_full_live_run_ssh(),
            sha256_file="a" * 64,
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True, no_voice=True))
            p["say"].assert_not_called()

    def test_voice_enabled_calls_say(self):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=_full_live_run_ssh(),
            sha256_file="a" * 64,
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True, no_voice=False))
            p["say"].assert_called()


class TestModelIdPassthrough:
    def test_model_id_passed_to_load_model(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            cmd_setup_nor_recovery(_args(model_id="custom-model", dry_run=True))
            p["load_model"].assert_called_with("custom-model")


# ---------------------------------------------------------------------------
# 2. SSH access verification (12 tests)
# ---------------------------------------------------------------------------

class TestSshKeyNotFound:
    def test_returns_1_when_no_ssh_key(self):
        with Patches(detect_key=""):
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 1

    def test_stderr_mentions_ssh_key(self, capsys):
        with Patches(detect_key=""):
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            assert "SSH private key" in capsys.readouterr().err


class TestSshConnectionFailures:
    def test_returns_1_when_no_ssh_ok_in_stdout(self):
        with Patches(subprocess_run=_cp(0, "WRONG", "")):
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 1

    def test_stderr_printed_when_ssh_fails(self, capsys):
        with Patches(subprocess_run=_cp(1, "", "Connection refused")):
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            assert "Connection refused" in capsys.readouterr().err

    def test_returns_1_on_timeout(self):
        with Patches() as p:
            p["subprocess_run"].side_effect = subprocess.TimeoutExpired("ssh", 15)
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 1

    def test_timeout_prints_error(self, capsys):
        with Patches() as p:
            p["subprocess_run"].side_effect = subprocess.TimeoutExpired("ssh", 15)
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            assert "timed out" in capsys.readouterr().err

    def test_returns_1_on_oserror(self):
        with Patches() as p:
            p["subprocess_run"].side_effect = OSError("Network unreachable")
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 1

    def test_oserror_prints_exc(self, capsys):
        with Patches() as p:
            p["subprocess_run"].side_effect = OSError("Network unreachable")
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            assert "Network unreachable" in capsys.readouterr().err

    def test_ssh_ok_proceeds_in_dry_run(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            assert cmd_setup_nor_recovery(_args(dry_run=True)) == 0

    def test_subprocess_called_with_ssh_cmd_output(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", "")) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            cmd_setup_nor_recovery(_args(dry_run=True))
            first_args = p["subprocess_run"].call_args_list[0]
            assert first_args[0][0] == ["ssh", "-i", "/fake/key", "root@192.168.1.1", "CMD"]

    def test_custom_ssh_key_path_passed(self):
        with Patches(detect_key="/custom/key", subprocess_run=_cp(0, "SSH_OK", "")) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            cmd_setup_nor_recovery(_args(dry_run=True))
            for c in p["ssh_cmd"].call_args_list:
                assert c[1].get("key") == "/custom/key"


# ---------------------------------------------------------------------------
# 3. Board name verification (10 tests)
# ---------------------------------------------------------------------------

class TestBoardNameVerification:
    def test_matching_board_name_proceeds(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            assert cmd_setup_nor_recovery(_args(dry_run=True)) == 0

    def test_mismatch_live_returns_1(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", "")) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(board_name="wrong-board")
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 1

    def test_mismatch_dryrun_proceeds_with_warning(self, capsys):
        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(board_name="wrong-board")
            assert cmd_setup_nor_recovery(_args(dry_run=True)) == 0
            assert "WARNING" in capsys.readouterr().err

    def test_no_expected_device_no_check(self):
        m = _model()
        del m["openwrt"]["device"]
        with Patches(load_model=m, subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(board_name="anything")
            assert cmd_setup_nor_recovery(_args(dry_run=True)) == 0

    def test_oserror_during_board_check_returns_1(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", "")) as p:
            p["subprocess_run"].side_effect = [
                _cp(0, "SSH_OK", ""),
                OSError("Connection lost"),
            ]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 1

    def test_whitespace_stripped_from_board_name(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(
                board_name="  glinet,gl-ar300m-nand  \n",
            )
            assert cmd_setup_nor_recovery(_args(dry_run=True)) == 0

    def test_mismatch_prints_expected_and_actual(self, capsys):
        with Patches(subprocess_run=_cp(0, "SSH_OK", "")) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(board_name="wrong-board")
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            err = capsys.readouterr().err
            assert "glinet,gl-ar300m-nand" in err
            assert "wrong-board" in err

    def test_board_check_uses_ssh_cmd(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            cmd_setup_nor_recovery(_args(dry_run=True))
            calls = p["ssh_cmd"].call_args_list
            assert any("cat /tmp/sysinfo/board_name" in str(c) for c in calls)

    def test_mismatch_live_aborts_with_message(self, capsys):
        with Patches(subprocess_run=_cp(0, "SSH_OK", "")) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(board_name="bad")
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            assert "Aborting" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# 4. Dry-run mode (15 tests)
# ---------------------------------------------------------------------------

class TestDryRunMode:
    def test_full_dryrun_returns_0(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            assert cmd_setup_nor_recovery(_args(dry_run=True)) == 0

    def test_creates_tmp_dir(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            cmd_setup_nor_recovery(_args(dry_run=True))
            p["makedirs"].assert_called_with("/tmp/conwrt-nor-dryrun", exist_ok=True)

    def test_calls_urlretrieve_for_uboot(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            cmd_setup_nor_recovery(_args(dry_run=True))
            calls = p["urlretrieve"].call_args_list
            assert any("uboot.bin" in str(c) for c in calls)

    def test_calls_urlretrieve_for_nor(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            cmd_setup_nor_recovery(_args(dry_run=True))
            calls = p["urlretrieve"].call_args_list
            assert any("nor.bin" in str(c) for c in calls)

    def test_calls_sha256_file(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            cmd_setup_nor_recovery(_args(dry_run=True))
            p["sha256_file"].assert_called()

    def test_uboot_sha256_mismatch_warns(self, capsys):
        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="wrong") as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            assert cmd_setup_nor_recovery(_args(dry_run=True)) == 0
            assert "mismatch" in capsys.readouterr().err.lower() or "WARNING" in capsys.readouterr().err

    def test_nor_sha256_mismatch_warns(self, capsys):
        with Patches(subprocess_run=_cp(0, "SSH_OK", "")) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            p["sha256_file"].side_effect = ["a" * 64, "wrong"]
            assert cmd_setup_nor_recovery(_args(dry_run=True)) == 0
            assert "mismatch" in capsys.readouterr().err.lower() or "WARNING" in capsys.readouterr().err

    def test_download_failure_continues(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            p["urlretrieve"].side_effect = OSError("fail")
            assert cmd_setup_nor_recovery(_args(dry_run=True)) == 0

    def test_skip_uboot_no_uboot_download(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            cmd_setup_nor_recovery(_args(dry_run=True, skip_uboot=True))
            calls = p["urlretrieve"].call_args_list
            uboot_calls = [c for c in calls if "uboot" in str(c)]
            assert len(uboot_calls) == 0

    def test_prints_dry_run_summary(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            cmd_setup_nor_recovery(_args(dry_run=True))
            log_calls = [str(c) for c in p["log"].call_args_list]
            assert any("DRY RUN" in c for c in log_calls)

    def test_empty_uboot_skips_uboot_steps(self):
        m = _model()
        m["nor_recovery"]["uboot_upgrade"] = {}
        with Patches(load_model=m, subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            assert cmd_setup_nor_recovery(_args(dry_run=True)) == 0

    def test_empty_boot_env(self):
        m = _model()
        m["nor_recovery"]["boot_env"] = {}
        with Patches(load_model=m, subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            assert cmd_setup_nor_recovery(_args(dry_run=True)) == 0

    def test_empty_nor_firmware(self):
        m = _model()
        m["nor_recovery"]["nor_firmware"] = {}
        with Patches(load_model=m, subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            assert cmd_setup_nor_recovery(_args(dry_run=True)) == 0

    def test_does_not_call_run_ssh(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            cmd_setup_nor_recovery(_args(dry_run=True))
            p["run_ssh"].assert_not_called()


# ---------------------------------------------------------------------------
# 5. Live mode - U-Boot upgrade
# ---------------------------------------------------------------------------

class TestLiveUbootDownloadAndScp:
    def test_download_failure_returns_1(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", "")) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            p["urlretrieve"].side_effect = OSError("fail")
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 1

    def test_sha256_mismatch_returns_1(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="wrong") as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects()
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 1

    def test_scp_timeout_returns_1(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                subprocess.TimeoutExpired("scp", 120),
            ])
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 1

    def test_scp_failure_returns_1(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(1, "", "SCP error"),
            ])
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 1

    def test_download_and_scp_success_continues(self):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=_full_live_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 0


class TestLiveKmodMtdRw:
    def test_not_required_skips(self):
        m = _model()
        m["nor_recovery"]["requires_kmod_mtd_rw"] = False
        with Patches(
            load_model=m,
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=_full_live_run_ssh(),
            sha256_file="b" * 64,
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""),  # SCP nor
            ])
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True, skip_uboot=True)) == 0

    def test_insmod_success(self):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=_full_live_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 0

    def test_insmod_fails_rmmod_retry_succeeds(self):
        insmod_count = [0]

        def run_ssh_side(ip, cmd, **kw):
            if "insmod" in cmd and "mtd-rw" in cmd:
                insmod_count[0] += 1
                if insmod_count[0] == 1:
                    return _cp(1, "", "File exists")
                return _cp(0, "ok", "")
            if "rmmod" in cmd:
                return _cp(0, "", "")
            return _full_live_run_ssh()(ip, cmd, **kw)

        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), run_ssh=run_ssh_side) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 0
            assert insmod_count[0] == 3  # first attempt fails, retry succeeds, re-install after reboot

    def test_insmod_fails_after_retry(self):
        def run_ssh_side(ip, cmd, **kw):
            if "insmod" in cmd and "mtd-rw" in cmd:
                return _cp(1, "", "Insmod failed")
            if "rmmod" in cmd:
                return _cp(0, "", "")
            if "opkg" in cmd:
                return _cp(0, "ok", "")
            return _cp(0, "", "")

        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), run_ssh=run_ssh_side, sha256_file="a" * 64) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""),  # SCP uboot
            ])
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 1


class TestLiveUbootFlash:
    def test_timeout_expired_tolerated(self):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=_full_live_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 0

    def test_oserror_reset_tolerated(self):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=_full_live_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), OSError("Connection reset by peer"), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 0

    def test_oserror_broken_pipe_tolerated(self):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=_full_live_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), OSError("Broken pipe"), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 0

    def test_oserror_unexpected_warns(self, capsys):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=_full_live_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), OSError("Something unexpected"), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 0
            err = capsys.readouterr().err
            assert "Unexpected" in err or "WARNING" in err

    def test_reboot_poll_success(self):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=_full_live_run_ssh(),
            poll_until=True,
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            p["poll_until"].assert_called()

    def test_reboot_poll_failure_returns_1(self, capsys):
        def run_ssh_side(ip, cmd, **kw):
            if "insmod" in cmd and "mtd-rw" in cmd:
                return _cp(0, "ok", "")
            if "opkg" in cmd:
                return _cp(0, "ok", "")
            return _cp(0, "", "")

        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=run_ssh_side,
            sha256_file="a" * 64,
            poll_until=False,
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120),
            ])
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 1
            assert "brick" in capsys.readouterr().err.lower()

    def test_sleep_called_before_polling(self):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=_full_live_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            p["sleep"].assert_any_call(10)


# ---------------------------------------------------------------------------
# 6. Live mode - NOR firmware
# ---------------------------------------------------------------------------

class TestLiveNorFirmware:
    def test_nor_download_failure_returns_1(self):
        def run_ssh_side(ip, cmd, **kw):
            if "insmod" in cmd and "mtd-rw" in cmd:
                return _cp(0, "ok", "")
            if "opkg" in cmd:
                return _cp(0, "ok", "")
            return _cp(0, "", "")

        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), run_ssh=run_ssh_side) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120),
            ])
            p["sha256_file"].return_value = "a" * 64
            p["urlretrieve"].side_effect = [None, OSError("fail")]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 1

    def test_nor_on_router_hash_mismatch(self):
        nor_hash = "b" * 64

        def run_ssh_side(ip, cmd, **kw):
            if "insmod" in cmd and "mtd-rw" in cmd:
                return _cp(0, "ok", "")
            if "opkg" in cmd:
                return _cp(0, "ok", "")
            if "sha256sum" in cmd:
                return _cp(0, "wrong_hash  /tmp/nor-firmware.bin", "")
            return _cp(0, "", "")

        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), run_ssh=run_ssh_side) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, nor_hash]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 1

    def test_nor_on_router_hash_matches(self):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=_full_live_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 0

    def test_nor_flash_failure_returns_1(self):
        nor_hash = "b" * 64

        def run_ssh_side(ip, cmd, **kw):
            if "insmod" in cmd and "mtd-rw" in cmd:
                return _cp(0, "ok", "")
            if "opkg" in cmd:
                return _cp(0, "ok", "")
            if "sha256sum" in cmd:
                return _cp(0, f"{nor_hash}  /tmp/nor-firmware.bin", "")
            if "mtd write" in cmd and "nor_firmware" in cmd:
                return _cp(1, "", "mtd error")
            return _cp(0, "", "")

        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), run_ssh=run_ssh_side) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, nor_hash]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 1

    def test_correct_mtd_partition_used(self):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=_full_live_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            mtd_calls = [c for c in p["run_ssh"].call_args_list if "mtd write" in str(c)]
            assert len(mtd_calls) > 0
            assert "nor_firmware" in str(mtd_calls[0])

    def test_default_mtd_partition(self):
        m = _model()
        del m["nor_recovery"]["nor_firmware"]["mtd_partition"]
        with Patches(
            load_model=m,
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=_full_live_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            mtd_calls = [c for c in p["run_ssh"].call_args_list if "mtd write" in str(c)]
            assert len(mtd_calls) > 0
            assert "nor_firmware" in str(mtd_calls[0])

    def test_nor_sha256sum_on_router_fails(self):
        nor_hash = "b" * 64

        def run_ssh_side(ip, cmd, **kw):
            if "insmod" in cmd and "mtd-rw" in cmd:
                return _cp(0, "ok", "")
            if "opkg" in cmd:
                return _cp(0, "ok", "")
            if "sha256sum" in cmd:
                return _cp(1, "", "error")
            return _cp(0, "", "")

        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), run_ssh=run_ssh_side) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, nor_hash]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 1


# ---------------------------------------------------------------------------
# 7. Live mode - Boot configuration
# ---------------------------------------------------------------------------

class TestLiveBootargs:
    def test_bootargs_fix_set_and_verified(self):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=_full_live_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 0

    def test_bootargs_fix_absent_skipped(self):
        m = _model()
        del m["nor_recovery"]["bootargs_fix"]
        with Patches(
            load_model=m,
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=_full_live_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            bootargs_calls = [c for c in p["run_ssh"].call_args_list
                              if "fw_setenv bootargs" in str(c)]
            assert len(bootargs_calls) == 0

    def test_bootargs_fw_setenv_failure_returns_1(self):
        nor_hash = "b" * 64

        def run_ssh_side(ip, cmd, **kw):
            if "insmod" in cmd and "mtd-rw" in cmd:
                return _cp(0, "ok", "")
            if "opkg" in cmd:
                return _cp(0, "ok", "")
            if "sha256sum" in cmd:
                return _cp(0, f"{nor_hash}  /tmp/nor-firmware.bin", "")
            if "mtd write" in cmd:
                return _cp(0, "", "")
            if "fw_setenv bootargs" in cmd:
                return _cp(1, "", "setenv error")
            return _cp(0, "", "")

        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), run_ssh=run_ssh_side) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, nor_hash]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 1


class TestLiveBootLocal:
    def test_boot_local_set_and_verified(self):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=_full_live_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 0

    def test_boot_local_absent_skipped(self):
        m = _model()
        del m["nor_recovery"]["boot_local"]
        with Patches(
            load_model=m,
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=_full_live_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            boot_local_calls = [c for c in p["run_ssh"].call_args_list
                                if "boot_local" in str(c)]
            assert len(boot_local_calls) == 0

    def test_boot_local_setenv_failure_returns_1(self):
        nor_hash = "b" * 64

        def run_ssh_side(ip, cmd, **kw):
            if "insmod" in cmd and "mtd-rw" in cmd:
                return _cp(0, "ok", "")
            if "opkg" in cmd:
                return _cp(0, "ok", "")
            if "sha256sum" in cmd:
                return _cp(0, f"{nor_hash}  /tmp/nor-firmware.bin", "")
            if "mtd write" in cmd:
                return _cp(0, "", "")
            if "fw_setenv bootargs" in cmd:
                return _cp(0, "", "")
            if "fw_printenv bootargs" in cmd:
                return _cp(0, "bootargs=x", "")
            if "fw_setenv boot_local" in cmd:
                return _cp(1, "", "setenv error")
            return _cp(0, "", "")

        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), run_ssh=run_ssh_side) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, nor_hash]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 1


class TestLiveBootEnv:
    def test_boot_env_set_and_verified(self):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=_full_live_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 0

    def test_boot_env_value_mismatch_warning(self, capsys):
        def run_ssh_side(ip, cmd, **kw):
            if "insmod" in cmd and "mtd-rw" in cmd:
                return _cp(0, "ok", "")
            if "opkg" in cmd:
                return _cp(0, "ok", "")
            if "sha256sum" in cmd:
                return _cp(0, f"{'b' * 64}  /tmp/nor-firmware.bin", "")
            if "mtd write" in cmd:
                return _cp(0, "", "")
            if "fw_setenv" in cmd:
                return _cp(0, "", "")
            if "fw_printenv bootargs" in cmd:
                return _cp(0, "bootargs=x", "")
            if "fw_printenv boot_local" in cmd:
                return _cp(0, "boot_local=nor", "")
            if "fw_printenv boot_dev" in cmd:
                return _cp(0, "boot_dev=off", "")  # mismatch
            if "bootcount" in cmd:
                return _cp(0, "bootcount=3", "")
            return _cp(0, "", "")

        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), run_ssh=run_ssh_side) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 0
            assert "WARNING" in capsys.readouterr().err

    def test_boot_env_absent_logged(self):
        m = _model()
        del m["nor_recovery"]["boot_env"]
        with Patches(
            load_model=m,
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=_full_live_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            log_calls = [str(c) for c in p["log"].call_args_list]
            assert any("No boot_env" in c for c in log_calls)

    def test_fw_printenv_failure_warning(self, capsys):
        def run_ssh_side(ip, cmd, **kw):
            if "insmod" in cmd and "mtd-rw" in cmd:
                return _cp(0, "ok", "")
            if "opkg" in cmd:
                return _cp(0, "ok", "")
            if "sha256sum" in cmd:
                return _cp(0, f"{'b' * 64}  /tmp/nor-firmware.bin", "")
            if "mtd write" in cmd:
                return _cp(0, "", "")
            if "fw_setenv" in cmd:
                return _cp(0, "", "")
            if "fw_printenv bootargs" in cmd:
                return _cp(0, "bootargs=x", "")
            if "fw_printenv boot_local" in cmd:
                return _cp(0, "boot_local=nor", "")
            if "fw_printenv boot_dev" in cmd:
                return _cp(1, "", "printenv error")
            if "bootcount" in cmd:
                return _cp(0, "bootcount=3", "")
            return _cp(0, "", "")

        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), run_ssh=run_ssh_side) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 0
            assert "WARNING" in capsys.readouterr().err

    def test_boot_env_setenv_failure_returns_1(self):
        def run_ssh_side(ip, cmd, **kw):
            if "insmod" in cmd and "mtd-rw" in cmd:
                return _cp(0, "ok", "")
            if "opkg" in cmd:
                return _cp(0, "ok", "")
            if "sha256sum" in cmd:
                return _cp(0, f"{'b' * 64}  /tmp/nor-firmware.bin", "")
            if "mtd write" in cmd:
                return _cp(0, "", "")
            if "fw_setenv bootargs" in cmd:
                return _cp(0, "", "")
            if "fw_printenv bootargs" in cmd:
                return _cp(0, "bootargs=x", "")
            if "fw_setenv boot_local" in cmd:
                return _cp(0, "", "")
            if "fw_printenv boot_local" in cmd:
                return _cp(0, "boot_local=nor", "")
            if "fw_setenv boot_dev" in cmd:
                return _cp(1, "", "setenv error")
            return _cp(0, "", "")

        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), run_ssh=run_ssh_side) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 1

    def test_fw_setenv_stderr_printed(self, capsys):
        def run_ssh_side(ip, cmd, **kw):
            if "insmod" in cmd and "mtd-rw" in cmd:
                return _cp(0, "ok", "")
            if "opkg" in cmd:
                return _cp(0, "ok", "")
            if "sha256sum" in cmd:
                return _cp(0, f"{'b' * 64}  /tmp/nor-firmware.bin", "")
            if "mtd write" in cmd:
                return _cp(0, "", "")
            if "fw_setenv bootargs" in cmd:
                return _cp(1, "", "setenv stderr msg")
            return _cp(0, "", "")

        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), run_ssh=run_ssh_side) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            assert "setenv stderr msg" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# 8. Live mode - Bootcount method
# ---------------------------------------------------------------------------

class TestLiveBootcount:
    def _make_run_ssh(self, nor_hash="b" * 64):
        def side(ip, cmd, **kw):
            if "insmod" in cmd and "mtd-rw" in cmd:
                return _cp(0, "ok", "")
            if "opkg" in cmd:
                return _cp(0, "ok", "")
            if "sha256sum" in cmd:
                return _cp(0, f"{nor_hash}  /tmp/nor-firmware.bin", "")
            if "mtd write" in cmd:
                return _cp(0, "", "")
            if "fw_setenv" in cmd:
                return _cp(0, "", "")
            if "fw_printenv bootargs" in cmd:
                return _cp(0, "bootargs=x", "")
            if "fw_printenv boot_local" in cmd:
                return _cp(0, "boot_local=nor", "")
            if "fw_printenv boot_dev" in cmd:
                return _cp(0, "boot_dev=on", "")
            if "fw_printenv bootcount" in cmd:
                return _cp(0, "bootcount=3", "")
            if "bootcount" in cmd:
                return _cp(0, "bootcount=3", "")
            return _cp(0, "", "")
        return side

    def _full_subprocess(self):
        return _ssh_and_board_side_effects(extra=[
            _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
        ])

    def test_bootcount_set_when_recommended(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), run_ssh=self._make_run_ssh()) as p:
            p["subprocess_run"].side_effect = self._full_subprocess()
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            bootcount_calls = [c for c in p["run_ssh"].call_args_list
                               if "bootcount" in str(c)]
            assert len(bootcount_calls) > 0

    def test_bootcount_failure_warning(self, capsys):
        def run_ssh_side(ip, cmd, **kw):
            if "insmod" in cmd and "mtd-rw" in cmd:
                return _cp(0, "ok", "")
            if "opkg" in cmd:
                return _cp(0, "ok", "")
            if "sha256sum" in cmd:
                return _cp(0, f"{'b' * 64}  /tmp/nor-firmware.bin", "")
            if "mtd write" in cmd:
                return _cp(0, "", "")
            if "fw_setenv bootargs" in cmd:
                return _cp(0, "", "")
            if "fw_printenv bootargs" in cmd:
                return _cp(0, "bootargs=x", "")
            if "fw_setenv boot_local" in cmd:
                return _cp(0, "", "")
            if "fw_printenv boot_local" in cmd:
                return _cp(0, "boot_local=nor", "")
            if "fw_setenv boot_dev" in cmd:
                return _cp(0, "", "")
            if "fw_printenv boot_dev" in cmd:
                return _cp(0, "boot_dev=on", "")
            if "fw_setenv bootcount" in cmd:
                return _cp(1, "", "setenv error")
            return _cp(0, "", "")

        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), run_ssh=run_ssh_side) as p:
            p["subprocess_run"].side_effect = self._full_subprocess()
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 0
            assert "WARNING" in capsys.readouterr().err

    def test_bootcount_success_printenv_logged(self):
        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), run_ssh=self._make_run_ssh()) as p:
            p["subprocess_run"].side_effect = self._full_subprocess()
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            printenv_calls = [c for c in p["run_ssh"].call_args_list
                              if "fw_printenv bootcount" in str(c)]
            assert len(printenv_calls) > 0

    def test_boot_method_not_bootcount_skipped(self):
        m = _model()
        m["nor_recovery"]["boot_method"] = {"recommended": "other"}

        def run_ssh_side(ip, cmd, **kw):
            if "insmod" in cmd and "mtd-rw" in cmd:
                return _cp(0, "ok", "")
            if "opkg" in cmd:
                return _cp(0, "ok", "")
            if "sha256sum" in cmd:
                return _cp(0, f"{'b' * 64}  /tmp/nor-firmware.bin", "")
            if "mtd write" in cmd:
                return _cp(0, "", "")
            if "fw_" in cmd:
                return _cp(0, "ok", "")
            return _cp(0, "", "")

        with Patches(load_model=m, subprocess_run=_cp(0, "SSH_OK", ""), run_ssh=run_ssh_side) as p:
            p["subprocess_run"].side_effect = self._full_subprocess()
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            bootcount_calls = [c for c in p["run_ssh"].call_args_list
                               if "bootcount" in str(c)]
            assert len(bootcount_calls) == 0

    def test_boot_method_absent_skipped(self):
        m = _model()
        del m["nor_recovery"]["boot_method"]

        def run_ssh_side(ip, cmd, **kw):
            if "insmod" in cmd and "mtd-rw" in cmd:
                return _cp(0, "ok", "")
            if "opkg" in cmd:
                return _cp(0, "ok", "")
            if "sha256sum" in cmd:
                return _cp(0, f"{'b' * 64}  /tmp/nor-firmware.bin", "")
            if "mtd write" in cmd:
                return _cp(0, "", "")
            if "fw_" in cmd:
                return _cp(0, "ok", "")
            return _cp(0, "", "")

        with Patches(load_model=m, subprocess_run=_cp(0, "SSH_OK", ""), run_ssh=run_ssh_side) as p:
            p["subprocess_run"].side_effect = self._full_subprocess()
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 0

    def test_recovery_hostname_printed(self, capsys):
        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), run_ssh=self._make_run_ssh()) as p:
            p["subprocess_run"].side_effect = self._full_subprocess()
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            assert "ar300-nor-recovery" in capsys.readouterr().out

    def test_no_recovery_hostname_skipped(self, capsys):
        m = _model()
        del m["nor_recovery"]["recovery_hostname"]

        def run_ssh_side(ip, cmd, **kw):
            if "insmod" in cmd and "mtd-rw" in cmd:
                return _cp(0, "ok", "")
            if "opkg" in cmd:
                return _cp(0, "ok", "")
            if "sha256sum" in cmd:
                return _cp(0, f"{'b' * 64}  /tmp/nor-firmware.bin", "")
            if "mtd write" in cmd:
                return _cp(0, "", "")
            if "fw_" in cmd:
                return _cp(0, "ok", "")
            if "bootcount" in cmd:
                return _cp(0, "bootcount=3", "")
            return _cp(0, "", "")

        with Patches(load_model=m, subprocess_run=_cp(0, "SSH_OK", ""), run_ssh=run_ssh_side) as p:
            p["subprocess_run"].side_effect = self._full_subprocess()
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            out = capsys.readouterr().out
            assert "hostname" not in out or "recovery" not in out.lower()


# ---------------------------------------------------------------------------
# 9. Live mode - Full success / summary
# ---------------------------------------------------------------------------

class TestLiveFullSuccess:
    def _full_subprocess(self):
        return _ssh_and_board_side_effects(extra=[
            _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
        ])

    def _full_run_ssh(self):
        return _full_live_run_ssh()

    def test_full_happy_path_returns_0(self):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=self._full_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = self._full_subprocess()
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True)) == 0

    def test_full_happy_path_skip_uboot(self):
        def run_ssh_side(ip, cmd, **kw):
            if "insmod" in cmd and "mtd-rw" in cmd:
                return _cp(0, "ok", "")
            if "opkg" in cmd:
                return _cp(0, "ok", "")
            if "sha256sum" in cmd:
                return _cp(0, f"{'b' * 64}  /tmp/nor-firmware.bin", "")
            if "mtd write" in cmd:
                return _cp(0, "", "")
            if "fw_" in cmd:
                return _cp(0, "ok", "")
            if "bootcount" in cmd:
                return _cp(0, "bootcount=3", "")
            return _cp(0, "", "")

        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), run_ssh=run_ssh_side) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""),  # SCP nor
            ])
            p["sha256_file"].return_value = "b" * 64
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True, skip_uboot=True)) == 0

    def test_summary_includes_uboot_version(self, capsys):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=self._full_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = self._full_subprocess()
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            assert "2022-02-16" in capsys.readouterr().out

    def test_summary_includes_nor_description(self, capsys):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=self._full_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = self._full_subprocess()
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            assert "NOR recovery firmware" in capsys.readouterr().out

    def test_summary_includes_boot_dev(self, capsys):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=self._full_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = self._full_subprocess()
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            assert "boot_dev" in capsys.readouterr().out

    def test_summary_includes_bootargs_fix(self, capsys):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=self._full_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = self._full_subprocess()
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            assert "bootargs" in capsys.readouterr().out

    def test_summary_includes_boot_local(self, capsys):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=self._full_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = self._full_subprocess()
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            assert "boot_local" in capsys.readouterr().out

    def test_post_setup_verification_printed(self, capsys):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=self._full_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = self._full_subprocess()
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            out = capsys.readouterr().out
            assert "Verification" in out
            assert "nand_boot" in out
            assert "nor_boot" in out

    def test_switch_instructions_printed(self, capsys):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=self._full_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = self._full_subprocess()
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            out = capsys.readouterr().out
            assert "bootcount" in out
            assert "NAND" in out


# ---------------------------------------------------------------------------
# 10. Integration / edge cases
# ---------------------------------------------------------------------------

class TestMinimalNorRecovery:
    def test_model_with_only_nor_firmware(self):
        m = {
            "id": "minimal",
            "openwrt": {"device": "minimal", "default_ip": "192.168.1.1"},
            "nor_recovery": {
                "nor_firmware": {
                    "url": "https://example.com/minimal.bin",
                    "sha256": "c" * 64,
                    "mtd_partition": "firmware",
                },
            },
        }
        nor_hash = "c" * 64

        def run_ssh_side(ip, cmd, **kw):
            if "sha256sum" in cmd:
                return _cp(0, f"{nor_hash}  /tmp/nor-firmware.bin", "")
            if "mtd write" in cmd:
                return _cp(0, "", "")
            return _cp(0, "", "")

        with Patches(load_model=m, subprocess_run=_cp(0, "SSH_OK", ""), run_ssh=run_ssh_side) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(board_name="minimal", extra=[
                _cp(0, "", ""),  # SCP nor
            ])
            p["sha256_file"].return_value = nor_hash
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True, skip_uboot=True)) == 0

    def test_model_requires_kmod_false(self):
        m = _model()
        m["nor_recovery"]["requires_kmod_mtd_rw"] = False

        def run_ssh_side(ip, cmd, **kw):
            if "sha256sum" in cmd:
                return _cp(0, f"{'b' * 64}  /tmp/nor-firmware.bin", "")
            if "mtd write" in cmd:
                return _cp(0, "", "")
            if "fw_" in cmd:
                return _cp(0, "ok", "")
            if "bootcount" in cmd:
                return _cp(0, "bootcount=3", "")
            return _cp(0, "", "")

        with Patches(load_model=m, subprocess_run=_cp(0, "SSH_OK", ""), run_ssh=run_ssh_side) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""),  # SCP nor
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True, skip_uboot=True))
            kmod_calls = [c for c in p["run_ssh"].call_args_list
                          if "kmod" in str(c) or "insmod" in str(c)]
            assert len(kmod_calls) == 0

    def test_model_empty_mtd_rw_param(self):
        m = _model()
        m["nor_recovery"]["mtd_rw_module_param"] = ""

        def run_ssh_side(ip, cmd, **kw):
            if "insmod" in cmd and "mtd-rw" in cmd:
                return _cp(0, "ok", "")
            if "opkg" in cmd:
                return _cp(0, "ok", "")
            if "sha256sum" in cmd:
                return _cp(0, f"{'b' * 64}  /tmp/nor-firmware.bin", "")
            if "mtd write" in cmd:
                return _cp(0, "", "")
            if "fw_" in cmd:
                return _cp(0, "ok", "")
            if "bootcount" in cmd:
                return _cp(0, "bootcount=3", "")
            return _cp(0, "", "")

        with Patches(load_model=m, subprocess_run=_cp(0, "SSH_OK", ""), run_ssh=run_ssh_side) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""),  # SCP nor
            ])
            p["sha256_file"].return_value = "b" * 64
            assert cmd_setup_nor_recovery(_args(i_want_a_brick=True, skip_uboot=True)) == 0


class TestSequentialRunSshCalls:
    def test_run_ssh_calls_in_correct_order(self):
        call_order = []

        def run_ssh_side(ip, cmd, **kw):
            call_order.append(cmd)
            return _full_live_run_ssh()(ip, cmd, **kw)

        with Patches(subprocess_run=_cp(0, "SSH_OK", ""), run_ssh=run_ssh_side) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True))
            next((i for i, c in enumerate(call_order) if "opkg" in c), -1)
            sha256_idx = next((i for i, c in enumerate(call_order) if "sha256sum" in c), -1)
            mtd_idx = next((i for i, c in enumerate(call_order) if "mtd write" in c), -1)
            assert sha256_idx < mtd_idx


class TestVoiceSuppressionAcrossCallSites:
    def test_no_voice_suppresses_all_say(self):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=_full_live_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True, no_voice=True))
            p["say"].assert_not_called()

    def test_voice_enabled_makes_say_calls(self):
        with Patches(
            subprocess_run=_cp(0, "SSH_OK", ""),
            run_ssh=_full_live_run_ssh(),
        ) as p:
            p["subprocess_run"].side_effect = _ssh_and_board_side_effects(extra=[
                _cp(0, "", ""), subprocess.TimeoutExpired("ssh", 120), _cp(0, "", ""),
            ])
            p["sha256_file"].side_effect = ["a" * 64, "b" * 64]
            cmd_setup_nor_recovery(_args(i_want_a_brick=True, no_voice=False))
            assert p["say"].call_count > 0
