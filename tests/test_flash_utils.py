from __future__ import annotations

import os
import tempfile
from unittest.mock import MagicMock, patch



def _mock_result(returncode: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


class TestScpUpload:
    @patch("conwrt.flash_utils.subprocess.run")
    @patch("conwrt.flash_utils.os.path.getsize", return_value=5 * 1024 * 1024)
    @patch("conwrt.flash_utils.scp_cmd", return_value=["scp", "src", "dst"])
    def test_success_returns_true(self, mock_scp_cmd, mock_getsize, mock_run):
        from conwrt.flash_utils import _scp_upload
        mock_run.return_value = _mock_result(0)
        ok, remote = _scp_upload("1.2.3.4", "/path/to/firmware.bin")
        assert ok is True
        assert remote == "/tmp/firmware.bin"

    @patch("conwrt.flash_utils.subprocess.run")
    @patch("conwrt.flash_utils.os.path.getsize", return_value=1024)
    @patch("conwrt.flash_utils.scp_cmd", return_value=["scp", "src", "dst"])
    def test_failure_returns_false(self, mock_scp_cmd, mock_getsize, mock_run):
        from conwrt.flash_utils import _scp_upload
        mock_run.return_value = _mock_result(1, stderr="some error")
        ok, remote = _scp_upload("1.2.3.4", "/fw.bin")
        assert ok is False
        assert remote == "/tmp/fw.bin"

    @patch("conwrt.flash_utils.subprocess.run", side_effect=__import__("subprocess").TimeoutExpired("scp", 120))
    @patch("conwrt.flash_utils.os.path.getsize", return_value=1024)
    @patch("conwrt.flash_utils.scp_cmd", return_value=["scp", "src", "dst"])
    def test_timeout_returns_false(self, mock_scp_cmd, mock_getsize, mock_run):
        from conwrt.flash_utils import _scp_upload
        ok, remote = _scp_upload("1.2.3.4", "/fw.bin")
        assert ok is False

    @patch("conwrt.flash_utils.subprocess.run", side_effect=OSError("network down"))
    @patch("conwrt.flash_utils.os.path.getsize", return_value=1024)
    @patch("conwrt.flash_utils.scp_cmd", return_value=["scp", "src", "dst"])
    def test_generic_exception_returns_false(self, mock_scp_cmd, mock_getsize, mock_run):
        from conwrt.flash_utils import _scp_upload
        ok, remote = _scp_upload("1.2.3.4", "/fw.bin")
        assert ok is False

    @patch("conwrt.flash_utils.subprocess.run")
    @patch("conwrt.flash_utils.os.path.getsize", return_value=1024)
    @patch("conwrt.flash_utils.scp_cmd", return_value=["scp", "src", "dst"])
    def test_permission_denied_returns_false(self, mock_scp_cmd, mock_getsize, mock_run):
        from conwrt.flash_utils import _scp_upload
        mock_run.return_value = _mock_result(255, stderr="Permission denied (publickey)")
        ok, remote = _scp_upload("1.2.3.4", "/fw.bin")
        assert ok is False

    @patch("conwrt.flash_utils.subprocess.run")
    @patch("conwrt.flash_utils.os.path.getsize", return_value=1024)
    @patch("conwrt.flash_utils.scp_cmd", return_value=["scp", "src", "dst"])
    def test_remote_path_uses_basename(self, mock_scp_cmd, mock_getsize, mock_run):
        from conwrt.flash_utils import _scp_upload
        mock_run.return_value = _mock_result(0)
        ok, remote = _scp_upload("1.2.3.4", "/some/deep/path/myimage.bin")
        assert remote == "/tmp/myimage.bin"


class TestFlashViaSysupgrade:
    @patch("conwrt.flash_utils.subprocess.run")
    @patch("conwrt.flash_utils.ssh_cmd", return_value=["ssh", "cmd"])
    @patch("conwrt.flash_utils.detect_platform", return_value="darwin")
    @patch("conwrt.flash_utils._scp_upload", return_value=(True, "/tmp/fw.bin"))
    def test_success_rc0(self, mock_upload, mock_platform, mock_ssh_cmd, mock_run):
        from conwrt.flash_utils import _flash_via_sysupgrade
        mock_run.return_value = _mock_result(0, stdout="Commencing upgrade")
        assert _flash_via_sysupgrade("1.2.3.4", "/fw.bin") is True

    @patch("conwrt.flash_utils.subprocess.run")
    @patch("conwrt.flash_utils.ssh_cmd", return_value=["ssh", "cmd"])
    @patch("conwrt.flash_utils.detect_platform", return_value="darwin")
    @patch("conwrt.flash_utils._scp_upload", return_value=(True, "/tmp/fw.bin"))
    def test_success_upgrading_in_output(self, mock_upload, mock_platform, mock_ssh_cmd, mock_run):
        from conwrt.flash_utils import _flash_via_sysupgrade
        mock_run.return_value = _mock_result(0, stderr="Upgrading firmware...")
        assert _flash_via_sysupgrade("1.2.3.4", "/fw.bin") is True

    @patch("conwrt.flash_utils.subprocess.run")
    @patch("conwrt.flash_utils.ssh_cmd", return_value=["ssh", "cmd"])
    @patch("conwrt.flash_utils.detect_platform", return_value="darwin")
    @patch("conwrt.flash_utils._scp_upload", return_value=(True, "/tmp/fw.bin"))
    def test_success_rebooting_in_output(self, mock_upload, mock_platform, mock_ssh_cmd, mock_run):
        from conwrt.flash_utils import _flash_via_sysupgrade
        mock_run.return_value = _mock_result(0, stderr="Rebooting...")
        assert _flash_via_sysupgrade("1.2.3.4", "/fw.bin") is True

    @patch("conwrt.flash_utils.subprocess.run")
    @patch("conwrt.flash_utils.ssh_cmd", return_value=["ssh", "cmd"])
    @patch("conwrt.flash_utils.detect_platform", return_value="darwin")
    @patch("conwrt.flash_utils._scp_upload", return_value=(True, "/tmp/fw.bin"))
    def test_connection_closed_treated_as_success(self, mock_upload, mock_platform, mock_ssh_cmd, mock_run):
        from conwrt.flash_utils import _flash_via_sysupgrade
        mock_run.return_value = _mock_result(1, stdout="", stderr="")
        assert _flash_via_sysupgrade("1.2.3.4", "/fw.bin") is True

    @patch("conwrt.flash_utils.subprocess.run")
    @patch("conwrt.flash_utils.ssh_cmd", return_value=["ssh", "cmd"])
    @patch("conwrt.flash_utils.detect_platform", return_value="darwin")
    @patch("conwrt.flash_utils._scp_upload", return_value=(True, "/tmp/fw.bin"))
    def test_connection_refused_returns_false(self, mock_upload, mock_platform, mock_ssh_cmd, mock_run):
        from conwrt.flash_utils import _flash_via_sysupgrade
        mock_run.return_value = _mock_result(1, stderr="Connection refused")
        assert _flash_via_sysupgrade("1.2.3.4", "/fw.bin") is False

    @patch("conwrt.flash_utils.subprocess.run")
    @patch("conwrt.flash_utils.ssh_cmd", return_value=["ssh", "cmd"])
    @patch("conwrt.flash_utils.detect_platform", return_value="darwin")
    @patch("conwrt.flash_utils._scp_upload", return_value=(True, "/tmp/fw.bin"))
    def test_connection_timed_out_returns_false(self, mock_upload, mock_platform, mock_ssh_cmd, mock_run):
        from conwrt.flash_utils import _flash_via_sysupgrade
        mock_run.return_value = _mock_result(1, stderr="Connection timed out")
        assert _flash_via_sysupgrade("1.2.3.4", "/fw.bin") is False

    @patch("conwrt.flash_utils.subprocess.run", side_effect=__import__("subprocess").TimeoutExpired("ssh", 30))
    @patch("conwrt.flash_utils.ssh_cmd", return_value=["ssh", "cmd"])
    @patch("conwrt.flash_utils.detect_platform", return_value="darwin")
    @patch("conwrt.flash_utils._scp_upload", return_value=(True, "/tmp/fw.bin"))
    def test_timeout_treated_as_success(self, mock_upload, mock_platform, mock_ssh_cmd, mock_run):
        from conwrt.flash_utils import _flash_via_sysupgrade
        assert _flash_via_sysupgrade("1.2.3.4", "/fw.bin") is True

    @patch("conwrt.flash_utils.subprocess.run")
    @patch("conwrt.flash_utils.ssh_cmd", return_value=["ssh", "cmd"])
    @patch("conwrt.flash_utils.detect_platform", return_value="darwin")
    @patch("conwrt.flash_utils._scp_upload", return_value=(True, "/tmp/fw.bin"))
    def test_unexpected_nonzero_with_output_returns_false(self, mock_upload, mock_platform, mock_ssh_cmd, mock_run):
        from conwrt.flash_utils import _flash_via_sysupgrade
        mock_run.return_value = _mock_result(1, stdout="error: bad image", stderr="some details")
        assert _flash_via_sysupgrade("1.2.3.4", "/fw.bin") is False

    @patch("conwrt.flash_utils.ssh_cmd", return_value=["ssh", "cmd"])
    @patch("conwrt.flash_utils.detect_platform", return_value="darwin")
    @patch("conwrt.flash_utils._scp_upload", return_value=(False, "/tmp/fw.bin"))
    def test_upload_failure_returns_false(self, mock_upload, mock_platform, mock_ssh_cmd):
        from conwrt.flash_utils import _flash_via_sysupgrade
        assert _flash_via_sysupgrade("1.2.3.4", "/fw.bin") is False

    @patch("conwrt.flash_utils.subprocess.run", side_effect=OSError("broken"))
    @patch("conwrt.flash_utils.ssh_cmd", return_value=["ssh", "cmd"])
    @patch("conwrt.flash_utils.detect_platform", return_value="darwin")
    @patch("conwrt.flash_utils._scp_upload", return_value=(True, "/tmp/fw.bin"))
    def test_generic_exception_returns_false(self, mock_upload, mock_platform, mock_ssh_cmd, mock_run):
        from conwrt.flash_utils import _flash_via_sysupgrade
        assert _flash_via_sysupgrade("1.2.3.4", "/fw.bin") is False


class TestFlashViaMtdWrite:
    @patch("conwrt.flash_utils.subprocess.run")
    @patch("conwrt.flash_utils.ssh_cmd", return_value=["ssh", "cmd"])
    @patch("conwrt.flash_utils._scp_upload", return_value=(True, "/tmp/fw.bin"))
    def test_success_rc0(self, mock_upload, mock_ssh_cmd, mock_run):
        from conwrt.flash_utils import _flash_via_mtd_write
        mock_run.return_value = _mock_result(0, stdout="Writing firmware...")
        assert _flash_via_mtd_write("1.2.3.4", "/fw.bin") is True

    @patch("conwrt.flash_utils.subprocess.run")
    @patch("conwrt.flash_utils.ssh_cmd", return_value=["ssh", "cmd"])
    @patch("conwrt.flash_utils._scp_upload", return_value=(True, "/tmp/fw.bin"))
    def test_success_rebooting_in_output(self, mock_upload, mock_ssh_cmd, mock_run):
        from conwrt.flash_utils import _flash_via_mtd_write
        mock_run.return_value = _mock_result(0, stderr="Rebooting...")
        assert _flash_via_mtd_write("1.2.3.4", "/fw.bin") is True

    @patch("conwrt.flash_utils.subprocess.run")
    @patch("conwrt.flash_utils.ssh_cmd", return_value=["ssh", "cmd"])
    @patch("conwrt.flash_utils._scp_upload", return_value=(True, "/tmp/fw.bin"))
    def test_connection_closed_treated_as_success(self, mock_upload, mock_ssh_cmd, mock_run):
        from conwrt.flash_utils import _flash_via_mtd_write
        mock_run.return_value = _mock_result(1, stdout="", stderr="")
        assert _flash_via_mtd_write("1.2.3.4", "/fw.bin") is True

    @patch("conwrt.flash_utils.subprocess.run")
    @patch("conwrt.flash_utils.ssh_cmd", return_value=["ssh", "cmd"])
    @patch("conwrt.flash_utils._scp_upload", return_value=(True, "/tmp/fw.bin"))
    def test_connection_refused_returns_false(self, mock_upload, mock_ssh_cmd, mock_run):
        from conwrt.flash_utils import _flash_via_mtd_write
        mock_run.return_value = _mock_result(1, stderr="Connection refused")
        assert _flash_via_mtd_write("1.2.3.4", "/fw.bin") is False

    @patch("conwrt.flash_utils.subprocess.run", side_effect=__import__("subprocess").TimeoutExpired("ssh", 60))
    @patch("conwrt.flash_utils.ssh_cmd", return_value=["ssh", "cmd"])
    @patch("conwrt.flash_utils._scp_upload", return_value=(True, "/tmp/fw.bin"))
    def test_timeout_treated_as_success(self, mock_upload, mock_ssh_cmd, mock_run):
        from conwrt.flash_utils import _flash_via_mtd_write
        assert _flash_via_mtd_write("1.2.3.4", "/fw.bin") is True

    @patch("conwrt.flash_utils.subprocess.run", side_effect=OSError("ssh binary missing"))
    @patch("conwrt.flash_utils.ssh_cmd", return_value=["ssh", "cmd"])
    @patch("conwrt.flash_utils._scp_upload", return_value=(True, "/tmp/fw.bin"))
    def test_oserror_returns_false(self, mock_upload, mock_ssh_cmd, mock_run):
        from conwrt.flash_utils import _flash_via_mtd_write
        assert _flash_via_mtd_write("1.2.3.4", "/fw.bin") is False

    @patch("conwrt.flash_utils.subprocess.run")
    @patch("conwrt.flash_utils.ssh_cmd", return_value=["ssh", "cmd"])
    @patch("conwrt.flash_utils._scp_upload", return_value=(True, "/tmp/fw.bin"))
    def test_generic_failure_with_output_returns_false(self, mock_upload, mock_ssh_cmd, mock_run):
        from conwrt.flash_utils import _flash_via_mtd_write
        mock_run.return_value = _mock_result(1, stderr="mtd: write failure")
        assert _flash_via_mtd_write("1.2.3.4", "/fw.bin") is False

    @patch("conwrt.flash_utils.subprocess.run")
    @patch("conwrt.flash_utils.ssh_cmd", return_value=["ssh", "cmd"])
    @patch("conwrt.flash_utils._scp_upload", return_value=(True, "/tmp/fw.bin"))
    def test_connection_timed_out_returns_false(self, mock_upload, mock_ssh_cmd, mock_run):
        from conwrt.flash_utils import _flash_via_mtd_write
        mock_run.return_value = _mock_result(1, stderr="Connection timed out")
        assert _flash_via_mtd_write("1.2.3.4", "/fw.bin") is False


class TestFlashViaSysupgradeOverlay:
    """Router-to-router flashing (platform=openwrt) uploads a DHCP-disabled
    overlay tarball alongside the firmware and runs sysupgrade -n -f."""

    @patch("conwrt.flash_utils.subprocess.run")
    @patch("conwrt.flash_utils.ssh_cmd")
    @patch("conwrt.flash_utils.detect_platform", return_value="openwrt")
    @patch("conwrt.flash_utils._scp_upload", return_value=(True, "/tmp/fw.bin"))
    @patch("profile.overlay.build_overlay_tarball", return_value="/tmp/overlay.tar.gz")
    def test_overlay_uploaded_runs_sysupgrade_with_f(
            self, mock_overlay, mock_upload, mock_platform, mock_ssh_cmd, mock_run):
        from conwrt.flash_utils import _flash_via_sysupgrade
        mock_ssh_cmd.side_effect = lambda ip, cmd, **kw: ["ssh", cmd]
        mock_run.side_effect = [
            _mock_result(0),
            _mock_result(0, stdout="Commencing upgrade"),
        ]
        assert _flash_via_sysupgrade("1.2.3.4", "/fw.bin") is True
        remote_cmd = mock_ssh_cmd.call_args[0][1]
        assert remote_cmd == "sysupgrade -n -f /tmp/overlay.tar.gz /tmp/fw.bin", remote_cmd

    @patch("conwrt.flash_utils.subprocess.run")
    @patch("conwrt.flash_utils.ssh_cmd")
    @patch("conwrt.flash_utils.detect_platform", return_value="openwrt")
    @patch("conwrt.flash_utils._scp_upload", return_value=(True, "/tmp/fw.bin"))
    @patch("profile.overlay.build_overlay_tarball", return_value="/tmp/overlay.tar.gz")
    def test_overlay_scp_failure_falls_back_to_plain_n(
            self, mock_overlay, mock_upload, mock_platform, mock_ssh_cmd, mock_run):
        from conwrt.flash_utils import _flash_via_sysupgrade
        mock_ssh_cmd.side_effect = lambda ip, cmd, **kw: ["ssh", cmd]
        mock_run.side_effect = [
            _mock_result(1, stderr="scp failed"),
            _mock_result(0, stdout="Commencing upgrade"),
        ]
        assert _flash_via_sysupgrade("1.2.3.4", "/fw.bin") is True
        remote_cmd = mock_ssh_cmd.call_args[0][1]
        assert remote_cmd == "sysupgrade -n /tmp/fw.bin", remote_cmd

    @patch("conwrt.flash_utils.subprocess.run")
    @patch("conwrt.flash_utils.ssh_cmd")
    @patch("conwrt.flash_utils.detect_platform", return_value="openwrt")
    @patch("conwrt.flash_utils._scp_upload", return_value=(True, "/tmp/fw.bin"))
    @patch("profile.overlay.build_overlay_tarball", return_value="/tmp/overlay.tar.gz")
    def test_overlay_scp_oserror_falls_back_to_plain_n(
            self, mock_overlay, mock_upload, mock_platform, mock_ssh_cmd, mock_run):
        from conwrt.flash_utils import _flash_via_sysupgrade
        mock_ssh_cmd.side_effect = lambda ip, cmd, **kw: ["ssh", cmd]
        mock_run.side_effect = [
            OSError("scp not found"),
            _mock_result(0, stdout="Commencing upgrade"),
        ]
        assert _flash_via_sysupgrade("1.2.3.4", "/fw.bin") is True
        remote_cmd = mock_ssh_cmd.call_args[0][1]
        assert remote_cmd == "sysupgrade -n /tmp/fw.bin", remote_cmd

    @patch("conwrt.flash_utils.subprocess.run")
    @patch("conwrt.flash_utils.ssh_cmd")
    @patch("conwrt.flash_utils.detect_platform", return_value="openwrt")
    @patch("conwrt.flash_utils._scp_upload", return_value=(True, "/tmp/fw.bin"))
    def test_overlay_tarball_removed_after_use(
            self, mock_upload, mock_platform, mock_ssh_cmd, mock_run):
        from conwrt.flash_utils import _flash_via_sysupgrade
        fd, overlay_path = tempfile.mkstemp(suffix=".tar.gz")
        os.write(fd, b"overlay")
        os.close(fd)
        mock_ssh_cmd.side_effect = lambda ip, cmd, **kw: ["ssh", cmd]
        mock_run.side_effect = [
            _mock_result(0),
            _mock_result(0, stdout="Commencing upgrade"),
        ]
        with patch("profile.overlay.build_overlay_tarball", return_value=overlay_path):
            assert _flash_via_sysupgrade("1.2.3.4", "/fw.bin") is True
        assert not os.path.exists(overlay_path)

    @patch("conwrt.flash_utils.subprocess.run")
    @patch("conwrt.flash_utils.ssh_cmd", return_value=["ssh", "cmd"])
    @patch("conwrt.flash_utils._scp_upload", return_value=(True, "/tmp/fw.bin"))
    def test_custom_mtd_command(self, mock_upload, mock_ssh_cmd, mock_run):
        from conwrt.flash_utils import _flash_via_mtd_write
        mock_run.return_value = _mock_result(0, stdout="Writing...")
        _flash_via_mtd_write("1.2.3.4", "/fw.bin", mtd_command="mtd -r write /tmp/fw.bin linux")
        args_passed = mock_ssh_cmd.call_args
        assert "mtd -r write /tmp/fw.bin linux" in str(args_passed)


class TestWaitForSysupgradeReboot:
    @patch("conwrt.flash_utils.time.sleep")
    @patch("conwrt.flash_utils.check_ssh", return_value=True)
    @patch("conwrt.flash_utils.ts", side_effect=[0, 5])
    def test_ssh_comes_back_returns_true(self, mock_ts, mock_check, mock_sleep):
        from conwrt.flash_utils import _wait_for_sysupgrade_reboot
        assert _wait_for_sysupgrade_reboot("1.2.3.4") is True

    @patch("conwrt.flash_utils.time.sleep")
    @patch("conwrt.flash_utils.check_ssh", return_value=False)
    @patch("conwrt.flash_utils.ts", side_effect=[0, 10, 190])
    def test_timeout_returns_false(self, mock_ts, mock_check, mock_sleep):
        from conwrt.flash_utils import _wait_for_sysupgrade_reboot
        assert _wait_for_sysupgrade_reboot("1.2.3.4", timeout=180) is False


class TestFindModelIdByBoard:
    @patch("conwrt.flash_utils.find_model_by_board_name", return_value={"id": "test-model-1"})
    def test_found_returns_id(self, mock_find):
        from conwrt.flash_utils import _find_model_id_by_board
        assert _find_model_id_by_board("vendor,board") == "test-model-1"

    @patch("conwrt.flash_utils.find_model_by_board_name", return_value=None)
    def test_not_found_returns_none(self, mock_find):
        from conwrt.flash_utils import _find_model_id_by_board
        assert _find_model_id_by_board("unknown,board") is None


class TestDetectSshKeyPath:
    @patch("conwrt.flash_utils._load_config")
    def test_returns_config_key_path(self, mock_load):
        from conwrt.flash_utils import _detect_ssh_key_path
        mock_cfg = MagicMock()
        mock_cfg.ssh_private_key_path = "/home/user/.ssh/id_ed25519"
        mock_load.return_value = mock_cfg
        assert _detect_ssh_key_path() == "/home/user/.ssh/id_ed25519"


class TestFlashViaSysupgradeKeepConfig:
    @patch("conwrt.flash_utils.subprocess.run")
    @patch("conwrt.flash_utils.ssh_cmd")
    @patch("conwrt.flash_utils.detect_platform", return_value="darwin")
    @patch("conwrt.flash_utils._scp_upload", return_value=(True, "/tmp/fw.bin"))
    def test_keep_config_runs_sysupgrade_without_reset(self, mock_upload, mock_platform, mock_ssh_cmd, mock_run):
        from conwrt.flash_utils import _flash_via_sysupgrade
        mock_ssh_cmd.side_effect = lambda ip, cmd, **kw: ["ssh", cmd]
        mock_run.return_value = _mock_result(0, stdout="Commencing upgrade")
        assert _flash_via_sysupgrade("1.2.3.4", "/fw.bin", keep_config=True) is True
        remote_cmd = mock_ssh_cmd.call_args[0][1]
        assert remote_cmd == "sysupgrade /tmp/fw.bin", remote_cmd

    @patch("conwrt.flash_utils.subprocess.run")
    @patch("conwrt.flash_utils.ssh_cmd")
    @patch("conwrt.flash_utils.detect_platform", return_value="darwin")
    @patch("conwrt.flash_utils._scp_upload", return_value=(True, "/tmp/fw.bin"))
    def test_default_resets_config(self, mock_upload, mock_platform, mock_ssh_cmd, mock_run):
        from conwrt.flash_utils import _flash_via_sysupgrade
        mock_ssh_cmd.side_effect = lambda ip, cmd, **kw: ["ssh", cmd]
        mock_run.return_value = _mock_result(0, stdout="Commencing upgrade")
        assert _flash_via_sysupgrade("1.2.3.4", "/fw.bin") is True
        remote_cmd = mock_ssh_cmd.call_args[0][1]
        assert remote_cmd == "sysupgrade -n /tmp/fw.bin", remote_cmd
