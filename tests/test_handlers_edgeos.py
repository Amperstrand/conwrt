import queue
import subprocess
import sys
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from flash.context import Event, RecoveryContext, State, Timeline
from conwrt.handlers_edgeos import (
    _handle_edgeos_stage1,
    _handle_edgeos_stage1_rebooting,
    _handle_edgeos_port_swap,
    _handle_edgeos_stage2_uploading,
    _handle_edgeos_stage2_flashing,
)


def _make_ctx(**overrides):
    profile = MagicMock()
    profile.edgeos_ip = overrides.pop("edgeos_ip", "192.168.1.1")
    profile.edgeos_user = overrides.pop("edgeos_user", "ubnt")
    profile.edgeos_password = overrides.pop("edgeos_password", "ubnt")
    profile.boot_partition = overrides.pop("boot_partition", "/dev/mmcblk0p1")
    profile.kernel_path = overrides.pop("kernel_path", "/vmlinux")
    profile.md5_path = overrides.pop("md5_path", "/vmlinux.md5")
    profile.openwrt_ip = overrides.pop("openwrt_ip", "192.168.1.1")
    profile.port_swap_required = overrides.pop("port_swap_required", False)
    profile.port_swap_note = overrides.pop("port_swap_note", "")
    profile.name = overrides.pop("name", "ubnt_edgerouter-6p")
    defaults = {
        "profile": profile,
        "image_path": "/tmp/sysupgrade.tar",
        "interface": "en0",
        "pcap_path": "/tmp/cap.pcap",
        "initramfs_path": "/tmp/initramfs.bin",
        "state": State.EDGEOS_STAGE1,
        "timeline": Timeline(),
        "_say_fn": MagicMock(),
        "ssh_key_path": "",
    }
    defaults.update(overrides)
    ctx = RecoveryContext(**defaults)
    return ctx


def _mock_run(stdout="", stderr="", returncode=0):
    return MagicMock(stdout=stdout, stderr=stderr, returncode=returncode)


def _mock_ssh_result(stdout="", stderr="", returncode=0):
    return MagicMock(stdout=stdout, stderr=stderr, returncode=returncode)


class TestStage1MissingInitramfs(TestCase):
    @patch("conwrt.handlers_edgeos.os.path.isfile", return_value=False)
    def test_missing_initramfs_goes_to_failed(self, mock_isfile):
        ctx = _make_ctx(initramfs_path="/nonexistent.bin")
        eq = queue.Queue()
        _handle_edgeos_stage1(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)


class TestStage1NoInitramfsPath(TestCase):
    @patch("conwrt.handlers_edgeos.os.path.isfile", return_value=False)
    def test_empty_initramfs_path_goes_to_failed(self, mock_isfile):
        ctx = _make_ctx(initramfs_path="")
        eq = queue.Queue()
        _handle_edgeos_stage1(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)


class TestStage1NoSshpass(TestCase):
    @patch("shutil.which", return_value=None)
    @patch("conwrt.handlers_edgeos.os.path.getsize", return_value=10 * 1024 * 1024)
    @patch("conwrt.handlers_edgeos.os.path.isfile", return_value=True)
    def test_sshpass_not_found_goes_to_failed(self, mock_isfile, mock_getsize, mock_which):
        ctx = _make_ctx()
        eq = queue.Queue()
        _handle_edgeos_stage1(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)


class TestStage1ScpTimeout(TestCase):
    @patch("conwrt.handlers_edgeos.subprocess.run", side_effect=subprocess.TimeoutExpired("scp", 120))
    @patch("shutil.which", return_value="/usr/bin/sshpass")
    @patch("conwrt.handlers_edgeos.os.path.getsize", return_value=5 * 1024 * 1024)
    @patch("conwrt.handlers_edgeos.os.path.isfile", return_value=True)
    def test_scp_timeout_goes_to_failed(self, mock_isfile, mock_getsize, mock_which, mock_run):
        ctx = _make_ctx()
        eq = queue.Queue()
        _handle_edgeos_stage1(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)


class TestStage1ScpFailure(TestCase):
    @patch("conwrt.handlers_edgeos.subprocess.run", return_value=_mock_run(stderr="Permission denied", returncode=1))
    @patch("shutil.which", return_value="/usr/bin/sshpass")
    @patch("conwrt.handlers_edgeos.os.path.getsize", return_value=5 * 1024 * 1024)
    @patch("conwrt.handlers_edgeos.os.path.isfile", return_value=True)
    def test_scp_failure_goes_to_failed(self, mock_isfile, mock_getsize, mock_which, mock_run):
        ctx = _make_ctx()
        eq = queue.Queue()
        _handle_edgeos_stage1(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)


class TestStage1KernelSwapSuccess(TestCase):
    @patch("conwrt.handlers_edgeos.sha256_file", return_value="abc123")
    @patch("conwrt.handlers_edgeos.ts", return_value=1000.0)
    @patch("conwrt.handlers_edgeos._ssh_with_password", return_value=_mock_ssh_result(stdout="Kernel swap complete", returncode=0))
    @patch("conwrt.handlers_edgeos.subprocess.run", return_value=_mock_run(stdout="", stderr="", returncode=0))
    @patch("shutil.which", return_value="/usr/bin/sshpass")
    @patch("conwrt.handlers_edgeos.os.path.getsize", return_value=5 * 1024 * 1024)
    @patch("conwrt.handlers_edgeos.os.path.isfile", return_value=True)
    def test_kernel_swap_success_goes_to_rebooting(self, mock_isfile, mock_getsize, mock_which, mock_run, mock_ssh, mock_ts, mock_sha):
        ctx = _make_ctx()
        eq = queue.Queue()
        _handle_edgeos_stage1(ctx, eq)
        self.assertEqual(ctx.state, State.EDGEOS_STAGE1_REBOOTING)
        self.assertEqual(ctx.sha256_before, "abc123")


class TestStage1KernelSwapConnectionClosed(TestCase):
    @patch("conwrt.handlers_edgeos.sha256_file", return_value="abc123")
    @patch("conwrt.handlers_edgeos.ts", return_value=1000.0)
    @patch("conwrt.handlers_edgeos._ssh_with_password", return_value=_mock_ssh_result(stdout="Connection closed by remote host", stderr="", returncode=1))
    @patch("conwrt.handlers_edgeos.subprocess.run", return_value=_mock_run(stdout="", stderr="", returncode=0))
    @patch("shutil.which", return_value="/usr/bin/sshpass")
    @patch("conwrt.handlers_edgeos.os.path.getsize", return_value=5 * 1024 * 1024)
    @patch("conwrt.handlers_edgeos.os.path.isfile", return_value=True)
    def test_kernel_swap_connection_closed_goes_to_rebooting(self, mock_isfile, mock_getsize, mock_which, mock_run, mock_ssh, mock_ts, mock_sha):
        ctx = _make_ctx()
        eq = queue.Queue()
        _handle_edgeos_stage1(ctx, eq)
        self.assertEqual(ctx.state, State.EDGEOS_STAGE1_REBOOTING)


class TestStage1KernelSwapFailure(TestCase):
    @patch("conwrt.handlers_edgeos._ssh_with_password", return_value=_mock_ssh_result(stdout="ERROR: kernel not found", stderr="", returncode=1))
    @patch("conwrt.handlers_edgeos.subprocess.run", return_value=_mock_run(stdout="", stderr="", returncode=0))
    @patch("shutil.which", return_value="/usr/bin/sshpass")
    @patch("conwrt.handlers_edgeos.os.path.getsize", return_value=5 * 1024 * 1024)
    @patch("conwrt.handlers_edgeos.os.path.isfile", return_value=True)
    def test_kernel_swap_failure_goes_to_failed(self, mock_isfile, mock_getsize, mock_which, mock_run, mock_ssh):
        ctx = _make_ctx()
        eq = queue.Queue()
        _handle_edgeos_stage1(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)


class TestStage1RebootingNoPortSwap(TestCase):
    @patch("conwrt.handlers_edgeos.time.sleep")
    def test_rebooting_no_port_swap_goes_to_uploading(self, mock_sleep):
        ctx = _make_ctx(port_swap_required=False, state=State.EDGEOS_STAGE1_REBOOTING)
        eq = queue.Queue()
        _handle_edgeos_stage1_rebooting(ctx, eq)
        self.assertEqual(ctx.state, State.EDGEOS_STAGE2_UPLOADING)


class TestStage1RebootingPortSwap(TestCase):
    @patch("conwrt.handlers_edgeos.time.sleep")
    def test_rebooting_port_swap_goes_to_port_swap(self, mock_sleep):
        ctx = _make_ctx(port_swap_required=True, state=State.EDGEOS_STAGE1_REBOOTING)
        eq = queue.Queue()
        _handle_edgeos_stage1_rebooting(ctx, eq)
        self.assertEqual(ctx.state, State.EDGEOS_PORT_SWAP)


class TestPortSwapSuccess(TestCase):
    @patch("conwrt.handlers_edgeos.poll_until", return_value=True)
    @patch("conwrt.handlers_edgeos.check_ssh", return_value=True)
    @patch("conwrt.handlers_edgeos.ts", return_value=2000.0)
    def test_port_swap_ssh_available_goes_to_uploading(self, mock_ts, mock_check, mock_poll):
        ctx = _make_ctx(port_swap_required=True, state=State.EDGEOS_PORT_SWAP)
        eq = queue.Queue()
        _handle_edgeos_port_swap(ctx, eq)
        self.assertEqual(ctx.state, State.EDGEOS_STAGE2_UPLOADING)
        event = eq.get_nowait()
        self.assertEqual(event[0], Event.EDGEOS_PORT_SWAP_DONE)


class TestPortSwapTimeout(TestCase):
    @patch("conwrt.handlers_edgeos.poll_until", return_value=False)
    @patch("conwrt.handlers_edgeos.check_ssh", return_value=False)
    def test_port_swap_timeout_goes_to_failed(self, mock_check, mock_poll):
        ctx = _make_ctx(port_swap_required=True, state=State.EDGEOS_PORT_SWAP)
        eq = queue.Queue()
        _handle_edgeos_port_swap(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)


class TestStage2UploadMissingImage(TestCase):
    @patch("conwrt.handlers_edgeos.os.path.isfile", return_value=False)
    def test_missing_image_goes_to_failed(self, mock_isfile):
        ctx = _make_ctx(image_path="/nonexistent.tar", state=State.EDGEOS_STAGE2_UPLOADING)
        eq = queue.Queue()
        _handle_edgeos_stage2_uploading(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)


class TestStage2UploadScpFailure(TestCase):
    @patch("conwrt.handlers_edgeos.scp_cmd", return_value=["scp", "src", "dst"])
    @patch("conwrt.handlers_edgeos.subprocess.run", return_value=_mock_run(stderr="Connection refused", returncode=1))
    @patch("conwrt.handlers_edgeos.os.path.getsize", return_value=20 * 1024 * 1024)
    @patch("conwrt.handlers_edgeos.os.path.isfile", return_value=True)
    def test_scp_failure_goes_to_failed(self, mock_isfile, mock_getsize, mock_run, mock_scp):
        ctx = _make_ctx(state=State.EDGEOS_STAGE2_UPLOADING)
        eq = queue.Queue()
        _handle_edgeos_stage2_uploading(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)


class TestStage2UploadScpTimeout(TestCase):
    @patch("conwrt.handlers_edgeos.scp_cmd", return_value=["scp", "src", "dst"])
    @patch("conwrt.handlers_edgeos.subprocess.run", side_effect=subprocess.TimeoutExpired("scp", 120))
    @patch("conwrt.handlers_edgeos.os.path.getsize", return_value=20 * 1024 * 1024)
    @patch("conwrt.handlers_edgeos.os.path.isfile", return_value=True)
    def test_scp_timeout_goes_to_failed(self, mock_isfile, mock_getsize, mock_run, mock_scp):
        ctx = _make_ctx(state=State.EDGEOS_STAGE2_UPLOADING)
        eq = queue.Queue()
        _handle_edgeos_stage2_uploading(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)


class TestStage2UploadSuccess(TestCase):
    @patch("conwrt.handlers_edgeos.ts", return_value=3000.0)
    @patch("conwrt.handlers_edgeos.ssh_cmd", return_value=["ssh", "md5sum"])
    @patch("conwrt.handlers_edgeos.scp_cmd", return_value=["scp", "src", "dst"])
    @patch("conwrt.handlers_edgeos.subprocess.run", return_value=_mock_run(stdout="abc123  /tmp/sysupgrade.tar", returncode=0))
    @patch("conwrt.handlers_edgeos.os.path.getsize", return_value=20 * 1024 * 1024)
    @patch("conwrt.handlers_edgeos.os.path.isfile", return_value=True)
    def test_upload_success_goes_to_flashing(self, mock_isfile, mock_getsize, mock_run, mock_scp, mock_ssh, mock_ts):
        ctx = _make_ctx(state=State.EDGEOS_STAGE2_UPLOADING)
        eq = queue.Queue()
        _handle_edgeos_stage2_uploading(ctx, eq)
        self.assertEqual(ctx.state, State.EDGEOS_STAGE2_FLASHING)
        self.assertIsNotNone(ctx.timeline.upload_complete)


class TestStage2FlashSuccess(TestCase):
    @patch("conwrt.handlers_edgeos.ts", return_value=4000.0)
    @patch("conwrt.handlers_edgeos.ssh_cmd", return_value=["ssh", "flash"])
    @patch("conwrt.handlers_edgeos.subprocess.run", return_value=_mock_run(stdout="Flash complete. Rebooting into permanent OpenWrt...", stderr="", returncode=0))
    def test_flash_success_goes_to_openwrt_booting(self, mock_run, mock_ssh, mock_ts):
        ctx = _make_ctx(state=State.EDGEOS_STAGE2_FLASHING)
        eq = queue.Queue()
        _handle_edgeos_stage2_flashing(ctx, eq)
        self.assertEqual(ctx.state, State.OPENWRT_BOOTING)
        self.assertIsNotNone(ctx.timeline.flash_triggered)


class TestStage2FlashConnectionClosed(TestCase):
    @patch("conwrt.handlers_edgeos.ts", return_value=4000.0)
    @patch("conwrt.handlers_edgeos.ssh_cmd", return_value=["ssh", "flash"])
    @patch("conwrt.handlers_edgeos.subprocess.run", return_value=_mock_run(stdout="", stderr="", returncode=1))
    def test_flash_connection_closed_goes_to_openwrt_booting(self, mock_run, mock_ssh, mock_ts):
        ctx = _make_ctx(state=State.EDGEOS_STAGE2_FLASHING)
        eq = queue.Queue()
        _handle_edgeos_stage2_flashing(ctx, eq)
        self.assertEqual(ctx.state, State.OPENWRT_BOOTING)


class TestStage2FlashTimeout(TestCase):
    @patch("conwrt.handlers_edgeos.ts", return_value=4000.0)
    @patch("conwrt.handlers_edgeos.ssh_cmd", return_value=["ssh", "flash"])
    @patch("conwrt.handlers_edgeos.subprocess.run", side_effect=subprocess.TimeoutExpired("ssh", 120))
    def test_flash_timeout_still_goes_to_openwrt_booting(self, mock_run, mock_ssh, mock_ts):
        ctx = _make_ctx(state=State.EDGEOS_STAGE2_FLASHING)
        eq = queue.Queue()
        _handle_edgeos_stage2_flashing(ctx, eq)
        self.assertEqual(ctx.state, State.OPENWRT_BOOTING)
