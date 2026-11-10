"""Tests for SSH/SCP command builders."""
import subprocess
import sys
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from ssh_utils import (
    DROPBEAR_AUTH_KEYS_PATH,
    DROPBEAR_SSH_OPTIONS,
    check_ssh,
    run_ssh,
    scp_cmd,
    ssh_cmd,
)


class TestSshCmd(TestCase):
    def test_basic_command(self):
        cmd = ssh_cmd("192.168.1.1", "uname -a")
        self.assertEqual(cmd[0], "ssh")
        self.assertIn("root@192.168.1.1", cmd)
        self.assertIn("uname -a", cmd)

    def test_batch_mode(self):
        cmd = ssh_cmd("192.168.1.1", "ls")
        self.assertIn("BatchMode=yes", cmd)

    def test_password_auth_disabled(self):
        cmd = ssh_cmd("192.168.1.1", "ls")
        self.assertIn("PasswordAuthentication=no", cmd)

    def test_with_ssh_key(self):
        cmd = ssh_cmd("192.168.1.1", "ls", key="/tmp/key")
        self.assertIn("-i", cmd)
        self.assertIn("/tmp/key", cmd)

    def test_without_ssh_key(self):
        cmd = ssh_cmd("192.168.1.1", "ls")
        self.assertNotIn("-i", cmd)

    def test_connect_timeout(self):
        cmd = ssh_cmd("192.168.1.1", "ls", connect_timeout=30)
        self.assertIn("ConnectTimeout=30", cmd)

    def test_sequence_command(self):
        cmd = ssh_cmd("192.168.1.1", ["sysupgrade", "-n", "/tmp/fw.bin"])
        self.assertIn("sysupgrade", cmd)
        self.assertIn("-n", cmd)
        self.assertIn("/tmp/fw.bin", cmd)

    def test_no_host_key_checking(self):
        cmd = ssh_cmd("192.168.1.1", "ls")
        self.assertIn("StrictHostKeyChecking=no", cmd)
        self.assertIn("UserKnownHostsFile=/dev/null", cmd)


class TestScpCmd(TestCase):
    def test_basic_scp(self):
        cmd = scp_cmd("192.168.1.1", "/tmp/fw.bin", "/tmp/fw.bin")
        self.assertEqual(cmd[0], "scp")
        self.assertIn("-O", cmd)
        self.assertIn("/tmp/fw.bin", cmd)

    def test_uses_legacy_protocol(self):
        cmd = scp_cmd("192.168.1.1", "/tmp/fw.bin", "/tmp/fw.bin")
        self.assertIn("-O", cmd)

    def test_with_ssh_key(self):
        cmd = scp_cmd("192.168.1.1", "/tmp/fw.bin", "/tmp/fw.bin", key="/tmp/key")
        self.assertIn("-i", cmd)
        self.assertIn("/tmp/key", cmd)

    def test_without_ssh_key(self):
        cmd = scp_cmd("192.168.1.1", "/tmp/fw.bin", "/tmp/fw.bin")
        self.assertNotIn("-i", cmd)

    def test_no_host_key_checking(self):
        cmd = scp_cmd("192.168.1.1", "/tmp/fw.bin", "/tmp/fw.bin")
        self.assertIn("StrictHostKeyChecking=no", cmd)
        self.assertIn("UserKnownHostsFile=/dev/null", cmd)

    def test_connect_timeout(self):
        cmd = scp_cmd("192.168.1.1", "/tmp/fw.bin", "/tmp/fw.bin", connect_timeout=15)
        self.assertIn("ConnectTimeout=15", cmd)

    def test_dropbear_target_adds_options(self):
        cmd = scp_cmd("192.168.1.1", "/tmp/fw.bin", "/tmp/fw.bin", dropbear_target=True)
        for opt in DROPBEAR_SSH_OPTIONS:
            self.assertIn(opt, cmd)

    def test_no_dropbear_target_omits_options(self):
        cmd = scp_cmd("192.168.1.1", "/tmp/fw.bin", "/tmp/fw.bin", dropbear_target=False)
        self.assertNotIn("HostKeyAlgorithms=+ssh-rsa,ssh-ed25519", cmd)

    def test_src_and_dst_at_end(self):
        cmd = scp_cmd("10.0.0.1", "/local/fw.bin", "/remote/fw.bin")
        self.assertEqual(cmd[-2], "/local/fw.bin")
        self.assertEqual(cmd[-1], "/remote/fw.bin")


class TestDropbearConstants(TestCase):
    def test_auth_keys_path(self):
        self.assertEqual(DROPBEAR_AUTH_KEYS_PATH, "/etc/dropbear/authorized_keys")

    def test_ssh_options_is_list(self):
        self.assertIsInstance(DROPBEAR_SSH_OPTIONS, list)
        self.assertTrue(len(DROPBEAR_SSH_OPTIONS) > 0)

    def test_ssh_options_contains_host_key_algos(self):
        self.assertTrue(
            any("HostKeyAlgorithms" in opt for opt in DROPBEAR_SSH_OPTIONS)
        )


class TestSshCmdDropbear(TestCase):
    def test_dropbear_target_adds_options(self):
        cmd = ssh_cmd("192.168.1.1", "ls", dropbear_target=True)
        for opt in DROPBEAR_SSH_OPTIONS:
            self.assertIn(opt, cmd)

    def test_no_dropbear_target_omits_options(self):
        cmd = ssh_cmd("192.168.1.1", "ls", dropbear_target=False)
        self.assertNotIn("HostKeyAlgorithms=+ssh-rsa,ssh-ed25519", cmd)

    def test_dropbear_with_key_and_sequence(self):
        cmd = ssh_cmd(
            "192.168.1.1",
            ["sysupgrade", "-n", "/tmp/fw.bin"],
            key="/tmp/id_dropbear",
            dropbear_target=True,
        )
        self.assertIn("-i", cmd)
        self.assertIn("/tmp/id_dropbear", cmd)
        self.assertIn("HostKeyAlgorithms=+ssh-rsa,ssh-ed25519", cmd)
        self.assertIn("sysupgrade", cmd)


class TestRunSsh(TestCase):
    @patch("ssh_utils.subprocess.run")
    def test_calls_subprocess_run(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="ok", stderr="")
        run_ssh("192.168.1.1", "uname -a")
        mock_run.assert_called_once()
        args = mock_run.call_args
        cmd = args[0][0]
        self.assertEqual(cmd[0], "ssh")
        self.assertIn("root@192.168.1.1", cmd)
        self.assertIn("uname -a", cmd)

    @patch("ssh_utils.subprocess.run")
    def test_passes_timeout(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        run_ssh("192.168.1.1", "ls", timeout=60)
        _, kwargs = mock_run.call_args
        self.assertEqual(kwargs["timeout"], 60)

    @patch("ssh_utils.subprocess.run")
    def test_capture_output_and_text(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        run_ssh("192.168.1.1", "ls")
        _, kwargs = mock_run.call_args
        self.assertTrue(kwargs["capture_output"])
        self.assertTrue(kwargs["text"])

    @patch("ssh_utils.subprocess.run")
    def test_check_is_false(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        run_ssh("192.168.1.1", "ls")
        _, kwargs = mock_run.call_args
        self.assertFalse(kwargs["check"])

    @patch("ssh_utils.subprocess.run")
    def test_ssh_options_prepended(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        run_ssh("192.168.1.1", "ls", ssh_options=["-o", "ProxyCommand=nc %h %p"])
        cmd = mock_run.call_args[0][0]
        self.assertIn("-o", cmd)
        self.assertIn("ProxyCommand=nc %h %p", cmd)

    @patch("ssh_utils.subprocess.run")
    def test_dropbear_target_forwarded(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        run_ssh("192.168.1.1", "ls", dropbear_target=True)
        cmd = mock_run.call_args[0][0]
        self.assertIn("HostKeyAlgorithms=+ssh-rsa,ssh-ed25519", cmd)

    @patch("ssh_utils.subprocess.run")
    def test_returns_completed_process(self, mock_run):
        expected = MagicMock(returncode=0, stdout="Linux", stderr="")
        mock_run.return_value = expected
        result = run_ssh("192.168.1.1", "uname")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "Linux")


class TestCheckSsh(TestCase):
    @patch("ssh_utils.run_ssh")
    def test_returns_true_on_success(self, mock_run_ssh):
        mock_run_ssh.return_value = MagicMock(returncode=0, stdout="SSH_OK\n")
        self.assertTrue(check_ssh("192.168.1.1"))

    @patch("ssh_utils.run_ssh")
    def test_returns_false_on_nonzero_returncode(self, mock_run_ssh):
        mock_run_ssh.return_value = MagicMock(returncode=1, stdout="", stderr="error")
        self.assertFalse(check_ssh("192.168.1.1"))

    @patch("ssh_utils.run_ssh")
    def test_returns_false_when_sentinel_missing(self, mock_run_ssh):
        mock_run_ssh.return_value = MagicMock(returncode=0, stdout="something_else\n")
        self.assertFalse(check_ssh("192.168.1.1"))

    @patch("ssh_utils.run_ssh")
    def test_returns_false_on_exception(self, mock_run_ssh):
        mock_run_ssh.side_effect = subprocess.TimeoutExpired(cmd="ssh", timeout=10)
        self.assertFalse(check_ssh("192.168.1.1"))

    @patch("ssh_utils.run_ssh")
    def test_custom_sentinel(self, mock_run_ssh):
        mock_run_ssh.return_value = MagicMock(returncode=0, stdout="CUSTOM_PONG\n")
        self.assertTrue(check_ssh("192.168.1.1", sentinel="CUSTOM_PONG"))

    @patch("ssh_utils.run_ssh")
    def test_passes_connect_timeout(self, mock_run_ssh):
        mock_run_ssh.return_value = MagicMock(returncode=0, stdout="SSH_OK\n")
        check_ssh("192.168.1.1", connect_timeout=5)
        _, kwargs = mock_run_ssh.call_args
        self.assertEqual(kwargs["connect_timeout"], 5)

    @patch("ssh_utils.run_ssh")
    def test_timeout_is_connect_timeout_plus_five(self, mock_run_ssh):
        mock_run_ssh.return_value = MagicMock(returncode=0, stdout="SSH_OK\n")
        check_ssh("192.168.1.1", connect_timeout=7)
        _, kwargs = mock_run_ssh.call_args
        self.assertEqual(kwargs["timeout"], 12)
