"""Tests for SSH/SCP command builders."""
import sys
from pathlib import Path
from unittest import TestCase

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from ssh_utils import ssh_cmd, scp_cmd


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
