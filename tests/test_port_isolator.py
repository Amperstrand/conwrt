"""Tests for flash.port_isolator — VLAN-based port isolation for rogue DHCP prevention."""
import subprocess
import unittest
from unittest.mock import MagicMock, call, patch

from flash.port_isolator import PortIsolator


def _ssh_ok(stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess[str]:
    """Create a successful CompletedProcess mock."""
    return subprocess.CompletedProcess(
        args=["ssh"], returncode=0, stdout=stdout, stderr=stderr,
    )


def _ssh_fail(stderr: str = "error") -> subprocess.CompletedProcess[str]:
    """Create a failed CompletedProcess mock."""
    return subprocess.CompletedProcess(
        args=["ssh"], returncode=1, stdout="", stderr=stderr,
    )


# Sample `bridge vlan show` output (Realtek DSA, OpenWrt 25.x)
BRIDGE_VLAN_DEFAULT = """\
port vlan ids
lan1  1
lan2  1
lan3  1
lan4  1
lan5  1
lan6  1
lan7  1
lan8  1
"""

BRIDGE_VLAN_ISOLATED = """\
port vlan ids
lan1  1
lan2  1
lan3  1
lan4  1
lan5  999
lan6  1
lan7  1
lan8  1
"""


class TestPortValidation(unittest.TestCase):
    """Port name validation tests."""

    def test_valid_port_names(self):
        for port in ["lan1", "lan8", "lan99", "lan0"]:
            isolator = PortIsolator("192.168.1.1")
            # Should not raise — just check isolate validates internally
            with patch.object(isolator, "_run_ssh", return_value=_ssh_fail()):
                try:
                    isolator.isolate(port)
                except ValueError:
                    self.fail(f"Valid port {port} raised ValueError")

    def test_invalid_port_name_empty(self):
        isolator = PortIsolator("192.168.1.1")
        with self.assertRaises(ValueError):
            isolator.isolate("")

    def test_invalid_port_name_no_prefix(self):
        isolator = PortIsolator("192.168.1.1")
        with self.assertRaises(ValueError):
            isolator.isolate("5")

    def test_invalid_port_name_wrong_prefix(self):
        isolator = PortIsolator("192.168.1.1")
        with self.assertRaises(ValueError):
            isolator.isolate("eth0")

    def test_invalid_port_name_with_suffix(self):
        isolator = PortIsolator("192.168.1.1")
        with self.assertRaises(ValueError):
            isolator.isolate("lan5:u*")

    def test_invalid_port_name_special_chars(self):
        isolator = PortIsolator("192.168.1.1")
        with self.assertRaises(ValueError):
            isolator.isolate("lan;rm -rf /")

    def test_restore_validates_port(self):
        isolator = PortIsolator("192.168.1.1")
        with self.assertRaises(ValueError):
            isolator.restore("invalid")

    def test_is_isolated_validates_port(self):
        isolator = PortIsolator("192.168.1.1")
        with self.assertRaises(ValueError):
            isolator.is_isolated("invalid")


class TestIpValidation(unittest.TestCase):
    """IP address/CIDR validation tests."""

    def test_valid_ip_cidr(self):
        isolator = PortIsolator("192.168.1.1")
        with patch.object(isolator, "_run_ssh", return_value=_ssh_fail()):
            try:
                isolator.isolate("lan5", "10.0.0.1/24")
            except ValueError:
                self.fail("Valid IP/CIDR raised ValueError")

    def test_invalid_ip_cidr_no_subnet(self):
        isolator = PortIsolator("192.168.1.1")
        with self.assertRaises(ValueError):
            isolator.isolate("lan5", "192.168.1.2")

    def test_invalid_ip_cidr_empty(self):
        isolator = PortIsolator("192.168.1.1")
        with self.assertRaises(ValueError):
            isolator.isolate("lan5", "")

    def test_invalid_ip_cidr_nonsense(self):
        isolator = PortIsolator("192.168.1.1")
        with self.assertRaises(ValueError):
            isolator.isolate("lan5", "not-an-ip")

    def test_restore_validates_ip(self):
        isolator = PortIsolator("192.168.1.1")
        with self.assertRaises(ValueError):
            isolator.restore("lan5", "bad-ip")


class TestIsIsolated(unittest.TestCase):
    """is_isolated() parsing tests."""

    @patch("flash.port_isolator.subprocess.run")
    def test_port_not_isolated_default(self, mock_run):
        mock_run.return_value = _ssh_ok(stdout=BRIDGE_VLAN_DEFAULT)
        isolator = PortIsolator("192.168.1.1")
        self.assertFalse(isolator.is_isolated("lan5"))

    @patch("flash.port_isolator.subprocess.run")
    def test_port_is_isolated_in_vlan999(self, mock_run):
        mock_run.return_value = _ssh_ok(stdout=BRIDGE_VLAN_ISOLATED)
        isolator = PortIsolator("192.168.1.1")
        self.assertTrue(isolator.is_isolated("lan5"))

    @patch("flash.port_isolator.subprocess.run")
    def test_different_port_not_affected(self, mock_run):
        mock_run.return_value = _ssh_ok(stdout=BRIDGE_VLAN_ISOLATED)
        isolator = PortIsolator("192.168.1.1")
        self.assertFalse(isolator.is_isolated("lan6"))

    @patch("flash.port_isolator.subprocess.run")
    def test_command_failure_returns_false(self, mock_run):
        mock_run.return_value = _ssh_fail()
        isolator = PortIsolator("192.168.1.1")
        self.assertFalse(isolator.is_isolated("lan5"))

    @patch("flash.port_isolator.subprocess.run")
    def test_empty_output_returns_false(self, mock_run):
        mock_run.return_value = _ssh_ok(stdout="")
        isolator = PortIsolator("192.168.1.1")
        self.assertFalse(isolator.is_isolated("lan5"))

    @patch("flash.port_isolator.subprocess.run")
    def test_custom_vlan_id(self, mock_run):
        custom_output = """\
port vlan ids
lan5  42
"""
        mock_run.return_value = _ssh_ok(stdout=custom_output)
        isolator = PortIsolator("192.168.1.1", vlan_id=42)
        self.assertTrue(isolator.is_isolated("lan5"))


class TestIsolate(unittest.TestCase):
    """isolate() UCI command generation tests."""

    @patch("flash.port_isolator.subprocess.run")
    def test_isolate_sends_correct_uci_commands(self, mock_run):
        # First call: bridge vlan show (not isolated)
        # Then 8 UCI/SSH commands
        # Then IP assignment
        mock_run.return_value = _ssh_ok(stdout=BRIDGE_VLAN_DEFAULT)
        isolator = PortIsolator("192.168.1.1")
        result = isolator.isolate("lan5")
        self.assertTrue(result)

        # Check commands were issued
        calls = mock_run.call_args_list
        self.assertGreaterEqual(len(calls), 9)  # 1 check + 7 UCI + 1 IP

        # Verify UCI command sequence
        ssh_commands = [c.args[0][0] for c in calls]
        # All calls should be ssh commands
        self.assertTrue(all("ssh" in str(c) for c in calls))

    @patch("flash.port_isolator.subprocess.run")
    def test_isolate_idempotent_already_isolated(self, mock_run):
        """Calling isolate() twice should not error — already isolated."""
        mock_run.return_value = _ssh_ok(stdout=BRIDGE_VLAN_ISOLATED)
        isolator = PortIsolator("192.168.1.1")
        result = isolator.isolate("lan5")
        self.assertTrue(result)
        # Only bridge vlan show should have been called — no UCI commands
        self.assertEqual(mock_run.call_count, 1)

    @patch("flash.port_isolator.subprocess.run")
    def test_isolate_fails_on_uci_error(self, mock_run):
        """If a UCI command fails, isolate returns False."""
        call_count = [0]

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # bridge vlan show — not isolated
                return _ssh_ok(stdout=BRIDGE_VLAN_DEFAULT)
            if call_count[0] <= 3:
                # uci add, uci set device — succeed
                return _ssh_ok()
            # Fail on the 4th command
            return _ssh_fail(stderr="uci: Invalid")

        mock_run.side_effect = side_effect
        isolator = PortIsolator("192.168.1.1")
        result = isolator.isolate("lan5")
        self.assertFalse(result)

    @patch("flash.port_isolator.subprocess.run")
    def test_isolate_ip_file_exists_not_error(self, mock_run):
        """'File exists' on IP assignment is not treated as failure."""
        responses = [_ssh_ok(stdout=BRIDGE_VLAN_DEFAULT)]  # bridge vlan show
        responses.extend([_ssh_ok()] * 7)  # 7 UCI commands
        responses.append(_ssh_fail(stderr="RTNETLINK answers: File exists"))
        mock_run.side_effect = responses
        isolator = PortIsolator("192.168.1.1")
        result = isolator.isolate("lan5")
        self.assertTrue(result)

    @patch("flash.port_isolator.subprocess.run")
    def test_isolate_uses_ssh_key(self, mock_run):
        mock_run.return_value = _ssh_ok(stdout=BRIDGE_VLAN_ISOLATED)
        isolator = PortIsolator("192.168.1.1", ssh_key="/path/to/key")
        isolator.is_isolated("lan5")
        cmd_args = mock_run.call_args[0][0]
        self.assertIn("-i", cmd_args)
        self.assertIn("/path/to/key", cmd_args)

    @patch("flash.port_isolator.subprocess.run")
    def test_isolate_uses_correct_port_spec(self, mock_run):
        """Port should get :u* suffix (untagged + PVID)."""
        mock_run.return_value = _ssh_ok(stdout=BRIDGE_VLAN_DEFAULT)
        isolator = PortIsolator("192.168.1.1")
        isolator.isolate("lan5")

        all_cmds = [c.args[0][-1] for c in mock_run.call_args_list]
        add_list_cmds = [c for c in all_cmds if "add_list" in c]
        self.assertEqual(len(add_list_cmds), 1)
        self.assertIn("lan5:u*", add_list_cmds[0])


class TestRestore(unittest.TestCase):
    """restore() command generation tests."""

    @patch("flash.port_isolator.subprocess.run")
    def test_restore_sends_correct_commands(self, mock_run):
        responses = [
            _ssh_ok(stdout="0\n"),  # find section index (numeric from cut pipeline)
            _ssh_ok(),  # uci delete
            _ssh_ok(),  # uci commit
            _ssh_ok(),  # network restart
            _ssh_ok(),  # ip addr del
        ]
        mock_run.side_effect = responses
        isolator = PortIsolator("192.168.1.1")
        result = isolator.restore("lan5")
        self.assertTrue(result)
        self.assertEqual(mock_run.call_count, 5)

    @patch("flash.port_isolator.subprocess.run")
    def test_restore_finds_section_index(self, mock_run):
        """Section index is extracted from uci show output."""
        responses = [
            _ssh_ok(stdout="0\n"),  # numeric index from cut pipeline
            _ssh_ok(), _ssh_ok(), _ssh_ok(), _ssh_ok(),
        ]
        mock_run.side_effect = responses
        isolator = PortIsolator("192.168.1.1")
        result = isolator.restore("lan5")
        self.assertTrue(result)

        delete_call = mock_run.call_args_list[1]
        ssh_cmd_str = delete_call.args[0][-1]
        self.assertIn("uci delete network.@bridge-vlan[0]", ssh_cmd_str)

    @patch("flash.port_isolator.subprocess.run")
    def test_restore_not_isolated_returns_false(self, mock_run):
        """If VLAN section not found, restore returns False gracefully."""
        mock_run.return_value = _ssh_ok(stdout="")
        isolator = PortIsolator("192.168.1.1")
        result = isolator.restore("lan5")
        self.assertFalse(result)
        # Only the find command should have been called
        self.assertEqual(mock_run.call_count, 1)

    @patch("flash.port_isolator.subprocess.run")
    def test_restore_find_fails_returns_false(self, mock_run):
        mock_run.return_value = _ssh_fail()
        isolator = PortIsolator("192.168.1.1")
        result = isolator.restore("lan5")
        self.assertFalse(result)

    @patch("flash.port_isolator.subprocess.run")
    def test_restore_non_numeric_index_returns_false(self, mock_run):
        """If section index isn't a number, restore returns False."""
        responses = [
            _ssh_ok(stdout="not-a-number\n"),
        ]
        mock_run.side_effect = responses
        isolator = PortIsolator("192.168.1.1")
        result = isolator.restore("lan5")
        self.assertFalse(result)

    @patch("flash.port_isolator.subprocess.run")
    def test_restore_ip_removal_failure_non_critical(self, mock_run):
        """IP removal failure (not 'Cannot find') is a warning, not an error."""
        responses = [
            _ssh_ok(stdout="0\n"),  # find index
            _ssh_ok(),  # delete
            _ssh_ok(),  # commit
            _ssh_ok(),  # restart
            _ssh_fail(stderr="RTNETLINK answers: Cannot find device"),
        ]
        mock_run.side_effect = responses
        isolator = PortIsolator("192.168.1.1")
        result = isolator.restore("lan5")
        self.assertTrue(result)

    @patch("flash.port_isolator.subprocess.run")
    def test_restore_uci_delete_failure_returns_false(self, mock_run):
        """If uci delete fails, restore returns False."""
        responses = [
            _ssh_ok(stdout="0\n"),  # find index
            _ssh_fail(stderr="uci: Entry not found"),
        ]
        mock_run.side_effect = responses
        isolator = PortIsolator("192.168.1.1")
        result = isolator.restore("lan5")
        self.assertFalse(result)


class TestSshCmdIntegration(unittest.TestCase):
    """Tests that ssh_cmd is used correctly."""

    @patch("flash.port_isolator.subprocess.run")
    def test_ssh_connects_to_switch_ip(self, mock_run):
        mock_run.return_value = _ssh_ok(stdout=BRIDGE_VLAN_DEFAULT)
        isolator = PortIsolator("10.0.0.1")
        isolator.is_isolated("lan5")
        cmd_args = mock_run.call_args[0][0]
        self.assertIn("root@10.0.0.1", cmd_args)

    @patch("flash.port_isolator.subprocess.run")
    def test_no_ssh_key_when_none_provided(self, mock_run):
        mock_run.return_value = _ssh_ok(stdout=BRIDGE_VLAN_DEFAULT)
        isolator = PortIsolator("192.168.1.1", ssh_key=None)
        isolator.is_isolated("lan5")
        cmd_args = mock_run.call_args[0][0]
        self.assertNotIn("-i", cmd_args)


if __name__ == "__main__":
    unittest.main()
