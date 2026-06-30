import importlib.util
import subprocess
import sys
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch


_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS))


def _load_wg_setup():
    spec = importlib.util.spec_from_file_location("wg_setup", _SCRIPTS / "wg-setup.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["wg_setup"] = module
    spec.loader.exec_module(module)
    return module


wg_setup = _load_wg_setup()


def _peer_config_lines():
    return (
        "PrivateKey = aBcDeFgH1234567890private\n"
        "Address = 10.0.0.5/32\n"
        "PresharedKey = sharedKeyValue\n"
        "PublicKey = ServerPubKey\n"
        "Endpoint = vpn.example.com:51820\n"
        "AllowedIPs = 10.0.0.0/24\n"
        "PersistentKeepalive = 25\n"
    )


def _mock_completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class TestFetchPeerConfigSuccess(TestCase):
    @patch("wg_setup.subprocess.run")
    def test_parses_all_fields(self, mock_run):
        mock_run.return_value = _mock_completed(stdout=_peer_config_lines())
        pc = wg_setup.fetch_peer_config("my-vpn", 3)
        self.assertEqual(pc.private_key, "aBcDeFgH1234567890private")
        self.assertEqual(pc.address, "10.0.0.5/32")
        self.assertEqual(pc.preshared_key, "sharedKeyValue")
        self.assertEqual(pc.server_public_key, "ServerPubKey")
        self.assertEqual(pc.endpoint_host, "vpn.example.com")
        self.assertEqual(pc.endpoint_port, 51820)
        self.assertEqual(pc.allowed_ips, "10.0.0.0/24")
        self.assertEqual(pc.keepalive, 25)

    @patch("wg_setup.subprocess.run")
    def test_calls_ssh_with_correct_path(self, mock_run):
        mock_run.return_value = _mock_completed(stdout=_peer_config_lines())
        wg_setup.fetch_peer_config("my-vpn", 7)
        cmd = mock_run.call_args[0][0]
        self.assertEqual(cmd[0], "ssh")
        self.assertEqual(cmd[1], "my-vpn")
        self.assertIn("/etc/wireguard/clients/peer-7.conf", cmd[2])

    @patch("wg_setup.subprocess.run")
    def test_skips_comments(self, mock_run):
        text = "# header comment\nPrivateKey = realkey\n#PublicKey = wrong\nPublicKey = realpub\n"
        mock_run.return_value = _mock_completed(stdout=text)
        pc = wg_setup.fetch_peer_config("srv", 1)
        self.assertEqual(pc.private_key, "realkey")
        self.assertEqual(pc.server_public_key, "realpub")

    @patch("wg_setup.subprocess.run")
    def test_missing_endpoint_port_uses_default(self, mock_run):
        # No "Endpoint = host:port" line, no endpoint_port either
        text = "PrivateKey = pk\nAddress = 10.0.0.1/32\n"
        mock_run.return_value = _mock_completed(stdout=text)
        pc = wg_setup.fetch_peer_config("srv", 1)
        self.assertEqual(pc.endpoint_port, 51820)
        self.assertEqual(pc.endpoint_host, "")

    @patch("wg_setup.subprocess.run")
    def test_missing_keepalive_uses_default(self, mock_run):
        text = "PrivateKey = pk\n"
        mock_run.return_value = _mock_completed(stdout=text)
        pc = wg_setup.fetch_peer_config("srv", 1)
        self.assertEqual(pc.keepalive, 25)

    @patch("wg_setup.subprocess.run")
    def test_endpoint_with_only_host_uses_default_port(self, mock_run):
        text = "Endpoint = vpn.example.com\n"
        mock_run.return_value = _mock_completed(stdout=text)
        pc = wg_setup.fetch_peer_config("srv", 1)
        self.assertEqual(pc.endpoint_host, "vpn.example.com")
        self.assertEqual(pc.endpoint_port, 51820)

    @patch("wg_setup.subprocess.run")
    def test_keys_are_case_insensitive(self, mock_run):
        text = "PRIVATEKEY = caps-key\nADDRESS = 10.1.1.1/32\n"
        mock_run.return_value = _mock_completed(stdout=text)
        pc = wg_setup.fetch_peer_config("srv", 1)
        self.assertEqual(pc.private_key, "caps-key")
        self.assertEqual(pc.address, "10.1.1.1/32")


class TestFetchPeerConfigFailure(TestCase):
    @patch("wg_setup.subprocess.run")
    def test_ssh_failure_exits(self, mock_run):
        mock_run.return_value = _mock_completed(returncode=255, stderr="Host unreachable")
        with self.assertRaises(SystemExit) as cm:
            wg_setup.fetch_peer_config("dead-host", 1)
        self.assertEqual(cm.exception.code, 1)


class TestBuildUciCommands(TestCase):
    def _sample_pc(self):
        return wg_setup.PeerConfig(
            private_key="PRIV",
            address="10.0.0.5/32",
            preshared_key="PSK",
            server_public_key="SRVPUB",
            endpoint_host="vpn.example.com",
            endpoint_port=51820,
            allowed_ips="10.0.0.0/24",
            keepalive=25,
        )

    def test_strips_slash_32_from_address(self):
        cmds = wg_setup.build_uci_commands(self._sample_pc())
        joined = "\n".join(cmds)
        self.assertIn("uci set network.wg0.addresses='10.0.0.5'", joined)
        self.assertNotIn("'10.0.0.5/32'", joined)

    def test_includes_interface_and_peer_blocks(self):
        cmds = wg_setup.build_uci_commands(self._sample_pc())
        joined = "\n".join(cmds)
        self.assertIn("uci set network.wg0=interface", joined)
        self.assertIn("uci set network.wg0.proto='wireguard'", joined)
        self.assertIn("uci set network.wg0_peer=wireguard_wg0", joined)

    def test_includes_keys_endpoint_and_keepalive(self):
        cmds = wg_setup.build_uci_commands(self._sample_pc())
        joined = "\n".join(cmds)
        self.assertIn("network.wg0.private_key='PRIV'", joined)
        self.assertIn("network.wg0_peer.public_key='SRVPUB'", joined)
        self.assertIn("network.wg0_peer.preshared_key='PSK'", joined)
        self.assertIn("network.wg0_peer.endpoint_host='vpn.example.com'", joined)
        self.assertIn("network.wg0_peer.endpoint_port='51820'", joined)
        self.assertIn("network.wg0_peer.persistent_keepalive='25'", joined)

    def test_allowed_ips_delete_then_add(self):
        cmds = wg_setup.build_uci_commands(self._sample_pc())
        joined = "\n".join(cmds)
        self.assertIn("uci del_list network.wg0_peer.allowed_ips='10.0.0.0/24'", joined)
        self.assertIn("uci add_list network.wg0_peer.allowed_ips='10.0.0.0/24'", joined)

    def test_ends_with_commit_and_restart(self):
        cmds = wg_setup.build_uci_commands(self._sample_pc())
        non_empty = [c for c in cmds if c]
        self.assertIn("uci commit network", non_empty)
        self.assertIn("uci commit firewall", non_empty)
        self.assertEqual(non_empty[-1], "/etc/init.d/network restart 2>/dev/null || true")

    def test_includes_route_allowed_ips_flag(self):
        cmds = wg_setup.build_uci_commands(self._sample_pc())
        joined = "\n".join(cmds)
        self.assertIn("network.wg0_peer.route_allowed_ips='1'", joined)


class TestMainDryRun(TestCase):
    @patch("wg_setup.subprocess.run")
    def test_dry_run_returns_zero_and_does_not_apply(self, mock_run):
        mock_run.return_value = _mock_completed(stdout=_peer_config_lines())
        argv = ["wg-setup.py", "--peer", "3", "--server", "my-vpn", "--dry-run"]
        with patch.object(sys, "argv", argv):
            rc = wg_setup.main()
        self.assertEqual(rc, 0)
        # Only one subprocess.run call (the fetch); no second call to apply
        self.assertEqual(mock_run.call_count, 1)


class TestMainEmptyPrivateKey(TestCase):
    @patch("wg_setup.subprocess.run")
    def test_no_private_key_returns_error(self, mock_run):
        mock_run.return_value = _mock_completed(stdout="PublicKey = abc\n")
        argv = ["wg-setup.py", "--peer", "1", "--server", "my-vpn"]
        with patch.object(sys, "argv", argv):
            rc = wg_setup.main()
        self.assertEqual(rc, 1)


class TestMainApplySuccess(TestCase):
    @patch("wg_setup.ssh_cmd", return_value=["ssh", "192.168.1.1", "uci..."])
    @patch("wg_setup.subprocess.run")
    def test_successful_apply_returns_zero(self, mock_run, mock_ssh):
        mock_run.side_effect = [
            _mock_completed(stdout=_peer_config_lines()),
            _mock_completed(returncode=0),
        ]
        argv = ["wg-setup.py", "--peer", "2", "--server", "srv", "--ip", "10.1.1.1"]
        with patch.object(sys, "argv", argv):
            rc = wg_setup.main()
        self.assertEqual(rc, 0)
        mock_ssh.assert_called_once()
        ssh_args = mock_ssh.call_args
        self.assertEqual(ssh_args.args[0], "10.1.1.1")

    @patch("wg_setup.ssh_cmd", return_value=["ssh", "192.168.1.1", "uci..."])
    @patch("wg_setup.subprocess.run")
    def test_passes_key_to_ssh_cmd(self, mock_run, mock_ssh):
        mock_run.side_effect = [
            _mock_completed(stdout=_peer_config_lines()),
            _mock_completed(returncode=0),
        ]
        argv = ["wg-setup.py", "--peer", "1", "--server", "srv", "--key", "/path/to/key"]
        with patch.object(sys, "argv", argv):
            wg_setup.main()
        self.assertEqual(mock_ssh.call_args.kwargs.get("key"), "/path/to/key")


class TestMainApplyFailure(TestCase):
    @patch("wg_setup.ssh_cmd", return_value=["ssh", "192.168.1.1", "uci..."])
    @patch("wg_setup.subprocess.run")
    def test_failed_apply_returns_one(self, mock_run, mock_ssh):
        mock_run.side_effect = [
            _mock_completed(stdout=_peer_config_lines()),
            _mock_completed(returncode=1, stderr="uci error"),
        ]
        argv = ["wg-setup.py", "--peer", "1", "--server", "srv"]
        with patch.object(sys, "argv", argv):
            rc = wg_setup.main()
        self.assertEqual(rc, 1)


class TestMainArgvParsing(TestCase):
    def test_missing_required_peer_exits(self):
        argv = ["wg-setup.py", "--server", "srv"]
        with patch.object(sys, "argv", argv):
            with self.assertRaises(SystemExit):
                wg_setup.main()

    def test_missing_required_server_exits(self):
        argv = ["wg-setup.py", "--peer", "1"]
        with patch.object(sys, "argv", argv):
            with self.assertRaises(SystemExit):
                wg_setup.main()
