"""Tests for pi_overlay.py (pure renderers + tmpdir file writes, no network)."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from pi_overlay import (
        HOST_KEY_FILES,
        render_dhcp_config,
        render_dropbear_config,
        render_network_config,
        render_password_setup,
        render_perms_fix,
        write_overlay,
)


class TestRenderNetwork(unittest.TestCase):
    def test_lan_is_dhcp_client_on_interface(self):
        cfg = render_network_config("eth0")
        self.assertIn('config interface "lan"', cfg)
        self.assertIn('option device "eth0"', cfg)
        self.assertIn('option proto "dhcp"', cfg)
        self.assertNotIn("192.168.1.1", cfg)

    def test_custom_interface(self):
        self.assertIn('option device "eth1"', render_network_config("eth1"))


class TestRenderDhcp(unittest.TestCase):
    def test_no_dhcp_pools(self):
        cfg = render_dhcp_config()
        self.assertIn("config dnsmasq", cfg)
        self.assertNotIn("config dhcp", cfg)
        self.assertNotIn("dhcp-option", cfg)
        self.assertNotIn("start ", cfg)


class TestRenderDropbear(unittest.TestCase):
    def test_password_and_root_auth_enabled(self):
        cfg = render_dropbear_config()
        self.assertIn('option PasswordAuth "on"', cfg)
        self.assertIn('option RootPasswordAuth "on"', cfg)


class TestRenderScripts(unittest.TestCase):
    def test_perms_fix_covers_both_authorized_keys_paths(self):
        script = render_perms_fix()
        self.assertIn("chmod 700 /root\n", script)
        self.assertIn("chmod 700 /etc/dropbear\n", script)
        self.assertIn("chmod 600 /etc/dropbear/authorized_keys", script)
        self.assertIn("chmod 600 /root/.ssh/authorized_keys", script)
        self.assertTrue(script.startswith("#!/bin/sh\n"))

    def test_password_setup_feeds_passwd_twice(self):
        script = render_password_setup("s3cret")
        self.assertIn("passwd root", script)
        self.assertEqual(script.count("s3cret"), 2)


class TestWriteOverlay(unittest.TestCase):
    def test_minimal_overlay_layout_and_modes(self):
        with tempfile.TemporaryDirectory() as td:
            key = Path(td) / "key.pub"
            key.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake user@host\n")
            out = Path(td) / "overlay"
            written = write_overlay(out, key)
            names = {str(p.relative_to(out)) for p in written}
            self.assertIn("etc/config/network", names)
            self.assertIn("etc/config/dhcp", names)
            self.assertIn("etc/config/dropbear", names)
            self.assertIn("etc/uci-defaults/98-conwrt-perms", names)
            self.assertIn("etc/dropbear/authorized_keys", names)
            self.assertIn("root/.ssh/authorized_keys", names)
            self.assertNotIn("etc/uci-defaults/99-conwrt-password", names)

            ak = out / "etc/dropbear/authorized_keys"
            self.assertEqual(ak.read_text(),
                             "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake user@host\n")
            self.assertEqual(ak.stat().st_mode & 0o777, 0o600)
            perms = out / "etc/uci-defaults/98-conwrt-perms"
            self.assertEqual(perms.stat().st_mode & 0o777, 0o755)

    def test_password_and_host_keys_optional(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            key = base / "key.pub"
            key.write_text("ssh-ed25519 AAAAfake user@host\n")
            hk = base / "hk"
            hk.mkdir()
            for name in HOST_KEY_FILES:
                (hk / name).write_bytes(b"fake-key-data")
            out = base / "overlay"
            written = write_overlay(out, key, root_password="pw",
                                    host_key_dir=hk)
            names = {str(p.relative_to(out)) for p in written}
            self.assertIn("etc/uci-defaults/99-conwrt-password", names)
            for name in HOST_KEY_FILES:
                self.assertIn(f"etc/dropbear/{name}", names)
                self.assertEqual(
                    (out / "etc/dropbear" / name).stat().st_mode & 0o777, 0o600)

    def test_rejects_non_pubkey_input(self):
        with tempfile.TemporaryDirectory() as td:
            key = Path(td) / "key.pub"
            key.write_text("not a key at all\n")
            with self.assertRaises(ValueError):
                write_overlay(Path(td) / "out", key)

    def test_missing_host_key_raises(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            key = base / "key.pub"
            key.write_text("ssh-ed25519 AAAAfake user@host\n")
            hk = base / "hk"
            hk.mkdir()
            with self.assertRaises(ValueError):
                write_overlay(base / "out", key, host_key_dir=hk)


if __name__ == "__main__":
    unittest.main()
