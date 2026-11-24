"""Tests for profile.overlay — post-flash overlay generation."""
import os
import tarfile
import unittest


class TestBuildOverlayTarball(unittest.TestCase):
    def test_overlay_contains_dhcp_config_when_disabled(self):
        from profile.overlay import build_overlay_tarball
        path = build_overlay_tarball(disable_dhcp=True)
        try:
            with tarfile.open(path, "r:gz") as tar:
                names = tar.getnames()
                self.assertIn("etc/config/dhcp", names)
                member = tar.getmember("etc/config/dhcp")
                self.assertEqual(member.mode, 0o644)
                f = tar.extractfile(member)
                content = f.read().decode()
                self.assertIn("option ignore '1'", content)
                self.assertIn("config dhcp 'lan'", content)
        finally:
            os.unlink(path)

    def test_overlay_no_dhcp_when_not_disabled(self):
        from profile.overlay import build_overlay_tarball
        path = build_overlay_tarball(disable_dhcp=False)
        try:
            with tarfile.open(path, "r:gz") as tar:
                names = tar.getnames()
                self.assertNotIn("etc/config/dhcp", names)
        finally:
            os.unlink(path)

    def test_overlay_includes_authorized_keys(self):
        from profile.overlay import build_overlay_tarball
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest test@host"
        path = build_overlay_tarball(disable_dhcp=False, authorized_keys=key)
        try:
            with tarfile.open(path, "r:gz") as tar:
                names = tar.getnames()
                self.assertIn("etc/dropbear/authorized_keys", names)
                member = tar.getmember("etc/dropbean/authorized_keys") if "etc/dropbean/authorized_keys" in names else None
                if "etc/dropbear/authorized_keys" in names:
                    member = tar.getmember("etc/dropbear/authorized_keys")
                    self.assertEqual(member.mode, 0o600)
                    f = tar.extractfile(member)
                    content = f.read().decode()
                    self.assertEqual(content, key)
        finally:
            os.unlink(path)

    def test_overlay_is_valid_gzip_tarball(self):
        from profile.overlay import build_overlay_tarball
        path = build_overlay_tarball(disable_dhcp=True)
        try:
            self.assertTrue(tarfile.is_tarfile(path))
            with tarfile.open(path, "r:gz") as tar:
                self.assertTrue(len(tar.getnames()) > 0)
        finally:
            os.unlink(path)

    def test_overlay_cleanup_by_caller(self):
        from profile.overlay import build_overlay_tarball
        path = build_overlay_tarball(disable_dhcp=True)
        self.assertTrue(os.path.isfile(path))
        os.unlink(path)
        self.assertFalse(os.path.isfile(path))


    def test_overlay_sets_lan_ip_via_uci_defaults(self):
        from profile.overlay import build_overlay_tarball
        path = build_overlay_tarball(disable_dhcp=False, lan_ip="192.168.63.10")
        try:
            with tarfile.open(path, "r:gz") as tar:
                name = "etc/uci-defaults/99-conwrt-lan-ip"
                self.assertIn(name, tar.getnames())
                member = tar.getmember(name)
                self.assertEqual(member.mode, 0o755)
                content = tar.extractfile(member).read().decode()
                self.assertIn("uci set network.lan.ipaddr='192.168.63.10'", content)
                self.assertIn("uci commit network", content)
        finally:
            os.unlink(path)

    def test_overlay_rejects_non_ipv4_lan_ip(self):
        from profile.overlay import build_overlay_tarball
        for bad in ["192.168.1.1; reboot", "not-an-ip", "fd00::1", ""]:
            with self.assertRaises(ValueError):
                build_overlay_tarball(disable_dhcp=False, lan_ip=bad)

    def test_overlay_without_lan_ip_has_no_uci_defaults(self):
        from profile.overlay import build_overlay_tarball
        path = build_overlay_tarball(disable_dhcp=True)
        try:
            with tarfile.open(path, "r:gz") as tar:
                self.assertNotIn("etc/uci-defaults/99-conwrt-lan-ip", tar.getnames())
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
