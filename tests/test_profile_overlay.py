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


if __name__ == "__main__":
    unittest.main()
