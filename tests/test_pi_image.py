"""Tests for pi_image.py pure helpers (device selection, cloud-init rendering)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from pi_image import (
    boot_partition,
    pick_target_device,
    render_meta_data,
    render_network_config,
    render_user_data,
)

GB = 1 << 30


def disk(name, size_gb, mounted_parts=(), model="FakeDisk"):
    children = [
        {"name": f"{name}1", "type": "part", "mountpoints": [None]},
        {"name": f"{name}2", "type": "part", "mountpoints": [None]},
    ]
    for i, mp in enumerate(mounted_parts):
        children[i]["mountpoints"] = [mp]
    return {"name": name, "size": size_gb * GB, "type": "disk",
            "model": model, "mountpoints": [None], "children": children}


def lsblk(*devices):
    import json
    return json.dumps({"blockdevices": list(devices)})


class TestPickTargetDevice(unittest.TestCase):
    def test_single_eligible_disk(self):
        out = lsblk(disk("sda", 1000))
        self.assertEqual(pick_target_device(out), "/dev/sda")

    def test_skips_small_disk(self):
        out = lsblk(disk("sda", 7), disk("sdb", 1000))
        self.assertEqual(pick_target_device(out), "/dev/sdb")

    def test_skips_mounted_disk(self):
        out = lsblk(
            disk("sda", 7, mounted_parts=("/boot/firmware", "/")),
            disk("sdb", 1000),
        )
        self.assertEqual(pick_target_device(out), "/dev/sdb")

    def test_refuses_when_only_mounted(self):
        with self.assertRaises(SystemExit):
            pick_target_device(lsblk(disk("sda", 1000,
                                          mounted_parts=("/",))))

    def test_refuses_multiple_candidates(self):
        with self.assertRaises(SystemExit):
            pick_target_device(lsblk(disk("sda", 1000), disk("sdb", 2000)))

    def test_refuses_no_disk(self):
        with self.assertRaises(SystemExit):
            pick_target_device(lsblk())


class TestBootPartition(unittest.TestCase):
    def test_sda(self):
        self.assertEqual(boot_partition("/dev/sda"), "/dev/sda1")

    def test_mmcblk(self):
        self.assertEqual(boot_partition("/dev/mmcblk0"), "/dev/mmcblk0p1")


class TestCloudInitRendering(unittest.TestCase):
    def test_user_data(self):
        ud = render_user_data("ubuntu", "pi4", ["ssh-ed25519 AAAA me@host"])
        self.assertTrue(ud.startswith("#cloud-config\n"))
        self.assertIn("hostname: pi4\n", ud)
        self.assertIn("name: ubuntu\n", ud)
        self.assertIn("ssh-ed25519 AAAA me@host", ud)
        self.assertIn("ssh_pwauth: false\n", ud)

    def test_user_data_forces_ssh_on(self):
        ud = render_user_data("ubuntu", "pi4", ["ssh-ed25519 AAAA me@host"])
        self.assertIn("runcmd:\n", ud)
        self.assertIn("systemctl enable --now ssh", ud)

    def test_user_data_break_glass_password(self):
        ud = render_user_data("ubuntu", "pi4", ["ssh-ed25519 AAAA me@host"],
                              password="s3cret!")
        # password must arrive UNLOCKED via chpasswd, never as a locked
        # `password:` stanza (lock_passwd:true made it unusable — #269)
        self.assertIn("lock_passwd: false\n", ud)
        self.assertIn("list: |\n      ubuntu:s3cret!\n", ud)
        self.assertNotIn("password: s3cret!\n", ud)
        self.assertIn("ssh_authorized_keys:\n", ud)

    def test_user_data_no_password_locks_account(self):
        ud = render_user_data("ubuntu", "pi4", ["ssh-ed25519 AAAA me@host"])
        self.assertIn("lock_passwd: true\n", ud)
        self.assertNotIn("list: |\n", ud)

    def test_user_data_no_keys_omits_authorized_keys_stanza(self):
        ud = render_user_data("ubuntu", "pi4", [])
        self.assertNotIn("ssh_authorized_keys:\n", ud)

    def test_meta_data(self):
        md = render_meta_data("pi4")
        self.assertIn("instance-id: pi4", md)
        self.assertIn("local-hostname: pi4", md)

    def test_network_config(self):
        nc = render_network_config()
        self.assertIn("version: 2\n", nc)
        self.assertIn("dhcp4: true", nc)


if __name__ == "__main__":
    unittest.main()


class TestProvisionParser(unittest.TestCase):
    def test_password_argument_defined(self):
        from pi_image import build_parser
        args = build_parser().parse_args(
            ["provision", "--host", "h", "--device", "auto",
             "--image", "i.img.xz", "--password", "s3cret"])
        self.assertEqual(args.password, "s3cret")

    def test_password_defaults_to_none(self):
        from pi_image import build_parser
        args = build_parser().parse_args(
            ["provision", "--host", "h", "--device", "auto", "--image", "i.img.xz"])
        self.assertIsNone(args.password)


class TestPreflightResolvesAuto(unittest.TestCase):
    def test_auto_returns_resolved_device(self):
        import pi_image
        canned = lsblk(disk("sda", 1000))
        orig = pi_image._ssh
        pi_image._ssh = lambda host, cmd, timeout=60, input_text=None: (0, canned, "")
        try:
            self.assertEqual(pi_image.preflight("h", "auto", 8), "/dev/sda")
        finally:
            pi_image._ssh = orig

    def test_explicit_returns_device(self):
        import pi_image
        canned = lsblk(disk("sda", 1000))
        orig = pi_image._ssh
        pi_image._ssh = lambda host, cmd, timeout=60, input_text=None: (0, canned, "")
        try:
            self.assertEqual(pi_image.preflight("h", "/dev/sda", 8), "/dev/sda")
        finally:
            pi_image._ssh = orig


class TestSpecimenGate(unittest.TestCase):
    def test_no_expectation_given_refuses(self):
        from pi_image import verify_specimen
        with self.assertRaises(SystemExit):
            verify_specimen("10000000abc", ["e4:5f:01:12:34:56"])

    def test_mac_match_passes(self):
        from pi_image import verify_specimen
        verify_specimen("10000000abc", ["e4:5f:01:12:34:56"],
                        expect_mac="E4:5F:01:12:34:56")

    def test_mac_mismatch_refuses(self):
        from pi_image import verify_specimen
        with self.assertRaises(SystemExit):
            verify_specimen("10000000abc", ["e4:5f:01:12:34:56"],
                            expect_mac="dc:a6:32:11:22:33")

    def test_serial_match_passes_case_insensitive(self):
        from pi_image import verify_specimen
        verify_specimen("10000000ABCD1234", ["e4:5f:01:12:34:56"],
                        expect_serial="10000000abcd1234")

    def test_serial_mismatch_refuses(self):
        from pi_image import verify_specimen
        with self.assertRaises(SystemExit):
            verify_specimen("10000000abcd1234", [], expect_serial="deadbeef")

    def test_both_given_both_must_match(self):
        from pi_image import verify_specimen
        with self.assertRaises(SystemExit):
            verify_specimen("10000000abcd1234", ["e4:5f:01:12:34:56"],
                            expect_mac="e4:5f:01:12:34:56",
                            expect_serial="wrong")

    def test_missing_remote_evidence_refuses(self):
        from pi_image import verify_specimen
        with self.assertRaises(SystemExit):
            verify_specimen(None, [], expect_serial="10000000abcd1234")
        with self.assertRaises(SystemExit):
            verify_specimen(None, [], expect_mac="e4:5f:01:12:34:56")


class TestSpecimenParsing(unittest.TestCase):
    def test_parse_cpuinfo_serial(self):
        from pi_image import parse_cpuinfo_serial
        text = ("Hardware\t: BCM2711\n"
                "Revision\t: d03114\n"
                "Serial\t\t: 10000000abcd1234\n")
        self.assertEqual(parse_cpuinfo_serial(text), "10000000abcd1234")

    def test_parse_cpuinfo_serial_absent(self):
        from pi_image import parse_cpuinfo_serial
        self.assertIsNone(parse_cpuinfo_serial("Hardware\t: BCM2711\n"))

    def test_parse_iface_macs(self):
        from pi_image import parse_iface_macs
        self.assertEqual(parse_iface_macs("e4:5f:01:12:34:56\n\ndc:a6:32:11:22:33\n"),
                         ["e4:5f:01:12:34:56", "dc:a6:32:11:22:33"])


def disk_with_lvm_grandchild(name, size_gb):
    """Disk whose LVM rootfs mounts appear on a GRANDCHILD (lvm on part)."""
    part = {"name": f"{name}2", "type": "part", "mountpoints": [None],
            "children": [
                {"name": f"{name}2", "type": "lvm", "size": 100 * GB,
                 "mountpoints": ["/"], "children": []},
            ]}
    return {"name": name, "size": size_gb * GB, "type": "disk",
            "model": "FakeDisk", "mountpoints": [None],
            "children": [
                {"name": f"{name}1", "type": "part", "mountpoints": [None]},
                part,
            ]}


class TestRecursiveMountCheck(unittest.TestCase):
    def test_grandchild_mounted_disk_not_eligible_auto(self):
        out = lsblk(disk_with_lvm_grandchild("sda", 1000), disk("sdb", 1000))
        self.assertEqual(pick_target_device(out), "/dev/sdb")

    def test_grandchild_mounted_only_disk_refuses(self):
        with self.assertRaises(SystemExit):
            pick_target_device(lsblk(disk_with_lvm_grandchild("sda", 1000)))

    def test_grandchild_mounted_explicit_refuses(self):
        import pi_image
        with self.assertRaises(SystemExit):
            pi_image._check_explicit(lsblk(disk_with_lvm_grandchild("sda", 1000)),
                                     "/dev/sda", 8)


class TestWritePathCommands(unittest.TestCase):
    def test_reread_pt_cmd_uses_partprobe_then_blockdev(self):
        from pi_image import reread_pt_cmd
        cmd = reread_pt_cmd("/dev/sda")
        self.assertIn("partprobe /dev/sda", cmd)
        self.assertIn("blockdev --rereadpt /dev/sda", cmd)

    def test_wait_for_part_cmd_waits_for_block_node(self):
        from pi_image import wait_for_part_cmd
        cmd = wait_for_part_cmd("/dev/sda1", tries=5)
        self.assertIn("test -b /dev/sda1", cmd)
        self.assertIn("sleep 1", cmd)

    def test_validate_archive_runs_xz_test(self):
        import pi_image
        seen = {}

        def fake_ssh(host, cmd, timeout=60, input_text=None):
            seen["cmd"] = cmd
            return (0, "", "")

        orig = pi_image._ssh
        pi_image._ssh = fake_ssh
        try:
            pi_image.validate_archive("h", "/tmp/img.img.xz")
        finally:
            pi_image._ssh = orig
        self.assertIn("xz -t /tmp/img.img.xz", seen["cmd"])

    def test_validate_archive_corrupt_archive_refuses(self):
        import pi_image
        orig = pi_image._ssh
        pi_image._ssh = lambda host, cmd, timeout=60, input_text=None: (1, "", "xz: (stdin): File format not recognized")
        try:
            with self.assertRaises(SystemExit):
                pi_image.validate_archive("h", "/tmp/img.img.xz")
        finally:
            pi_image._ssh = orig


class TestCredentialsFile(unittest.TestCase):
    def test_written_mode_0600(self):
        import tempfile
        from pi_image import write_credentials
        with tempfile.TemporaryDirectory() as td:
            creds = Path(td) / "img.img.xz.credentials.txt"
            write_credentials(creds, "host=pi4\nuser=ubuntu\npassword=x\n")
            self.assertEqual(creds.stat().st_mode & 0o777, 0o600)
            self.assertIn("password=x", creds.read_text())


class TestServeFileAllowlist(unittest.TestCase):
    def test_only_requested_filename_served(self):
        import tempfile
        import urllib.request
        import urllib.error
        from pi_image import serve_file
        with tempfile.TemporaryDirectory() as td:
            image = Path(td) / "img.img.xz"
            image.write_bytes(b"IMAGEDATA")
            (Path(td) / "img.img.xz.credentials.txt").write_text("password=x")
            server, port = serve_file(image)
            try:
                with urllib.request.urlopen(
                        f"http://127.0.0.1:{port}/{image.name}", timeout=5) as r:
                    self.assertEqual(r.status, 200)
                    self.assertEqual(r.read(), b"IMAGEDATA")
                with self.assertRaises(urllib.error.HTTPError) as cm:
                    urllib.request.urlopen(
                        f"http://127.0.0.1:{port}/img.img.xz.credentials.txt",
                        timeout=5)
                self.assertEqual(cm.exception.code, 404)
            finally:
                server.shutdown()
