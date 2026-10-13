"""Tests for maas_portable_lab use case (no hardware needed)."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts" / "use_cases"))

from maas_portable_lab import (
    DEFAULTS,
    DESCRIPTION,
    POST_FLASH,
    REQUIRED,
    get_first_boot_script,
    get_flash_config,
    get_pi_network_config,
    get_pi_user_data,
    validate,
)


class TestValidation(unittest.TestCase):
    def test_empty_params_catches_required(self):
        errors = validate({})
        self.assertTrue(any("uplink_ssid" in e for e in errors))
        self.assertTrue(any("uplink_password" in e for e in errors))

    def test_empty_params_catches_swapfile(self):
        errors = validate({})
        self.assertTrue(any("swapfile" in e.lower() for e in errors))

    def test_full_params_pass(self):
        params = {**DEFAULTS, "uplink_ssid": "test", "uplink_password": "p",
                  "zram_percent": 75, "swapfile_size_mb": 2048}
        self.assertEqual(validate(params), [])

    def test_high_zram_warns(self):
        params = {**DEFAULTS, "uplink_ssid": "t", "uplink_password": "p",
                  "zram_percent": 95, "swapfile_size_mb": 2048}
        errors = validate(params)
        self.assertTrue(any("zram" in e.lower() for e in errors))

    def test_low_swapfile_warns(self):
        params = {**DEFAULTS, "uplink_ssid": "t", "uplink_password": "p",
                  "zram_percent": 75, "swapfile_size_mb": 512}
        errors = validate(params)
        self.assertTrue(any("swap" in e.lower() for e in errors))


class TestUserDataGeneration(unittest.TestCase):
    def setUp(self):
        self.params = {
            **DEFAULTS,
            "uplink_ssid": "MyNetwork",
            "uplink_password": "secret123",
            "ssh_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest test@host",
            "maas_admin_password": "adminpw",
            "break_glass_password": "breakglass",
            "zram_percent": 75,
            "swapfile_size_mb": 2048,
        }

    def test_starts_with_cloud_config(self):
        ud = get_pi_user_data(self.params)
        self.assertTrue(ud.startswith("#cloud-config"))

    def test_contains_hostname(self):
        ud = get_pi_user_data(self.params)
        self.assertIn("hostname: maas", ud)

    def test_contains_ssh_key(self):
        ud = get_pi_user_data(self.params)
        self.assertIn("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItest", ud)

    def test_contains_growpart_off(self):
        ud = get_pi_user_data(self.params)
        self.assertIn('mode: "off"', ud)

    def test_contains_accept_ra_false(self):
        nc = get_pi_network_config(self.params)
        self.assertIn("accept-ra: false", nc)

    def test_contains_dhcp6_false(self):
        nc = get_pi_network_config(self.params)
        self.assertIn("dhcp6: false", nc)

    def test_default_ip_params(self):
        nc = get_pi_network_config(self.params)
        self.assertIn("10.50.0.5/24", nc)
        self.assertIn("10.50.0.1", nc)

    def test_custom_ip_params(self):
        params = {**self.params, "maas_ip": "192.168.100.10",
                  "bench_gateway": "192.168.100.1"}
        nc = get_pi_network_config(params)
        self.assertIn("192.168.100.10/24", nc)
        self.assertIn("192.168.100.1", nc)
        self.assertNotIn("10.50.0", nc)

    def test_contains_maas_channel(self):
        ud = get_pi_user_data(self.params)
        self.assertIn("3.6/stable", ud)

    def test_contains_zram_percent(self):
        ud = get_pi_user_data(self.params)
        self.assertIn("PERCENT=75", ud)

    def test_contains_swapfile_size(self):
        ud = get_pi_user_data(self.params)
        self.assertIn("2048M", ud)

    def test_contains_upstream_dns(self):
        ud = get_pi_user_data(self.params)
        self.assertIn("upstream_dns", ud)

    def test_contains_disable_discovery(self):
        ud = get_pi_user_data(self.params)
        self.assertIn("network_discovery", ud)

    def test_contains_beacon_infrastructure(self):
        ud = get_pi_user_data(self.params)
        self.assertIn("/usr/local/bin/beacon", ud)
        self.assertIn("/dev/udp/", ud)

    def test_contains_temp_monitor(self):
        ud = get_pi_user_data(self.params)
        self.assertIn("temp-watch", ud)
        self.assertIn("TEMP-HIGH", ud)

    def test_contains_netconsole(self):
        ud = get_pi_user_data(self.params)
        self.assertIn("netconsole", ud)

    def test_phase_beacons_present(self):
        ud = get_pi_user_data(self.params)
        for phase in ["phase1-memory-floor", "phase2-snap-install",
                      "phase3-maas-init", "phase4-bench-config"]:
            self.assertIn(phase, ud)

    def test_subnet_create_before_dhcp_on(self):
        ud = get_pi_user_data(self.params)
        subnet_pos = ud.find("subnets create")
        dhcp_pos = ud.find("dhcp_on=True")
        self.assertGreater(dhcp_pos, subnet_pos,
                          "dhcp_on must come after subnet creation")

    def test_force_confold_on_apt(self):
        ud = get_pi_user_data(self.params)
        self.assertIn("--force-confold", ud)

    def test_maas_test_db_explicit(self):
        ud = get_pi_user_data(self.params)
        self.assertIn("snap install maas-test-db", ud)


class TestBenchScript(unittest.TestCase):
    def setUp(self):
        self.params = {
            **DEFAULTS,
            "uplink_ssid": "MyNetwork",
            "uplink_password": "secret",
            "ssh_key": "ssh-ed25519 AAAA test",
        }

    def test_contains_bench_config(self):
        bs = get_first_boot_script(self.params)
        self.assertIn("network.lan.ipaddr", bs)
        self.assertIn("ports='internet'", bs)

    def test_contains_wifi_sta(self):
        bs = get_first_boot_script(self.params)
        self.assertIn("sta5", bs)
        self.assertIn("MyNetwork", bs)
        self.assertIn("secret", bs)

    def test_contains_firewall_pinhole(self):
        bs = get_first_boot_script(self.params)
        self.assertIn("House-to-MAAS-mgmt", bs)

    def test_contains_ssh_key(self):
        bs = get_first_boot_script(self.params)
        self.assertIn("ssh-ed25519 AAAA test", bs)

    def test_contains_both_ports(self):
        bs = get_first_boot_script(self.params)
        self.assertIn("ethernet", bs)  # LAN port DSA name
        self.assertIn("internet", bs)  # WAN port DSA name


class TestFlashConfig(unittest.TestCase):
    def test_default_partition_size(self):
        fc = get_flash_config({})
        self.assertEqual(fc["partition_size"], "50G")

    def test_custom_partition_size(self):
        fc = get_flash_config({"root_partition_size": "100G"})
        self.assertEqual(fc["partition_size"], "100G")

    def test_serial_whitelist_required(self):
        fc = get_flash_config({})
        self.assertTrue(fc["serial_whitelist_required"])

    def test_verify_enabled(self):
        fc = get_flash_config({})
        self.assertTrue(fc["verify_chunks"])

    def test_boot_injection(self):
        fc = get_flash_config({})
        self.assertTrue(fc["inject_boot_files"])


class TestDefaults(unittest.TestCase):
    def test_bench_subnet(self):
        self.assertIn("10.50.0.0/24", DEFAULTS["bench_subnet"])

    def test_maas_ip(self):
        self.assertEqual(DEFAULTS["maas_ip"], "10.50.0.5")

    def test_dhcp_range(self):
        self.assertEqual(DEFAULTS["dhcp_range_start"], "10.50.0.100")
        self.assertEqual(DEFAULTS["dhcp_range_end"], "10.50.0.200")

    def test_maas_channel(self):
        self.assertIn("3.6", DEFAULTS["maas_channel"])

    def test_description_mentions_portable(self):
        self.assertIn("portable", DESCRIPTION.lower())

    def test_post_flash_is_true(self):
        self.assertTrue(POST_FLASH)


if __name__ == "__main__":
    unittest.main()
