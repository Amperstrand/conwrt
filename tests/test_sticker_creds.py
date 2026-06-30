"""Tests for sticker_creds — factory WiFi credential and MAC extraction
from D-Link COVR-X1860 config2 MTD partition dumps.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from sticker_creds import (
    parse_config2,
    extract_wifi_credentials,
    _mac_to_int,
    _int_to_mac,
    _derive_mac,
    extract_mac_addresses,
    _is_valid_mac,
    _format_output,
    _find_config2_mtd_index,
)


# ===================================================================
# _is_valid_mac
# ===================================================================

class TestIsValidMac(TestCase):
    """_is_valid_mac(s) — validates MAC address format xx:xx:xx:xx:xx:xx."""

    def test_valid_lowercase(self):
        self.assertTrue(_is_valid_mac("aa:bb:cc:dd:ee:ff"))

    def test_valid_uppercase(self):
        self.assertTrue(_is_valid_mac("AA:BB:CC:DD:EE:FF"))

    def test_valid_mixed_case(self):
        self.assertTrue(_is_valid_mac("Aa:Bb:Cc:Dd:Ee:Ff"))

    def test_valid_with_numerics(self):
        self.assertTrue(_is_valid_mac("00:11:22:33:44:55"))

    def test_invalid_no_colons(self):
        self.assertFalse(_is_valid_mac("aabbccddeeff"))

    def test_invalid_five_octets(self):
        self.assertFalse(_is_valid_mac("aa:bb:cc:dd:ee"))

    def test_invalid_seven_octets(self):
        self.assertFalse(_is_valid_mac("aa:bb:cc:dd:ee:ff:00"))

    def test_invalid_empty_string(self):
        self.assertFalse(_is_valid_mac(""))

    def test_valid_leading_trailing_whitespace_stripped(self):
        self.assertTrue(_is_valid_mac("  aa:bb:cc:dd:ee:ff  "))

    def test_invalid_dashes_instead_of_colons(self):
        self.assertFalse(_is_valid_mac("aa-bb-cc-dd-ee-ff"))

    def test_invalid_hex_letter_g(self):
        self.assertFalse(_is_valid_mac("gg:bb:cc:dd:ee:ff"))

    def test_invalid_single_octet(self):
        self.assertFalse(_is_valid_mac("aa"))

    def test_invalid_non_hex_characters(self):
        self.assertFalse(_is_valid_mac("zz:bb:cc:dd:ee:ff"))

    def test_valid_all_zeros(self):
        self.assertTrue(_is_valid_mac("00:00:00:00:00:00"))

    def test_valid_all_ff(self):
        self.assertTrue(_is_valid_mac("ff:ff:ff:ff:ff:ff"))


# ===================================================================
# _mac_to_int
# ===================================================================

class TestMacToInt(TestCase):
    """_mac_to_int(mac) — converts MAC string to integer."""

    def test_all_zeros(self):
        self.assertEqual(_mac_to_int("00:00:00:00:00:00"), 0)

    def test_one(self):
        self.assertEqual(_mac_to_int("00:00:00:00:00:01"), 1)

    def test_lowercase_hex(self):
        self.assertEqual(_mac_to_int("aa:bb:cc:dd:ee:ff"), 0xAABBCCDDEEFF)

    def test_uppercase_hex(self):
        self.assertEqual(_mac_to_int("AA:BB:CC:DD:EE:FF"), 0xAABBCCDDEEFF)

    def test_max_mac(self):
        self.assertEqual(_mac_to_int("ff:ff:ff:ff:ff:ff"), 0xFFFFFFFFFFFF)

    def test_arbitrary_mac(self):
        self.assertEqual(_mac_to_int("12:34:56:78:9a:bc"), 0x12345678_9ABC)


# ===================================================================
# _int_to_mac
# ===================================================================

class TestIntToMac(TestCase):
    """_int_to_mac(val) — converts integer to MAC string (lowercase)."""

    def test_zero(self):
        self.assertEqual(_int_to_mac(0), "00:00:00:00:00:00")

    def test_one(self):
        self.assertEqual(_int_to_mac(1), "00:00:00:00:00:01")

    def test_known_hex(self):
        self.assertEqual(_int_to_mac(0xAABBCCDDEEFF), "aa:bb:cc:dd:ee:ff")

    def test_max_value(self):
        self.assertEqual(_int_to_mac(0xFFFFFFFFFFFF), "ff:ff:ff:ff:ff:ff")

    def test_returns_lowercase(self):
        result = _int_to_mac(0xAABBCCDDEEFF)
        self.assertEqual(result, result.lower())

    def test_roundtrip(self):
        original = "12:34:56:78:9a:bc"
        self.assertEqual(_int_to_mac(_mac_to_int(original)), original)

    def test_roundtrip_all_zeros(self):
        self.assertEqual(_int_to_mac(_mac_to_int("00:00:00:00:00:00")), "00:00:00:00:00:00")

    def test_roundtrip_all_ff(self):
        self.assertEqual(_int_to_mac(_mac_to_int("ff:ff:ff:ff:ff:ff")), "ff:ff:ff:ff:ff:ff")


# ===================================================================
# _derive_mac
# ===================================================================

class TestDeriveMac(TestCase):
    """_derive_mac(base_mac, offset) — derive MAC by adding offset."""

    def test_offset_one(self):
        self.assertEqual(
            _derive_mac("aa:bb:cc:dd:ee:00", 1),
            "aa:bb:cc:dd:ee:01",
        )

    def test_offset_three(self):
        self.assertEqual(
            _derive_mac("aa:bb:cc:dd:ee:00", 3),
            "aa:bb:cc:dd:ee:03",
        )

    def test_carry_across_octet(self):
        self.assertEqual(
            _derive_mac("aa:bb:cc:dd:ee:ff", 1),
            "aa:bb:cc:dd:ef:00",
        )

    def test_offset_zero_returns_same(self):
        mac = "aa:bb:cc:dd:ee:00"
        self.assertEqual(_derive_mac(mac, 0), mac)

    def test_offset_zero_all_zeros(self):
        self.assertEqual(
            _derive_mac("00:00:00:00:00:00", 0),
            "00:00:00:00:00:00",
        )

    def test_negative_offset(self):
        self.assertEqual(
            _derive_mac("aa:bb:cc:dd:ee:03", -3),
            "aa:bb:cc:dd:ee:00",
        )

    def test_large_offset(self):
        # 0x100 = 256, should increment third-from-last octet
        self.assertEqual(
            _derive_mac("aa:bb:cc:dd:ee:00", 0x100),
            "aa:bb:cc:dd:ef:00",
        )

    def test_derive_then_reverse(self):
        base = "aa:bb:cc:dd:ee:00"
        derived = _derive_mac(base, 5)
        self.assertEqual(_derive_mac(derived, -5), base)


# ===================================================================
# parse_config2
# ===================================================================

class TestParseConfig2(TestCase):
    """parse_config2(data) — parse binary config2 for key=value pairs."""

    def test_simple_pair(self):
        data = b"ssid=MyWiFi\n"
        result = parse_config2(data)
        self.assertEqual(result, {"ssid": "MyWiFi"})

    def test_multiple_pairs_null_separated(self):
        data = b"ssid=MyWiFi\x00key=secret"
        result = parse_config2(data)
        self.assertEqual(result, {"ssid": "MyWiFi", "key": "secret"})

    def test_null_bytes_skipped(self):
        data = b"\x00\x00ssid=test\x00"
        result = parse_config2(data)
        self.assertEqual(result, {"ssid": "test"})

    def test_ff_bytes_skipped(self):
        data = b"\xff\xffssid=test\xff"
        result = parse_config2(data)
        self.assertEqual(result, {"ssid": "test"})

    def test_key_must_start_with_letter_or_underscore(self):
        data = b"1invalid=test"
        result = parse_config2(data)
        self.assertNotIn("1invalid", result)

    def test_key_starting_with_underscore(self):
        data = b"_key=value"
        result = parse_config2(data)
        self.assertEqual(result, {"_key": "value"})

    def test_single_char_key(self):
        data = b"a=value"
        result = parse_config2(data)
        self.assertEqual(result, {"a": "value"})

    def test_value_all_same_char_filtered(self):
        """Fill detection: values with all identical characters are skipped."""
        data = b"key=aaaaaa"
        result = parse_config2(data)
        self.assertNotIn("key", result)

    def test_empty_bytes(self):
        self.assertEqual(parse_config2(b""), {})

    def test_key_with_underscore(self):
        data = b"wlan_ssid=test"
        result = parse_config2(data)
        self.assertEqual(result, {"wlan_ssid": "test"})

    def test_nand_noise_with_embedded_data(self):
        data = b"\xff\x00\xff\x00ssid=TestNet\x00\xff\x00key=MyPass123\x00\xff"
        result = parse_config2(data)
        self.assertEqual(result, {"ssid": "TestNet", "key": "MyPass123"})

    def test_newline_in_data(self):
        data = b"ssid=MyWiFi\nkey=secret\n"
        result = parse_config2(data)
        # Newline (0x0A) is below 0x20 so it breaks the match;
        # the second key=value still matches after skipping \n
        self.assertIn("ssid", result)
        self.assertIn("key", result)

    def test_overwrite_same_key(self):
        """If a key appears twice, the later occurrence overwrites."""
        data = b"ssid=first\x00ssid=second"
        result = parse_config2(data)
        self.assertEqual(result["ssid"], "second")

    def test_all_null_bytes(self):
        self.assertEqual(parse_config2(b"\x00" * 100), {})

    def test_all_ff_bytes(self):
        self.assertEqual(parse_config2(b"\xff" * 100), {})

    def test_key_with_numbers(self):
        data = b"wlan0_ssid=test"
        result = parse_config2(data)
        self.assertEqual(result, {"wlan0_ssid": "test"})

    def test_value_with_special_chars(self):
        data = b"password=Abc!@#$%"
        result = parse_config2(data)
        self.assertEqual(result, {"password": "Abc!@#$%"})

    def test_value_single_char_filtered_as_fill(self):
        """Single-char values are filtered: len(set('x')) == 1 → fill detection."""
        data = b"flag=x"
        result = parse_config2(data)
        self.assertNotIn("flag", result)

    def test_value_two_different_chars(self):
        data = b"key=ab"
        result = parse_config2(data)
        self.assertEqual(result, {"key": "ab"})


# ===================================================================
# extract_wifi_credentials
# ===================================================================

class TestExtractWifiCredentials(TestCase):
    """extract_wifi_credentials(config) — find SSID/password for both bands."""

    def test_ssid_24g_wlan_ssid(self):
        config = {"wlan_ssid": "test24"}
        result = extract_wifi_credentials(config)
        self.assertEqual(result["ssid_24g"], "test24")

    def test_ssid_5g_wlan1_ssid(self):
        config = {"wlan1_ssid": "test5"}
        result = extract_wifi_credentials(config)
        self.assertEqual(result["ssid_5g"], "test5")

    def test_password_24g_wlan_wpa_key(self):
        config = {"wlan_wpa_key": "pass123"}
        result = extract_wifi_credentials(config)
        self.assertEqual(result["password_24g"], "pass123")

    def test_password_5g_wlan1_wpa_key(self):
        config = {"wlan1_wpa_key": "pass5xx"}
        result = extract_wifi_credentials(config)
        self.assertEqual(result["password_5g"], "pass5xx")

    def test_first_matching_key_wins(self):
        """Both wlan_ssid and wifi_ssid present → wlan_ssid wins."""
        config = {"wlan_ssid": "primary", "wifi_ssid": "secondary"}
        result = extract_wifi_credentials(config)
        self.assertEqual(result["ssid_24g"], "primary")

    def test_empty_config(self):
        result = extract_wifi_credentials({})
        self.assertEqual(result, {
            "ssid_24g": "",
            "password_24g": "",
            "ssid_5g": "",
            "password_5g": "",
        })

    def test_unknown_keys_only(self):
        config = {"foo": "bar", "baz": "qux"}
        result = extract_wifi_credentials(config)
        self.assertEqual(result["ssid_24g"], "")
        self.assertEqual(result["password_24g"], "")
        self.assertEqual(result["ssid_5g"], "")
        self.assertEqual(result["password_5g"], "")

    def test_returns_all_four_keys(self):
        result = extract_wifi_credentials({})
        self.assertIn("ssid_24g", result)
        self.assertIn("password_24g", result)
        self.assertIn("ssid_5g", result)
        self.assertIn("password_5g", result)

    def test_5g_password_key_variations(self):
        for key in ["wlan1_wpa_key", "wlan5g_wpa_key", "wpa_key_5g"]:
            config = {key: "pass5"}
            result = extract_wifi_credentials(config)
            self.assertEqual(result["password_5g"], "pass5", f"Failed for key: {key}")

    def test_24g_password_key_variations(self):
        for key in ["wlan_wpa_key", "wlan0_wpa_key", "wpa_key", "wifi_key"]:
            config = {key: "pass24"}
            result = extract_wifi_credentials(config)
            self.assertEqual(result["password_24g"], "pass24", f"Failed for key: {key}")

    def test_24g_ssid_key_variations(self):
        for key in ["wlan_ssid", "wlan0_ssid", "wifi_ssid", "ssid"]:
            config = {key: "net24"}
            result = extract_wifi_credentials(config)
            self.assertEqual(result["ssid_24g"], "net24", f"Failed for key: {key}")

    def test_5g_ssid_key_variations(self):
        for key in ["wlan1_ssid", "wlan5g_ssid", "wifi5g_ssid", "ssid_5g"]:
            config = {key: "net5"}
            result = extract_wifi_credentials(config)
            self.assertEqual(result["ssid_5g"], "net5", f"Failed for key: {key}")

    def test_full_config_both_bands(self):
        config = {
            "wlan_ssid": "dlink-2g",
            "wlan_wpa_key": "pass2g",
            "wlan1_ssid": "dlink-5g",
            "wlan1_wpa_key": "pass5g",
        }
        result = extract_wifi_credentials(config)
        self.assertEqual(result["ssid_24g"], "dlink-2g")
        self.assertEqual(result["password_24g"], "pass2g")
        self.assertEqual(result["ssid_5g"], "dlink-5g")
        self.assertEqual(result["password_5g"], "pass5g")

    def test_empty_string_value_skipped(self):
        """Empty string values are not returned by _find_first."""
        config = {"wlan_ssid": ""}
        result = extract_wifi_credentials(config)
        self.assertEqual(result["ssid_24g"], "")


# ===================================================================
# extract_mac_addresses
# ===================================================================

class TestExtractMacAddresses(TestCase):
    """extract_mac_addresses(config, model) — extract and derive MAC addresses."""

    def test_factory_mac_key(self):
        config = {"factory_mac": "aa:bb:cc:dd:ee:00"}
        result = extract_mac_addresses(config)
        self.assertEqual(result["factory_mac"], "aa:bb:cc:dd:ee:00")

    def test_lan_mac_key(self):
        config = {"lan_mac": "aa:bb:cc:dd:ee:00"}
        result = extract_mac_addresses(config)
        self.assertEqual(result["factory_mac"], "aa:bb:cc:dd:ee:00")

    def test_default_derivation_offsets(self):
        """Default offsets: WAN=+3, 2.4G=+1, 5G=+2."""
        config = {"factory_mac": "aa:bb:cc:dd:ee:00"}
        result = extract_mac_addresses(config)
        self.assertEqual(result["wan_mac"], "aa:bb:cc:dd:ee:03")
        self.assertEqual(result["wifi_24g_mac"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(result["wifi_5g_mac"], "aa:bb:cc:dd:ee:02")

    def test_custom_offsets_from_model(self):
        model = {
            "sticker_credentials": {
                "mac_derivation": {"wan": 5, "wifi_24g": 2, "wifi_5g": 4},
            },
        }
        config = {"factory_mac": "aa:bb:cc:dd:ee:00"}
        result = extract_mac_addresses(config, model=model)
        self.assertEqual(result["wan_mac"], "aa:bb:cc:dd:ee:05")
        self.assertEqual(result["wifi_24g_mac"], "aa:bb:cc:dd:ee:02")
        self.assertEqual(result["wifi_5g_mac"], "aa:bb:cc:dd:ee:04")

    def test_no_mac_found(self):
        result = extract_mac_addresses({"foo": "bar"})
        self.assertEqual(result, {
            "factory_mac": "",
            "wan_mac": "",
            "wifi_24g_mac": "",
            "wifi_5g_mac": "",
        })

    def test_mac_found_via_scan(self):
        """Non-standard key name containing 'mac' still found by value scan."""
        config = {"custom_mac_addr": "aa:bb:cc:dd:ee:00"}
        result = extract_mac_addresses(config)
        self.assertEqual(result["factory_mac"], "aa:bb:cc:dd:ee:00")

    def test_mac_lowercase_normalization(self):
        """MACs are normalized to lowercase."""
        config = {"factory_mac": "AA:BB:CC:DD:EE:00"}
        result = extract_mac_addresses(config)
        self.assertEqual(result["factory_mac"], "aa:bb:cc:dd:ee:00")

    def test_invalid_mac_skipped(self):
        """Non-MAC format values are skipped."""
        config = {"factory_mac": "not-a-mac"}
        result = extract_mac_addresses(config)
        self.assertEqual(result["factory_mac"], "")

    def test_model_partial_override(self):
        """Model only overriding one offset leaves others as defaults."""
        model = {
            "sticker_credentials": {
                "mac_derivation": {"wan": 10},
            },
        }
        config = {"factory_mac": "aa:bb:cc:dd:ee:00"}
        result = extract_mac_addresses(config, model=model)
        self.assertEqual(result["wan_mac"], "aa:bb:cc:dd:ee:0a")
        self.assertEqual(result["wifi_24g_mac"], "aa:bb:cc:dd:ee:01")  # default
        self.assertEqual(result["wifi_5g_mac"], "aa:bb:cc:dd:ee:02")  # default

    def test_ethaddr_key(self):
        config = {"ethaddr": "11:22:33:44:55:66"}
        result = extract_mac_addresses(config)
        self.assertEqual(result["factory_mac"], "11:22:33:44:55:66")

    def test_mac_key(self):
        config = {"mac": "11:22:33:44:55:66"}
        result = extract_mac_addresses(config)
        self.assertEqual(result["factory_mac"], "11:22:33:44:55:66")

    def test_known_key_takes_priority_over_scan(self):
        """Known key (e.g. factory_mac) takes priority over scan match."""
        config = {"factory_mac": "aa:bb:cc:dd:ee:00", "alt_mac": "11:22:33:44:55:66"}
        result = extract_mac_addresses(config)
        self.assertEqual(result["factory_mac"], "aa:bb:cc:dd:ee:00")

    def test_model_none_uses_defaults(self):
        config = {"factory_mac": "aa:bb:cc:dd:ee:00"}
        result = extract_mac_addresses(config, model=None)
        self.assertEqual(result["wan_mac"], "aa:bb:cc:dd:ee:03")

    def test_empty_model_uses_defaults(self):
        config = {"factory_mac": "aa:bb:cc:dd:ee:00"}
        result = extract_mac_addresses(config, model={})
        self.assertEqual(result["wan_mac"], "aa:bb:cc:dd:ee:03")

    def test_scan_skips_non_mac_key_name(self):
        """Value scan requires 'mac' in the key name."""
        config = {"serial_number": "aa:bb:cc:dd:ee:00"}
        result = extract_mac_addresses(config)
        self.assertEqual(result["factory_mac"], "")


# ===================================================================
# _format_output
# ===================================================================

class TestFormatOutput(TestCase):
    """_format_output(data) — human-readable credential formatting."""

    def _make_data(self, macs=None, wifi=None, config=None):
        return {
            "macs": macs or {},
            "wifi": wifi or {},
            "config": config or {},
        }

    def test_with_macs_contains_mac_section(self):
        data = self._make_data(macs={
            "factory_mac": "aa:bb:cc:dd:ee:00",
            "wan_mac": "aa:bb:cc:dd:ee:03",
            "wifi_24g_mac": "aa:bb:cc:dd:ee:01",
            "wifi_5g_mac": "aa:bb:cc:dd:ee:02",
        })
        output = _format_output(data)
        self.assertIn("MAC Addresses:", output)
        self.assertIn("aa:bb:cc:dd:ee:00", output)

    def test_with_wifi_contains_wifi_section(self):
        data = self._make_data(wifi={
            "ssid_24g": "MyNet",
            "password_24g": "secret",
            "ssid_5g": "MyNet5G",
            "password_5g": "secret5",
        })
        output = _format_output(data)
        self.assertIn("WiFi Credentials:", output)
        self.assertIn("MyNet", output)

    def test_without_macs_no_mac_section(self):
        data = self._make_data(macs={"factory_mac": ""})
        output = _format_output(data)
        self.assertNotIn("MAC Addresses:", output)

    def test_without_wifi_no_wifi_section(self):
        data = self._make_data(wifi={
            "ssid_24g": "",
            "password_24g": "",
            "ssid_5g": "",
            "password_5g": "",
        })
        output = _format_output(data)
        self.assertNotIn("WiFi Credentials:", output)

    def test_contains_config_key_count(self):
        data = self._make_data(config={"ssid": "test", "key": "secret"})
        output = _format_output(data)
        self.assertIn("2 found", output)

    def test_empty_data_still_has_header(self):
        data = self._make_data()
        output = _format_output(data)
        self.assertIn("Sticker Credentials", output)
        self.assertIn("0 found", output)

    def test_config_keys_sorted(self):
        data = self._make_data(config={"z_key": "z", "a_key": "a"})
        output = _format_output(data)
        a_pos = output.index("a_key")
        z_pos = output.index("z_key")
        self.assertLess(a_pos, z_pos)

    def test_macs_and_wifi_both_present(self):
        data = self._make_data(
            macs={
                "factory_mac": "aa:bb:cc:dd:ee:00",
                "wan_mac": "aa:bb:cc:dd:ee:03",
                "wifi_24g_mac": "aa:bb:cc:dd:ee:01",
                "wifi_5g_mac": "aa:bb:cc:dd:ee:02",
            },
            wifi={
                "ssid_24g": "Net",
                "password_24g": "p",
                "ssid_5g": "",
                "password_5g": "",
            },
        )
        output = _format_output(data)
        self.assertIn("MAC Addresses:", output)
        self.assertIn("WiFi Credentials:", output)
        self.assertIn("2.4 GHz SSID:", output)

    def test_5g_only_wifi(self):
        data = self._make_data(wifi={
            "ssid_24g": "",
            "password_24g": "",
            "ssid_5g": "Net5G",
            "password_5g": "p5",
        })
        output = _format_output(data)
        self.assertIn("WiFi Credentials:", output)
        self.assertIn("5 GHz SSID:", output)
        self.assertNotIn("2.4 GHz SSID:", output)


# ===================================================================
# _find_config2_mtd_index
# ===================================================================

class TestFindConfig2MtdIndex(TestCase):
    """_find_config2_mtd_index(ip, key) — find MTD partition via SSH."""

    @patch("sticker_creds.run_ssh")
    def test_valid_mtd_with_config2(self, mock_ssh):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "dev:    size   erasesize  name\n"
            'mtd0 00080000 "bootloader"\n'
            'mtd7 00080000 "config2"\n'
        )
        mock_ssh.return_value = mock_result
        self.assertEqual(
            _find_config2_mtd_index("192.168.1.1"),
            "/dev/mtd7",
        )

    @patch("sticker_creds.run_ssh")
    def test_no_config2_partition(self, mock_ssh):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = (
            "dev:    size   erasesize  name\n"
            'mtd0 00080000 "bootloader"\n'
            'mtd1 00080000 "firmware"\n'
        )
        mock_ssh.return_value = mock_result
        self.assertIsNone(_find_config2_mtd_index("192.168.1.1"))

    @patch("sticker_creds.run_ssh")
    def test_ssh_command_fails(self, mock_ssh):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "Connection refused"
        mock_ssh.return_value = mock_result
        self.assertIsNone(_find_config2_mtd_index("192.168.1.1"))

    @patch("sticker_creds.run_ssh")
    def test_correct_mtd_device_from_first_column(self, mock_ssh):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = 'mtd3 00010000 "config2"\n'
        mock_ssh.return_value = mock_result
        self.assertEqual(
            _find_config2_mtd_index("192.168.1.1"),
            "/dev/mtd3",
        )

    @patch("sticker_creds.run_ssh")
    def test_empty_mtd_output(self, mock_ssh):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_ssh.return_value = mock_result
        self.assertIsNone(_find_config2_mtd_index("192.168.1.1"))

    @patch("sticker_creds.run_ssh")
    def test_passes_key_argument(self, mock_ssh):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = ""
        mock_ssh.return_value = mock_result
        _find_config2_mtd_index("192.168.1.1", key="/path/to/key")
        mock_ssh.assert_called_once_with(
            "192.168.1.1", "cat /proc/mtd", key="/path/to/key", timeout=15,
        )


# ===================================================================
# Integration-style: parse → extract round-trips
# ===================================================================

class TestIntegration(TestCase):
    """End-to-end through parse_config2 → extract_wifi_credentials + extract_mac_addresses."""

    def _build_partition(self, pairs: list[tuple[str, str]]) -> bytes:
        """Build a fake config2 binary with key=value pairs separated by nulls."""
        parts = []
        for k, v in pairs:
            parts.append(f"{k}={v}".encode("ascii"))
        return b"\x00\xff" + b"\x00".join(parts) + b"\xff\x00"

    def test_full_roundtrip(self):
        data = self._build_partition([
            ("wlan_ssid", "dlink-aabb"),
            ("wlan_wpa_key", "secure123"),
            ("wlan1_ssid", "dlink-aabb_5g"),
            ("wlan1_wpa_key", "secure456"),
            ("factory_mac", "a0:bb:cc:dd:ee:00"),
        ])
        config = parse_config2(data)
        wifi = extract_wifi_credentials(config)
        macs = extract_mac_addresses(config)

        self.assertEqual(wifi["ssid_24g"], "dlink-aabb")
        self.assertEqual(wifi["password_24g"], "secure123")
        self.assertEqual(wifi["ssid_5g"], "dlink-aabb_5g")
        self.assertEqual(wifi["password_5g"], "secure456")
        self.assertEqual(macs["factory_mac"], "a0:bb:cc:dd:ee:00")
        self.assertEqual(macs["wan_mac"], "a0:bb:cc:dd:ee:03")
        self.assertEqual(macs["wifi_24g_mac"], "a0:bb:cc:dd:ee:01")
        self.assertEqual(macs["wifi_5g_mac"], "a0:bb:cc:dd:ee:02")

    def test_roundtrip_minimal_data(self):
        data = self._build_partition([
            ("lan_mac", "11:22:33:44:55:66"),
            ("ssid", "MinimalNet"),
        ])
        config = parse_config2(data)
        wifi = extract_wifi_credentials(config)
        macs = extract_mac_addresses(config)

        self.assertEqual(wifi["ssid_24g"], "MinimalNet")
        self.assertEqual(macs["factory_mac"], "11:22:33:44:55:66")
        self.assertEqual(macs["wan_mac"], "11:22:33:44:55:69")  # +3

    def test_roundtrip_no_credentials(self):
        data = self._build_partition([
            ("some_key", "some_value"),
        ])
        config = parse_config2(data)
        wifi = extract_wifi_credentials(config)
        macs = extract_mac_addresses(config)

        self.assertEqual(wifi["ssid_24g"], "")
        self.assertEqual(macs["factory_mac"], "")

    def test_format_output_with_full_data(self):
        data = self._build_partition([
            ("wlan_ssid", "TestNet"),
            ("wlan_wpa_key", "TestPass"),
            ("factory_mac", "aa:bb:cc:dd:ee:00"),
        ])
        config = parse_config2(data)
        wifi = extract_wifi_credentials(config)
        macs = extract_mac_addresses(config)

        output = _format_output({"config": config, "wifi": wifi, "macs": macs})
        self.assertIn("TestNet", output)
        self.assertIn("TestPass", output)
        self.assertIn("aa:bb:cc:dd:ee:00", output)
        self.assertIn("aa:bb:cc:dd:ee:03", output)
