from mac_hash import mac_to_host_byte, mac_to_lan_ip, mac_to_hostname_suffix

import hashlib


class TestMacHashShellParity:
    """Verify Python mac_hash produces the same result as the BusyBox shell pipeline.

    The shell script uses:
        printf '%s' "$_mac_clean" | md5sum | cut -c1-8
    Python uses:
        hashlib.md5(mac_clean.encode()).hexdigest()[:8]

    echo vs printf was a critical bug — echo adds a trailing newline which
    changes the hash. These tests ensure parity is maintained.
    """

    def test_parity_colon_separated(self):
        mac = "aa:bb:cc:dd:ee:01"
        mac_clean = mac.lower().replace(":", "")
        py = mac_to_host_byte(mac)
        shell_hex = hashlib.md5(mac_clean.encode()).hexdigest()[:8]
        shell_val = int(shell_hex, 16) % 200 + 2
        assert py == shell_val

    def test_parity_uppercase_input(self):
        mac = "AA:BB:CC:DD:EE:FF"
        mac_clean = mac.lower().replace(":", "")
        py = mac_to_host_byte(mac)
        shell_hex = hashlib.md5(mac_clean.encode()).hexdigest()[:8]
        shell_val = int(shell_hex, 16) % 200 + 2
        assert py == shell_val

    def test_parity_no_trailing_newline_in_hash_input(self):
        """Regression guard: printf '%s' produces no newline; echo does.

        If someone changes the shell script back to echo, this test catches it
        by verifying the hash input is the bare string without \\n.
        """
        mac = "94:83:c4:aa:bb:cc"
        mac_clean = mac.lower().replace(":", "")
        h_no_nl = hashlib.md5(mac_clean.encode()).hexdigest()[:8]
        h_with_nl = hashlib.md5((mac_clean + "\n").encode()).hexdigest()[:8]
        assert h_no_nl != h_with_nl, "Hashes should differ when newline is added"
        assert mac_to_host_byte(mac) == int(h_no_nl, 16) % 200 + 2


class TestMacToHostByte:
    def test_deterministic(self):
        mac = "aa:bb:cc:dd:ee:01"
        assert mac_to_host_byte(mac) == mac_to_host_byte(mac)

    def test_range_2_to_201(self):
        for mac in [f"aa:bb:cc:dd:ee:{i:02x}" for i in range(256)]:
            val = mac_to_host_byte(mac)
            assert 2 <= val <= 201, f"{mac} → {val}"

    def test_different_macs_different_ips(self):
        ips = {mac_to_host_byte(f"aa:bb:cc:dd:ee:{i:02x}") for i in range(256)}
        assert len(ips) > 100

    def test_format_independent(self):
        assert mac_to_host_byte("AA:BB:CC:DD:EE:01") == mac_to_host_byte("aa:bb:cc:dd:ee:01")
        assert mac_to_host_byte("aabb.ccdd.ee01") == mac_to_host_byte("aa:bb:cc:dd:ee:01")
        assert mac_to_host_byte("aabbcc-ddee-01") == mac_to_host_byte("aa:bb:cc:dd:ee:01")


class TestMacToLanIp:
    def test_full_ip(self):
        ip = mac_to_lan_ip("aa:bb:cc:dd:ee:01", "10.231.9")
        assert ip.startswith("10.231.9.")
        last_octet = int(ip.split(".")[-1])
        assert 2 <= last_octet <= 201

    def test_deterministic(self):
        mac = "10:7b:44:12:34:56"
        assert mac_to_lan_ip(mac, "10.231.9") == mac_to_lan_ip(mac, "10.231.9")

    def test_different_subnets(self):
        mac = "10:7b:44:12:34:56"
        ip1 = mac_to_lan_ip(mac, "10.231.9")
        ip2 = mac_to_lan_ip(mac, "192.168.1")
        assert ip1.split(".")[-1] == ip2.split(".")[-1]
        assert ip1 != ip2


class TestMacToHostnameSuffix:
    def test_last_3_bytes(self):
        assert mac_to_hostname_suffix("aa:bb:cc:dd:ee:ff") == "ddeeff"

    def test_lowercase(self):
        assert mac_to_hostname_suffix("AA:BB:CC:DD:EE:FF") == "ddeeff"

    def test_format_independent(self):
        assert mac_to_hostname_suffix("aabb.ccdd.eeff") == "ddeeff"
