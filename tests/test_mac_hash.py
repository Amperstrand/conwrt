from mac_hash import mac_to_subnet_octets, mac_to_lan_ip, mac_to_lan_prefix, mac_to_hostname_suffix

import hashlib


class TestMacHashShellParity:
    """Verify Python mac_hash produces the same result as the BusyBox shell pipeline.

    The shell script uses:
        _hash=$(printf '%s' "$_mac_clean" | md5sum)
        _o2=$(printf '%d' 0x$(printf '%s' "$_hash" | cut -c1-8))
        _o2=$((_o2 % 250 + 1))
        _o3=$(printf '%d' 0x$(printf '%s' "$_hash" | cut -c9-16))
        _o3=$((_o3 % 250 + 1))

    Python uses:
        hashlib.md5(mac_clean.encode()).hexdigest()
        int(h[:8], 16) % 250 + 1
        int(h[8:16], 16) % 250 + 1
    """

    def test_parity_colon_separated(self):
        mac = "aa:bb:cc:dd:ee:01"
        mac_clean = mac.lower().replace(":", "")
        py_o2, py_o3 = mac_to_subnet_octets(mac)
        h = hashlib.md5(mac_clean.encode()).hexdigest()
        shell_o2 = int(h[:8], 16) % 250 + 1
        shell_o3 = int(h[8:16], 16) % 250 + 1
        assert (py_o2, py_o3) == (shell_o2, shell_o3)

    def test_parity_uppercase_input(self):
        mac = "AA:BB:CC:DD:EE:FF"
        mac_clean = mac.lower().replace(":", "")
        py_o2, py_o3 = mac_to_subnet_octets(mac)
        h = hashlib.md5(mac_clean.encode()).hexdigest()
        shell_o2 = int(h[:8], 16) % 250 + 1
        shell_o3 = int(h[8:16], 16) % 250 + 1
        assert (py_o2, py_o3) == (shell_o2, shell_o3)

    def test_parity_no_trailing_newline_in_hash_input(self):
        """Regression guard: printf '%s' produces no newline; echo does."""
        mac = "94:83:c4:aa:bb:cc"
        mac_clean = mac.lower().replace(":", "")
        h_no_nl = hashlib.md5(mac_clean.encode()).hexdigest()
        h_with_nl = hashlib.md5((mac_clean + "\n").encode()).hexdigest()
        assert h_no_nl != h_with_nl, "Hashes should differ when newline is added"
        py_o2, py_o3 = mac_to_subnet_octets(mac)
        assert py_o2 == int(h_no_nl[:8], 16) % 250 + 1
        assert py_o3 == int(h_no_nl[8:16], 16) % 250 + 1


class TestMacToSubnetOctets:
    def test_deterministic(self):
        assert mac_to_subnet_octets("aa:bb:cc:dd:ee:01") == mac_to_subnet_octets("aa:bb:cc:dd:ee:01")

    def test_range_1_to_250(self):
        for mac in [f"aa:bb:cc:dd:ee:{i:02x}" for i in range(256)]:
            o2, o3 = mac_to_subnet_octets(mac)
            assert 1 <= o2 <= 250, f"{mac} → o2={o2}"
            assert 1 <= o3 <= 250, f"{mac} → o3={o3}"

    def test_different_macs_different_subnets(self):
        subnets = {mac_to_subnet_octets(f"aa:bb:cc:dd:ee:{i:02x}") for i in range(256)}
        assert len(subnets) > 100

    def test_format_independent(self):
        assert mac_to_subnet_octets("AA:BB:CC:DD:EE:01") == mac_to_subnet_octets("aa:bb:cc:dd:ee:01")
        assert mac_to_subnet_octets("aabb.ccdd.ee01") == mac_to_subnet_octets("aa:bb:cc:dd:ee:01")
        assert mac_to_subnet_octets("aabbcc-ddee-01") == mac_to_subnet_octets("aa:bb:cc:dd:ee:01")

    def test_two_independent_octets(self):
        """Octets 2 and 3 are derived from different parts of the hash."""
        mac = "aa:bb:cc:dd:ee:01"
        o2, o3 = mac_to_subnet_octets(mac)
        # They CAN collide (both are hash-derived), but with 256 MACs they shouldn't always match.
        all_same = all(
            mac_to_subnet_octets(f"aa:bb:cc:dd:ee:{i:02x}")[0]
            == mac_to_subnet_octets(f"aa:bb:cc:dd:ee:{i:02x}")[1]
            for i in range(256)
        )
        assert not all_same


class TestMacToLanIp:
    def test_format_10_x_y_1(self):
        ip = mac_to_lan_ip("aa:bb:cc:dd:ee:01")
        parts = ip.split(".")
        assert len(parts) == 4
        assert parts[0] == "10"
        assert parts[3] == "1"
        assert 1 <= int(parts[1]) <= 250
        assert 1 <= int(parts[2]) <= 250

    def test_deterministic(self):
        mac = "10:7b:44:12:34:56"
        assert mac_to_lan_ip(mac) == mac_to_lan_ip(mac)

    def test_same_mac_same_ip(self):
        assert mac_to_lan_ip("aa:bb:cc:dd:ee:01") == mac_to_lan_ip("aa:bb:cc:dd:ee:01")

    def test_different_macs_likely_different_ips(self):
        ips = {mac_to_lan_ip(f"aa:bb:cc:dd:ee:{i:02x}") for i in range(256)}
        assert len(ips) > 100

    def test_matches_subnet_octets(self):
        mac = "bc:22:28:99:1d:0e"
        o2, o3 = mac_to_subnet_octets(mac)
        assert mac_to_lan_ip(mac) == f"10.{o2}.{o3}.1"


class TestMacToLanPrefix:
    def test_format(self):
        prefix = mac_to_lan_prefix("aa:bb:cc:dd:ee:01")
        parts = prefix.split(".")
        assert len(parts) == 3
        assert parts[0] == "10"

    def test_matches_ip_prefix(self):
        mac = "bc:22:28:99:1d:0e"
        ip = mac_to_lan_ip(mac)
        prefix = mac_to_lan_prefix(mac)
        assert ip.startswith(prefix + ".")


class TestMacToHostnameSuffix:
    def test_last_3_bytes(self):
        assert mac_to_hostname_suffix("aa:bb:cc:dd:ee:ff") == "ddeeff"

    def test_lowercase(self):
        assert mac_to_hostname_suffix("AA:BB:CC:DD:EE:FF") == "ddeeff"

    def test_format_independent(self):
        assert mac_to_hostname_suffix("aabb.ccdd.eeff") == "ddeeff"
