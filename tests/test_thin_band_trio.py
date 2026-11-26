"""Thin-band coverage: bench_scout + fleet_secrets + maas_wol_webhook (#794 tail).

bench_scout: the parser layer (carrier, DHCP events, leases, title)
and the VLAN→port mapping — pure functions.

fleet_secrets: the deterministic derivation contract — clean_mac,
salt validation, domain-separated sha256 derivation (pinned with a
hard vector so ANY drift in the material string breaks fleet
credentials loudly), derive_all composition, hostname/ssid shapes.

maas_wol_webhook: the magic-packet builder (stubbed socket), the
interface-bind refusal (#367 item 2 — no silent default-route
fallback), and ping_host's three-verdict semantics (#367 item 1).
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import bench_scout as scout  # noqa: E402
import fleet_secrets as fs  # noqa: E402
import maas_wol_webhook as wol  # noqa: E402


class TestScoutParsing:
    def test_port_of_vlan(self):
        assert scout.port_of_vlan(1002) == "lan2"
        assert scout.port_of_vlan(1099) == "lan99"
        with pytest.raises(scout.ScoutError):
            scout.port_of_vlan(1000)
        with pytest.raises(scout.ScoutError):
            scout.port_of_vlan(1100)

    def test_parse_carrier(self):
        assert scout.parse_carrier("state UP mode DEFAULT") is True
        assert scout.parse_carrier("state DOWN mode DEFAULT NO-CARRIER") is False
        assert scout.parse_carrier("state DOWN LOWERLAYERDOWN") is False

    def test_parse_dhcp_events(self):
        lines = [
            "dnsmasq[1]: DHCPDISCOVER(br-lan) 00:11:22:33:44:55",
            "dnsmasq[1]: DHCPACK(br-lan) 192.168.1.50 00:11:22:33:44:55",
            "dnsmasq[1]: read /etc/hosts - 4 addresses",
            "dnsmasq[1]: DHCPNAK(br-lan) 192.168.1.99 aa:bb:cc:dd:ee:01",
        ]
        keep = scout.parse_dhcp_events(lines)
        assert len(keep) == 3
        assert all("DHCP" in line for line in keep)

    def test_parse_leases(self):
        raw = ("1764000000 00:11:22:33:44:55 192.168.1.50 unit-a 01:00:11:22\n"
               "garbage line\n"
               "1764000001 AA:BB:CC:DD:EE:01 192.168.1.51 *\n")
        leases = scout.parse_leases(raw)
        assert leases[0].mac == "00:11:22:33:44:55"
        assert leases[0].ip == "192.168.1.50"
        assert leases[0].hostname == "unit-a"
        assert leases[1].mac == "aa:bb:cc:dd:ee:01"
        assert leases[1].hostname == "*"  # dnsmasq's no-hostname marker

    def test_extract_title(self):
        assert scout.extract_title("<html><TITLE>Netgear GS108T</TITLE>") == "Netgear GS108T"
        assert scout.extract_title("<title>\n  Long Title\n</title>") == "Long Title"
        assert scout.extract_title("<html>no title</html>") == ""

    def test_arm_script_shape(self):
        script = scout.arm_script(1005)
        assert "flock /tmp/amperstrand-bench" in script
        assert "--interface=switch.1005" in script
        assert "192.168.105.50,192.168.105.60" in script
        assert "--no-resolv --dhcp-authoritative" in script
        assert "SCOUT-ARMED" in script
        # rogue discipline: port=0 (DNS off) + no-resolv — the scout
        # serves DHCP ONLY, never a competing resolver
        assert "--port=0" in script and "--no-resolv" in script


class TestFleetSecrets:
    def test_clean_mac(self):
        assert fs.clean_mac("DC:B8:08:6C:EA:7F") == "dcb8086cea7f"
        assert fs.clean_mac("dc-b8-08-6c-ea-7f") == "dcb8086cea7f"
        assert fs.clean_mac("dcb8.086c.ea7f") == "dcb8086cea7f"

    def test_validate_salt(self):
        with pytest.raises(ValueError, match="shell-safe"):
            fs.validate_salt("bad'salt")
        with pytest.raises(ValueError):
            fs.validate_salt("short")
        assert fs.validate_salt("0123456789abcdef") == "0123456789abcdef"

    def test_derive_hard_vector(self):
        # THE material string, pinned: version:domain:salt:mac — any
        # drift here silently rotates every fleet credential
        mac, salt = "dc:b8:08:6c:ea:7f", "testsalt-0123456789"
        expected = hashlib.sha256(
            b"conwrt-fleet-v1:root:testsalt-0123456789:dcb8086cea7f").hexdigest()[:20]
        assert expected == "ddf6d3a29a086134366f"
        with pytest.warns(DeprecationWarning):
            got = fs.derive(mac, salt, "root", 20)
        assert got == expected

    def test_domain_separation(self):
        with pytest.warns(DeprecationWarning):
            root = fs.derive("aa:bb:cc:dd:ee:01", "s" * 8, "root", 20)
            wifi = fs.derive("aa:bb:cc:dd:ee:01", "s" * 8, "wifi:fleet", 20)
        assert root != wifi

    def test_length_bounds(self):
        with pytest.warns(DeprecationWarning):
            with pytest.raises(ValueError, match="length"):
                fs.derive("aa:bb:cc:dd:ee:01", "s" * 8, "root", 4)
            with pytest.raises(ValueError, match="length"):
                fs.derive("aa:bb:cc:dd:ee:01", "s" * 8, "root", 200)

    def test_hostname_and_ssid(self):
        assert fs.hostname("aa:bb:cc:dd:ee:01") == "nr7101-aabbccddee01"
        assert fs.hostname("aa:bb:cc:dd:ee:01", prefix="tg") == "tg-aabbccddee01"
        assert fs.wifi_ssid("aa:bb:cc:dd:ee:01", prefix="tg") == "tg_aabbccddee01"

    def test_derive_all_composition(self):
        with pytest.warns(DeprecationWarning):
            want_root = fs.root_password("aa:bb:cc:dd:ee:01", "s" * 8)
            want_wifi = fs.wifi_password("aa:bb:cc:dd:ee:01", "s" * 8)
        allv = fs.derive_all("aa:bb:cc:dd:ee:01", "s" * 8)
        assert allv["mac"] == "aabbccddee01"
        assert allv["root_password"] == want_root
        assert allv["wifi_password"] == want_wifi
        assert allv["hostname"] == fs.hostname("aabbccddee01")
        assert "lan_ip" in allv  # composed from mac_hash


class TestSendWol:
    def _sock(self):
        sent = []
        sock = SimpleNamespace(
            setsockopt=lambda level, name, val: None,
            sendto=lambda data, addr: sent.append((data, addr)),
            close=lambda: None,
        )
        return sock, sent

    @patch("socket.socket")
    def test_magic_packet_shape(self, mock_cls):
        sock, sent = self._sock()
        mock_cls.return_value = sock
        assert wol.send_wol("AA:BB:CC:DD:EE:01") is True
        magic = b"\xff" * 6 + bytes.fromhex("aabbccddee01") * 16
        # broadcast, both standard ports (9 and 7)
        assert (magic, ("255.255.255.255", 9)) in sent
        assert (magic, ("255.255.255.255", 7)) in sent

    @patch("socket.socket")
    def test_bad_mac_rejected(self, mock_cls):
        assert wol.send_wol("not-a-mac") is False
        mock_cls.assert_not_called()

    @patch("socket.socket")
    def test_unbindable_interface_refuses(self, mock_cls):
        # #367 item 2: a requested-but-unbindable interface must FAIL,
        # never silently broadcast via the default route
        def boom(level, name, val):
            raise OSError("no such device")
        sock = SimpleNamespace(setsockopt=boom, close=lambda: None,
                               sendto=lambda d, a: None)
        mock_cls.return_value = sock
        assert wol.send_wol("aa:bb:cc:dd:ee:01", interface="missing0") is False


class TestPingHost:
    def test_three_verdicts(self):
        rcs = iter([0, 0, 0])

        def run_ok(cmd, **kw):
            return SimpleNamespace(returncode=next(rcs))
        with patch("maas_wol_webhook.subprocess.run", run_ok):
            assert wol.ping_host("1.2.3.4", attempts=3) == "running"

        rcs = iter([0, 1, 0])

        def run_mixed(cmd, **kw):
            return SimpleNamespace(returncode=next(rcs))
        with patch("maas_wol_webhook.subprocess.run", run_mixed):
            assert wol.ping_host("1.2.3.4", attempts=3) == "degraded"

        def run_bad(cmd, **kw):
            return SimpleNamespace(returncode=1)
        with patch("maas_wol_webhook.subprocess.run", run_bad):
            assert wol.ping_host("1.2.3.4", attempts=3) == "stopped"

    def test_timeout_counts_as_failure(self):
        import subprocess as sp

        def run_to(cmd, **kw):
            raise sp.TimeoutExpired(cmd, 1)
        with patch("maas_wol_webhook.subprocess.run", run_to):
            assert wol.ping_host("1.2.3.4", attempts=2) == "stopped"
