"""Offline tests for the bootlisten classifier (#323 item 2).

Pure text-in → verdict-out: every verdict path is pinned with
real-shaped `tcpdump -ne` lines; no hardware needed.
"""
import json
from pathlib import Path

import pytest

from conwrt.bootlisten import BootVerdict, classify, parse_line

KERNEL_LINE = (
    "14:52:01.012345 b4:2d:56:25:47:a2 > 33:33:00:00:00:01, ethertype IPv6"
    " (0x86dd), length 90: fe80::b62d:56ff:fe25:47a2 > ff02::1: ICMP6,"
    " multicast listener report v2, 1 record(s)"
)
RS_LINE = (
    "14:52:01.223001 b4:2d:56:25:47:a2 > 33:33:00:00:00:02, ethertype IPv6"
    " (0x86dd), length 86: fe80::b62d:56ff:fe25:47a2 > ff02::2: ICMP6,"
    " router solicitation"
)
DAD_LINE = (
    "14:52:01.410112 b4:2d:56:25:47:a2 > 33:33:ff:25:47:a2, ethertype IPv6"
    " (0x86dd), length 78: :: > ff02::1:ff25:47a2: ICMP6, neighbor"
    " solicitation, who has fe80::b62d:56ff:fe25:47a2, length 24"
)
ARP_LEAK = (
    "14:53:00.000001 00:11:22:33:44:55 > ff:ff:ff:ff:ff:ff, ARP, length 42:"
    " Request who-has 192.168.13.1 tell 192.168.13.77, length 28"
)
DHCP_LINE = (
    "14:53:02.515001 aa:bb:cc:dd:ee:01 > ff:ff:ff:ff:ff:ff, ethertype IPv4"
    " (0x0800), length 305: 0.0.0.0.68 > 255.255.255.255.67: BOOTP/DHCP,"
    " Request from aa:bb:cc:dd:ee:01, length 271"
)
BEACON_LINE = (
    "14:54:00.000001 aa:bb:cc:dd:ee:ff > ff:ff:ff:ff:ff:ff, ethertype IPv4"
    " (0x0800), length 81: 10.0.0.5.4919 > 255.255.255.255.4919: UDP,"
    " length 39"
)


class TestParseLine:
    def test_tcpdump_noise_is_skipped(self):
        assert parse_line("tcpdump: listening on eth0, link-type EN10MB") is None
        assert parse_line("") is None

    def test_mld(self):
        o = parse_line(KERNEL_LINE)
        assert o is not None and o.kind == "mld"
        assert o.src_mac == "b4:2d:56:25:47:a2"

    def test_dad_ns_vs_generic_ns(self):
        assert parse_line(DAD_LINE).kind == "dad_ns"  # ff02::1-targeted

    def test_excluded_mac_is_ignored(self):
        assert parse_line(KERNEL_LINE, exclude_macs=("B4:2D:56:25:47:A2",)) is None

    def test_beacon_port_match(self):
        assert parse_line(BEACON_LINE).kind == "udp_beacon"
        assert parse_line(BEACON_LINE, beacon_ports=(9999,)).kind == "other"


class TestVerdicts:
    def test_kernel_up_points_at_v6door(self):
        v = classify([KERNEL_LINE, RS_LINE, DAD_LINE])
        assert v.kernel_up
        assert set(v.kernel_evidence) == {"mld", "rs", "dad_ns"}
        assert v.next_action == "v6door"
        assert "conwrt v6door --mac b4:2d:56:25:47:a2" in v.next_action_reason

    def test_arp_leak_names_the_static_ip(self):
        v = classify([ARP_LEAK])
        assert not v.kernel_up
        assert v.next_action == "alias-probe"
        assert "192.168.13.77" in v.arp_leak_candidates[0]
        assert "192.168.13.77/24" in v.next_action_reason

    def test_kernel_up_outranks_arp_leak(self):
        # ladder order: v6 door is cheaper than v4 archaeology
        v = classify([ARP_LEAK, KERNEL_LINE])
        assert v.next_action == "v6door"

    def test_dhcp_client_verdict(self):
        v = classify([DHCP_LINE])
        assert v.dhcp_client and v.next_action == "dhcp-adopt"
        assert "ONE DHCP authority" in v.next_action_reason

    def test_vendor_beacon_verdict(self):
        v = classify([BEACON_LINE])
        assert 4919 in v.vendor_fallback_ports
        assert v.next_action == "vendor-fallback"
        assert "detection.vendor_subnets" in v.next_action_reason

    def test_silence_goes_phy_first(self):
        v = classify([])
        assert v.next_action == "no-frames"
        assert "carrier" in v.next_action_reason

    def test_frames_without_signature_capture_longer(self):
        v = classify(["14:00:00.000001 01:80:c2:00:00:00 > 01:80:c2:00:00:00, STP, length 60"])
        assert v.frames == 1 and v.next_action == "capture-longer"

    def test_json_roundtrip(self):
        v = classify([KERNEL_LINE])
        d = json.loads(v.to_json())
        assert d["kernel_up"] is True and d["next_action"] == "v6door"


class TestModelHints:
    def test_ap3915i_detection_block_present_and_evidence_only(self):
        repo = Path(__file__).resolve().parents[1]
        m = json.loads((repo / "models" / "extreme-networks-ws-ap3915i.json").read_text())
        d = m.get("detection", {})
        assert d.get("vendor_subnets") == ["192.168.1.0/24"]
        # no fabricated telemetry: watts/beacon_ports stay absent until measured
        assert "watts" not in d and "beacon_ports" not in d
