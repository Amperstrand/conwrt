"""Offline checks for bench_scout — parsers and gating only; no SSH."""

from __future__ import annotations

import pytest

import bench_scout as bs


def test_port_of_vlan_maps_bench_pattern() -> None:
    assert bs.port_of_vlan(1007) == "lan7"
    assert bs.port_of_vlan(1002) == "lan2"
    with pytest.raises(bs.ScoutError):
        bs.port_of_vlan(24)  # outside the 100N bench pattern
    with pytest.raises(bs.ScoutError):
        bs.port_of_vlan(10700)


def test_parse_carrier_detects_no_link() -> None:
    assert not bs.parse_carrier(
        "9: lan7@eth0: <NO-CARRIER,BROADCAST,MULTICAST,UP> "
        "mtu 1500 qdisc noqueue master switch state LOWERLAYERDOWN")
    assert bs.parse_carrier(
        "7: lan6@eth0: <BROADCAST,MULTICAST,UP> mtu 1500 "
        "qdisc noqueue master switch state UP")


def test_parse_dhcp_events_keeps_the_interesting_lines() -> None:
    lines = [
        "Sep 23 20:54:38 dnsmasq[8352]: started, version 2.93 DNS disabled",
        "Sep 23 20:55:01 dnsmasq-dhcp[8352]: DHCPDISCOVER(eth1) 28:xx:xx:xx:xx:xx",
        "Sep 23 20:55:01 dnsmasq-dhcp[8352]: DHCPACK(eth1) 192.168.107.50 28:xx:xx:xx:xx:xx gs108",
        "Sep 23 20:55:02 dnsmasq-dhcp[8352]: not old news",
    ]
    events = bs.parse_dhcp_events(lines)
    assert len(events) == 2
    assert "DHCPDISCOVER" in events[0] and "DHCPACK" in events[1]


def test_parse_leases_dnsmasq_format() -> None:
    raw = ("1761234567 28:9c:e2:11:22:33 192.168.107.50 GS108P 01:28:9c:e2:11:22:33\n"
           "\n"
           "garbage line without fields\n")
    leases = bs.parse_leases(raw)
    assert leases == [bs.Lease(mac="28:9c:e2:11:22:33", ip="192.168.107.50",
                                hostname="GS108P")]


def test_extract_title_handles_case_and_whitespace() -> None:
    assert bs.extract_title("<html><HEAD><TITLE>\n  NETGEAR Switch  </TiTle></head>") \
        == "NETGEAR Switch"
    assert bs.extract_title("<html>no title here</html>") == ""


def test_arm_script_uses_flock_and_scopes_to_one_svi() -> None:
    script = bs.arm_script(1007)
    assert "flock /tmp/amperstrand-bench" in script
    assert "--interface=switch.1007" in script
    assert "--bind-dynamic" in script and "--port=0" in script
    assert "192.168.107.50,192.168.107.60" in script
    # must NOT be a committed-config change
    assert "uci" not in script and "commit" not in script


def test_no_committed_coordinates() -> None:
    source = open(bs.__file__).read()
    assert "192.168.13." not in source and "20408" not in source
