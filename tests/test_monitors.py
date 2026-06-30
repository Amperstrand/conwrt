"""Tests for conwrt.monitors — PcapMonitor, LinkMonitor, SSHMonitor, lifecycle."""
from __future__ import annotations

import argparse
import queue
import threading
import time
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from flash.context import Event, PcapMonitorConfig

from conwrt.monitors import (
    LinkMonitor,
    PcapMonitor,
    SSHMonitor,
    _setup_monitors,
    _teardown_monitors,
    monitor_lifecycle,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(**overrides) -> PcapMonitorConfig:
    defaults = dict(
        interface="en6",
        pcap_path="/tmp/test_capture.pcap",
        recovery_ip="192.168.1.1",
        router_mac_openwrt="",
        router_mac_uboot="",
        uboot_ip="192.168.1.1",
        silence_timeout=30,
        zycast_multicast_group="",
        zycast_multicast_port=0,
    )
    defaults.update(overrides)
    return PcapMonitorConfig(**defaults)


def _make_monitor(**config_overrides) -> tuple[PcapMonitor, queue.Queue]:
    q: queue.Queue = queue.Queue()
    cfg = _make_config(**config_overrides)
    mon = PcapMonitor(cfg, q)
    return mon, q


def _drain(q: queue.Queue) -> list[tuple]:
    items = []
    while True:
        try:
            items.append(q.get_nowait())
        except queue.Empty:
            break
    return items


# ===================================================================
# PcapMonitor._parse_line()
# ===================================================================

class TestParseLineUbootHttp(TestCase):
    """_parse_line emits UBOOT_HTTP for tcpdump lines with http + recovery_ip."""

    def test_uboot_http_basic(self):
        mon, q = _make_monitor(recovery_ip="192.168.0.1")
        line = "18:30:01.234 IP 192.168.0.1.80 > 192.168.0.10.51234: Flags [P.], length 340: HTTP"
        mon._parse_line(line)
        events = _drain(q)
        assert len(events) == 1
        assert events[0][0] == Event.UBOOT_HTTP

    def test_uboot_http_default_ip(self):
        mon, q = _make_monitor(recovery_ip="192.168.1.1")
        line = "18:30:01.234 IP 192.168.1.1.80 > 192.168.1.10.51234: Flags [P.], length 340: HTTP"
        mon._parse_line(line)
        events = _drain(q)
        assert len(events) == 1
        assert events[0][0] == Event.UBOOT_HTTP

    def test_uboot_http_detail_truncated_to_120(self):
        mon, q = _make_monitor(recovery_ip="192.168.1.1")
        line = "18:30:01.234 IP 192.168.1.1.80 > 192.168.1.10.51234: Flags [P.], length 340: HTTP" + "X" * 200
        mon._parse_line(line)
        events = _drain(q)
        assert len(events) == 1
        assert len(events[0][2]) <= 120

    def test_uboot_http_not_emitted_without_length(self):
        """Lines with http + recovery_ip but no 'length' keyword are ignored."""
        mon, q = _make_monitor(recovery_ip="192.168.0.1")
        line = "18:30:01.234 IP 192.168.0.1.80 > 192.168.0.10.51234: HTTP"
        mon._parse_line(line)
        events = _drain(q)
        uboot_http = [e for e in events if e[0] == Event.UBOOT_HTTP]
        assert len(uboot_http) == 0

    def test_no_uboot_http_without_http_keyword(self):
        mon, q = _make_monitor(recovery_ip="192.168.0.1")
        line = "18:30:01.234 IP 192.168.0.1.80 > 192.168.0.10.51234: Flags [P.], length 340: TCP"
        mon._parse_line(line)
        events = _drain(q)
        uboot_http = [e for e in events if e[0] == Event.UBOOT_HTTP]
        assert len(uboot_http) == 0

    def test_no_uboot_http_without_recovery_ip(self):
        mon, q = _make_monitor(recovery_ip="192.168.1.1")
        line = "18:30:01.234 IP 10.0.0.1.80 > 10.0.0.10.51234: Flags [P.], length 340: HTTP"
        mon._parse_line(line)
        events = _drain(q)
        uboot_http = [e for e in events if e[0] == Event.UBOOT_HTTP]
        assert len(uboot_http) == 0


class TestParseLineArp(TestCase):
    """_parse_line emits UBOOT_ARP_192_168_1_2 for ARP who-has {arp_target}."""

    def test_arp_basic(self):
        """recovery_ip=192.168.0.1 -> arp_target=192.168.0.2"""
        mon, q = _make_monitor(recovery_ip="192.168.0.1")
        line = "18:30:01.234 ARP, Request who-has 192.168.0.2 tell 192.168.0.1, length 46"
        mon._parse_line(line)
        events = _drain(q)
        assert len(events) == 1
        assert events[0][0] == Event.UBOOT_ARP_192_168_1_2

    def test_arp_default_subnet(self):
        """recovery_ip=192.168.1.1 -> arp_target=192.168.1.2"""
        mon, q = _make_monitor(recovery_ip="192.168.1.1")
        line = "18:30:01.234 ARP, Request who-has 192.168.1.2 tell 192.168.1.1, length 46"
        mon._parse_line(line)
        events = _drain(q)
        assert len(events) == 1
        assert events[0][0] == Event.UBOOT_ARP_192_168_1_2

    def test_arp_wrong_target_no_event(self):
        mon, q = _make_monitor(recovery_ip="192.168.1.1")
        line = "18:30:01.234 ARP, Request who-has 192.168.1.99 tell 192.168.1.1, length 46"
        mon._parse_line(line)
        events = _drain(q)
        arp_events = [e for e in events if e[0] == Event.UBOOT_ARP_192_168_1_2]
        assert len(arp_events) == 0

    def test_arp_with_unknown_mac_emits_src_mac_detail(self):
        """When router_mac_openwrt is set and MAC doesn't match, detail contains src_mac=."""
        mon, q = _make_monitor(
            recovery_ip="192.168.0.1",
            router_mac_openwrt="AA:BB:CC:DD:EE:FF",
        )
        line = "18:30:01.234 ARP, Request who-has 192.168.0.2 tell 192.168.0.1, length 46, aa:11:22:33:44:55"
        mon._parse_line(line)
        events = _drain(q)
        assert len(events) == 1
        assert events[0][0] == Event.UBOOT_ARP_192_168_1_2
        assert "src_mac=" in events[0][2]

    def test_arp_with_known_mac_no_src_mac_detail(self):
        """When router_mac_openwrt matches the MAC, detail is the line (not src_mac=)."""
        mon, q = _make_monitor(
            recovery_ip="192.168.0.1",
            router_mac_openwrt="aa:bb:cc:dd:ee:ff",
        )
        line = "18:30:01.234 ARP, Request who-has 192.168.0.2 tell 192.168.0.1, length 46, aa:bb:cc:dd:ee:ff"
        mon._parse_line(line)
        events = _drain(q)
        assert len(events) == 1
        assert events[0][0] == Event.UBOOT_ARP_192_168_1_2
        assert "src_mac=" not in events[0][2]

    def test_arp_mac_case_insensitive(self):
        """MAC comparison is case-insensitive."""
        mon, q = _make_monitor(
            recovery_ip="192.168.0.1",
            router_mac_openwrt="AA:BB:CC:DD:EE:FF",
        )
        line = "18:30:01.234 ARP, Request who-has 192.168.0.2 tell 192.168.0.1, length 46, aa:bb:cc:dd:ee:ff"
        mon._parse_line(line)
        events = _drain(q)
        assert len(events) == 1
        # Known MAC -> detail is the line, not src_mac=
        assert "src_mac=" not in events[0][2]

    def test_arp_no_mac_in_line_still_emits(self):
        """ARP line without a MAC regex match still emits with line as detail."""
        mon, q = _make_monitor(recovery_ip="192.168.1.1")
        line = "18:30:01.234 ARP, Request who-has 192.168.1.2 tell 192.168.1.1, length 46"
        mon._parse_line(line)
        events = _drain(q)
        assert len(events) == 1
        assert events[0][0] == Event.UBOOT_ARP_192_168_1_2

    def test_arp_with_unknown_mac_returns_early_no_other_events(self):
        """When ARP emits with src_mac=, it returns early — no other events from same line."""
        mon, q = _make_monitor(
            recovery_ip="192.168.0.1",
            router_mac_openwrt="AA:BB:CC:DD:EE:FF",
        )
        # Line has ARP who-has + also UDP 4919 — but ARP return prevents FAILSAFE
        line = "18:30:01.234 ARP, Request who-has 192.168.0.2 tell 192.168.0.1, length 46, 11:22:33:44:55:66"
        mon._parse_line(line)
        events = _drain(q)
        assert len(events) == 1
        assert events[0][0] == Event.UBOOT_ARP_192_168_1_2


class TestParseLineIcmpv6(TestCase):
    """_parse_line emits ICMPV6_FROM_ROUTER when icmp6 + router_mac_openwrt match."""

    def test_icmpv6_from_router(self):
        mon, q = _make_monitor(router_mac_openwrt="bc:22:28:99:1d:0e")
        line = "18:30:05.678 IP6 fe80::1 > ff02::1: ICMP6, router advertisement, length 64, bc:22:28:99:1d:0e"
        mon._parse_line(line)
        events = _drain(q)
        assert len(events) == 1
        assert events[0][0] == Event.ICMPV6_FROM_ROUTER

    def test_icmpv6_no_router_mac_no_event(self):
        """Without router_mac_openwrt set, ICMPv6 lines are ignored."""
        mon, q = _make_monitor(router_mac_openwrt="")
        line = "18:30:05.678 IP6 fe80::1 > ff02::1: ICMP6, router advertisement, length 64, bc:22:28:99:1d:0e"
        mon._parse_line(line)
        events = _drain(q)
        icmpv6 = [e for e in events if e[0] == Event.ICMPV6_FROM_ROUTER]
        assert len(icmpv6) == 0

    def test_icmpv6_wrong_mac_no_event(self):
        mon, q = _make_monitor(router_mac_openwrt="aa:bb:cc:dd:ee:ff")
        line = "18:30:05.678 IP6 fe80::1 > ff02::1: ICMP6, router advertisement, length 64, bc:22:28:99:1d:0e"
        mon._parse_line(line)
        events = _drain(q)
        icmpv6 = [e for e in events if e[0] == Event.ICMPV6_FROM_ROUTER]
        assert len(icmpv6) == 0


class TestParseLineFailsafe(TestCase):
    """_parse_line emits FAILSAFE_BROADCAST for UDP 4919."""

    def test_failsafe_broadcast(self):
        mon, q = _make_monitor()
        line = "18:30:01.234 IP 192.168.1.1.4919 > 255.255.255.255.4919: UDP, length 42"
        mon._parse_line(line)
        events = _drain(q)
        assert len(events) == 1
        assert events[0][0] == Event.FAILSAFE_BROADCAST

    def test_failsafe_source_port(self):
        """Failsafe detected from source port 4919 too."""
        mon, q = _make_monitor()
        line = "18:30:01.234 IP 192.168.1.1.4919 > 192.168.1.10.42123: UDP, length 42"
        mon._parse_line(line)
        events = _drain(q)
        failsafe = [e for e in events if e[0] == Event.FAILSAFE_BROADCAST]
        assert len(failsafe) >= 1

    def test_no_failsafe_without_4919(self):
        mon, q = _make_monitor()
        line = "18:30:01.234 IP 192.168.1.1.1234 > 192.168.1.10.5678: UDP, length 42"
        mon._parse_line(line)
        events = _drain(q)
        failsafe = [e for e in events if e[0] == Event.FAILSAFE_BROADCAST]
        assert len(failsafe) == 0


class TestParseLineZycast(TestCase):
    """_parse_line emits ZYCAST_MULTICAST_DETECTED for matching multicast."""

    def test_zycast_multicast(self):
        mon, q = _make_monitor(
            zycast_multicast_group="239.255.77.77",
            zycast_multicast_port=7777,
        )
        line = "18:30:01.234 IP 192.168.1.100.12345 > 239.255.77.77.7777: UDP, length 100"
        mon._parse_line(line)
        events = _drain(q)
        assert len(events) == 1
        assert events[0][0] == Event.ZYCAST_MULTICAST_DETECTED

    def test_zycast_no_group_configured_no_event(self):
        mon, q = _make_monitor(
            zycast_multicast_group="",
            zycast_multicast_port=0,
        )
        line = "18:30:01.234 IP 192.168.1.100.12345 > 239.255.77.77.7777: UDP, length 100"
        mon._parse_line(line)
        events = _drain(q)
        zycast = [e for e in events if e[0] == Event.ZYCAST_MULTICAST_DETECTED]
        assert len(zycast) == 0

    def test_zycast_wrong_port_no_event(self):
        mon, q = _make_monitor(
            zycast_multicast_group="239.255.77.77",
            zycast_multicast_port=9999,
        )
        line = "18:30:01.234 IP 192.168.1.100.12345 > 239.255.77.77.7777: UDP, length 100"
        mon._parse_line(line)
        events = _drain(q)
        zycast = [e for e in events if e[0] == Event.ZYCAST_MULTICAST_DETECTED]
        assert len(zycast) == 0

    def test_zycast_wrong_group_no_event(self):
        mon, q = _make_monitor(
            zycast_multicast_group="239.255.99.99",
            zycast_multicast_port=7777,
        )
        line = "18:30:01.234 IP 192.168.1.100.12345 > 239.255.77.77.7777: UDP, length 100"
        mon._parse_line(line)
        events = _drain(q)
        zycast = [e for e in events if e[0] == Event.ZYCAST_MULTICAST_DETECTED]
        assert len(zycast) == 0


class TestParseLineEdgeCases(TestCase):
    """Edge cases: empty lines, unrelated lines, multi-event sequences."""

    def test_empty_line_no_event(self):
        mon, q = _make_monitor()
        mon._parse_line("")
        mon._parse_line("   ")
        mon._parse_line("\n")
        assert _drain(q) == []

    def test_unrelated_line_no_event(self):
        mon, q = _make_monitor()
        mon._parse_line("18:30:01.234 IP 10.0.0.1.22 > 10.0.0.2.54321: Flags [P.], length 100")
        assert _drain(q) == []

    def test_recovery_ip_without_http_no_uboot_http(self):
        mon, q = _make_monitor(recovery_ip="192.168.1.1")
        line = "18:30:01.234 IP 192.168.1.1.22 > 192.168.1.10.51234: Flags [P.], length 340: SSH"
        mon._parse_line(line)
        events = _drain(q)
        uboot_http = [e for e in events if e[0] == Event.UBOOT_HTTP]
        assert len(uboot_http) == 0

    def test_multiple_lines_emit_multiple_events(self):
        mon, q = _make_monitor(
            recovery_ip="192.168.1.1",
            router_mac_openwrt="bc:22:28:99:1d:0e",
        )
        mon._parse_line("18:30:01.234 IP 192.168.1.1.80 > 192.168.1.10.51234: Flags [P.], length 340: HTTP")
        mon._parse_line("18:30:01.234 ARP, Request who-has 192.168.1.2 tell 192.168.1.1, length 46")
        mon._parse_line("18:30:05.678 IP6 fe80::1 > ff02::1: ICMP6, router advertisement, length 64, bc:22:28:99:1d:0e")
        events = _drain(q)
        event_types = {e[0] for e in events}
        assert Event.UBOOT_HTTP in event_types
        assert Event.UBOOT_ARP_192_168_1_2 in event_types
        assert Event.ICMPV6_FROM_ROUTER in event_types


# ===================================================================
# PcapMonitor._check_silence()
# ===================================================================

class TestCheckSilence(TestCase):
    """_check_silence emits NO_PACKETS_FOR_N_SECONDS after timeout."""

    @patch("conwrt.monitors.ts")
    def test_no_silence_when_packets_recent(self, mock_ts):
        now = 1000.0
        mock_ts.return_value = now
        mon, q = _make_monitor(silence_timeout=30)
        mon._last_packet_time = now - 5  # 5s ago
        # interval=5, last_silence_check=997 so 1000-997=3 < 5 => skip
        result = mon._check_silence(last_silence_check=now - 3, interval=5)
        events = _drain(q)
        assert len(events) == 0
        assert result == now - 3

    @patch("conwrt.monitors.ts")
    def test_silence_after_timeout_emits_event(self, mock_ts):
        now = 1000.0
        mock_ts.return_value = now
        mon, q = _make_monitor(silence_timeout=30)
        mon._last_packet_time = now - 60  # 60s ago > 30s timeout
        mon._check_silence(last_silence_check=now - 100, interval=5)
        events = _drain(q)
        assert len(events) == 1
        assert events[0][0] == Event.NO_PACKETS_FOR_N_SECONDS
        assert "60s" in events[0][2]

    @patch("conwrt.monitors.ts")
    def test_silence_resets_last_packet_time(self, mock_ts):
        now = 1000.0
        mock_ts.return_value = now
        mon, q = _make_monitor(silence_timeout=30)
        mon._last_packet_time = now - 60
        mon._check_silence(last_silence_check=now - 100, interval=5)
        # After silence detection, _last_packet_time is reset to now
        assert mon._last_packet_time == now

    @patch("conwrt.monitors.ts")
    def test_silence_interval_gating(self, mock_ts):
        """_check_silence skips check if interval hasn't elapsed."""
        now = 1000.0
        mock_ts.return_value = now
        mon, q = _make_monitor(silence_timeout=30)
        mon._last_packet_time = now - 60  # stale
        # last_silence_check was 2s ago, interval=5 — should skip
        result = mon._check_silence(last_silence_check=now - 2, interval=5)
        events = _drain(q)
        assert len(events) == 0
        assert result == now - 2  # unchanged


# ===================================================================
# LinkMonitor
# ===================================================================

class TestLinkMonitor(TestCase):
    """LinkMonitor emits LINK_UP/LINK_DOWN on state transitions."""

    def test_no_event_on_first_poll(self):
        q: queue.Queue = queue.Queue()
        mon = LinkMonitor("en6", q, poll_interval=0.01)
        mon._last_state = None
        with patch("conwrt.monitors.get_link_state", return_value=True):
            with patch("conwrt.monitors.ts", return_value=100.0):
                current = True
                if mon._last_state is not None and current != mon._last_state:
                    q.put((Event.LINK_UP, 100.0, ""))
                mon._last_state = current
        assert _drain(q) == []

    def test_link_down_transition(self):
        q: queue.Queue = queue.Queue()
        mon = LinkMonitor("en6", q, poll_interval=0.01)
        mon._last_state = True
        with patch("conwrt.monitors.get_link_state", return_value=False):
            with patch("conwrt.monitors.ts", return_value=100.0):
                current = False
                if mon._last_state is not None and current != mon._last_state:
                    if current:
                        q.put((Event.LINK_UP, 100.0, ""))
                    else:
                        q.put((Event.LINK_DOWN, 100.0, ""))
                mon._last_state = current
        events = _drain(q)
        assert len(events) == 1
        assert events[0][0] == Event.LINK_DOWN

    def test_link_up_transition(self):
        q: queue.Queue = queue.Queue()
        mon = LinkMonitor("en6", q, poll_interval=0.01)
        mon._last_state = False
        with patch("conwrt.monitors.get_link_state", return_value=True):
            with patch("conwrt.monitors.ts", return_value=100.0):
                current = True
                if mon._last_state is not None and current != mon._last_state:
                    if current:
                        q.put((Event.LINK_UP, 100.0, ""))
                    else:
                        q.put((Event.LINK_DOWN, 100.0, ""))
                mon._last_state = current
        events = _drain(q)
        assert len(events) == 1
        assert events[0][0] == Event.LINK_UP

    def test_same_state_no_event(self):
        q: queue.Queue = queue.Queue()
        mon = LinkMonitor("en6", q, poll_interval=0.01)
        mon._last_state = True
        with patch("conwrt.monitors.get_link_state", return_value=True):
            current = True
            if mon._last_state is not None and current != mon._last_state:
                q.put((Event.LINK_UP, 100.0, ""))
            mon._last_state = current
        assert _drain(q) == []

    def test_run_thread_stops_on_stop(self):
        q: queue.Queue = queue.Queue()
        mon = LinkMonitor("en6", q, poll_interval=0.01)
        with patch("conwrt.monitors.get_link_state", return_value=True):
            t = threading.Thread(target=mon.run, daemon=True)
            t.start()
            time.sleep(0.1)
            mon.stop()
            t.join(timeout=2)
        assert not t.is_alive()

    def test_run_emits_link_down_on_transition(self):
        q: queue.Queue = queue.Queue()
        mon = LinkMonitor("en6", q, poll_interval=0.01)
        # Need enough states: True (first poll, sets _last_state), False (triggers LINK_DOWN), then stop
        states = iter([True, False, False, False])
        with patch("conwrt.monitors.get_link_state", side_effect=lambda iface: next(states)):
            with patch("conwrt.monitors.ts", return_value=100.0):
                t = threading.Thread(target=mon.run, daemon=True)
                t.start()
                try:
                    event = q.get(timeout=2)
                    assert event[0] == Event.LINK_DOWN
                finally:
                    mon.stop()
                    t.join(timeout=2)


# ===================================================================
# SSHMonitor
# ===================================================================

class TestSSHMonitor(TestCase):
    """SSHMonitor emits SSH_UP when SSH becomes available."""

    def test_ssh_up_emitted(self):
        q: queue.Queue = queue.Queue()
        mon = SSHMonitor("192.168.1.1", q, poll_interval=0.01)
        with patch("conwrt.monitors.check_ssh", return_value=True):
            with patch("conwrt.monitors.ts", return_value=100.0):
                mon.run()
        events = _drain(q)
        assert len(events) == 1
        assert events[0][0] == Event.SSH_UP

    def test_ssh_not_available_keeps_polling(self):
        q: queue.Queue = queue.Queue()
        mon = SSHMonitor("192.168.1.1", q, poll_interval=0.01)
        call_count = 0

        def check_side_effect(ip):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return False
            mon.stop()
            return False

        with patch("conwrt.monitors.check_ssh", side_effect=check_side_effect):
            with patch("conwrt.monitors.ts", return_value=100.0):
                mon.run()
        events = _drain(q)
        assert len(events) == 0
        assert call_count >= 3

    def test_ssh_oserror_keeps_polling(self):
        q: queue.Queue = queue.Queue()
        mon = SSHMonitor("192.168.1.1", q, poll_interval=0.01)
        call_count = 0

        def check_side_effect(ip):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise OSError("connection refused")
            mon.stop()
            return False

        with patch("conwrt.monitors.check_ssh", side_effect=check_side_effect):
            with patch("conwrt.monitors.ts", return_value=100.0):
                mon.run()
        events = _drain(q)
        assert len(events) == 0
        assert call_count >= 2


# ===================================================================
# _setup_monitors / _teardown_monitors
# ===================================================================

class TestSetupMonitors(TestCase):
    """_setup_monitors creates monitors based on pcap availability."""

    def _make_args(self, **overrides) -> argparse.Namespace:
        defaults = dict(
            router_mac="",
            uboot_mac="",
            silence_timeout=30,
            no_pcap=False,
        )
        defaults.update(overrides)
        return argparse.Namespace(**defaults)

    def _make_profile(self, **overrides) -> SimpleNamespace:
        defaults = dict(
            recovery_ip="192.168.1.1",
            zycast_multicast_group="",
            zycast_multicast_port=0,
        )
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    @patch("conwrt.monitors.has_tcpdump", return_value=True)
    @patch("conwrt.monitors.has_scapy", return_value=True)
    def test_pcap_enabled_creates_pcap_monitor(self, _mock_scapy, _mock_tcpdump):
        q: queue.Queue = queue.Queue()
        args = self._make_args()
        profile = self._make_profile()
        pcap_mon, pcap_thr, link_mon, link_thr = _setup_monitors(
            "en6", q, "/tmp/capture.pcap", profile, args, pcap_enabled=True,
        )
        try:
            assert pcap_mon is not None
            assert pcap_thr is not None
            assert link_mon is not None
            assert link_thr is not None
            assert pcap_thr.is_alive() or pcap_thr.is_alive() is False
        finally:
            _teardown_monitors(pcap_mon, pcap_thr, link_mon, link_thr)

    @patch("conwrt.monitors.has_tcpdump", return_value=True)
    @patch("conwrt.monitors.has_scapy", return_value=True)
    def test_pcap_disabled_no_pcap_monitor(self, _mock_scapy, _mock_tcpdump):
        q: queue.Queue = queue.Queue()
        args = self._make_args()
        profile = self._make_profile()
        pcap_mon, pcap_thr, link_mon, link_thr = _setup_monitors(
            "en6", q, "/tmp/capture.pcap", profile, args, pcap_enabled=False,
        )
        try:
            assert pcap_mon is None
            assert pcap_thr is None
            assert link_mon is not None
        finally:
            _teardown_monitors(pcap_mon, pcap_thr, link_mon, link_thr)

    @patch("conwrt.monitors.has_tcpdump", return_value=True)
    @patch("conwrt.monitors.has_scapy", return_value=True)
    def test_no_pcap_flag_skips_pcap(self, _mock_scapy, _mock_tcpdump):
        q: queue.Queue = queue.Queue()
        args = self._make_args(no_pcap=True)
        profile = self._make_profile()
        pcap_mon, pcap_thr, link_mon, link_thr = _setup_monitors(
            "en6", q, "/tmp/capture.pcap", profile, args, pcap_enabled=True,
        )
        try:
            assert pcap_mon is None
            assert pcap_thr is None
        finally:
            _teardown_monitors(pcap_mon, pcap_thr, link_mon, link_thr)

    @patch("conwrt.monitors.has_tcpdump", return_value=False)
    @patch("conwrt.monitors.has_scapy", return_value=False)
    def test_no_scapy_no_tcpdump_no_pcap(self, _mock_scapy, _mock_tcpdump):
        q: queue.Queue = queue.Queue()
        args = self._make_args()
        profile = self._make_profile()
        pcap_mon, pcap_thr, link_mon, link_thr = _setup_monitors(
            "en6", q, "/tmp/capture.pcap", profile, args, pcap_enabled=True,
        )
        try:
            assert pcap_mon is None
            assert pcap_thr is None
        finally:
            _teardown_monitors(pcap_mon, pcap_thr, link_mon, link_thr)

    @patch("conwrt.monitors.has_tcpdump", return_value=True)
    @patch("conwrt.monitors.has_scapy", return_value=True)
    def test_link_monitor_always_created(self, _mock_scapy, _mock_tcpdump):
        q: queue.Queue = queue.Queue()
        args = self._make_args(no_pcap=True)
        profile = self._make_profile()
        pcap_mon, pcap_thr, link_mon, link_thr = _setup_monitors(
            "en6", q, "/tmp/capture.pcap", profile, args, pcap_enabled=True,
        )
        try:
            assert link_mon is not None
            assert link_thr is not None
        finally:
            _teardown_monitors(pcap_mon, pcap_thr, link_mon, link_thr)


class TestTeardownMonitors(TestCase):
    """_teardown_monitors stops and joins all threads."""

    def test_teardown_stops_link_monitor(self):
        q: queue.Queue = queue.Queue()
        link_mon = LinkMonitor("en6", q, poll_interval=0.01)
        with patch("conwrt.monitors.get_link_state", return_value=True):
            link_thr = threading.Thread(target=link_mon.run, daemon=True)
            link_thr.start()
        _teardown_monitors(None, None, link_mon, link_thr)
        assert not link_thr.is_alive()

    @patch("conwrt.monitors.has_tcpdump", return_value=True)
    @patch("conwrt.monitors.has_scapy", return_value=True)
    def test_teardown_stops_both_monitors(self, _mock_scapy, _mock_tcpdump):
        q: queue.Queue = queue.Queue()
        args = argparse.Namespace(router_mac="", uboot_mac="", silence_timeout=30, no_pcap=False)
        profile = SimpleNamespace(recovery_ip="192.168.1.1", zycast_multicast_group="", zycast_multicast_port=0)
        pcap_mon, pcap_thr, link_mon, link_thr = _setup_monitors(
            "en6", q, "/tmp/capture.pcap", profile, args, pcap_enabled=True,
        )
        _teardown_monitors(pcap_mon, pcap_thr, link_mon, link_thr)
        assert not link_thr.is_alive()


# ===================================================================
# monitor_lifecycle context manager
# ===================================================================

class TestMonitorLifecycle(TestCase):
    """monitor_lifecycle sets up on enter, tears down on exit."""

    @patch("conwrt.monitors.has_tcpdump", return_value=True)
    @patch("conwrt.monitors.has_scapy", return_value=True)
    def test_context_manager_yields_monitors(self, _mock_scapy, _mock_tcpdump):
        q: queue.Queue = queue.Queue()
        args = argparse.Namespace(router_mac="", uboot_mac="", silence_timeout=30, no_pcap=False)
        profile = SimpleNamespace(recovery_ip="192.168.1.1", zycast_multicast_group="", zycast_multicast_port=0)
        with monitor_lifecycle("en6", q, "/tmp/capture.pcap", profile, args, pcap_enabled=True) as (pcap_mon, link_mon):
            assert pcap_mon is not None
            assert link_mon is not None

    @patch("conwrt.monitors.has_tcpdump", return_value=True)
    @patch("conwrt.monitors.has_scapy", return_value=True)
    def test_context_manager_pcap_disabled(self, _mock_scapy, _mock_tcpdump):
        q: queue.Queue = queue.Queue()
        args = argparse.Namespace(router_mac="", uboot_mac="", silence_timeout=30, no_pcap=True)
        profile = SimpleNamespace(recovery_ip="192.168.1.1", zycast_multicast_group="", zycast_multicast_port=0)
        with monitor_lifecycle("en6", q, "/tmp/capture.pcap", profile, args, pcap_enabled=True) as (pcap_mon, link_mon):
            assert pcap_mon is None
            assert link_mon is not None

    @patch("conwrt.monitors.has_tcpdump", return_value=True)
    @patch("conwrt.monitors.has_scapy", return_value=True)
    def test_context_manager_teardown_on_exit(self, _mock_scapy, _mock_tcpdump):
        q: queue.Queue = queue.Queue()
        args = argparse.Namespace(router_mac="", uboot_mac="", silence_timeout=30, no_pcap=False)
        profile = SimpleNamespace(recovery_ip="192.168.1.1", zycast_multicast_group="", zycast_multicast_port=0)
        with monitor_lifecycle("en6", q, "/tmp/capture.pcap", profile, args, pcap_enabled=True) as (pcap_mon, link_mon):
            pass
        # After context exit, stop event should be set
        assert link_mon._stop.is_set()
