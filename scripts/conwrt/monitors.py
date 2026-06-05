import argparse
import os
import queue
import re
import subprocess
import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Optional

from flash.context import DEFAULT_IP, Event, PcapMonitorConfig, get_link_state, log, ts
from platform_utils import is_root, has_scapy, has_tcpdump
from ssh_utils import check_ssh, ssh_cmd


class PcapMonitor:
    """Background thread that captures packets and emits events to a queue."""

    def __init__(self, config: PcapMonitorConfig, event_queue: queue.Queue):
        self.config = config
        self.event_queue = event_queue
        self._stop = threading.Event()
        self._last_packet_time: float = ts()
        self._silence_timeout = config.silence_timeout
        self._writer_proc: Optional[subprocess.Popen] = None
        self._reader_proc: Optional[subprocess.Popen] = None
        self._known_uboot_macs: set[str] = set()
        self._pcap_writer = None
        self._scapy = None

    def stop(self) -> None:
        self._stop.set()

    def _start_writer(self) -> Optional[subprocess.Popen]:
        try:
            tcpdump_cmd = ["tcpdump", "-i", self.config.interface,
                           "-w", self.config.pcap_path, "-n", "-U", "--immediate-mode",
                           "--buffer-size=16384"]
            if not is_root():
                tcpdump_cmd = ["sudo", "-n"] + tcpdump_cmd
            proc = subprocess.Popen(
                tcpdump_cmd,
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            time.sleep(0.5)
            if proc.poll() is not None:
                err = proc.stderr.read().decode(errors="replace")
                log(f"tcpdump writer failed: {err.strip()}")
                return None
            return proc
        except FileNotFoundError:
            log("tcpdump not found")
            return None

    def _start_reader(self) -> Optional[subprocess.Popen]:
        if not os.path.isfile(self.config.pcap_path):
            return None
        try:
            proc = subprocess.Popen(
                ["tcpdump", "-r", self.config.pcap_path, "-nn", "-l"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            return proc
        except FileNotFoundError:
            return None

    def _restart_writer(self) -> None:
        if self._writer_proc and self._writer_proc.poll() is None:
            self._writer_proc.terminate()
            try:
                self._writer_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._writer_proc.kill()
        time.sleep(2)
        new_proc = self._start_writer()
        if new_proc:
            self._writer_proc = new_proc
            log("tcpdump writer restarted")

    def _emit(self, event: Event, detail: str = "") -> None:
        self._last_packet_time = ts()
        self.event_queue.put((event, ts(), detail))

    def _open_pcap_writer(self, append: bool) -> None:
        if self._scapy is None:
            raise RuntimeError("scapy not initialized")
        pcap_dir = os.path.dirname(self.config.pcap_path)
        if pcap_dir:
            os.makedirs(pcap_dir, exist_ok=True)
        self._pcap_writer = self._scapy.PcapWriter(
            self.config.pcap_path,
            append=append,
            sync=True,
        )

    def _close_pcap_writer(self) -> None:
        if self._pcap_writer is None:
            return
        try:
            self._pcap_writer.close()
        except Exception:
            pass
        self._pcap_writer = None

    def _write_packet(self, packet: object) -> None:
        if self._pcap_writer is None:
            self._open_pcap_writer(append=os.path.exists(self.config.pcap_path))
        try:
            self._pcap_writer.write(packet)
        except Exception as e:
            log(f"pcap writer error, reopening append writer: {e}")
            self._close_pcap_writer()
            self._open_pcap_writer(append=os.path.exists(self.config.pcap_path))
            self._pcap_writer.write(packet)

    def _packet_detail(self, packet: object) -> str:
        try:
            return str(packet.summary())[:120]
        except Exception:
            return packet.__class__.__name__[:120]

    def _payload_looks_like_http(self, packet: object) -> bool:
        if self._scapy is None or not packet.haslayer(self._scapy.Raw):
            return False
        try:
            raw_layer = packet.getlayer(self._scapy.Raw)
            if raw_layer is None:
                return False
            payload = bytes(getattr(raw_layer, "load", b""))
        except Exception:
            return False
        return payload.startswith((
            b"GET ",
            b"POST ",
            b"HEAD ",
            b"PUT ",
            b"DELETE ",
            b"OPTIONS ",
            b"PATCH ",
            b"HTTP/1.",
        ))

    def _handle_packet(self, packet: object) -> None:
        if self._scapy is None:
            return

        self._last_packet_time = ts()
        self._write_packet(packet)

        arp_target = self.config.recovery_ip.rsplit(".", 1)[0] + ".2"
        detail = self._packet_detail(packet)

        if packet.haslayer(self._scapy.ARP):
            try:
                arp = packet.getlayer(self._scapy.ARP)
                if arp is None:
                    raise ValueError("missing ARP layer")
                src_mac = getattr(arp, "hwsrc", "").lower()
                if int(getattr(arp, "op", 0)) == 1 and getattr(arp, "pdst", "") == arp_target:
                    if self.config.router_mac_openwrt and src_mac != self.config.router_mac_openwrt.lower():
                        self._emit(Event.UBOOT_ARP_192_168_1_2, f"src_mac={src_mac}")
                        return
                    self._emit(Event.UBOOT_ARP_192_168_1_2, detail)
                    return
            except Exception:
                pass

        if packet.haslayer(self._scapy.IP):
            try:
                ip = packet.getlayer(self._scapy.IP)
                if ip is None:
                    raise ValueError("missing IP layer")
                if (
                    getattr(ip, "src", "") == self.config.recovery_ip
                    and packet.haslayer(self._scapy.TCP)
                    and self._payload_looks_like_http(packet)
                ):
                    self._emit(Event.UBOOT_HTTP, detail)
            except Exception:
                pass

        if self.config.router_mac_openwrt and packet.haslayer(self._scapy.IPv6):
            try:
                ether = packet.getlayer(self._scapy.Ether) if packet.haslayer(self._scapy.Ether) else None
                ipv6 = packet.getlayer(self._scapy.IPv6)
                if ipv6 is None:
                    raise ValueError("missing IPv6 layer")
                if (
                    ether is not None
                    and getattr(ether, "src", "").lower() == self.config.router_mac_openwrt.lower()
                    and int(getattr(ipv6, "nh", -1)) == 58
                ):
                    self._emit(Event.ICMPV6_FROM_ROUTER, detail)
            except Exception:
                pass

        if packet.haslayer(self._scapy.UDP):
            try:
                udp = packet.getlayer(self._scapy.UDP)
                if udp is None:
                    raise ValueError("missing UDP layer")
                if int(getattr(udp, "sport", 0)) == 4919 or int(getattr(udp, "dport", 0)) == 4919:
                    self._emit(Event.FAILSAFE_BROADCAST, detail)
                if (
                    self.config.zycast_multicast_group
                    and packet.haslayer(self._scapy.IP)
                ):
                    ip_layer = packet.getlayer(self._scapy.IP)
                    if ip_layer is not None:
                        dst_ip = getattr(ip_layer, "dst", "")
                        dst_port = int(getattr(udp, "dport", 0))
                        if (
                            dst_ip == self.config.zycast_multicast_group
                            and dst_port == self.config.zycast_multicast_port
                        ):
                            self._emit(Event.ZYCAST_MULTICAST_DETECTED, detail)
            except Exception:
                pass

    def _check_silence(self, last_silence_check: float, interval: int = 5) -> float:
        now = ts()
        if now - last_silence_check < interval:
            return last_silence_check
        if now - self._last_packet_time >= self._silence_timeout:
            self.event_queue.put((
                Event.NO_PACKETS_FOR_N_SECONDS, now,
                f"no packets for {int(now - self._last_packet_time)}s",
            ))
            self._last_packet_time = now
        return now

    def _parse_line(self, line: str) -> None:
        line = line.strip()
        if not line:
            return

        lower = line.lower()
        recovery_ip = self.config.recovery_ip
        arp_target = recovery_ip.rsplit(".", 1)[0] + ".2"

        if "http" in lower and recovery_ip in lower:
            if "length" in lower:
                self._emit(Event.UBOOT_HTTP, line[:120])

        if "arp" in lower and f"who-has {arp_target}" in lower:
            mac_match = re.search(
                r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:'
                r'[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', line,
            )
            if mac_match:
                src_mac = mac_match.group(1).lower()
                if self.config.router_mac_openwrt and src_mac != self.config.router_mac_openwrt.lower():
                    self._emit(Event.UBOOT_ARP_192_168_1_2, f"src_mac={src_mac}")
                    return
            self._emit(Event.UBOOT_ARP_192_168_1_2, line[:120])

        # ICMPv6 from router's real MAC (OpenWrt booting — uses different MAC than U-Boot)
        if "icmp6" in lower and self.config.router_mac_openwrt:
            router_mac = self.config.router_mac_openwrt.lower()
            if router_mac in lower:
                self._emit(Event.ICMPV6_FROM_ROUTER, line[:120])

        # Failsafe broadcast (UDP 4919)
        if "udp" in lower and "4919" in lower:
            self._emit(Event.FAILSAFE_BROADCAST, line[:120])

        if (
            self.config.zycast_multicast_group
            and "udp" in lower
            and self.config.zycast_multicast_group in line
            and str(self.config.zycast_multicast_port) in line
        ):
            self._emit(Event.ZYCAST_MULTICAST_DETECTED, line[:120])

    def _run_tcpdump_fallback(self) -> Optional[bool]:
        self._writer_proc = self._start_writer()

        if not self._writer_proc:
            return None

        # Wait for pcap file header to be written
        time.sleep(1)

        self._reader_proc = self._start_reader()

        last_silence_check = ts()

        while not self._stop.is_set():
            if self._writer_proc and self._writer_proc.poll() is not None:
                log("tcpdump writer died (interface gone?), will restart when link returns")
                time.sleep(3)
                if get_link_state(self.config.interface):
                    self._restart_writer()
                    if self._reader_proc and self._reader_proc.poll() is None:
                        self._reader_proc.terminate()
                        try:
                            self._reader_proc.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            self._reader_proc.kill()
                    time.sleep(1)
                    self._reader_proc = self._start_reader()

            if self._reader_proc and self._reader_proc.poll() is None:
                try:
                    import selectors
                    sel = selectors.DefaultSelector()
                    sel.register(self._reader_proc.stdout, selectors.EVENT_READ)
                    ready = sel.select(timeout=0.1)
                    sel.close()
                    if ready:
                        raw_line = self._reader_proc.stdout.readline()
                        if raw_line:
                            self._parse_line(raw_line.decode(errors="replace"))
                except Exception:
                    pass
            else:
                if self._reader_proc:
                    time.sleep(1)
                    self._reader_proc = self._start_reader()
                time.sleep(0.2)

            last_silence_check = self._check_silence(last_silence_check)

        if self._reader_proc and self._reader_proc.poll() is None:
            self._reader_proc.terminate()
            try:
                self._reader_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._reader_proc.kill()

        if self._writer_proc and self._writer_proc.poll() is None:
            self._writer_proc.terminate()
            try:
                self._writer_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._writer_proc.kill()

    def run(self) -> None:
        log(f"Pcap monitor starting: iface={self.config.interface} pcap={self.config.pcap_path}")

        try:
            from scapy.all import ARP, Ether, IP, IPv6, PcapWriter, Raw, TCP, UDP, sniff
            self._scapy = SimpleNamespace(
                ARP=ARP,
                Ether=Ether,
                IP=IP,
                IPv6=IPv6,
                PcapWriter=PcapWriter,
                Raw=Raw,
                TCP=TCP,
                UDP=UDP,
                sniff=sniff,
            )
            # Test if we can actually sniff (needs root for raw sockets)
            test_sock = None
            try:
                from scapy.all import L2socket
                test_sock = L2socket(iface=self.config.interface)
                test_sock.close()
            except Exception:
                raise PermissionError(
                    f"no permission to capture on {self.config.interface} "
                    f"(need root or CAP_NET_RAW)"
                ) from None
        except PermissionError:
            log(f"scapy: permission denied — trying sudo tcpdump fallback")
            self._run_tcpdump_fallback()
            log("Pcap monitor stopped")
            return
        except Exception as e:
            log(f"scapy unavailable, falling back to tcpdump capture: {e}")
            tcpdump_result = self._run_tcpdump_fallback()
            if tcpdump_result is None:
                log("WARNING: no packet capture available (no root). "
                    "State machine will rely on link monitoring and SSH polling only.")
                return
            log("Pcap monitor stopped")
            return

        try:
            if os.path.exists(self.config.pcap_path):
                os.remove(self.config.pcap_path)
            self._open_pcap_writer(append=False)

            last_silence_check = ts()
            last_link_state: Optional[bool] = None

            while not self._stop.is_set():
                link_up = get_link_state(self.config.interface)
                if link_up != last_link_state:
                    if link_up:
                        log(f"scapy capture active on {self.config.interface}")
                    else:
                        log(f"scapy capture paused, link down on {self.config.interface}")
                    last_link_state = link_up

                if not link_up:
                    time.sleep(0.5)
                    last_silence_check = self._check_silence(last_silence_check)
                    continue

                try:
                    self._scapy.sniff(
                        iface=self.config.interface,
                        store=False,
                        prn=self._handle_packet,
                        timeout=1,
                        stop_filter=lambda _pkt: self._stop.is_set(),
                    )
                except Exception as e:
                    if not self._stop.is_set():
                        log(f"scapy sniff error on {self.config.interface}: {e}")
                        time.sleep(1)

                last_silence_check = self._check_silence(last_silence_check)
        finally:
            self._close_pcap_writer()
            log("Pcap monitor stopped")


class LinkMonitor:
    """Polls link state in a background thread and emits LINK_UP/LINK_DOWN events."""

    def __init__(self, interface: str, event_queue: queue.Queue, poll_interval: float = 0.5):
        self.interface = interface
        self.event_queue = event_queue
        self._stop = threading.Event()
        self._poll_interval = poll_interval
        self._last_state: Optional[bool] = None

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                current = get_link_state(self.interface)
                if self._last_state is not None and current != self._last_state:
                    if current:
                        self.event_queue.put((Event.LINK_UP, ts(), ""))
                    else:
                        self.event_queue.put((Event.LINK_DOWN, ts(), ""))
                self._last_state = current
            except Exception:
                pass
            self._stop.wait(self._poll_interval)


class SSHMonitor:
    """Polls SSH availability in background and emits SSH_UP event."""

    def __init__(self, ip: str, event_queue: queue.Queue, poll_interval: float = 5.0):
        self.ip = ip
        self.event_queue = event_queue
        self._stop = threading.Event()
        self._poll_interval = poll_interval

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                if check_ssh(self.ip):
                    self.event_queue.put((Event.SSH_UP, ts(), ""))
                    return
            except Exception:
                pass
            self._stop.wait(self._poll_interval)


def _setup_monitors(
    interface: str,
    event_queue: queue.Queue,
    pcap_path: str,
    profile: object,
    args: argparse.Namespace,
    pcap_enabled: bool = True,
) -> tuple[Optional[PcapMonitor], Optional[threading.Thread], LinkMonitor, threading.Thread]:
    """Create and start PcapMonitor (optional) and LinkMonitor."""
    pcap_monitor = None
    pcap_thread = None

    if pcap_enabled and not getattr(args, 'no_pcap', False) and has_scapy() and has_tcpdump():
        zycast_group = getattr(profile, 'zycast_multicast_group', '')
        zycast_port = getattr(profile, 'zycast_multicast_port', 0)
        monitor_config = PcapMonitorConfig(
            interface=interface,
            pcap_path=pcap_path,
            recovery_ip=profile.recovery_ip,
            router_mac_openwrt=args.router_mac,
            router_mac_uboot=args.uboot_mac,
            silence_timeout=args.silence_timeout,
            zycast_multicast_group=zycast_group,
            zycast_multicast_port=zycast_port,
        )
        pcap_monitor = PcapMonitor(monitor_config, event_queue)
        pcap_thread = threading.Thread(target=pcap_monitor.run, daemon=True)
        pcap_thread.start()
    elif pcap_enabled:
        log("pcap monitoring disabled (polling-only mode)")

    link_monitor = LinkMonitor(interface, event_queue)
    link_thread = threading.Thread(target=link_monitor.run, daemon=True)
    link_thread.start()

    return pcap_monitor, pcap_thread, link_monitor, link_thread


def _teardown_monitors(
    pcap_monitor: Optional[PcapMonitor],
    pcap_thread: Optional[threading.Thread],
    link_monitor: LinkMonitor,
    link_thread: threading.Thread,
) -> None:
    """Stop and join monitor threads."""
    if pcap_monitor:
        pcap_monitor.stop()
    link_monitor.stop()
    if pcap_thread:
        pcap_thread.join(timeout=5)
    link_thread.join(timeout=5)


@contextmanager
def monitor_lifecycle(
    interface: str,
    event_queue: queue.Queue,
    pcap_path: str,
    profile: object,
    args: argparse.Namespace,
    pcap_enabled: bool = True,
):
    """Context manager for monitor setup/teardown.

    Yields (pcap_monitor, link_monitor) tuple.
    """
    pcap_mon, pcap_thr, link_mon, link_thr = _setup_monitors(
        interface, event_queue, pcap_path, profile, args, pcap_enabled=pcap_enabled)

    try:
        yield pcap_mon, link_mon
    finally:
        _teardown_monitors(pcap_mon, pcap_thr, link_mon, link_thr)
