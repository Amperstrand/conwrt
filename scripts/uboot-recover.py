#!/usr/bin/env python3
"""U-Boot recovery script with pcap monitor and event-driven state machine.

Reads device profiles from conwrt model JSON files via model_loader.
Background pcap monitor thread parses packets in real-time and emits events
to a queue. The main thread runs a state machine that consumes events and
drives the recovery workflow.

Usage:
    python3 scripts/uboot-recover.py --model-id glinet-mt3000 --image firmware.bin
    python3 scripts/uboot-recover.py --model-id dlink-covr-x1860-a1 --image firmware.bin
    python3 scripts/uboot-recover.py --model-id glinet-mt3000 --image fw.bin --no-upload
    python3 scripts/uboot-recover.py --model-id glinet-mt3000 --image fw.bin --no-voice
    python3 scripts/uboot-recover.py --model-id glinet-mt3000 --image fw.bin --capture /tmp/boot.pcap

Use 'python3 scripts/model_loader.py list' to see all available model IDs.
"""

import argparse
import hashlib
import json
import os
import queue
import re
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from types import SimpleNamespace
from typing import Optional

# model_loader is in the same directory
sys.path.insert(0, str(Path(__file__).resolve().parent))
from model_loader import load_model, list_models


UBOOT_IP = "192.168.1.1"
UBOOT_LED_PATTERN = "blue flashes 6x then solid white"
UBOOT_FLASH_COUNT = 6
UBOOT_FLASH_TIME_SECONDS = 240
UBOOT_REBOOT_TIMEOUT = 360
SILENCE_TIMEOUT_DEFAULT = 30


def _find_recovery_flash_method(model: dict) -> dict:
    """Auto-detect the recovery/U-Boot HTTP flash method from the model definition.

    Iterates model["flash_methods"] and picks the one that contains "recovery_ip",
    which is the marker for an HTTP-based recovery method.
    """
    for method_name, method_cfg in model.get("flash_methods", {}).items():
        if "recovery_ip" in method_cfg:
            return method_cfg
    available = list(model.get("flash_methods", {}).keys())
    raise ValueError(
        f"No HTTP recovery flash method found in model '{model.get('id', '?')}'. "
        f"Available methods: {available}"
    )


def _build_profile_from_model(model_id: str) -> SimpleNamespace:
    """Load a model and build a runtime profile namespace for the recovery script.

    Returns a SimpleNamespace with the same attributes that DeviceProfile used to have,
    so the rest of the state machine code works unchanged.
    """
    model = load_model(model_id)
    fm = _find_recovery_flash_method(model)

    client_ip = fm["client_ip"]
    return SimpleNamespace(
        name=model["id"],
        vendor=model["vendor"],
        description=model["description"],
        recovery_ip=fm["recovery_ip"],
        client_ip=client_ip,
        client_subnet=fm.get("client_subnet", "255.255.255.0"),
        reset_instructions=fm["reset_instructions"],
        led_pattern=fm["led_pattern"],
        upload_endpoint=fm["upload_endpoint"],
        upload_field=fm["upload_field"],
        trigger_flash_endpoint=fm.get("trigger_flash_endpoint", ""),
        flash_time_seconds=fm["flash_time_seconds"],
        silence_timeout=fm.get("silence_timeout", 30),
        openwrt_ip=model["openwrt"]["default_ip"],
        openwrt_client_ip=fm.get("openwrt_client_ip", client_ip),
    )


def _setup_interface_ips(interface: str, profile: SimpleNamespace) -> None:
    existing = subprocess.run(
        ["ifconfig", interface], capture_output=True, text=True, check=False,
    ).stdout

    if profile.client_ip not in existing:
        result = subprocess.run(
            ["ifconfig", interface, profile.client_ip, "netmask", profile.client_subnet, "up"],
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            print(f"ERROR: need sudo to configure {interface}: {result.stderr.strip()}", file=sys.stderr)
            print(f"  sudo ifconfig {interface} {profile.client_ip} netmask {profile.client_subnet} up", file=sys.stderr)
            sys.exit(1)
        log(f"Configured {interface}: {profile.client_ip}/{profile.client_subnet}")
    else:
        log(f"Interface {interface} already has {profile.client_ip}")

    openwrt_client = profile.openwrt_client_ip
    if openwrt_client and openwrt_client != profile.client_ip and openwrt_client not in existing:
        result = subprocess.run(
            ["ifconfig", interface, openwrt_client, "netmask", "255.255.255.0", "alias"],
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            log(f"WARNING: could not add alias {openwrt_client}: {result.stderr.strip()}")
        else:
            log(f"Added alias {interface}: {openwrt_client}/255.255.255.0")


def _arp_target_for_profile(profile: SimpleNamespace) -> str:
    parts = profile.recovery_ip.rsplit(".", 1)
    return f"{parts[0]}.2"


class Event(Enum):
    LINK_DOWN = auto()
    LINK_UP = auto()
    UBOOT_HTTP = auto()
    UBOOT_ARP_192_168_1_2 = auto()
    ICMPV6_FROM_ROUTER = auto()
    SSH_UP = auto()
    FAILSAFE_BROADCAST = auto()
    NO_PACKETS_FOR_N_SECONDS = auto()
    UPLOAD_COMPLETE = auto()
    FLASH_TRIGGERED = auto()


class State(Enum):
    WAITING_FOR_POWER_OFF = auto()
    WAITING_FOR_UBOOT = auto()
    UBOOT_UPLOADING = auto()
    UBOOT_FLASHING = auto()
    REBOOTING = auto()
    OPENWRT_BOOTING = auto()
    COMPLETE = auto()
    FAILED = auto()


@dataclass
class Timeline:
    power_off: Optional[float] = None
    link_up: Optional[float] = None
    uboot_http_first: Optional[float] = None
    upload_start: Optional[float] = None
    upload_complete: Optional[float] = None
    flash_triggered: Optional[float] = None
    flash_complete: Optional[float] = None
    first_openwrt_packet: Optional[float] = None
    ssh_available: Optional[float] = None
    recovery_start: Optional[float] = None


@dataclass
class PcapMonitorConfig:
    interface: str
    pcap_path: str
    recovery_ip: str = UBOOT_IP
    router_mac_openwrt: str = ""
    router_mac_uboot: str = ""
    uboot_ip: str = UBOOT_IP
    silence_timeout: int = SILENCE_TIMEOUT_DEFAULT


def ts() -> float:
    return time.time()


def ts_str(t: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(t))


def say(msg: str) -> None:
    subprocess.run(["say", "-v", "Samantha", msg], check=False, timeout=10)


def log(msg: str) -> None:
    t = time.strftime("%H:%M:%S")
    print(f"  [{t}] {msg}")
    sys.stdout.flush()


def get_link_state(interface: str) -> bool:
    r = subprocess.run(
        ["ifconfig", interface],
        capture_output=True, text=True, timeout=5, check=False,
    )
    return "status: active" in r.stdout.lower()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def detect_uboot_http(recovery_ip: str = UBOOT_IP) -> tuple[bool, str]:
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", "2", f"http://{recovery_ip}/"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if "FIRMWARE UPDATE" in r.stdout or "firmware" in r.stdout.lower():
            return True, "firmware page"
        if r.stdout.strip().startswith("<!DOCTYPE"):
            return True, "HTML response"
        return False, r.stdout[:100] if r.stdout.strip() else "no response"
    except Exception as e:
        return False, str(e)[:80]


def upload_firmware(image_path: str, profile: SimpleNamespace, timeout: int = 300) -> tuple[bool, str]:
    size_mb = os.path.getsize(image_path) / 1024 / 1024
    endpoint = f"http://{profile.recovery_ip}{profile.upload_endpoint}"
    log(f"Uploading {os.path.basename(image_path)} ({size_mb:.1f} MB) to {profile.upload_endpoint}...")
    try:
        r = subprocess.run(
            [
                "curl", "-sk", "--show-error",
                "--max-time", str(timeout),
                "-F", f"{profile.upload_field}=@{image_path};type=application/octet-stream",
                endpoint,
            ],
            capture_output=True, text=True, timeout=timeout + 30, check=False,
        )
        if r.returncode == 0 and r.stdout.strip():
            parts = r.stdout.strip().split()
            uboot_md5 = parts[1] if len(parts) > 1 else "?"
            log(f"Upload accepted: size={parts[0]} bytes, uboot_md5={uboot_md5}")
            return True, r.stdout.strip()
        log(f"Upload failed (exit {r.returncode}): {r.stderr[:300]}")
        return False, r.stderr[:300]
    except subprocess.TimeoutExpired:
        log("Upload timed out.")
        return False, "timeout"
    except Exception as e:
        log(f"Upload error: {e}")
        return False, str(e)


def trigger_flash(profile: SimpleNamespace) -> bool:
    if not profile.trigger_flash_endpoint:
        return True
    log(f"Triggering flash via {profile.trigger_flash_endpoint}...")
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", "5",
             f"http://{profile.recovery_ip}{profile.trigger_flash_endpoint}"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if "Update in progress" in r.stdout:
            log("Flash triggered — 'Update in progress' page returned.")
            return True
        log(f"Unexpected flash response: {r.stdout[:100]}")
    except Exception as e:
        log(f"Flash trigger error: {e}")
    return False


def check_ssh(ip: str = UBOOT_IP) -> bool:
    try:
        r = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null",
             "-o", "ConnectTimeout=3",
             "-o", "PasswordAuthentication=no",
             f"root@{ip}", "echo SSH_OK"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        return "SSH_OK" in r.stdout
    except Exception:
        return False


def verify_router(ip: str = UBOOT_IP) -> list[tuple[str, str]]:
    log("Verifying router state...")
    checks: list[tuple[str, str]] = []
    try:
        r = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null",
             "-o", "ConnectTimeout=5",
             "-o", "PasswordAuthentication=no",
             f"root@{ip}",
             "echo hostname=$(cat /proc/sys/kernel/hostname); "
             "echo sshkey=$(wc -c < /etc/dropbear/authorized_keys); "
             "echo wan_ssh=$(uci show firewall | grep Allow-SSH-WAN | wc -l); "
             "echo uci_defaults=$(ls /etc/uci-defaults/ 2>/dev/null | wc -l); "
             "echo kernel=$(uname -r)"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        for line in r.stdout.strip().split('\n'):
            if '=' in line:
                key, val = line.split('=', 1)
                checks.append((key, val))
                log(f"  {key}: {val}")
    except Exception as e:
        log(f"Verification failed: {e}")
    return checks


def probe_router_info(ip: str = UBOOT_IP) -> Optional[dict]:
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from router_probe import probe_router as _probe_router
        result = _probe_router(ip=ip)
        return {
            "model": result.model,
            "vendor": result.vendor,
            "firmware_version": result.firmware_version,
            "mac": result.mac,
            "ssh_key_count": result.ssh_key_count,
            "state": result.state,
        }
    except Exception as e:
        log(f"Router probe failed: {e}")
        return None


class PcapMonitor:
    """Background thread that captures packets and emits events to a queue.

    Uses two subprocess.Popen instances:
    1. Writer: sudo tcpdump -i <iface> -w <path> -n -U --immediate-mode
       This process may die when the USB ethernet adapter disconnects on reboot.
       The monitor watches it and restarts when the interface comes back.
    2. Reader: tcpdump -r <path> -nn -l (reads the growing pcap file in real-time)
       Parses packets and emits events.
    """

    def __init__(self, config: PcapMonitorConfig, event_queue: queue.Queue):
        self.config = config
        self.event_queue = event_queue
        self._stop = threading.Event()
        self._last_packet_time: float = ts()
        self._silence_timeout = config.silence_timeout
        self._writer_proc: Optional[subprocess.Popen] = None
        self._reader_proc: Optional[subprocess.Popen] = None
        self._known_uboot_macs: set[str] = set()

    def stop(self) -> None:
        self._stop.set()

    def _start_writer(self) -> Optional[subprocess.Popen]:
        try:
            proc = subprocess.Popen(
                ["sudo", "-n", "tcpdump", "-i", self.config.interface,
                 "-w", self.config.pcap_path, "-n", "-U", "--immediate-mode",
                 "--buffer-size=16384"],
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

    def run(self) -> None:
        log(f"Pcap monitor starting: iface={self.config.interface} pcap={self.config.pcap_path}")

        self._writer_proc = self._start_writer()

        # Wait for pcap file header to be written
        time.sleep(1)

        self._reader_proc = self._start_reader()

        silence_check_interval = 5
        last_silence_check = ts()

        while not self._stop.is_set():
            # tcpdump writer dies when USB ethernet adapter disconnects on reboot
            if self._writer_proc and self._writer_proc.poll() is not None:
                log("tcpdump writer died (interface gone?), will restart when link returns")
                time.sleep(3)
                if get_link_state(self.config.interface):
                    self._restart_writer()
                    # pcap file has a gap after writer restart, restart reader
                    if self._reader_proc and self._reader_proc.poll() is None:
                        self._reader_proc.terminate()
                        self._reader_proc.wait(timeout=3)
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

            now = ts()
            if now - last_silence_check >= silence_check_interval:
                last_silence_check = now
                if now - self._last_packet_time >= self._silence_timeout:
                    self.event_queue.put((
                        Event.NO_PACKETS_FOR_N_SECONDS, now,
                        f"no packets for {int(now - self._last_packet_time)}s",
                    ))
                    self._last_packet_time = now

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


@dataclass
class RecoveryContext:
    profile: object  # SimpleNamespace loaded from model JSON via model_loader
    image_path: str
    interface: str
    pcap_path: str
    no_upload: bool = False
    no_voice: bool = False
    router_mac_openwrt: str = ""
    router_mac_uboot: str = ""
    timeline: Timeline = field(default_factory=Timeline)
    state: State = State.WAITING_FOR_POWER_OFF
    sha256_before: str = ""
    sha256_after: str = ""
    _say_fn: object = field(default=None, repr=False)

    def __post_init__(self):
        if self._say_fn is None:
            self._say_fn = say


def _run_state_machine(
    ctx: RecoveryContext,
    event_queue: queue.Queue,
    pcap_monitor: PcapMonitor,
    link_monitor: LinkMonitor,
) -> int:
    ctx.timeline.recovery_start = ts()

    while ctx.state not in (State.COMPLETE, State.FAILED):
        if ctx.state == State.WAITING_FOR_POWER_OFF:
            _handle_waiting_for_power_off(ctx, event_queue)
        elif ctx.state == State.WAITING_FOR_UBOOT:
            _handle_waiting_for_uboot(ctx, event_queue, link_monitor)
        elif ctx.state == State.UBOOT_UPLOADING:
            _handle_uboot_uploading(ctx, event_queue)
        elif ctx.state == State.UBOOT_FLASHING:
            _handle_uboot_flashing(ctx, event_queue, pcap_monitor)
        elif ctx.state == State.REBOOTING:
            _handle_rebooting(ctx, event_queue)
        elif ctx.state == State.OPENWRT_BOOTING:
            _handle_openwrt_booting(ctx, event_queue)
        else:
            log(f"Unknown state: {ctx.state}")
            ctx.state = State.FAILED

    if ctx.state == State.COMPLETE:
        _print_timeline(ctx)
        _record_inventory(ctx)
        return 0
    return 1


def _handle_waiting_for_power_off(ctx: RecoveryContext, eq: queue.Queue) -> None:
    link_up = get_link_state(ctx.interface)
    if link_up:
        ctx._say_fn("Ready. Please unplug the power cable from the router now.")
        log("STEP 1: Unplug power (keep ethernet in LAN port)")

        _wait_for_event_or_timeout(
            eq, timeout=300,
            target_events={Event.LINK_DOWN},
            success_state=State.WAITING_FOR_UBOOT,
            fail_message="Timed out waiting for power off.",
            fail_say="Timed out. Please unplug the power cable from the router.",
            ctx=ctx,
        )
        if ctx.state == State.WAITING_FOR_UBOOT:
            ctx._say_fn("Power disconnected. Good.")
            ctx.timeline.power_off = ts()
    else:
        log("Router already powered off.")
        ctx._say_fn("Router is off. Good.")
        ctx.timeline.power_off = ts()
        ctx.state = State.WAITING_FOR_UBOOT


def _handle_waiting_for_uboot(ctx: RecoveryContext, eq: queue.Queue, link_monitor: LinkMonitor) -> None:
    print()
    profile = ctx.profile
    ctx._say_fn(profile.reset_instructions)
    log(f"STEP 2: {profile.reset_instructions}")
    time.sleep(4)

    ctx._say_fn("While still holding reset, plug in the power cable.")
    log("STEP 3: Plug in power WHILE STILL HOLDING reset")
    time.sleep(2)

    ctx._say_fn(
        f"Watch the LED. {profile.led_pattern}. "
        "Release reset when the LED shows the recovery pattern."
    )
    log(f"Waiting for recovery LED pattern: {profile.led_pattern}")
    print()

    got_link_up = _wait_for_event_or_timeout(
        eq, timeout=30,
        target_events={Event.LINK_UP},
        success_state=None,
        fail_message="Ethernet link did not come up.",
        fail_say="Ethernet link did not come up. Check the cable is in the LAN port.",
        ctx=ctx,
    )
    if got_link_up is None:
        ctx.state = State.FAILED
        return

    ctx.timeline.link_up = ts()
    ctx._say_fn("Link detected. Waiting for recovery mode.")
    log(f"Link up — waiting for recovery HTTP: {profile.led_pattern}")
    time.sleep(8)

    log("Scanning for recovery HTTP server...")
    uboot_found = False
    probe_start = ts()
    probe_timeout = 90

    while ts() - probe_start < probe_timeout:
        found, detail = detect_uboot_http(profile.recovery_ip)
        if found:
            log(f"Recovery mode detected: {detail}")
            ctx.timeline.uboot_http_first = ts()
            ctx._say_fn("Recovery mode detected. You can release the button now.")
            ctx.state = State.UBOOT_UPLOADING
            uboot_found = True
            break

        _drain_events(eq, ctx)

        time.sleep(1)

    if not uboot_found:
        ctx._say_fn(f"Recovery mode not found. Check the LED pattern: {profile.led_pattern}")
        log("FAIL: Recovery HTTP server not detected.")
        ctx.state = State.FAILED


def _handle_uboot_uploading(ctx: RecoveryContext, eq: queue.Queue) -> None:
    profile = ctx.profile
    if ctx.no_upload:
        ctx._say_fn("Dry run. Recovery server is ready but not uploading.")
        log(f"DRY RUN: Recovery server ready at http://{profile.recovery_ip}")
        log(f"  Upload: curl -F {profile.upload_field}=@{ctx.image_path} http://{profile.recovery_ip}{profile.upload_endpoint}")
        if profile.trigger_flash_endpoint:
            log(f"  Flash:  curl http://{profile.recovery_ip}{profile.trigger_flash_endpoint}")
        ctx.state = State.COMPLETE
        return

    ctx.sha256_before = sha256_file(ctx.image_path)
    log(f"SHA-256 (before upload): {ctx.sha256_before}")

    ctx.timeline.upload_start = ts()
    ok, response = upload_firmware(ctx.image_path, profile)
    if not ok:
        ctx._say_fn(f"Upload failed. Try a browser at http://{profile.recovery_ip} instead.")
        ctx.state = State.FAILED
        return

    ctx.timeline.upload_complete = ts()
    eq.put((Event.UPLOAD_COMPLETE, ts(), response))

    ctx.sha256_after = sha256_file(ctx.image_path)
    if ctx.sha256_after != ctx.sha256_before:
        log("WARNING: SHA-256 mismatch! File may have been modified on disk during upload.")
    else:
        log(f"SHA-256 verified (after upload): {ctx.sha256_after}")

    if trigger_flash(profile):
        ctx.timeline.flash_triggered = ts()
        eq.put((Event.FLASH_TRIGGERED, ts(), ""))
    else:
        log("Flash trigger may have failed. Router may still flash on its own.")
        ctx.timeline.flash_triggered = ts()

    ctx._say_fn("Firmware flashing. Do not unplug.")
    ctx.state = State.UBOOT_FLASHING


def _handle_uboot_flashing(ctx: RecoveryContext, eq: queue.Queue, pcap_monitor: PcapMonitor) -> None:
    profile = ctx.profile
    timeout = profile.flash_time_seconds + 120
    result = _wait_for_event_or_timeout(
        eq, timeout=timeout,
        target_events={Event.UBOOT_ARP_192_168_1_2, Event.LINK_DOWN},
        success_state=State.REBOOTING,
        fail_message=f"Flash did not complete within {timeout}s.",
        fail_say="Flash is taking too long. Something went wrong.",
        ctx=ctx,
    )
    if result is None:
        ctx.state = State.FAILED
        return

    ctx.timeline.flash_complete = ts()
    log(f"Flash complete (event: {result})")


def _handle_rebooting(ctx: RecoveryContext, eq: queue.Queue) -> None:
    timeout = UBOOT_REBOOT_TIMEOUT
    result = _wait_for_event_or_timeout(
        eq, timeout=timeout,
        target_events={Event.LINK_UP, Event.ICMPV6_FROM_ROUTER},
        success_state=State.OPENWRT_BOOTING,
        fail_message=f"Router did not reboot within {timeout}s.",
        fail_say="Router is taking longer than expected.",
        ctx=ctx,
    )
    if result is None:
        ctx.state = State.FAILED
        return

    if result == Event.ICMPV6_FROM_ROUTER:
        ctx.timeline.first_openwrt_packet = ts()
        log("ICMPv6 from router MAC detected — OpenWrt is booting")


def _handle_openwrt_booting(ctx: RecoveryContext, eq: queue.Queue) -> None:
    openwrt_ip = ctx.profile.openwrt_ip or ctx.profile.recovery_ip
    ssh_monitor = SSHMonitor(openwrt_ip, eq, poll_interval=5.0)
    ssh_thread = threading.Thread(target=ssh_monitor.run, daemon=True)
    ssh_thread.start()

    timeout = 120
    result = _wait_for_event_or_timeout(
        eq, timeout=timeout,
        target_events={Event.SSH_UP, Event.LINK_UP},
        success_state=None,
        fail_message=f"SSH not available within {timeout}s.",
        fail_say="Router is taking longer than expected. Check SSH in a few minutes.",
        ctx=ctx,
    )

    ssh_monitor.stop()

    if result == Event.SSH_UP:
        ctx.timeline.ssh_available = ts()
        ctx._say_fn("Recovery complete! Router is back online.")
        log("SUCCESS — router recovered.")
        verify_router(openwrt_ip)
        ctx.state = State.COMPLETE
    else:
        if check_ssh(openwrt_ip):
            ctx.timeline.ssh_available = ts()
            ctx._say_fn("Recovery complete! Router is back online.")
            log("SUCCESS — router recovered (SSH fallback check).")
            verify_router(openwrt_ip)
            ctx.state = State.COMPLETE
        else:
            ctx.state = State.FAILED


def _wait_for_event_or_timeout(
    eq: queue.Queue,
    timeout: int,
    target_events: set[Event],
    success_state: Optional[State],
    fail_message: str,
    fail_say: str,
    ctx: RecoveryContext,
) -> Optional[Event]:
    """Wait for one of the target events or timeout.

    Returns the Event that was found, or None on timeout.
    Sets ctx.state to success_state on success, or State.FAILED on timeout.
    """
    start = ts()
    while ts() - start < timeout:
        try:
            event, event_ts, detail = eq.get(timeout=1.0)

            if event in target_events:
                if success_state is not None:
                    ctx.state = success_state
                return event

            if event == Event.LINK_UP and ctx.timeline.link_up is None:
                ctx.timeline.link_up = event_ts
            elif event == Event.LINK_DOWN and ctx.timeline.power_off is None:
                ctx.timeline.power_off = event_ts
            elif event == Event.ICMPV6_FROM_ROUTER and ctx.timeline.first_openwrt_packet is None:
                ctx.timeline.first_openwrt_packet = event_ts
            elif event == Event.SSH_UP:
                ctx.timeline.ssh_available = event_ts
                if success_state is not None:
                    ctx.state = success_state
                return event
            elif event == Event.UBOOT_HTTP and ctx.timeline.uboot_http_first is None:
                ctx.timeline.uboot_http_first = event_ts

        except queue.Empty:
            pass

    log(fail_message)
    ctx._say_fn(fail_say)
    if success_state is not None:
        ctx.state = State.FAILED
    return None


def _drain_events(eq: queue.Queue, ctx: RecoveryContext) -> None:
    """Non-blocking drain of any pending events to update timeline."""
    while True:
        try:
            event, event_ts, detail = eq.get_nowait()
            if event == Event.LINK_UP and ctx.timeline.link_up is None:
                ctx.timeline.link_up = event_ts
            elif event == Event.LINK_DOWN and ctx.timeline.power_off is None:
                ctx.timeline.power_off = event_ts
            elif event == Event.UBOOT_HTTP and ctx.timeline.uboot_http_first is None:
                ctx.timeline.uboot_http_first = event_ts
        except queue.Empty:
            break


def _print_timeline(ctx: RecoveryContext) -> None:
    print()
    log("=" * 50)
    log("RECOVERY TIMELINE")
    log("=" * 50)

    tl = ctx.timeline
    start = tl.recovery_start or tl.power_off or ts()

    def elapsed(t: Optional[float]) -> str:
        if t is None:
            return "N/A"
        return f"+{int(t - start)}s ({ts_str(t)})"

    log(f"  Recovery start:    {ts_str(start)}")
    log(f"  Power off:         {elapsed(tl.power_off)}")
    log(f"  Link up:           {elapsed(tl.link_up)}")
    log(f"  U-Boot HTTP:       {elapsed(tl.uboot_http_first)}")
    log(f"  Upload start:      {elapsed(tl.upload_start)}")
    log(f"  Upload complete:   {elapsed(tl.upload_complete)}")
    log(f"  Flash triggered:   {elapsed(tl.flash_triggered)}")
    log(f"  Flash complete:    {elapsed(tl.flash_complete)}")
    log(f"  First OpenWrt pkt: {elapsed(tl.first_openwrt_packet)}")
    log(f"  SSH available:     {elapsed(tl.ssh_available)}")

    if tl.ssh_available and start:
        total = int(tl.ssh_available - start)
        log(f"  TOTAL TIME:        {total}s ({total // 60}m {total % 60}s)")

    log(f"  SHA-256:           {ctx.sha256_before}")
    log("=" * 50)

    if ctx.pcap_path and os.path.isfile(ctx.pcap_path):
        size_kb = os.path.getsize(ctx.pcap_path) / 1024
        log(f"  Pcap: {ctx.pcap_path} ({size_kb:.1f} KB)")


def _record_inventory(ctx: RecoveryContext) -> None:
    info = probe_router_info(ctx.profile.openwrt_ip or ctx.profile.recovery_ip)
    if not info:
        log("Could not probe router for inventory.")
        return

    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "device_serial": "",
        "model": info.get("model", ""),
        "vendor": info.get("vendor", ""),
        "firmware_version": info.get("firmware_version", ""),
        "openwrt_target": "",
        "mac_addresses": [info.get("mac", "")] if info.get("mac") else [],
        "ssh_key_fingerprint": "",
        "password_set": False,
        "sha256_firmware": ctx.sha256_before,
        "flashed_by": os.environ.get("USER", ""),
        "notes": "Recovered via uboot-recover.py",
    }

    inventory_path = Path(__file__).resolve().parent.parent / "data" / "inventory.jsonl"
    try:
        inventory_path.parent.mkdir(parents=True, exist_ok=True)
        with open(inventory_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
        log(f"Inventory entry appended to {inventory_path}")
    except Exception as e:
        log(f"Failed to write inventory: {e}")


def auto_detect_interface(subnet_prefix: str = "") -> Optional[str]:
    """Find the single active physical ethernet interface.

    Skips en0 (WiFi), Thunderbolt bridge members, and Thunderbolt bridge
    virtual interfaces (mtu 16000). Asserts exactly one candidate exists.
    """
    bridge_members = set()
    br_r = subprocess.run(["ifconfig", "bridge0"], capture_output=True, text=True, check=False)
    for line in br_r.stdout.splitlines():
        if "member:" in line.lower():
            bridge_members.add(line.strip().split()[1])

    candidates = []
    for n in range(1, 21):
        iface = f"en{n}"
        r = subprocess.run(
            ["ifconfig", iface], capture_output=True, text=True, check=False,
        )
        if r.returncode != 0:
            continue
        if "status: active" not in r.stdout.lower():
            continue
        if iface in bridge_members:
            continue
        if "mtu 16000" in r.stdout:  # Thunderbolt bridge
            continue
        if "base" not in r.stdout or "duplex" not in r.stdout:
            continue
        candidates.append(iface)

    if len(candidates) == 0:
        return None
    if len(candidates) > 1:
        log(f"WARNING: multiple ethernet interfaces active: {candidates}, using first")
    return candidates[0]


def main() -> int:
    try:
        available_ids = [m["id"] for m in list_models()]
    except Exception:
        available_ids = []

    parser = argparse.ArgumentParser(
        description="U-Boot recovery for OpenWrt devices (reads profiles from conwrt models/)",
    )
    parser.add_argument("--model-id", required=True,
                        help=f"Model ID from models/ directory (e.g. glinet-mt3000, dlink-covr-x1860-a1). "
                             f"Use 'model_loader.py list' to see all available. "
                             f"Known: {', '.join(sorted(available_ids)) or 'none loaded'}")
    parser.add_argument("--image", required=True, help="Firmware image to upload")
    parser.add_argument("--interface", default=None,
                        help="Ethernet interface (auto-detected if omitted)")
    parser.add_argument("--no-voice", action="store_true", help="Disable voice guidance")
    parser.add_argument("--no-upload", action="store_true",
                        help="Stop after detecting U-Boot (dry run)")
    parser.add_argument("--capture", default=None,
                        help="Save pcap capture to file (requires sudo)")
    parser.add_argument("--router-mac", default="",
                        help="Router's OpenWrt MAC address (for ICMPv6 detection)")
    parser.add_argument("--uboot-mac", default="",
                        help="Router's U-Boot MAC address (for ARP detection)")
    parser.add_argument("--silence-timeout", type=int, default=SILENCE_TIMEOUT_DEFAULT,
                        help="Seconds of no packets before silence event")
    args = parser.parse_args()

    try:
        profile = _build_profile_from_model(args.model_id)
    except (FileNotFoundError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    if not os.path.isfile(args.image):
        print(f"ERROR: image not found: {args.image}", file=sys.stderr)
        return 1

    interface = args.interface or auto_detect_interface()
    if not interface:
        print("ERROR: no active ethernet interface found. Use --interface.", file=sys.stderr)
        return 1

    pcap_path = args.capture or os.path.join(tempfile.gettempdir(), "uboot-capture.pcap")

    log(f"{profile.description} Recovery")
    log(f"Model:      {profile.name} ({profile.vendor})")
    log(f"Image:      {args.image}")
    log(f"Interface:  {interface}")
    log(f"Pcap:       {pcap_path}")
    log(f"LED signal: {profile.led_pattern}")
    print()

    _say_fn = (lambda m: None) if args.no_voice else say

    ctx = RecoveryContext(
        profile=profile,
        image_path=args.image,
        interface=interface,
        pcap_path=pcap_path,
        no_upload=args.no_upload,
        no_voice=args.no_voice,
        router_mac_openwrt=args.router_mac,
        router_mac_uboot=args.uboot_mac,
        _say_fn=_say_fn,
    )

    event_queue: queue.Queue = queue.Queue()

    _setup_interface_ips(interface, profile)

    monitor_config = PcapMonitorConfig(
        interface=interface,
        pcap_path=pcap_path,
        recovery_ip=profile.recovery_ip,
        router_mac_openwrt=args.router_mac,
        router_mac_uboot=args.uboot_mac,
        silence_timeout=args.silence_timeout,
    )

    pcap_monitor = PcapMonitor(monitor_config, event_queue)
    link_monitor = LinkMonitor(interface, event_queue)

    pcap_thread = threading.Thread(target=pcap_monitor.run, daemon=True)
    link_thread = threading.Thread(target=link_monitor.run, daemon=True)
    pcap_thread.start()
    link_thread.start()

    _say_fn(f"Starting {profile.description} recovery. Listen for instructions.")

    try:
        rc = _run_state_machine(ctx, event_queue, pcap_monitor, link_monitor)
    except KeyboardInterrupt:
        log("Interrupted by user.")
        rc = 1
    finally:
        pcap_monitor.stop()
        link_monitor.stop()
        pcap_thread.join(timeout=5)

    return rc


if __name__ == "__main__":
    sys.exit(main())
