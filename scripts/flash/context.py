# pyright: reportCallIssue=false
"""Flash state machine types and logging."""
from __future__ import annotations
import hashlib
import queue
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Callable, Optional, TypedDict

from platform_utils import get_link_state as platform_get_link_state

DEFAULT_IP = "192.168.1.1"
DEFAULT_CLIENT_IP = "192.168.1.2"
PROBE_IPS = [DEFAULT_IP, "192.168.0.1"]
REBOOT_TIMEOUT = 360
SILENCE_TIMEOUT_DEFAULT = 30


class OemState(TypedDict, total=False):
    cookie: str
    cookie_file: str
    password: str


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
    SERIAL_UBOOT_READY = auto()
    SERIAL_COMMAND_DONE = auto()
    SERIAL_ALL_DONE = auto()
    ZYCAST_MULTICAST_DETECTED = auto()
    ZYCAST_SENDING_DONE = auto()
    EDGEOS_PORT_SWAP_DONE = auto()
    EXTREME_UBOOT_ENV_SAVED = auto()
    EXTREME_TFTP_INITRAMFS_READY = auto()
    EXTREME_BACKUP_COMPLETE = auto()
    EXTREME_BOOTCMD_RESTORED = auto()


class State(Enum):
    DETECTING = auto()
    SYSUPGRADE_UPLOADING = auto()
    SYSUPGRADE_REBOOTING = auto()
    SYSUPGRADE_BOOTING = auto()
    WAITING_FOR_POWER_OFF = auto()
    WAITING_FOR_UBOOT = auto()
    UBOOT_UPLOADING = auto()
    UBOOT_FLASHING = auto()
    SERIAL_WAITING_FOR_BOOTMENU = auto()
    SERIAL_UBOOT_INTERACTING = auto()
    ZYCAST_WAITING_FOR_DEVICE = auto()
    ZYCAST_SENDING = auto()
    EDGEOS_STAGE1 = auto()
    EDGEOS_STAGE1_REBOOTING = auto()
    EDGEOS_PORT_SWAP = auto()
    EDGEOS_STAGE2_UPLOADING = auto()
    EDGEOS_STAGE2_FLASHING = auto()
    EXTREME_STOCK_PREFLIGHT = auto()
    EXTREME_STOCK_WRITING_UBOOT = auto()
    EXTREME_STOCK_REBOOTING = auto()
    EXTREME_OPENWRT_INITRAMFS_WAITING = auto()
    EXTREME_OPENWRT_BACKUP = auto()
    EXTREME_BOOTCMD_RESTORE = auto()
    EXTREME_SYSUPGRADE_UPLOADING = auto()
    EXTREME_SYSUPGRADE_FLASHING = auto()
    PORT_ISOLATION = auto()
    OEM_LOGIN = auto()
    OEM_PREPARE = auto()
    OEM_UPLOADING = auto()
    OEM_REBOOTING = auto()
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
    recovery_ip: str = DEFAULT_IP
    router_mac_openwrt: str = ""
    router_mac_uboot: str = ""
    uboot_ip: str = DEFAULT_IP
    silence_timeout: int = SILENCE_TIMEOUT_DEFAULT
    zycast_multicast_group: str = ""
    zycast_multicast_port: int = 0


@dataclass
class RecoveryContext:
    profile: object
    image_path: str
    interface: str
    pcap_path: str
    initramfs_path: str = ""
    no_upload: bool = False
    no_voice: bool = False
    router_mac_openwrt: str = ""
    router_mac_uboot: str = ""
    timeline: Timeline = field(default_factory=Timeline)
    state: State = State.WAITING_FOR_POWER_OFF
    sha256_before: str = ""
    sha256_after: str = ""
    generated_password: str = ""
    password_set: bool = False
    auth_type: str = ""
    wireguard_pubkey: str = ""
    wan_ssh_enabled: bool = False
    force_uboot: bool = False
    no_pcap: bool = False
    boot_state: str = "unknown"
    ssh_key_path: str = ""
    serial_port: str = ""
    serial_method: str = ""
    serial_baud: int = 115200
    tftp_root: str = ""
    uboot_commands: list = field(default_factory=list)
    request_hash: str = ""
    cache_key: str = ""
    packages: list = field(default_factory=list)
    defaults_script: str = ""
    assume_yes: bool = False
    _say_fn: object = field(default=None, repr=False)
    oem_state: dict | OemState = field(default_factory=dict)
    isolate_port: str = ""
    port_isolator: object | None = field(default=None, repr=False)

    def __post_init__(self):
        if self._say_fn is None:
            self._say_fn = say

    def mark_success(self, message: str, verify_fn: object = None) -> None:
        """Mark recovery as complete with a success message."""
        self.timeline.ssh_available = ts()
        self._say_fn("Recovery complete! Router is back online.")
        log(f"SUCCESS — {message}")
        if verify_fn is not None:
            verify_fn(
                self.profile.openwrt_ip or self.profile.recovery_ip,
                wan_ssh_expected=self.wan_ssh_enabled,
                mgmt_wifi_expected=bool(self.defaults_script),
            )
        self.state = State.COMPLETE


def ts() -> float:
    return time.time()


def ts_str(t: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(t))


def say(msg: str) -> None:
    import platform
    if platform.system() == "Darwin":
        try:
            subprocess.run(["say", "-v", "Samantha", msg], check=False, timeout=30)
        except subprocess.TimeoutExpired:
            pass
    else:
        print(f"\033[1m>>> {msg}\033[0m")
        sys.stdout.flush()


def log(msg: str) -> None:
    t = time.strftime("%H:%M:%S")
    print(f"  [{t}] {msg}")
    sys.stdout.flush()


def get_link_state(interface: str) -> bool:
    return platform_get_link_state(interface)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(str(path), "rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def poll_until(predicate: Callable[[], bool], timeout: float, interval: float = 1.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def wait_for_event(
    eq: queue.Queue,
    timeout: int,
    target_events: set[Event],
    success_state: Optional[State],
    fail_message: str,
    fail_say: str,
    ctx: RecoveryContext,
) -> Optional[Event]:
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
                if ctx.state in (State.REBOOTING, State.OPENWRT_BOOTING):
                    ctx._say_fn("Link up. Waiting for OpenWrt to boot.")
            elif event == Event.LINK_DOWN and ctx.timeline.power_off is None:
                ctx.timeline.power_off = event_ts
            elif event == Event.ICMPV6_FROM_ROUTER and ctx.timeline.first_openwrt_packet is None:
                ctx.timeline.first_openwrt_packet = event_ts
                ctx._say_fn("OpenWrt is booting.")
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
