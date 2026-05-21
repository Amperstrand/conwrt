"""Flash state machine types and logging."""
from __future__ import annotations
import hashlib
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional, TypedDict

from platform_utils import get_link_state as platform_get_link_state

DEFAULT_IP = "192.168.1.1"
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
    SYSUPGRADE_FLASHING = auto()
    SYSUPGRADE_REBOOTING = auto()
    SYSUPGRADE_BOOTING = auto()
    WAITING_FOR_POWER_OFF = auto()
    WAITING_FOR_UBOOT = auto()
    UBOOT_UPLOADING = auto()
    UBOOT_FLASHING = auto()
    SERIAL_WAITING_FOR_BOOTMENU = auto()
    SERIAL_UBOOT_INTERACTING = auto()
    SERIAL_TFTP_FLASHING = auto()
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
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()
