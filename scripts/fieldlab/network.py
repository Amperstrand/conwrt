"""Platform-abstracted network operations for field-lab serve commands.

Detects the host platform and provides the right commands for:
- IP assignment (ifconfig alias on macOS, ip addr add on Linux/OpenWrt)
- DHCP server (dnsmasq on Linux/OpenWrt, Python fallback on macOS)
- TFTP server (conwrt's tftp-server.py or dnsmasq --enable-tftp)

Designed to be DRY with conwrt's existing primitives: the macOS ifconfig-alias
pattern comes from cmd_probe._configure_interface, the TFTP server reuses
scripts/tftp-server.py, and the platform detection aligns with platform_utils.
"""

from __future__ import annotations

import platform
import shlex
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

MACOS = "macos"
LINUX = "linux"
OPENWRT = "openwrt"


def detect_platform_local() -> str:
    """Detect the platform we're running on."""
    system = platform.system()
    if system == "Darwin":
        return MACOS
    if system == "Linux":
        if _is_openwrt():
            return OPENWRT
        return LINUX
    return LINUX


def _is_openwrt() -> bool:
    try:
        with open("/etc/openwrt_release") as f:
            return "OpenWrt" in f.read()
    except OSError:
        return False


# ---------------------------------------------------------------------------
# IP assignment (platform-abstracted)
# ---------------------------------------------------------------------------

@dataclass
class IpAssignment:
    """Represents an IP address assignment to an interface."""
    interface: str
    ip: str
    cidr: int = 24

    @property
    def ip_cidr(self) -> str:
        return f"{self.ip}/{self.cidr}"

    @property
    def netmask(self) -> str:
        return _cidr_to_netmask(self.cidr)

    @property
    def network(self) -> str:
        parts = self.ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0"


def _cidr_to_netmask(cidr: int) -> str:
    bits = (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF
    return f"{bits >> 24 & 0xFF}.{bits >> 16 & 0xFF}.{bits >> 8 & 0xFF}.{bits & 0xFF}"


def assign_ip_commands(iface: str, ip: str, cidr: int = 24, os_platform: str = "") -> str:
    """Return the shell command to assign an IP to an interface.

    Mirrors cmd_probe._configure_interface (macOS ifconfig alias) and
    the Linux ip addr add pattern used throughout conwrt.
    """
    os_platform = os_platform or detect_platform_local()
    assignment = IpAssignment(iface, ip, cidr)
    if os_platform == MACOS:
        return (
            f"ifconfig {shlex.quote(iface)} inet {ip} "
            f"netmask {assignment.netmask} alias"
        )
    return f"ip addr add {assignment.ip_cidr} dev {shlex.quote(iface)}"


def remove_ip_commands(iface: str, ip: str, os_platform: str = "") -> str:
    """Return the shell command to remove an IP from an interface."""
    os_platform = os_platform or detect_platform_local()
    if os_platform == MACOS:
        return f"ifconfig {shlex.quote(iface)} inet {ip} -alias"
    return f"ip addr del {ip}/32 dev {shlex.quote(iface)} 2>/dev/null; true"


# ---------------------------------------------------------------------------
# DHCP server (platform-abstracted)
# ---------------------------------------------------------------------------

@dataclass
class DhcpServerConfig:
    """Configuration for a temporary DHCP server on a probe interface."""
    interface: str
    server_ip: str
    pool_start: str
    pool_end: str
    lease_time: str = "1h"
    cidr: int = 24

    @property
    def netmask(self) -> str:
        return _cidr_to_netmask(self.cidr)

    @property
    def gateway(self) -> str:
        return self.server_ip

    @property
    def dns(self) -> str:
        return self.server_ip


def dhcp_start_command(config: DhcpServerConfig, os_platform: str = "") -> str:
    """Return the command to start a DHCP server.

    On Linux/OpenWrt: runs a standalone dnsmasq bound to the interface
    (non-invasive — doesn't touch the main dnsmasq config, kill to stop).
    On macOS: not yet supported via dnsmasq — caller should use Python fallback.
    """
    os_platform = os_platform or detect_platform_local()
    if os_platform in (LINUX, OPENWRT):
        return (
            f"dnsmasq --no-daemon --log-dhcp "
            f"--interface={shlex.quote(config.interface)} --bind-interfaces "
            f"--dhcp-range={config.pool_start},{config.pool_end},{config.lease_time} "
            f"--dhcp-option=3,{config.gateway} "
            f"--dhcp-option=6,{config.dns} "
            f"--except-interface=lo 2>&1"
        )
    return ""


def dhcp_stop_command(interface: str, os_platform: str = "") -> str:
    """Return the command to stop the field-lab DHCP server."""
    os_platform = os_platform or detect_platform_local()
    if os_platform in (LINUX, OPENWRT):
        return "killall dnsmasq-fieldlab 2>/dev/null; pkill -f 'dnsmasq.*fieldlab.*internet' 2>/dev/null; true"
    return ""


# ---------------------------------------------------------------------------
# TFTP server (reuses conwrt's tftp-server.py)
# ---------------------------------------------------------------------------

@dataclass
class TftpServerConfig:
    """Configuration for a TFTP server on a probe interface."""
    interface: str
    root_dir: str
    port: int = 69


def tftp_start_command(config: TftpServerConfig, os_platform: str = "") -> str:
    """Return the command to start a TFTP server.

    On Linux/OpenWrt: uses dnsmasq's built-in TFTP (can run alongside DHCP).
    On macOS: uses conwrt's scripts/tftp-server.py (pure Python, portable).
    """
    os_platform = os_platform or detect_platform_local()
    if os_platform in (LINUX, OPENWRT):
        return (
            f"dnsmasq --no-daemon "
            f"--interface={shlex.quote(config.interface)} --bind-interfaces "
            f"--enable-tftp --tftp-root={shlex.quote(config.root_dir)} "
            f"--except-interface=lo 2>&1"
        )
    return ""


# ---------------------------------------------------------------------------
# Combined DHCP+TFTP server (for U-Boot netboot scenarios)
# ---------------------------------------------------------------------------

@dataclass
class ServeConfig:
    """Combined configuration for the serve command."""
    dhcp: DhcpServerConfig | None = None
    tftp: TftpServerConfig | None = None
    platform: str = ""

    def __post_init__(self):
        self.platform = self.platform or detect_platform_local()


def build_serve_command(config: ServeConfig) -> str:
    """Build a single dnsmasq command that does DHCP+TFTP (Linux/OpenWrt).

    dnsmasq can serve both DHCP and TFTP in one process, which is ideal
    for U-Boot netboot scenarios (device gets IP + downloads firmware).
    """
    if config.platform not in (LINUX, OPENWRT):
        return ""

    parts = [
        "dnsmasq", "--no-daemon", "--log-dhcp",
        f"--interface={shlex.quote(config.dhcp.interface)}",
        "--bind-interfaces",
        "--except-interface=lo",
    ]

    if config.dhcp:
        parts.append(
            f"--dhcp-range={config.dhcp.pool_start},{config.dhcp.pool_end},"
            f"{config.dhcp.lease_time}"
        )
        parts.append(f"--dhcp-option=3,{config.dhcp.gateway}")
        parts.append(f"--dhcp-option=6,{config.dhcp.dns}")

    if config.tftp:
        parts.append("--enable-tftp")
        parts.append(f"--tftp-root={shlex.quote(config.tftp.root_dir)}")

    return " ".join(parts) + " 2>&1"
