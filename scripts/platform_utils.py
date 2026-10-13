"""Platform abstraction for conwrt — Linux, macOS, and OpenWrt."""
from __future__ import annotations

import os
import platform
import re
import subprocess


def detect_platform() -> str:
    """Detect the runtime platform. Returns "openwrt" | "linux" | "darwin"."""
    if os.path.isfile("/etc/openwrt_release"):
        return "openwrt"
    return platform.system().lower()


def is_root() -> bool:
    """Check if running as root."""
    try:
        return os.getuid() == 0
    except AttributeError:
        return False


def list_interface_ips(interface: str) -> list[str]:
    """Return the interface's IPv4 addresses, primary first.

    Both ``ip addr`` and ``ifconfig`` list the primary address before any
    aliases, so position encodes the operator-configured address vs. alias
    additions.
    """
    plat = detect_platform()
    try:
        if plat == "darwin":
            r = subprocess.run(["ifconfig", interface],
                               capture_output=True, text=True, check=False)
        else:
            r = subprocess.run(["ip", "addr", "show", interface],
                               capture_output=True, text=True, check=False)
    except (FileNotFoundError, OSError):
        return []
    if r.returncode != 0:
        return []
    return re.findall(r"inet\s+(\d+\.\d+\.\d+\.\d+)", r.stdout)


def interface_has_ip(interface: str, ip_addr: str) -> bool:
    """True if *ip_addr* is already assigned to *interface*."""
    return ip_addr in list_interface_ips(interface)


def interface_addr_is_alias(interface: str, ip_addr: str) -> bool:
    """True if *ip_addr* may be an address conwrt added (safe to remove).

    A secondary address (listed after the primary) is alias-style — conwrt's
    own leftovers land there. A sole address on an otherwise empty interface
    is treated as an alias too (bare bench NIC carrying only a conwrt
    client_ip). A primary address sharing the interface with others is the
    operator's configuration and is never conwrt's to remove.
    """
    ips = list_interface_ips(interface)
    if ip_addr not in ips:
        return False
    return len(ips) == 1 or ips[0] != ip_addr


def configure_interface_ip(interface: str, ip_addr: str, subnet: str = "24") -> bool:
    """Add an IP address to a network interface.

    Uses ``ip addr`` on Linux/OpenWrt and ``ifconfig`` on macOS.
    """
    plat = detect_platform()

    if plat == "darwin":
        # macOS: check with ifconfig, add with ifconfig alias
        r = subprocess.run(
            ["ifconfig", interface],
            capture_output=True, text=True, check=False,
        )
        if r.returncode != 0:
            return False
        if ip_addr in r.stdout:
            return True
        cmd = ["ifconfig", interface, "inet", f"{ip_addr}/{subnet}", "alias"]
        if not is_root():
            cmd = ["sudo", "-n"] + cmd
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            if ("permission denied" in result.stderr.lower()
                    or "sorry" in result.stderr.lower()
                    or not result.stderr.strip()):
                import sys
                print(f"ERROR: sudo required to configure {interface}. "
                      f"Run 'sudo -v' in your terminal to cache credentials, then retry.",
                      file=sys.stderr)
            return False
        return True

    # Linux/OpenWrt: use ip addr
    r = subprocess.run(
        ["ip", "addr", "show", interface],
        capture_output=True, text=True, check=False,
    )
    if ip_addr in r.stdout:
        return True

    cmd = ["ip", "addr", "add", f"{ip_addr}/{subnet}", "dev", interface]
    if not is_root():
        cmd = ["sudo", "-n"] + cmd
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0 and "File exists" not in result.stderr:
        if is_root():
            return False
        # retry without sudo in case we have capabilities
        result2 = subprocess.run(
            ["ip", "addr", "add", f"{ip_addr}/{subnet}", "dev", interface],
            capture_output=True, text=True, check=False,
        )
        if result2.returncode != 0 and "File exists" not in result2.stderr:
            return False

    subprocess.run(
        ["ip", "link", "set", interface, "up"],
        capture_output=True, text=True, check=False,
    )
    return True


def remove_interface_ip(interface: str, ip_addr: str, subnet: str = "24") -> bool:
    """Remove an IP address alias from a network interface.

    Uses ``ifconfig`` on macOS and ``ip addr`` on Linux/OpenWrt.
    """
    plat = detect_platform()

    if plat == "darwin":
        cmd = ["ifconfig", interface, "inet", f"{ip_addr}/{subnet}", "-alias"]
        if not is_root():
            cmd = ["sudo", "-n"] + cmd
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return result.returncode == 0

    # Linux/OpenWrt: use ip addr del
    cmd = ["ip", "addr", "del", f"{ip_addr}/{subnet}", "dev", interface]
    if not is_root():
        cmd = ["sudo", "-n"] + cmd
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0 and "Cannot find device" not in result.stderr:
        if is_root():
            return False
        # retry without sudo
        result2 = subprocess.run(
            ["ip", "addr", "del", f"{ip_addr}/{subnet}", "dev", interface],
            capture_output=True, text=True, check=False,
        )
        return result2.returncode == 0
    return True


def get_link_state(interface: str) -> bool:
    """Check if an interface has carrier (link up)."""
    # Linux/OpenWrt: /sys/class/net/ (Linux kernel sysfs)
    try:
        r = subprocess.run(
            ["cat", f"/sys/class/net/{interface}/operstate"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if r.returncode == 0:
            return r.stdout.strip().lower() == "up"
    except (subprocess.SubprocessError, OSError):
        pass

    # macOS fallback: parse ifconfig output
    try:
        r = subprocess.run(
            ["ifconfig", interface],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if r.returncode == 0 and "status: active" in r.stdout.lower():
            return True
    except (subprocess.SubprocessError, OSError):
        pass

    return False


def add_host_route(interface: str, target_ip: str) -> bool:
    """Force traffic for a single host out a specific interface.

    Installs a ``/32`` route for *target_ip* via *interface* so recovery
    traffic uses the wired interface even when another interface (e.g. host
    WiFi) shares the target subnet. Returns True on success.
    """
    plat = detect_platform()
    if plat == "darwin":
        cmd = ["route", "-n", "add", "-host", target_ip, "-interface", interface]
    else:
        cmd = ["ip", "route", "replace", f"{target_ip}/32", "dev", interface]
    if not is_root():
        cmd = ["sudo", "-n"] + cmd
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=5, check=False)
        return result.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def remove_host_route(interface: str, target_ip: str) -> bool:
    """Remove a host route previously installed by :func:`add_host_route`."""
    plat = detect_platform()
    if plat == "darwin":
        cmd = ["route", "-n", "delete", "-host", target_ip]
    else:
        cmd = ["ip", "route", "del", f"{target_ip}/32", "dev", interface]
    if not is_root():
        cmd = ["sudo", "-n"] + cmd
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=5, check=False)
        return result.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def _which(tool: str) -> bool:
    from shutil import which
    return which(tool) is not None


def _macos_wifi_device() -> str:
    """Return the macOS WiFi BSD device name (e.g. en0), or ''."""
    try:
        result = subprocess.run(
            ["networksetup", "-listallhardwareports"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (subprocess.SubprocessError, OSError):
        return ""
    lines = result.stdout.splitlines()
    for i, line in enumerate(lines):
        if "Wi-Fi" in line or "AirPort" in line:
            for j in range(i + 1, min(i + 3, len(lines))):
                if lines[j].startswith("Device:"):
                    return lines[j].split(":", 1)[1].strip()
    return ""


def suspend_wifi() -> str:
    """Best-effort temporary WiFi shutdown; returns a token for :func:`restore_wifi`.

    Returns "" when no supported WiFi control tool is available (the caller
    should proceed — the wired host route is the primary collision fix).
    """
    plat = detect_platform()
    if plat == "darwin":
        device = _macos_wifi_device()
        if not device:
            return ""
        subprocess.run(["networksetup", "-setairportpower", device, "off"],
                       capture_output=True, text=True, check=False)
        return device
    if _which("nmcli"):
        subprocess.run(["nmcli", "radio", "wifi", "off"],
                       capture_output=True, text=True, check=False)
        return "nmcli"
    return ""


def restore_wifi(token: str) -> None:
    """Undo :func:`suspend_wifi` using the returned token."""
    if not token:
        return
    if token == "nmcli":
        subprocess.run(["nmcli", "radio", "wifi", "on"],
                       capture_output=True, text=True, check=False)
        return
    subprocess.run(["networksetup", "-setairportpower", token, "on"],
                   capture_output=True, text=True, check=False)


def has_scapy() -> bool:
    """Check if scapy is importable."""
    try:
        import scapy  # noqa: F401
        return True
    except ImportError:
        return False


def has_tcpdump() -> bool:
    """Check if tcpdump is available."""
    try:
        r = subprocess.run(
            ["which", "tcpdump"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        return r.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


def check_external_deps() -> list[str]:
    """Return list of missing external dependencies (curl, ssh)."""
    missing = []
    for tool in ["curl"]:
        try:
            r = subprocess.run(
                ["which", tool],
                capture_output=True, text=True, timeout=5, check=False,
            )
            if r.returncode != 0:
                missing.append(tool)
        except (subprocess.SubprocessError, OSError):
            missing.append(tool)
    try:
        subprocess.run(
            ["ssh", "-V"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except FileNotFoundError:
        missing.append("ssh (dropbear or openssh)")
    return missing
