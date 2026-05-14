"""Platform abstraction for conwrt — Linux, macOS, and OpenWrt."""
from __future__ import annotations

import os
import platform
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
        if ip_addr in r.stdout:
            return True
        cmd = ["ifconfig", interface, "inet", f"{ip_addr}/{subnet}", "alias"]
        if not is_root():
            cmd = ["sudo"] + cmd
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
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
    except Exception:
        pass

    # macOS fallback: parse ifconfig output
    try:
        r = subprocess.run(
            ["ifconfig", interface],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if r.returncode == 0 and "status: active" in r.stdout.lower():
            return True
    except Exception:
        pass

    return False


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
    except Exception:
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
        except Exception:
            missing.append(tool)
    try:
        subprocess.run(
            ["ssh", "-V"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except FileNotFoundError:
        missing.append("ssh (dropbear or openssh)")
    return missing
