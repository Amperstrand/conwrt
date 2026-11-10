#!/usr/bin/env python3
"""router-probe — comprehensive router state identification via passive and active probing.

Identifies router boot state by combining non-intrusive observation (link state,
packet capture, broadcast detection) with active probes (HTTP, SSH, ICMP).

Usage as CLI:
    python3 scripts/router-probe.py --interface en6 --ip 192.168.1.1

Usage as module:
    from router_probe import probe_router, RouterState
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import subprocess
import sys
import time
import importlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from datetime import datetime
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from probe_utils import curl_get, curl_head, ping_host
from ssh_utils import ssh_cmd, run_ssh
from oui import oui_lookup

logger = logging.getLogger("conwrt.probe")

REPO_ROOT = Path(__file__).resolve().parent.parent
CAPTURES_DIR = REPO_ROOT / "captures"

try:
    _auto_flash_run_cmd = importlib.import_module("auto_flash").run_cmd
    run_cmd = _auto_flash_run_cmd
except ImportError:
    def run_cmd(
        cmd: list[str],
        timeout: int | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        logger.debug("running: %s", " ".join(cmd))
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
        )


ProbeResult = tuple[str, str, str]

RouterStates = (
    "off",
    "uboot",
    "openwrt_booting",
    "openwrt_failsafe",
    "openwrt_running",
    "glinet_stock",
    "linksys_stock",
    "unknown",
)


@dataclass
class RouterState:
    """Result of probing a router's current state."""
    state: str = "unknown"
    ip: str = ""
    mac: str = ""
    model: str = ""
    vendor: str = ""
    firmware_version: str = ""
    uptime: str = ""
    ssh_key_count: int = 0
    evidence: list[ProbeResult] = field(default_factory=list)


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


# ---------------------------------------------------------------------------
# Passive probes (non-intrusive)
# ---------------------------------------------------------------------------

def probe_link_state(interface: str) -> ProbeResult:
    status = "no_link"
    detail = ""
    try:
        import platform
        if platform.system() == "Linux":
            try:
                operstate = Path(f"/sys/class/net/{interface}/operstate").read_text().strip()
                carrier = Path(f"/sys/class/net/{interface}/carrier").read_text().strip()
            except (OSError, PermissionError):
                operstate = ""
                carrier = "0"
            if operstate == "up" and carrier == "1":
                status = "link_up"
                detail = "interface up"
            try:
                addr = Path(f"/sys/class/net/{interface}/address").read_text().strip()
                if addr:
                    detail = f"local_mac={addr}"
            except (OSError, PermissionError):
                pass
        else:
            r = run_cmd(["ifconfig", interface], check=False)
            output = r.stdout
            if "status: active" in output:
                status = "link_up"
                detail = "interface active"
            elif "RUNNING" in output:
                status = "link_up"
                detail = "interface running"
            elif "media:" in output:
                m = re.search(r"media:\s*(.+)", output)
                if m:
                    detail = m.group(1).strip()
    except (subprocess.SubprocessError, OSError) as exc:
        detail = str(exc)
    return ("link_state", status, detail)


def probe_arp(mac_prefix: str, interface: str) -> ProbeResult:
    status = "not_seen"
    detail = ""
    try:
        r = run_cmd(["arp", "-a"], check=False)
        for line in r.stdout.splitlines():
            if mac_prefix and mac_prefix.lower() in line.lower():
                status = "seen"
                m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", line)
                detail = m.group(1) if m else line.strip()
                break
        if not mac_prefix:
            import platform
            if platform.system() == "Linux":
                try:
                    addr = Path(f"/sys/class/net/{interface}/address").read_text().strip()
                    if addr:
                        detail = f"local_mac={addr}"
                except (OSError, PermissionError):
                    pass
            else:
                r2 = run_cmd(["ifconfig", interface], check=False)
                ether_m = re.search(r"ether\s+([\da-fA-F:]{17})", r2.stdout)
                if ether_m:
                    detail = f"local_mac={ether_m.group(1)}"
    except (subprocess.SubprocessError, OSError) as exc:
        detail = str(exc)
    return ("arp_from_router", status, detail)


def probe_failsafe_broadcast(interface: str, timeout: int = 10) -> ProbeResult:
    status = "not_detected"
    detail = ""
    try:
        r = run_cmd(
            ["tcpdump", "-Ani", interface, "-c", "1", "-t", "port", "4919", "and", "udp"],
            timeout=timeout,
            check=False,
        )
        if "Please press button now to enter failsafe" in r.stdout:
            status = "detected"
            detail = "OpenWrt failsafe UDP broadcast on port 4919"
        elif r.returncode != 0 and "Permission denied" in r.stderr:
            status = "permission_denied"
            detail = "tcpdump requires sudo for packet capture"
    except subprocess.TimeoutExpired:
        status = "timeout"
        detail = f"no failsafe broadcast within {timeout}s"
    except FileNotFoundError:
        status = "unavailable"
        detail = "tcpdump not installed"
    except OSError as exc:
        detail = str(exc)
    return ("failsafe_broadcast", status, detail)


def probe_icmpv6_ra(interface: str, timeout: int = 5) -> ProbeResult:
    status = "not_detected"
    detail = ""
    try:
        r = run_cmd(
            ["tcpdump", "-Ani", interface, "-c", "1", "-t",
             "icmp6", "and", "ip6[40] == 134"],
            timeout=timeout,
            check=False,
        )
        if "router advertisement" in r.stdout.lower():
            status = "detected"
            detail = "ICMPv6 Router Advertisement seen"
        elif r.returncode != 0 and "Permission denied" in r.stderr:
            status = "permission_denied"
            detail = "tcpdump requires sudo"
    except subprocess.TimeoutExpired:
        status = "timeout"
        detail = f"no RA within {timeout}s"
    except FileNotFoundError:
        status = "unavailable"
        detail = "tcpdump not installed"
    except OSError as exc:
        detail = str(exc)
    return ("icmpv6_ra", status, detail)


# Regexes for DHCP option extraction from tcpdump -vv output.
# tcpdump prints:   Hostname Option (12), length 14: "tollgate-37c0"
# and:              Vendor-Class Option (60), length 7: "MSFT 5.0"
_DHCP_HOSTNAME_RE = re.compile(r'Hostname Option \(12\)[^:]*:\s*"([^"]*)"')
_DHCP_VENDOR_CLASS_RE = re.compile(r'Vendor-Class Option \(60\)[^:]*:\s*"([^"]*)"')
# Client MAC appears as:  Client-Ethernet-Address d8:5d:84:aa:bb:cc
# or in the summary line: Request from d8:5d:84:aa:bb:cc
_DHCP_CLIENT_MAC_RE = re.compile(
    r'(?:Client-Ethernet-Address\s+|Request from\s+)([\da-fA-F]{2}(?::[\da-fA-F]{2}){5})'
)

# TFTP RRQ: tcpdump prints "read request, filename vmlinux.gz.uImage.3912"
_TFTP_FILENAME_RE = re.compile(r'read request,?\s*filename:?\s*(\S+)')


def probe_dhcp(interface: str, timeout: int = 30) -> ProbeResult:
    """Passive probe: capture a DHCP packet to extract client identification.

    Runs tcpdump listening on ports 67/68 (DHCP server/client). When a
    packet is seen, extracts:
      - Client MAC address (for OUI vendor lookup)
      - Option 12: Hostname (e.g., "tollgate-37c0")
      - Option 60: Vendor class identifier (e.g., "MSFT 5.0")

    Returns a ProbeResult tuple: ("dhcp", status, detail).
    Status is "detected" on success, "timeout" if no packet arrives,
    "unavailable" if tcpdump is missing, "permission_denied" if no sudo.
    """
    status = "not_seen"
    detail = ""
    try:
        r = run_cmd(
            ["tcpdump", "-i", interface, "-nn", "-s", "0", "-vv",
             "port 67 or port 68", "-c", "1"],
            timeout=timeout,
            check=False,
        )
        output = r.stdout

        client_mac = ""
        mac_m = _DHCP_CLIENT_MAC_RE.search(output)
        if mac_m:
            client_mac = mac_m.group(1)

        hostname = ""
        host_m = _DHCP_HOSTNAME_RE.search(output)
        if host_m:
            hostname = host_m.group(1)

        vendor_class = ""
        vc_m = _DHCP_VENDOR_CLASS_RE.search(output)
        if vc_m:
            vendor_class = vc_m.group(1)

        if client_mac or hostname or vendor_class:
            status = "detected"
            parts = []
            if client_mac:
                parts.append(f"mac={client_mac}")
            if hostname:
                parts.append(f"hostname={hostname}")
            if vendor_class:
                parts.append(f"vendor_class={vendor_class}")
            detail = ", ".join(parts)
        elif r.returncode != 0 and "Permission denied" in r.stderr:
            status = "permission_denied"
            detail = "tcpdump requires sudo for packet capture"
        # else: packet captured but no recognizable DHCP fields → not_seen
    except subprocess.TimeoutExpired:
        status = "timeout"
        detail = f"no DHCP packet within {timeout}s"
    except FileNotFoundError:
        status = "unavailable"
        detail = "tcpdump not installed"
    except OSError as exc:
        detail = str(exc)
    return ("dhcp", status, detail)


def probe_tftp(interface: str, timeout: int = 30) -> ProbeResult:
    """Passive probe: capture a TFTP read request (RRQ) to extract filename.

    Bootloaders like U-Boot request specific filenames via TFTP when
    booting from network (e.g., "vmlinux.gz.uImage.3912"). Capturing
    this filename can identify the device model or boot configuration.

    Returns a ProbeResult tuple: ("tftp", status, detail).
    Status is "detected" with the filename in detail, "timeout" if no
    packet arrives, "unavailable" if tcpdump is missing.
    """
    status = "not_seen"
    detail = ""
    try:
        r = run_cmd(
            ["tcpdump", "-i", interface, "-nn", "-s", "0", "-vv",
             "port 69", "-c", "1"],
            timeout=timeout,
            check=False,
        )
        output = r.stdout

        filename = ""
        fn_m = _TFTP_FILENAME_RE.search(output)
        if fn_m:
            filename = fn_m.group(1).strip()

        if filename:
            status = "detected"
            detail = f"filename={filename}"
        elif r.returncode != 0 and "Permission denied" in r.stderr:
            status = "permission_denied"
            detail = "tcpdump requires sudo for packet capture"
        # else: non-RRQ TFTP packet or no match → not_seen
    except subprocess.TimeoutExpired:
        status = "timeout"
        detail = f"no TFTP packet within {timeout}s"
    except FileNotFoundError:
        status = "unavailable"
        detail = "tcpdump not installed"
    except OSError as exc:
        detail = str(exc)
    return ("tftp", status, detail)


def start_pcap_capture(interface: str, state_label: str) -> Optional[subprocess.Popen[bytes]]:
    CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    ts = _timestamp()
    outfile = CAPTURES_DIR / f"{ts}-{state_label}.pcap"
    try:
        proc = subprocess.Popen(
            ["tcpdump", "-i", interface, "-w", str(outfile), "-c", "500"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return proc
    except FileNotFoundError:
        logger.debug("tcpdump not available for pcap capture")
        return None
    except OSError as exc:
        logger.debug("pcap capture failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Active probes
# ---------------------------------------------------------------------------

def probe_http_get(device_ip: str) -> ProbeResult:
    status = "no_response"
    detail = ""
    try:
        rc, body, _err = curl_get(f"http://{device_ip}/", timeout=3)
        if "FIRMWARE UPDATE" in body:
            return ("http_get", "uboot", "U-Boot firmware update page detected via GET")
        if "firmware" in body.lower() and "<form" in body.lower():
            return ("http_get", "uboot", "U-Boot firmware form page detected via GET")
        if "luci" in body.lower() or "openwrt" in body.lower():
            return ("http_get", "openwrt_luci", "LuCI/OpenWrt web interface detected")
        if "gl-inet" in body.lower() or "glinet" in body.lower():
            return ("http_get", "glinet_stock", "GL.iNet admin panel detected")
        if "jnap" in body.lower() or "linksys" in body.lower():
            return ("http_get", "linksys_stock", "Linksys web interface detected")
        if "uIP" in body:
            return ("http_get", "uboot", "uIP server signature in body")
        if rc == 0 and len(body) > 0:
            status = "unknown_http"
            detail = f"got {len(body)} bytes, no known signature"
    except (subprocess.SubprocessError, OSError) as exc:
        detail = str(exc)
    return ("http_get", status, detail)


def probe_http_head(device_ip: str) -> ProbeResult:
    status = "no_response"
    detail = ""
    try:
        rc, headers, _err = curl_head(f"http://{device_ip}/", timeout=3)
        if "uIP" in headers:
            return ("http_head", "uboot", "Server header contains uIP")
        if "HTTP/1.1 405" in headers:
            return ("http_head", "method_not_allowed", "HEAD rejected with 405 (MT3000 U-Boot behavior)")
        if rc == 0 and headers.strip():
            status = "headers_received"
            server_m = re.search(r"Server:\s*(.+)", headers, re.IGNORECASE)
            detail = server_m.group(1).strip() if server_m else headers.split("\n")[0].strip()
    except (subprocess.SubprocessError, OSError) as exc:
        detail = str(exc)
    return ("http_head", status, detail)


def probe_ssh(device_ip: str) -> ProbeResult:
    status = "no_response"
    detail = ""
    try:
        r = run_ssh(
            device_ip,
            ["cat", "/etc/openwrt_release"],
            connect_timeout=3,
            timeout=8,
            ssh_options=["-o", "LogLevel=ERROR"],
        )
        if r.returncode == 0:
            release_info = r.stdout.strip()
            status = "openwrt_ssh"
            detail = release_info[:200]
        else:
            r2 = run_ssh(
                device_ip,
                ["true"],
                connect_timeout=3,
                timeout=8,
                ssh_options=["-o", "LogLevel=ERROR"],
            )
            if r2.returncode == 0:
                status = "ssh_ok"
                detail = "SSH connected but /etc/openwrt_release not found"
            elif "Permission denied" in r2.stderr or "permission denied" in r2.stderr.lower():
                status = "ssh_auth_required"
                detail = "SSH requires key/password"
            elif "Connection refused" in r2.stderr:
                status = "ssh_refused"
                detail = "SSH port closed"
    except subprocess.TimeoutExpired:
        status = "ssh_timeout"
        detail = "SSH connection timed out"
    except (subprocess.SubprocessError, OSError) as exc:
        detail = str(exc)
    return ("ssh", status, detail)


def probe_ssh_failsafe(device_ip: str) -> ProbeResult:
    status = "not_failsafe"
    detail = ""
    try:
        failsafe_cmd = ssh_cmd(device_ip, ["ls", "/tmp/failsafe"], connect_timeout=3)
        failsafe_cmd[1:1] = ["-o", "LogLevel=ERROR"]
        r = run_cmd(failsafe_cmd, timeout=8, check=False)
        if r.returncode == 0:
            status = "failsafe"
            detail = "/tmp/failsafe exists"
        else:
            r2 = run_ssh(
                device_ip,
                ["mount"],
                connect_timeout=3,
                timeout=8,
                ssh_options=["-o", "LogLevel=ERROR"],
            )
            if r2.returncode == 0 and "jffs2" not in r2.stdout and "overlay" not in r2.stdout:
                status = "failsafe"
                detail = "no overlay mount — likely failsafe mode"
    except (subprocess.SubprocessError, OSError) as exc:
        detail = str(exc)
    return ("ssh_failsafe", status, detail)


def probe_ping(device_ip: str) -> ProbeResult:
    status = "unreachable"
    detail = ""
    try:
        if ping_host(device_ip, timeout=2):
            status = "reachable"
            detail = "reply received"
    except (subprocess.SubprocessError, OSError) as exc:
        detail = str(exc)
    return ("ping", status, detail)


def probe_ssh_details(device_ip: str) -> tuple[str, str, str, int]:
    model = ""
    vendor = ""
    firmware_version = ""
    ssh_key_count = 0
    try:
        r = run_ssh(
            device_ip,
            ["cat", "/etc/openwrt_release"],
            connect_timeout=3,
            timeout=8,
            ssh_options=["-o", "LogLevel=ERROR"],
        )
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if "DISTRIB_ID" in line:
                    vendor = line.split("'", 1)[1].rstrip("'") if "'" in line else ""
                if "DISTRIB_RELEASE" in line:
                    firmware_version = line.split("'", 1)[1].rstrip("'") if "'" in line else ""
                if "DISTRIB_TARGET" in line:
                    pass

        r2 = run_ssh(
            device_ip,
            ["cat", "/tmp/sysinfo/model"],
            connect_timeout=3,
            timeout=8,
            ssh_options=["-o", "LogLevel=ERROR"],
        )
        if r2.returncode == 0:
            model = r2.stdout.strip()

        r3 = run_ssh(
            device_ip,
            ["wc", "-l", "/etc/dropbear/authorized_keys"],
            connect_timeout=3,
            timeout=8,
            ssh_options=["-o", "LogLevel=ERROR"],
        )
        if r3.returncode == 0:
            ssh_key_count = int(r3.stdout.strip().split()[0])
    except (subprocess.SubprocessError, OSError, ValueError):
        pass
    return model, vendor, firmware_version, ssh_key_count


# ---------------------------------------------------------------------------
# State classification
# ---------------------------------------------------------------------------

def classify_state(evidence: list[ProbeResult]) -> str:
    probe_map = {name: (result, detail) for name, result, detail in evidence}

    http_get = probe_map.get("http_get", ("no_response", ""))
    http_head = probe_map.get("http_head", ("no_response", ""))
    ssh_probe = probe_map.get("ssh", ("no_response", ""))
    link = probe_map.get("link_state", ("no_link", ""))
    failsafe_udp = probe_map.get("failsafe_broadcast", ("not_detected", ""))
    ping_result = probe_map.get("ping", ("unreachable", ""))
    ssh_failsafe = probe_map.get("ssh_failsafe", ("not_failsafe", ""))

    if http_get[0] == "uboot" or http_head[0] == "uboot":
        return "uboot"

    if ssh_probe[0] == "openwrt_ssh":
        if ssh_failsafe[0] == "failsafe":
            return "openwrt_failsafe"
        return "openwrt_running"

    if http_get[0] == "glinet_stock":
        return "glinet_stock"

    if http_get[0] == "linksys_stock":
        return "linksys_stock"

    if link[0] == "link_up" and failsafe_udp[0] == "detected" and ssh_probe[0] != "openwrt_ssh":
        return "openwrt_booting"

    if link[0] == "no_link" and ping_result[0] == "unreachable":
        return "off"

    if ping_result[0] == "reachable" or link[0] == "link_up":
        return "unknown"

    return "unknown"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def probe_router(
    interface: str = "",
    ip: str = "192.168.1.1",
    mac: str = "",
    passive_timeout: int = 10,
    verbose: bool = False,
) -> RouterState:
    """Probe a router and return its current state.

    Runs passive probes (link, ARP, broadcast capture) then active probes
    (HTTP, SSH, ping) to classify the router's boot state.
    """
    state = RouterState(ip=ip, mac=mac)
    pcap_proc = None

    pcap_proc = start_pcap_capture(interface, "probing")

    state.evidence.append(probe_link_state(interface))
    state.evidence.append(probe_arp(mac, interface))

    # Time-limited capture probes run in parallel to minimize wall-clock time.
    # Each blocks until a packet arrives or timeout expires; sequential would
    # cost up to 4x the timeout in total.
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {
            "failsafe": pool.submit(
                partial(probe_failsafe_broadcast, interface, timeout=passive_timeout)),
            "ra": pool.submit(
                partial(probe_icmpv6_ra, interface, timeout=min(passive_timeout, 5))),
            "dhcp": pool.submit(
                partial(probe_dhcp, interface, timeout=passive_timeout)),
            "tftp": pool.submit(
                partial(probe_tftp, interface, timeout=passive_timeout)),
        }
        for key in ("failsafe", "ra", "dhcp", "tftp"):
            state.evidence.append(futures[key].result())

    # OUI-based hardware vendor identification from MAC address.
    # This gives the hardware manufacturer (e.g., "D-Link"); if the device
    # is running OpenWrt, probe_ssh_details will override with the OS vendor.
    if mac:
        vendor = oui_lookup(mac)
        if vendor:
            state.vendor = vendor

    state.evidence.append(probe_http_get(ip))
    state.evidence.append(probe_http_head(ip))
    state.evidence.append(probe_ping(ip))
    state.evidence.append(probe_ssh(ip))
    state.evidence.append(probe_ssh_failsafe(ip))

    state.state = classify_state(state.evidence)

    if state.state == "openwrt_running":
        model, vendor, fw_ver, key_count = probe_ssh_details(ip)
        state.model = model
        if vendor:
            state.vendor = vendor
        state.firmware_version = fw_ver
        state.ssh_key_count = key_count

    if pcap_proc and pcap_proc.poll() is None:
        time.sleep(2)
        pcap_proc.terminate()
        try:
            pcap_proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pcap_proc.kill()

    if verbose:
        for name, result, detail in state.evidence:
            print(f"  {name}: {result} — {detail}")

    return state


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Probe a router to identify its current boot state",
    )
    parser.add_argument("--interface", "-i", default="", help="Network interface to probe on (auto-detected if omitted)")
    parser.add_argument("--ip", default="192.168.1.1", help="Target IP address")
    parser.add_argument("--mac", default="", help="Expected router MAC address")
    parser.add_argument("--passive-timeout", type=int, default=10, help="Seconds to listen for broadcasts")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show individual probe results")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s: %(message)s")

    result = probe_router(
        interface=args.interface,
        ip=args.ip,
        mac=args.mac,
        passive_timeout=args.passive_timeout,
        verbose=args.verbose,
    )
    print(json.dumps({
        "state": result.state,
        "ip": result.ip,
        "mac": result.mac,
        "model": result.model,
        "vendor": result.vendor,
        "firmware_version": result.firmware_version,
        "uptime": result.uptime,
        "ssh_key_count": result.ssh_key_count,
        "evidence": [
            {"probe": name, "result": res, "detail": det}
            for name, res, det in result.evidence
        ],
    }, indent=2))


if __name__ == "__main__":
    main()
