#!/usr/bin/env python3
"""router-probe — comprehensive router state identification via passive and active probing.

Identifies router boot state by combining non-intrusive observation (link state,
packet capture, broadcast detection) with active probes (HTTP, SSH, ICMP).

Usage as CLI:
    python3 scripts/router-probe.py --interface en6 --ip 192.168.1.1

Usage as module:
    from router_probe import probe_router, RouterState
"""

import argparse
import json
import logging
import os
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger("conwrt.probe")

REPO_ROOT = Path(__file__).resolve().parent.parent
CAPTURES_DIR = REPO_ROOT / "captures"

try:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from auto_flash import run_cmd as _auto_flash_run_cmd
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
    except Exception as exc:
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
            r2 = run_cmd(["ifconfig", interface], check=False)
            ether_m = re.search(r"ether\s+([\da-fA-F:]{17})", r2.stdout)
            if ether_m:
                detail = f"local_mac={ether_m.group(1)}"
    except Exception as exc:
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
    except Exception as exc:
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
    except Exception as exc:
        detail = str(exc)
    return ("icmpv6_ra", status, detail)


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
    except Exception as exc:
        logger.debug("pcap capture failed: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Active probes
# ---------------------------------------------------------------------------

def probe_http_get(device_ip: str) -> ProbeResult:
    status = "no_response"
    detail = ""
    try:
        r = run_cmd(
            ["curl", "-s", "--max-time", "3", f"http://{device_ip}/"],
            check=False,
        )
        body = r.stdout
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
        if r.returncode == 0 and len(body) > 0:
            status = "unknown_http"
            detail = f"got {len(body)} bytes, no known signature"
    except Exception as exc:
        detail = str(exc)
    return ("http_get", status, detail)


def probe_http_head(device_ip: str) -> ProbeResult:
    status = "no_response"
    detail = ""
    try:
        r = run_cmd(
            ["curl", "-sI", "--max-time", "3", f"http://{device_ip}/"],
            check=False,
        )
        headers = r.stdout
        if "uIP" in headers:
            return ("http_head", "uboot", f"Server header contains uIP")
        if "HTTP/1.1 405" in headers:
            return ("http_head", "method_not_allowed", "HEAD rejected with 405 (MT3000 U-Boot behavior)")
        if r.returncode == 0 and headers.strip():
            status = "headers_received"
            server_m = re.search(r"Server:\s*(.+)", headers, re.IGNORECASE)
            detail = server_m.group(1).strip() if server_m else headers.split("\n")[0].strip()
    except Exception as exc:
        detail = str(exc)
    return ("http_head", status, detail)


def probe_ssh(device_ip: str) -> ProbeResult:
    status = "no_response"
    detail = ""
    try:
        r = run_cmd(
            ["ssh", "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null",
             "-o", "ConnectTimeout=3",
             "-o", "LogLevel=ERROR",
             "-o", "BatchMode=yes",
             f"root@{device_ip}", "cat", "/etc/openwrt_release"],
            timeout=8,
            check=False,
        )
        if r.returncode == 0:
            release_info = r.stdout.strip()
            status = "openwrt_ssh"
            detail = release_info[:200]
        else:
            r2 = run_cmd(
                ["ssh", "-o", "StrictHostKeyChecking=no",
                 "-o", "UserKnownHostsFile=/dev/null",
                 "-o", "ConnectTimeout=3",
                 "-o", "LogLevel=ERROR",
                 "-o", "BatchMode=yes",
                 f"root@{device_ip}", "true"],
                timeout=8,
                check=False,
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
    except Exception as exc:
        detail = str(exc)
    return ("ssh", status, detail)


def probe_ssh_failsafe(device_ip: str) -> ProbeResult:
    status = "not_failsafe"
    detail = ""
    try:
        r = run_cmd(
            ["ssh", "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null",
             "-o", "ConnectTimeout=3",
             "-o", "LogLevel=ERROR",
             "-o", "BatchMode=yes",
             f"root@{device_ip}", "ls", "/tmp/failsafe"],
            timeout=8,
            check=False,
        )
        if r.returncode == 0:
            status = "failsafe"
            detail = "/tmp/failsafe exists"
        else:
            r2 = run_cmd(
                ["ssh", "-o", "StrictHostKeyChecking=no",
                 "-o", "UserKnownHostsFile=/dev/null",
                 "-o", "ConnectTimeout=3",
                 "-o", "LogLevel=ERROR",
                 "-o", "BatchMode=yes",
                 f"root@{device_ip}", "mount"],
                timeout=8,
                check=False,
            )
            if r2.returncode == 0 and "jffs2" not in r2.stdout and "overlay" not in r2.stdout:
                status = "failsafe"
                detail = "no overlay mount — likely failsafe mode"
    except Exception as exc:
        detail = str(exc)
    return ("ssh_failsafe", status, detail)


def probe_ping(device_ip: str) -> ProbeResult:
    status = "unreachable"
    detail = ""
    try:
        r = run_cmd(
            ["ping", "-c", "1", "-W", "2", "-t", "1", device_ip],
            check=False,
        )
        if r.returncode == 0:
            m = re.search(r"time[= ]([\d.]+)\s*ms", r.stdout)
            detail = f"reply in {m.group(1)}ms" if m else "reply received"
            status = "reachable"
    except Exception as exc:
        detail = str(exc)
    return ("ping", status, detail)


def probe_ssh_details(device_ip: str) -> tuple[str, str, str, int]:
    model = ""
    vendor = ""
    firmware_version = ""
    ssh_key_count = 0
    try:
        r = run_cmd(
            ["ssh", "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null",
             "-o", "ConnectTimeout=3",
             "-o", "LogLevel=ERROR",
             "-o", "BatchMode=yes",
             f"root@{device_ip}",
             "cat", "/etc/openwrt_release"],
            timeout=8,
            check=False,
        )
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if "DISTRIB_ID" in line:
                    vendor = line.split("'", 1)[1].rstrip("'") if "'" in line else ""
                if "DISTRIB_RELEASE" in line:
                    firmware_version = line.split("'", 1)[1].rstrip("'") if "'" in line else ""
                if "DISTRIB_TARGET" in line:
                    pass

        r2 = run_cmd(
            ["ssh", "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null",
             "-o", "ConnectTimeout=3",
             "-o", "LogLevel=ERROR",
             "-o", "BatchMode=yes",
             f"root@{device_ip}",
             "cat", "/tmp/sysinfo/model"],
            timeout=8,
            check=False,
        )
        if r2.returncode == 0:
            model = r2.stdout.strip()

        r3 = run_cmd(
            ["ssh", "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null",
             "-o", "ConnectTimeout=3",
             "-o", "LogLevel=ERROR",
             "-o", "BatchMode=yes",
             f"root@{device_ip}",
             "wc", "-l", "/etc/dropbear/authorized_keys"],
            timeout=8,
            check=False,
        )
        if r3.returncode == 0:
            ssh_key_count = int(r3.stdout.strip().split()[0])
    except Exception:
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
    interface: str = "en0",
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
    state.evidence.append(probe_failsafe_broadcast(interface, timeout=passive_timeout))
    state.evidence.append(probe_icmpv6_ra(interface, timeout=min(passive_timeout, 5)))

    state.evidence.append(probe_http_get(ip))
    state.evidence.append(probe_http_head(ip))
    state.evidence.append(probe_ping(ip))
    state.evidence.append(probe_ssh(ip))
    state.evidence.append(probe_ssh_failsafe(ip))

    state.state = classify_state(state.evidence)

    if state.state == "openwrt_running":
        model, vendor, fw_ver, key_count = probe_ssh_details(ip)
        state.model = model
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
    parser.add_argument("--interface", "-i", default="en0", help="Network interface to probe on")
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
