#!/usr/bin/env python3
"""Auto-detect routers on the local ethernet segment."""

import argparse
import json
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lldp import (
    LLDPInfo as LLDPInfo,
    lldp_probe as lldp_probe,
    _parse_lldp_hex_block as _parse_lldp_hex_block,
    _parse_zyxel_lldp as _parse_zyxel_lldp,
)
from model_match import (
    lookup_mac_vendor,
    match_models_by_oui,
    match_model_by_board,
    match_model_by_http,
    match_model_by_lldp,
    _normalize_mac,
    _mac_prefix as _mac_prefix,  # re-export for tests
)
from platform_utils import configure_interface_ip, detect_platform, get_link_state, is_root
from probe_utils import curl_get as _curl_get, curl_head as _curl_head, ping_host as _ping
from router_classify import classify_http_response, classify_web_ui, assess_readiness
from router_display import _print_router, interactive_menu
from ssh_utils import run_ssh


COMMON_GATEWAY_IPS = [
    "192.168.0.1",
    "192.168.1.1",
    "192.168.8.1",
    "10.0.0.1",
    "192.168.2.1",
]

SEPARATOR = "=" * 45


@dataclass
class DetectedRouter:
    ip: str
    mac: str
    vendor: str = ""
    model_id: str = ""
    model_name: str = ""
    firmware_state: str = ""
    confidence: str = ""
    web_ui_type: str = ""
    ssh_available: bool = False
    ssh_info: dict = field(default_factory=dict)
    dhcp_server: bool = False
    dhcp_info: dict = field(default_factory=dict)
    http_response_preview: str = ""
    http_headers: str = ""
    evidence: list = field(default_factory=list)
    flash_methods: list = field(default_factory=list)
    default_password: str = ""
    lldp_info: Optional[LLDPInfo] = None
    stock_firmware_version: str = ""
    readiness: dict = field(default_factory=dict)


def _add_evidence(router: DetectedRouter, phase: str, message: str) -> None:
    router.evidence.append(f"[{phase}] {message}")


def _ensure_route(subnet_ip: str, interface: str) -> bool:
    """Ensure a subnet route exists via the given interface on macOS/Linux."""
    parts = subnet_ip.split(".")
    subnet = ".".join(parts[:3])
    target_net = f"{subnet}.0/24"
    plat = detect_platform()

    try:
        if plat == "darwin":
            r = subprocess.run(
                ["netstat", "-rn", "-f", "inet"],
                capture_output=True, text=True, timeout=5, check=False,
            )
            if r.returncode == 0 and target_net in r.stdout:
                return True
            our_ip = f"{subnet}.2"
            cmd = ["route", "add", "-net", target_net, our_ip]
            if not is_root():
                cmd = ["sudo", "-n"] + cmd
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
            return result.returncode == 0
        else:
            r = subprocess.run(
                ["ip", "route", "show", target_net],
                capture_output=True, text=True, timeout=5, check=False,
            )
            if r.returncode == 0 and r.stdout.strip():
                return True
            our_ip = f"{subnet}.2"
            configure_interface_ip(interface, our_ip, "24")
            return True
    except (subprocess.SubprocessError, OSError):
        return False



# Phase 1: Passive Listen

def passive_listen(interface: str, timeout: int = 10) -> dict:
    result: dict = {
        "macs": {},
        "dhcp_servers": [],
        "arp_hosts": [],
        "icmpv6_routers": [],
    }

    try:
        from scapy.all import sniff, DHCP, ARP, ICMPv6ND_RA, Ether, conf
    except ImportError:
        _passive_listen_tcpdump(interface, timeout, result)
        return result

    def _packet_callback(pkt):
        if pkt.haslayer(DHCP):
            dhcp_layer = pkt[DHCP]
            src_mac = _normalize_mac(pkt[Ether].src) if pkt.haslayer(Ether) else ""
            if src_mac and src_mac not in result["macs"]:
                result["macs"][src_mac] = {"source": "dhcp"}
            for opt_type, opt_val in dhcp_layer.options:
                if opt_type == "router" and opt_val:
                    result["dhcp_servers"].append({
                        "ip": opt_val,
                        "mac": src_mac,
                    })
                    if src_mac:
                        result["macs"][src_mac]["ip"] = opt_val

        elif pkt.haslayer(ARP):
            arp = pkt[ARP]
            src_mac = _normalize_mac(arp.hwsrc) if arp.hwsrc else ""
            src_ip = arp.psrc
            if src_mac and src_ip and src_ip != "0.0.0.0":
                if src_mac not in result["macs"]:
                    result["macs"][src_mac] = {"source": "arp", "ip": src_ip}
                else:
                    result["macs"][src_mac].setdefault("ip", src_ip)
                result["arp_hosts"].append({"mac": src_mac, "ip": src_ip})

        elif pkt.haslayer(ICMPv6ND_RA):
            src_mac = _normalize_mac(pkt[Ether].src) if pkt.haslayer(Ether) else ""
            if src_mac and src_mac not in result["macs"]:
                result["macs"][src_mac] = {"source": "icmpv6_ra"}
            result["icmpv6_routers"].append({"mac": src_mac})

    try:
        conf.iface = interface
        sniff(iface=interface, timeout=timeout, store=False, prn=_packet_callback)
    except (PermissionError, OSError):
        _passive_listen_tcpdump(interface, timeout, result)

    return result


def _passive_listen_tcpdump(interface: str, timeout: int, result: dict) -> None:
    tcpdump_path = None
    for candidate in ["tcpdump", "/usr/sbin/tcpdump"]:
        try:
            r = subprocess.run(
                ["which", candidate],
                capture_output=True, text=True, timeout=5, check=False,
            )
            if r.returncode == 0:
                tcpdump_path = candidate
                break
        except (subprocess.SubprocessError, FileNotFoundError):
            continue

    if not tcpdump_path:
        return

    try:
        proc = subprocess.Popen(
            [
                "sudo", "-n", tcpdump_path,
                "-i", interface,
                "-c", "200",
                "-l", "-n",
                "port 67 or port 68 or arp or icmp6",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        end_time = time.monotonic() + timeout
        while time.monotonic() < end_time:
            line = proc.stdout.readline()
            if not line:
                break
            arp_match = re.search(
                r"ARP?,? Reply\s+(\S+)\s+is-at\s+(\S+)", line, re.IGNORECASE,
            )
            if arp_match:
                ip_addr = arp_match.group(1)
                mac = _normalize_mac(arp_match.group(2).rstrip(","))
                result["arp_hosts"].append({"mac": mac, "ip": ip_addr})
                result["macs"][mac] = {"source": "arp", "ip": ip_addr}
        proc.terminate()
        proc.wait(timeout=3)
    except (subprocess.SubprocessError, OSError):
        pass


# Phase 2: DHCP Client Probe

def dhcp_client_probe(interface: str, timeout: int = 5) -> dict:
    result: dict = {
        "gateway_ip": "",
        "subnet_mask": "",
        "dns_server": "",
        "lease_time": "",
        "server_mac": "",
    }

    try:
        from scapy.all import Ether, IP, UDP, DHCP, srp1, conf
    except ImportError:
        return result

    dhcp_discover = (
        Ether(dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / DHCP(options=[
            ("message-type", "discover"),
            ("param_req_list", [1, 3, 6, 51]),
            ("end"),
        ])
    )

    try:
        conf.iface = interface
        reply = srp1(dhcp_discover, iface=interface, timeout=timeout, verbose=False)
    except (PermissionError, OSError):
        return result

    if reply is None:
        return result

    if reply.haslayer(DHCP):
        dhcp_layer = reply[DHCP]
        result["server_mac"] = _normalize_mac(reply[Ether].src) if reply.haslayer(Ether) else ""

        msg_type = None
        for opt_type, opt_val in dhcp_layer.options:
            if opt_type == "message-type":
                msg_type = opt_val
            elif opt_type == "router":
                result["gateway_ip"] = opt_val
            elif opt_type == "subnet_mask":
                result["subnet_mask"] = opt_val
            elif opt_type == "name_server":
                result["dns_server"] = opt_val
            elif opt_type == "lease_time":
                result["lease_time"] = str(opt_val)

        if msg_type != 2:
            result["gateway_ip"] = ""

    return result


# Phase 3: ARP Scan

def arp_scan(interface: str, target_ips: Optional[list[str]] = None) -> list[dict]:
    if target_ips is None:
        target_ips = list(COMMON_GATEWAY_IPS)

    found: list[dict] = []

    try:
        from scapy.all import ARP, Ether, srp1, conf
    except ImportError:
        return _arp_scan_fallback(interface, target_ips)

    for ip in target_ips:
        subnet = ".".join(ip.split(".")[:3])
        our_ip = f"{subnet}.10"
        configure_interface_ip(interface, our_ip, "24")
        time.sleep(0.3)

        arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        try:
            conf.iface = interface
            reply = srp1(arp_req, iface=interface, timeout=3, verbose=False)
        except (PermissionError, OSError):
            reply = _arp_lookup(ip)

        if reply and reply.haslayer(ARP):
            found.append({
                "ip": ip,
                "mac": _normalize_mac(reply[ARP].hwsrc),
            })

    return found


def _arp_scan_fallback(interface: str, target_ips: list[str]) -> list[dict]:
    found: list[dict] = []
    for ip in target_ips:
        subnet = ".".join(ip.split(".")[:3])
        our_ip = f"{subnet}.10"
        configure_interface_ip(interface, our_ip, "24")
        time.sleep(0.3)

        if _ping(ip, timeout=2):
            mac = _arp_lookup(ip)
            if mac:
                found.append({"ip": ip, "mac": _normalize_mac(mac)})
    return found


def _arp_lookup(ip: str) -> str:
    plat = detect_platform()
    if plat == "darwin":
        cmd = ["arp", "-n", ip]
    else:
        cmd = ["arp", "-n", ip]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
        match = re.search(r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})", r.stdout)
        if match:
            return match.group(1)
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    return ""


# Phase 4: Active Probing

def probe_http_get(ip: str) -> dict:
    rc, body, err = _curl_get(f"http://{ip}/")
    if rc == -1:
        return {"success": False, "body": "", "error": err}
    return {"success": rc == 0, "body": body, "error": err}


def probe_http_head(ip: str) -> dict:
    rc, headers, err = _curl_head(f"http://{ip}/")
    if rc == -1:
        return {"success": False, "headers": "", "error": err}
    return {"success": rc == 0, "headers": headers, "error": err}


def probe_ssh(ip: str, port: int = 22) -> dict:
    result: dict = {
        "available": False,
        "banner": "",
        "board_json": "",
        "info": {},
    }
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        sock.close()
        result["banner"] = banner

        if "ssh" in banner.lower():
            result["available"] = True
            r = run_ssh(ip, "cat /etc/board.json", connect_timeout=5, timeout=10)
            if r.returncode == 0:
                result["board_json"] = r.stdout.strip()
                try:
                    board = json.loads(r.stdout)
                    result["info"] = {
                        "model": board.get("model", {}).get("id", ""),
                        "target": "",
                    }
                except json.JSONDecodeError:
                    pass

            r2 = run_ssh(ip, "cat /etc/openwrt_release", connect_timeout=5, timeout=10)
            if r2.returncode == 0:
                result["info"]["openwrt_release"] = r2.stdout.strip()

    except (socket.timeout, ConnectionRefusedError, OSError):
        pass

    return result


def probe_hnap(ip: str) -> dict:
    url = f"http://{ip}/HNAP1/"
    headers = [
        "-H", "Content-Type: text/xml; charset=utf-8",
        "-H", 'SOAPAction: "http://purenetworks.com/HNAP1/GetDeviceSettings"',
        "-X", "POST",
        "-d", '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><GetDeviceSettings></GetDeviceSettings></soap:Body></soap:Envelope>',
    ]
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", "3"] + headers + [url],
            capture_output=True, text=True, timeout=5, check=False,
        )
        return {
            "success": r.returncode == 0 and len(r.stdout) > 0,
            "body": r.stdout[:2000],
            "detected": "HNAP" in r.stdout or "GetDeviceSettings" in r.stdout,
        }
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return {"success": False, "body": "", "detected": False}


def probe_ping(ip: str) -> bool:
    return _ping(ip)


def active_probe(ip: str) -> dict:
    probe_data: dict = {
        "ip": ip,
        "http_get": {},
        "http_head": {},
        "ssh": {},
        "hnap": {},
        "ping": False,
    }

    probe_data["ping"] = probe_ping(ip)
    probe_data["http_get"] = probe_http_get(ip)
    probe_data["http_head"] = probe_http_head(ip)
    probe_data["ssh"] = probe_ssh(ip)
    probe_data["hnap"] = probe_hnap(ip)

    return probe_data


# Phase 5: Identification


def identify_router(probe_data: dict, passive_data: dict, lldp_data: Optional[dict[str, LLDPInfo]] = None) -> DetectedRouter:
    ip = probe_data["ip"]
    mac = ""

    for entry in passive_data.get("arp_hosts", []):
        if entry["ip"] == ip:
            mac = entry["mac"]
            break
    if not mac:
        for entry in passive_data.get("dhcp_servers", []):
            if entry["ip"] == ip:
                mac = entry.get("mac", "")
                break
    if not mac:
        mac_lookup = _arp_lookup(ip)
        if mac_lookup:
            mac = _normalize_mac(mac_lookup)

    # Try LLDP for MAC if not found yet
    lldp_info: Optional[LLDPInfo] = None
    if lldp_data:
        for _, info in lldp_data.items():
            if info.management_ip == ip:
                lldp_info = info
                if not mac and info.chassis_mac:
                    mac = _normalize_mac(info.chassis_mac)
                break
        if not lldp_info and lldp_data:
            first_info = next(iter(lldp_data.values()))
            lldp_info = first_info
            if not mac and first_info.chassis_mac:
                mac = _normalize_mac(first_info.chassis_mac)

    if not mac:
        mac = "unknown"

    router = DetectedRouter(ip=ip, mac=mac, lldp_info=lldp_info)
    _add_evidence(router, "probe", f"Probing {ip}")

    if lldp_info:
        if lldp_info.chassis_name:
            _add_evidence(router, "lldp", f"LLDP chassis: {lldp_info.chassis_name}")
        if lldp_info.management_ip:
            _add_evidence(router, "lldp", f"LLDP management IP: {lldp_info.management_ip}")
        zyxel_fw = lldp_info.vendor_specific.get("zyxel_firmware", "")
        zyxel_dev = lldp_info.vendor_specific.get("zyxel_device", "")
        if zyxel_fw:
            router.stock_firmware_version = zyxel_fw
            _add_evidence(router, "lldp", f"ZyXEL firmware: {zyxel_fw}")
        if zyxel_dev:
            _add_evidence(router, "lldp", f"ZyXEL device: {zyxel_dev}")
        if lldp_info.management_url:
            _add_evidence(router, "lldp", f"Management URL: {lldp_info.management_url}")

    body = probe_data.get("http_get", {}).get("body", "")
    headers = probe_data.get("http_head", {}).get("headers", "")
    ssh_data = probe_data.get("ssh", {})
    hnap_data = probe_data.get("hnap", {})

    router.firmware_state = classify_http_response(body, headers)
    router.web_ui_type = classify_web_ui(probe_data)

    if body:
        preview = body[:500] if len(body) > 500 else body
        router.http_response_preview = preview
        _add_evidence(router, "http", f"GET response: {len(body)} bytes, classified as {router.firmware_state}")
    if headers:
        router.http_headers = headers
        _add_evidence(router, "http", f"HEAD headers: {headers[:200]}")

    # Override firmware_state with web_ui_type for ZyXEL
    if router.web_ui_type == "zyxel_stock" and router.firmware_state != "openwrt":
        router.firmware_state = "zyxel_stock"

    router.ssh_available = ssh_data.get("available", False)
    if router.ssh_available:
        router.ssh_info = ssh_data.get("info", {})
        _add_evidence(router, "ssh", f"SSH banner: {ssh_data.get('banner', '')}")

    if hnap_data.get("detected"):
        _add_evidence(router, "hnap", "HNAP API detected")

    if passive_data.get("dhcp_servers"):
        for dhcp in passive_data["dhcp_servers"]:
            if dhcp["ip"] == ip:
                router.dhcp_server = True
                router.dhcp_info = {
                    "gateway": dhcp["ip"],
                    "mac": dhcp.get("mac", ""),
                }
                _add_evidence(router, "dhcp", f"DHCP server at {ip}")
                break

    vendor = ""
    if mac != "unknown":
        vendor = lookup_mac_vendor(mac)
    router.vendor = vendor
    _add_evidence(router, "oui", f"MAC vendor lookup: {vendor or 'unknown'}")

    oui_models = match_models_by_oui(mac) if mac != "unknown" else []
    _add_evidence(router, "model", f"OUI model matches: {[m['id'] for m in oui_models]}")

    board_match = None
    if router.ssh_available and ssh_data.get("board_json"):
        board_match = match_model_by_board(ssh_data["board_json"])
        if board_match:
            _add_evidence(router, "model", f"Board match: {board_match['id']}")

    http_matches = match_model_by_http(body, headers)
    if http_matches:
        _add_evidence(router, "model", f"HTTP matches: {[m['id'] for m in http_matches]}")

    lldp_matches: list[dict] = []
    if lldp_info:
        lldp_matches = match_model_by_lldp(lldp_info)
        if lldp_matches:
            _add_evidence(router, "model", f"LLDP matches: {[m['id'] for m in lldp_matches]}")

    matched_model = None
    confidence = ""

    if board_match:
        matched_model = board_match
        confidence = "certain"
    elif lldp_matches:
        matched_model = lldp_matches[0]
        if oui_models and any(m["id"] == matched_model["id"] for m in oui_models):
            confidence = "certain"
        else:
            confidence = "likely"
    elif http_matches:
        matched_model = http_matches[0]
        if oui_models and any(m["id"] == matched_model["id"] for m in oui_models):
            confidence = "certain"
        else:
            confidence = "likely"
    elif oui_models:
        matched_model = oui_models[0]
        confidence = "possible"

    if matched_model:
        router.model_id = matched_model.get("id", "")
        router.model_name = matched_model.get("description", "")
        router.flash_methods = list(matched_model.get("flash_methods", {}).keys())
        router.confidence = confidence

        if not router.vendor:
            router.vendor = matched_model.get("vendor", "")

        for _method_name, method_cfg in matched_model.get("flash_methods", {}).items():
            if "default_password" in method_cfg:
                router.default_password = method_cfg["default_password"]
                break

        _add_evidence(router, "model", f"Final: {router.model_id} ({confidence})")
    else:
        router.confidence = "possible"
        _add_evidence(router, "model", "No model match found")

    router.readiness = assess_readiness(router)

    return router


# Main Orchestration

def auto_detect(interface: str, passive_timeout: int = 10) -> list[DetectedRouter]:
    if not get_link_state(interface):
        print(f"Warning: No link detected on {interface}. Check cable.")

    discovered_ips: dict[str, str] = {}
    all_passive: dict = {"macs": {}, "dhcp_servers": [], "arp_hosts": [], "icmpv6_routers": []}

    print(f"[Phase 1] Passive listening on {interface} ({passive_timeout}s)...")
    passive = passive_listen(interface, timeout=passive_timeout)
    for mac, info in passive.get("macs", {}).items():
        all_passive["macs"][mac] = info
    all_passive["dhcp_servers"].extend(passive.get("dhcp_servers", []))
    all_passive["arp_hosts"].extend(passive.get("arp_hosts", []))
    all_passive["icmpv6_routers"].extend(passive.get("icmpv6_routers", []))

    for entry in all_passive["arp_hosts"]:
        discovered_ips.setdefault(entry["ip"], entry["mac"])
    for entry in all_passive["dhcp_servers"]:
        if entry.get("ip"):
            discovered_ips.setdefault(entry["ip"], entry.get("mac", ""))

    print(f"  Found {len(passive.get('macs', {}))} MACs, {len(all_passive['arp_hosts'])} ARP hosts, {len(all_passive['dhcp_servers'])} DHCP servers")

    # LLDP phase — run concurrently with passive
    lldp_results: dict[str, LLDPInfo] = {}
    print("[Phase 1b] LLDP probe...")
    lldp_results = lldp_probe(interface, timeout=8)
    if lldp_results:
        for _ip_key, info in lldp_results.items():
            if info.management_ip:
                discovered_ips.setdefault(info.management_ip, info.chassis_mac)
            print(f"  LLDP: {info.chassis_name or info.chassis_mac} at {info.management_ip or 'unknown IP'}")
            zyxel_fw = info.vendor_specific.get("zyxel_firmware", "")
            if zyxel_fw:
                print(f"    Firmware: {zyxel_fw}")
            zyxel_dev = info.vendor_specific.get("zyxel_device", "")
            if zyxel_dev:
                print(f"    Device: {zyxel_dev}")
    else:
        print("  No LLDP frames captured")

    dhcp_gateway = ""
    if not all_passive["dhcp_servers"]:
        print("[Phase 2] DHCP client probe...")
        dhcp_result = dhcp_client_probe(interface, timeout=5)
        if dhcp_result["gateway_ip"]:
            dhcp_gateway = dhcp_result["gateway_ip"]
            discovered_ips.setdefault(dhcp_gateway, dhcp_result.get("server_mac", ""))
            all_passive["dhcp_servers"].append({
                "ip": dhcp_gateway,
                "mac": dhcp_result.get("server_mac", ""),
            })
            all_passive["macs"][dhcp_result.get("server_mac", "")] = {
                "source": "dhcp_probe",
                "ip": dhcp_gateway,
            }
            print(f"  DHCP gateway: {dhcp_gateway}")
        else:
            print("  No DHCP offer received")
    else:
        print("[Phase 2] Skipping (DHCP already discovered)")

    if not discovered_ips:
        print("[Phase 3] ARP scan of common gateway IPs...")
        arp_results = arp_scan(interface)
        for entry in arp_results:
            discovered_ips.setdefault(entry["ip"], entry["mac"])
        print(f"  ARP found {len(arp_results)} hosts: {list(discovered_ips.keys())}")
    else:
        print("[Phase 3] Skipping (hosts already discovered)")

    if not discovered_ips:
        print("No devices found on any phase.")
        return []

    # Ensure routes exist for discovered IPs
    for ip in discovered_ips:
        _ensure_route(ip, interface)

    print(f"[Phase 4] Active probing {len(discovered_ips)} host(s)...")
    probed_routers: list[DetectedRouter] = []
    for ip in sorted(discovered_ips.keys()):
        print(f"  Probing {ip}...")
        probe_data = active_probe(ip)
        print(f"[Phase 5] Identifying {ip}...")
        router = identify_router(probe_data, all_passive, lldp_results)
        probed_routers.append(router)

    return probed_routers


def main() -> None:
    parser = argparse.ArgumentParser(description="Auto-detect routers on local ethernet")
    parser.add_argument(
        "--interface", "-i",
        required=True,
        help="Network interface to scan (e.g. en6, eth0)",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=10,
        help="Passive listen timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--no-menu",
        action="store_true",
        help="Skip interactive menu",
    )
    args = parser.parse_args()

    routers = auto_detect(args.interface, passive_timeout=args.timeout)

    if args.json:
        output = []
        for r in routers:
            output.append({
                "ip": r.ip,
                "mac": r.mac,
                "vendor": r.vendor,
                "model_id": r.model_id,
                "model_name": r.model_name,
                "firmware_state": r.firmware_state,
                "stock_firmware_version": r.stock_firmware_version,
                "confidence": r.confidence,
                "web_ui_type": r.web_ui_type,
                "ssh_available": r.ssh_available,
                "dhcp_server": r.dhcp_server,
                "flash_methods": r.flash_methods,
                "readiness": r.readiness,
                "lldp": {
                    "chassis_name": r.lldp_info.chassis_name if r.lldp_info else None,
                    "chassis_mac": r.lldp_info.chassis_mac if r.lldp_info else None,
                    "management_ip": r.lldp_info.management_ip if r.lldp_info else None,
                    "vendor_specific": r.lldp_info.vendor_specific if r.lldp_info else None,
                } if r.lldp_info else None,
            })
        print(json.dumps(output, indent=2))
    elif not args.no_menu:
        interactive_menu(routers)
    else:
        for router in routers:
            _print_router(router)


if __name__ == "__main__":
    main()
