#!/usr/bin/env python3
"""Auto-detect routers on the local ethernet segment."""

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.request import urlopen, Request
from urllib.error import URLError

sys.path.insert(0, str(Path(__file__).resolve().parent))

from model_loader import list_models, load_model, find_model_by_mac_oui
from platform_utils import configure_interface_ip, detect_platform, get_link_state
from ssh_utils import run_ssh


COMMON_GATEWAY_IPS = [
    "192.168.0.1",
    "192.168.1.1",
    "192.168.8.1",
    "10.0.0.1",
    "192.168.2.1",
]

FIRMWARE_PATTERNS = [
    (re.compile(r"FIRMWARE.?UPDATE|firmware.*<form", re.IGNORECASE), "uboot"),
    (re.compile(r"uIP|u%-Boot|U%-Boot HTTP", re.IGNORECASE), "uboot"),
    (re.compile(r"openwrt|luci", re.IGNORECASE), "openwrt"),
    (re.compile(r"gl[\-_.]?inet|glinet", re.IGNORECASE), "glinet_stock"),
    (re.compile(r"linksys|jnap", re.IGNORECASE), "linksys_stock"),
    (re.compile(r"d[\-_.]?link|hnap|covr", re.IGNORECASE), "dlink_stock"),
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


def _add_evidence(router: DetectedRouter, phase: str, message: str) -> None:
    router.evidence.append(f"[{phase}] {message}")


def _curl_get(url: str, timeout: int = 3) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", str(timeout), url],
            capture_output=True, text=True, timeout=timeout + 2, check=False,
        )
        return r.returncode, r.stdout, r.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return -1, "", "curl failed"


def _curl_head(url: str, timeout: int = 3) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            ["curl", "-sI", "--max-time", str(timeout), url],
            capture_output=True, text=True, timeout=timeout + 2, check=False,
        )
        return r.returncode, r.stdout, r.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return -1, "", "curl head failed"


def _ping(ip: str, timeout: int = 2) -> bool:
    plat = detect_platform()
    if plat == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(timeout * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout + 2, check=False)
        return r.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _normalize_mac(mac: str) -> str:
    return mac.upper().replace("-", ":")


def _mac_prefix(mac: str) -> str:
    parts = _normalize_mac(mac).split(":")
    return ":".join(parts[:3])


# Phase 1: Passive Listen

def passive_listen(interface: str, timeout: int = 10) -> dict:
    result: dict = {
        "macs": {},
        "dhcp_servers": [],
        "arp_hosts": [],
        "icmpv6_routers": [],
    }

    try:
        from scapy.all import sniff, DHCP, ARP, ICMPv6ND_RA, Ether, IP, conf
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
    except (PermissionError, OSError, Exception):
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
        except Exception:
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
    except Exception:
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
    except (PermissionError, OSError, Exception):
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
        except (PermissionError, OSError, Exception):
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
    except Exception:
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


def classify_http_response(body: str, headers: str) -> str:
    combined = f"{headers}\n{body}"
    for pattern, label in FIRMWARE_PATTERNS:
        if pattern.search(combined):
            return label
    if "<html" in combined.lower() or "<!doctype" in combined.lower():
        return "unknown_http"
    return "unknown"


def classify_web_ui(probe_data: dict) -> str:
    body = probe_data.get("http_get", {}).get("body", "")
    headers = probe_data.get("http_head", {}).get("headers", "")
    hnap = probe_data.get("hnap", {})

    if hnap.get("detected"):
        return "dlink_hnap"
    combined = f"{headers}\n{body}"
    if re.search(r"luci|openwrt", combined, re.IGNORECASE):
        return "openwrt_luci"
    if re.search(r"gl[\-_.]?inet|glinet", combined, re.IGNORECASE):
        return "glinet_admin"
    if re.search(r"linksys|jnap", combined, re.IGNORECASE):
        return "linksys"
    if re.search(r"FIRMWARE.?UPDATE|uIP|u%-Boot", combined, re.IGNORECASE):
        return "uboot"
    if body.strip():
        return "unknown"
    return "none"


# Phase 5: Identification

def lookup_mac_vendor(mac: str) -> str:
    prefix = _mac_prefix(mac)
    try:
        url = f"https://api.macvendors.com/{prefix}"
        req = Request(url, headers={"User-Agent": "conwrt/1.0"})
        resp = urlopen(req, timeout=5)
        return resp.read().decode("utf-8", errors="replace").strip()
    except (URLError, OSError):
        return ""


def match_models_by_oui(mac: str) -> list[dict]:
    prefix = _mac_prefix(mac)
    return find_model_by_mac_oui(prefix)


def match_model_by_board(board_json_str: str) -> Optional[dict]:
    if not board_json_str:
        return None
    try:
        board = json.loads(board_json_str)
    except json.JSONDecodeError:
        return None
    board_model = board.get("model", {}).get("id", "")
    if not board_model:
        return None

    for model_def in list_models():
        owrt = model_def.get("openwrt", {})
        device = owrt.get("device", "")
        if device and device == board_model:
            return model_def
        if board_model in device:
            return model_def
    return None


def match_model_by_http(body: str, headers: str) -> list[dict]:
    combined = f"{headers}\n{body}"
    matches: list[dict] = []
    for model_def in list_models():
        sigs = model_def.get("signatures", {})
        recovery_sig = sigs.get("recovery", {})
        http_title = recovery_sig.get("http_title", "")
        if http_title and http_title.lower() in combined.lower():
            matches.append(model_def)
            continue
        vendor = model_def.get("vendor", "").lower()
        if vendor and vendor in combined.lower():
            model_id = model_def.get("id", "")
            if vendor in ("d-link", "dlink") and ("d-link" in combined.lower() or "dlink" in combined.lower()):
                matches.append(model_def)
            elif vendor in ("gl-inet", "glinet") and ("gl-inet" in combined.lower() or "glinet" in combined.lower()):
                matches.append(model_def)
            elif vendor in ("linksys",) and "linksys" in combined.lower():
                matches.append(model_def)
    return matches


def identify_router(probe_data: dict, passive_data: dict) -> DetectedRouter:
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
    if not mac:
        mac = "unknown"

    router = DetectedRouter(ip=ip, mac=mac)
    _add_evidence(router, "probe", f"Probing {ip}")

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

    matched_model = None
    confidence = ""

    if board_match:
        matched_model = board_match
        confidence = "certain"
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

        for method_name, method_cfg in matched_model.get("flash_methods", {}).items():
            if "default_password" in method_cfg:
                router.default_password = method_cfg["default_password"]
                break

        _add_evidence(router, "model", f"Final: {router.model_id} ({confidence})")
    else:
        router.confidence = "possible"
        _add_evidence(router, "model", "No model match found")

    return router


# Phase 6: Interactive Menu

def _print_router(router: DetectedRouter) -> None:
    print(f"\n{SEPARATOR}")
    print(f"Router detected at {router.ip}")
    print(f"MAC:        {router.mac}")
    vendor_source = ""
    if router.vendor:
        oui_models = match_models_by_oui(router.mac) if router.mac != "unknown" else []
        vendor_source = " (OUI match)" if oui_models else ""
    print(f"Vendor:     {router.vendor}{vendor_source}")

    if router.model_id:
        print(f"Model:      {router.model_name or router.model_id} ({router.confidence})")
    else:
        print(f"Model:      Not identified ({router.confidence})")

    fw_label = {
        "uboot": "U-Boot recovery mode",
        "openwrt": "OpenWrt",
        "glinet_stock": "GL.iNet stock firmware",
        "linksys_stock": "Linksys stock firmware",
        "dlink_stock": "Stock D-Link firmware",
        "unknown_http": "Unknown web interface",
        "unknown": "Unknown firmware state",
    }.get(router.firmware_state, router.firmware_state)
    print(f"Firmware:   {fw_label}")

    ssh_label = "Available" if router.ssh_available else "Not available"
    if router.ssh_available and router.ssh_info:
        board = router.ssh_info.get("model", "")
        if board:
            ssh_label += f" (board: {board})"
    print(f"SSH:        {ssh_label}")

    web_label = {
        "dlink_hnap": "D-Link admin panel (HNAP API detected)",
        "openwrt_luci": "OpenWrt LuCI web interface",
        "glinet_admin": "GL.iNet admin panel",
        "linksys": "Linksys admin panel (JNAP API)",
        "uboot": "U-Boot HTTP recovery page",
        "unknown": "Unknown web interface",
        "none": "No web interface detected",
    }.get(router.web_ui_type, router.web_ui_type)
    print(f"Web UI:     {web_label}")
    print(f"Confidence: {router.confidence}")
    print(f"{SEPARATOR}")


def interactive_menu(routers: list[DetectedRouter]) -> None:
    if not routers:
        print("\nNo routers detected.")
        return

    print(f"\n{'=' * 45}")
    print(f"  DETECTED {len(routers)} ROUTER(S)")
    print(f"{'=' * 45}")

    for router in routers:
        _print_router(router)

    while True:
        router = routers[0] if len(routers) == 1 else None
        if router is None:
            print("\nMultiple routers detected. Select one:")
            for i, r in enumerate(routers, 1):
                label = r.model_name or r.vendor or r.mac
                print(f"  [{i}] {r.ip} — {label}")
            choice = input("Router number (or q to quit): ").strip().lower()
            if choice == "q":
                return
            try:
                idx = int(choice) - 1
                router = routers[idx]
            except (ValueError, IndexError):
                print("Invalid selection.")
                continue

        print(f"\nWhat would you like to do with {router.ip}?")
        print("  [1] Flash with OpenWrt (request custom image from ASU)")
        print("  [2] Flash with existing firmware image")
        print("  [3] Enter recovery mode first, then flash")
        print("  [4] Show detailed detection info")
        print("  [5] Re-scan")
        print("  [q] Quit")

        choice = input("Choice: ").strip().lower()

        if choice == "1":
            model_flag = f"--model-id {router.model_id}" if router.model_id else ""
            iface = ""
            print(f"\n  conwrt flash {model_flag} {iface}--request-image")
            print("  (Edit config.toml for SSH keys, passwords, and use case presets)")
            input("\nPress Enter to continue...")

        elif choice == "2":
            image_path = input("Path to firmware image: ").strip()
            if image_path:
                model_flag = f"--model-id {router.model_id}" if router.model_id else ""
                print(f"\n  conwrt flash {model_flag} --image {image_path}")
            input("\nPress Enter to continue...")

        elif choice == "3":
            model_flag = f"--model-id {router.model_id}" if router.model_id else ""
            print(f"\n  conwrt flash {model_flag} --force-uboot")
            if router.model_id:
                model_def = None
                try:
                    model_def = load_model(router.model_id)
                except FileNotFoundError:
                    pass
                if model_def:
                    for method_name, method_cfg in model_def.get("flash_methods", {}).items():
                        if "reset_instructions" in method_cfg:
                            print(f"\n  Recovery instructions ({method_name}):")
                            for line in method_cfg["reset_instructions"].split(". "):
                                if line.strip():
                                    print(f"    {line.strip()}")
                            break
            input("\nPress Enter to continue...")

        elif choice == "4":
            print(f"\n{'─' * 45}")
            print(f"DETAILED INFO: {router.ip}")
            print(f"{'─' * 45}")
            print(f"MAC:            {router.mac}")
            print(f"Vendor:         {router.vendor}")
            print(f"Model ID:       {router.model_id or 'N/A'}")
            print(f"Model name:     {router.model_name or 'N/A'}")
            print(f"Firmware state: {router.firmware_state}")
            print(f"Web UI type:    {router.web_ui_type}")
            print(f"SSH available:  {router.ssh_available}")
            if router.ssh_info:
                for k, v in router.ssh_info.items():
                    print(f"  SSH {k}: {v}")
            print(f"DHCP server:    {router.dhcp_server}")
            if router.dhcp_info:
                for k, v in router.dhcp_info.items():
                    print(f"  DHCP {k}: {v}")
            print(f"Confidence:     {router.confidence}")
            print(f"Flash methods:  {', '.join(router.flash_methods) if router.flash_methods else 'N/A'}")
            if router.http_response_preview:
                print(f"\nHTTP preview (first 300 chars):")
                print(router.http_response_preview[:300])
            if router.http_headers:
                print(f"\nHTTP headers:")
                print(router.http_headers[:300])
            print(f"\nEvidence chain:")
            for ev in router.evidence:
                print(f"  {ev}")
            input("\nPress Enter to continue...")

        elif choice == "5":
            return

        elif choice == "q":
            sys.exit(0)

        else:
            print("Invalid choice.")


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

    print(f"[Phase 4] Active probing {len(discovered_ips)} host(s)...")
    probed_routers: list[DetectedRouter] = []
    for ip in sorted(discovered_ips.keys()):
        print(f"  Probing {ip}...")
        probe_data = active_probe(ip)
        print(f"[Phase 5] Identifying {ip}...")
        router = identify_router(probe_data, all_passive)
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
                "confidence": r.confidence,
                "web_ui_type": r.web_ui_type,
                "ssh_available": r.ssh_available,
                "dhcp_server": r.dhcp_server,
                "flash_methods": r.flash_methods,
            })
        print(json.dumps(output, indent=2))
    elif not args.no_menu:
        interactive_menu(routers)
    else:
        for router in routers:
            _print_router(router)


if __name__ == "__main__":
    main()
