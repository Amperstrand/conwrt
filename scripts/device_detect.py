"""Passive and active device fingerprinting for conwrt auto-detect."""

from __future__ import annotations

import json
import re
import socket
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DeviceCandidate:
    vendor: str
    model_id: str | None
    confidence: str  # low / medium / high
    evidence: list[str] = field(default_factory=list)
    mac_oui: str | None = None
    hostname: str | None = None
    dhcp_vendor_class: str | None = None
    open_ports: list[int] = field(default_factory=list)
    ssh_banner: str | None = None


@dataclass
class FingerprintResult:
    candidates: list[DeviceCandidate] = field(default_factory=list)
    passive_complete: bool = False
    active_complete: bool = False
    raw_signals: dict = field(default_factory=dict)


_OUI_TABLE: dict[str, str] = {
    "00:01:30": "Extreme Networks",
    "00:04:96": "Extreme Networks",
    "4C:9E:FF": "Zyxel",
    "BC:CF:4F": "Zyxel",
    "E8:37:7A": "Zyxel",
    "A0:6C:EC": "Zyxel",
    "00:05:5D": "D-Link",
    "00:0D:88": "D-Link",
    "1C:69:7A": "D-Link",
    "E8:CC:18": "D-Link",
    "94:83:C4": "GL.iNet",
    "E4:95:6E": "GL.iNet",
    "00:14:BF": "Linksys",
    "48:F8:B3": "Linksys",
    "E8:9F:80": "Linksys",
    "04:18:D6": "Ubiquiti",
    "24:A4:3C": "Ubiquiti",
    "78:8A:20": "Ubiquiti",
    "50:C7:BF": "TP-Link",
    "60:E3:27": "TP-Link",
    "AC:15:A2": "TP-Link",
    "00:09:5B": "Netgear",
    "A0:21:B7": "Netgear",
    "60:38:E0": "Netgear",
    "00:0B:86": "Aruba/HP",
    "00:1A:1E": "Aruba/HP",
}

_DHCP_MAC_RE = re.compile(
    r"BOOTP/DHCP.*?\s+from\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"
)
_DHCP_HOSTNAME_RE = re.compile(r"hostname\s+['\"]?(\S+?)['\"]?")
_DHCP_VENDOR_RE = re.compile(
    r"Vendor-Class[^\n]*?:\s*['\"]?([^\n'\"]+?)['\"]?\s*$", re.MULTILINE
)
_DHCP_REQUESTED_IP_RE = re.compile(r"Requested-IP\s+([0-9.]+)")
_ARP_RE = re.compile(
    r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s.*?\s(\d+\.\d+\.\d+\.\d+)"
)


def parse_tcpdump_dhcp(line: str) -> dict | None:
    """Extract DHCP fields from a tcpdump verbose output line."""
    if "BOOTP" not in line and "DHCP" not in line:
        return None

    result: dict = {}

    mac_match = _DHCP_MAC_RE.search(line)
    if mac_match:
        result["mac"] = mac_match.group(1).lower()

    host_match = _DHCP_HOSTNAME_RE.search(line)
    if host_match:
        result["hostname"] = host_match.group(1)

    vendor_match = _DHCP_VENDOR_RE.search(line)
    if vendor_match:
        result["vendor_class"] = vendor_match.group(1).strip()

    ip_match = _DHCP_REQUESTED_IP_RE.search(line)
    if ip_match:
        result["requested_ip"] = ip_match.group(1)

    return result if result else None


def parse_arp(line: str) -> tuple[str, str] | None:
    """Extract (mac, ip) from an ARP output line."""
    match = _ARP_RE.search(line)
    if match:
        return match.group(1).lower(), match.group(2)
    return None


def lookup_oui(mac: str) -> str | None:
    """Return vendor name for a MAC address using the built-in OUI table."""
    octets = mac.lower().replace("-", ":").split(":")
    if len(octets) < 3:
        return None
    prefix = ":".join(octets[:3]).upper()
    return _OUI_TABLE.get(prefix)


def passive_fingerprint(
    tcpdump_lines: list[str], models: list[dict] | None = None
) -> FingerprintResult:
    """Analyze passive tcpdump capture output to identify devices."""
    signals: dict = {"dhcp": [], "arp": []}
    candidates: list[DeviceCandidate] = []

    for line in tcpdump_lines:
        dhcp = parse_tcpdump_dhcp(line)
        if dhcp:
            signals["dhcp"].append(dhcp)
            continue

        arp = parse_arp(line)
        if arp:
            signals["arp"].append({"mac": arp[0], "ip": arp[1]})

    seen_macs: set[str] = set()
    for dhcp in signals["dhcp"]:
        mac = dhcp.get("mac", "")
        oui = lookup_oui(mac) if mac else None
        hostname = dhcp.get("hostname")
        vendor_class = dhcp.get("vendor_class")
        evidence_parts: list[str] = []
        if oui:
            evidence_parts.append(f"OUI={oui}")
        if hostname:
            evidence_parts.append(f"hostname={hostname}")
        if vendor_class:
            evidence_parts.append(f"vendor_class={vendor_class}")

        candidate = DeviceCandidate(
            vendor=oui or "unknown",
            model_id=None,
            confidence=_oui_confidence(oui, vendor_class, hostname),
            evidence=evidence_parts,
            mac_oui=":".join(mac.split(":")[:3]) if mac else None,
            hostname=hostname,
            dhcp_vendor_class=vendor_class,
        )
        candidates.append(candidate)
        if mac:
            seen_macs.add(mac)

    for arp_entry in signals["arp"]:
        mac = arp_entry["mac"]
        if mac in seen_macs:
            continue
        oui = lookup_oui(mac)
        candidate = DeviceCandidate(
            vendor=oui or "unknown",
            model_id=None,
            confidence="low" if not oui else "medium",
            evidence=[f"OUI={oui}"] if oui else ["ARP only"],
            mac_oui=":".join(mac.split(":")[:3]),
        )
        candidates.append(candidate)

    if models:
        _enrich_from_models(candidates, models)

    return FingerprintResult(
        candidates=candidates,
        passive_complete=True,
        active_complete=False,
        raw_signals=signals,
    )


def _oui_confidence(
    oui: str | None, vendor_class: str | None, hostname: str | None
) -> str:
    score = 0
    if oui:
        score += 1
    if vendor_class:
        score += 1
    if hostname:
        score += 1
    if score >= 3:
        return "high"
    if score >= 2:
        return "medium"
    return "low"


def _enrich_from_models(candidates: list[DeviceCandidate], models: list[dict]) -> None:
    for candidate in candidates:
        for model in models:
            model_ouis = model.get("mac_oui", [])
            if candidate.mac_oui and candidate.mac_oui.upper() in [
                o.upper() for o in model_ouis
            ]:
                candidate.model_id = model.get("id")
                candidate.vendor = model.get("vendor", candidate.vendor)
                if candidate.confidence == "low":
                    candidate.confidence = "medium"
                candidate.evidence.append(f"model_match={model.get('id')}")


def grab_ssh_banner(ip: str, port: int = 22, timeout: float = 5.0) -> str | None:
    """Connect to SSH port and read the banner string."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        banner = sock.recv(1024)
        sock.close()
        return banner.decode("utf-8", errors="replace").strip()
    except (OSError, socket.timeout):
        return None


def probe_http_title(ip: str, port: int = 80, timeout: float = 5.0) -> str | None:
    """GET / from ip:port and extract the HTML title tag."""
    try:
        request = (
            f"GET / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.sendall(request.encode())
        chunks: list[bytes] = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        sock.close()
        body = b"".join(chunks).decode("utf-8", errors="replace")
        title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        return title_match.group(1).strip() if title_match else None
    except (OSError, socket.timeout):
        return None


def _scan_port(ip: str, port: int, timeout: float = 2.0) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except OSError:
        return False


_COMMON_PORTS = [22, 23, 80, 443, 8080, 8443, 161, 4430, 5903]


def active_fingerprint(ip: str, timeout: float = 10.0) -> FingerprintResult:
    """Run active probes against a device to identify it."""
    per_probe_timeout = min(timeout / 3, 5.0)
    signals: dict = {}

    ssh_banner = grab_ssh_banner(ip, timeout=per_probe_timeout)
    if ssh_banner:
        signals["ssh_banner"] = ssh_banner

    http_title = probe_http_title(ip, timeout=per_probe_timeout)
    if http_title:
        signals["http_title"] = http_title

    open_ports: list[int] = []
    for port in _COMMON_PORTS:
        if _scan_port(ip, port, timeout=per_probe_timeout):
            open_ports.append(port)
    if open_ports:
        signals["open_ports"] = open_ports

    evidence: list[str] = []
    vendor = "unknown"
    if ssh_banner:
        evidence.append(f"ssh_banner={ssh_banner}")
        vendor = _vendor_from_ssh_banner(ssh_banner) or vendor
    if http_title:
        evidence.append(f"http_title={http_title}")
    if open_ports:
        evidence.append(f"open_ports={open_ports}")

    confidence = "low"
    if ssh_banner and http_title:
        confidence = "high"
    elif ssh_banner or http_title:
        confidence = "medium"

    candidate = DeviceCandidate(
        vendor=vendor,
        model_id=None,
        confidence=confidence,
        evidence=evidence,
        open_ports=open_ports,
        ssh_banner=ssh_banner,
    )

    return FingerprintResult(
        candidates=[candidate],
        passive_complete=False,
        active_complete=True,
        raw_signals=signals,
    )


def _vendor_from_ssh_banner(banner: str) -> str | None:
    banner_lower = banner.lower()
    if "edgeos" in banner_lower or "ubnt" in banner_lower:
        return "Ubiquiti"
    if "extreme" in banner_lower:
        return "Extreme Networks"
    if "zyxel" in banner_lower or "zywall" in banner_lower:
        return "Zyxel"
    if "d-link" in banner_lower or "dlink" in banner_lower:
        return "D-Link"
    if "dropbear" in banner_lower:
        return None
    return None


def match_models(
    result: FingerprintResult, model_dir: str = "models"
) -> list[DeviceCandidate]:
    """Match fingerprint results against model JSON files in model_dir."""
    model_path = Path(model_dir)
    if not model_path.is_dir():
        return []

    model_files = sorted(model_path.glob("*.json"))
    candidates: list[DeviceCandidate] = []

    for mf in model_files:
        try:
            model = json.loads(mf.read_text())
        except (json.JSONDecodeError, OSError):
            continue

        score = 0
        match_evidence: list[str] = []
        model_id = model.get("id", mf.stem)
        vendor = model.get("vendor", "unknown")
        model_ouis = [o.upper() for o in model.get("mac_oui", [])]
        sigs = model.get("signatures", {})

        for c in result.candidates:
            if c.mac_oui and c.mac_oui.upper() in model_ouis:
                score += 2
                match_evidence.append(f"oui_match={c.mac_oui}")

        for c in result.candidates:
            if c.hostname and model_id in (c.hostname or "").lower():
                score += 1
                match_evidence.append(f"hostname_match={c.hostname}")

        ssh_banner_sig = (
            sigs.get("edgeos", {}).get("ssh_banner")
            or sigs.get("active", {}).get("ssh_banner")
            or sigs.get("passive", {}).get("ssh_banner")
        )
        if ssh_banner_sig:
            for c in result.candidates:
                if c.ssh_banner and ssh_banner_sig.lower() in c.ssh_banner.lower():
                    score += 3
                    match_evidence.append(f"ssh_banner_match={ssh_banner_sig}")

        http_title_sig = (
            sigs.get("recovery", {}).get("http_title")
            or sigs.get("active", {}).get("http_title")
            or sigs.get("passive", {}).get("http_title")
        )
        if http_title_sig:
            for c in result.candidates:
                if (
                    c.ssh_banner is None
                    and "http_title" in result.raw_signals
                    and http_title_sig.lower()
                    in result.raw_signals.get("http_title", "").lower()
                ):
                    score += 3
                    match_evidence.append(f"http_title_match={http_title_sig}")
                elif hasattr(c, "_http_title"):
                    pass

        model_ports = sigs.get("openwrt_ready", {}).get("ssh_port")
        if result.raw_signals.get("open_ports") and model_ports:
            if model_ports in result.raw_signals["open_ports"]:
                score += 1
                match_evidence.append(f"port_match={model_ports}")

        if score == 0:
            continue

        confidence = "low"
        if score >= 5:
            confidence = "high"
        elif score >= 3:
            confidence = "medium"

        candidates.append(
            DeviceCandidate(
                vendor=vendor,
                model_id=model_id,
                confidence=confidence,
                evidence=match_evidence,
            )
        )

    candidates.sort(
        key=lambda c: (0 if c.confidence == "high" else 1 if c.confidence == "medium" else 2)
    )
    return candidates
