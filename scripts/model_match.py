"""model_match — model identification functions for conwrt.

Provides firmware pattern matching, MAC vendor lookup, and model matching
by OUI, board.json, HTTP response, and LLDP data.
"""

from __future__ import annotations

import json
import re
from typing import Optional
from urllib.request import urlopen, Request
from urllib.error import URLError

from lldp import LLDPInfo
from model_loader import list_models, find_model_by_mac_oui


FIRMWARE_PATTERNS = [
    (re.compile(r"FIRMWARE.?UPDATE|firmware.*<form", re.IGNORECASE), "uboot"),
    (re.compile(r"uIP|u%-Boot|U%-Boot HTTP", re.IGNORECASE), "uboot"),
    (re.compile(r"openwrt|luci", re.IGNORECASE), "openwrt"),
    (re.compile(r"gl[\-_.]?inet|glinet", re.IGNORECASE), "glinet_stock"),
    (re.compile(r"linksys|jnap", re.IGNORECASE), "linksys_stock"),
    (re.compile(r"d[\-_.]?link|hnap|covr", re.IGNORECASE), "dlink_stock"),
    (re.compile(r"dispatcher\.cgi|intelligent[\s\-_]?switch", re.IGNORECASE), "zyxel_stock"),
]


def _normalize_mac(mac: str) -> str:
    return mac.upper().replace("-", ":")


def _mac_prefix(mac: str) -> str:
    parts = _normalize_mac(mac).split(":")
    return ":".join(parts[:3])


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


def match_model_by_lldp(lldp_info: LLDPInfo) -> list[dict]:
    """Match LLDP system description / device name against model JSONs."""
    matches: list[dict] = []
    search_text = f"{lldp_info.system_description} {lldp_info.chassis_name}".lower()
    search_text += f" {lldp_info.vendor_specific.get('zyxel_device', '')}".lower()

    for model_def in list_models():
        desc = model_def.get("description", "").lower()
        model_id = model_def.get("id", "").lower()

        # Extract model keywords from description (e.g. "GS1900-8HP")
        model_keywords = re.findall(r"[a-z]{2,}\d{3,}[\-]?\w*", desc)
        for kw in model_keywords:
            if kw in search_text:
                matches.append(model_def)
                break
            # Also try without hyphens
            if kw.replace("-", "") in search_text.replace("-", ""):
                matches.append(model_def)
                break

    return matches
