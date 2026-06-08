"""router_classify — firmware classification and readiness assessment.

Pure functions extracted from auto_detect for testability.
"""

from __future__ import annotations

import re
from typing import Optional

from model_match import FIRMWARE_PATTERNS
from model_loader import load_model


def classify_http_response(body: str, headers: str) -> str:
    """Classify firmware type from HTTP response body and headers."""
    combined = f"{headers}\n{body}"
    for pattern, label in FIRMWARE_PATTERNS:
        if pattern.search(combined):
            return label
    if "<html" in combined.lower() or "<!doctype" in combined.lower():
        return "unknown_http"
    return "unknown"


def classify_web_ui(probe_data: dict) -> str:
    """Classify the web UI type from combined probe data."""
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
    if re.search(r"dispatcher\.cgi", combined, re.IGNORECASE):
        server_m = re.search(r"Server:\s*(.+)", headers, re.IGNORECASE)
        if server_m and "hydra" in server_m.group(1).lower():
            return "zyxel_stock"
    if re.search(r"intelligent[\s\-_]?switch", combined, re.IGNORECASE):
        return "zyxel_stock"
    if body.strip():
        return "unknown"
    return "none"


def assess_readiness(router: object) -> dict:
    """Assess whether a device is ready for OpenWrt flashing."""
    result: dict = {
        "ready": False,
        "issues": [],
        "warnings": [],
    }

    if getattr(router, "firmware_state", "") == "openwrt":
        result["ready"] = True
        return result

    if not getattr(router, "model_id", ""):
        result["issues"].append("Device model not identified — cannot determine flash method")
        return result

    model_def = None
    try:
        model_def = load_model(router.model_id)
    except FileNotFoundError:
        pass

    if not model_def:
        result["issues"].append(f"No model definition found for {router.model_id}")
        return result

    flash_methods = model_def.get("flash_methods", {})
    if not flash_methods:
        result["issues"].append("No flash methods defined for this model")
        return result

    stock_creds = model_def.get("stock_default_creds", {})
    if stock_creds:
        result["default_credentials"] = True
        result["warnings"].append(f"Default credentials: {stock_creds.get('username', '')}/{stock_creds.get('password', '')}")

    safety = model_def.get("safety", {})
    serial_warning = safety.get("serial_number_warning", "")
    if serial_warning:
        result["warnings"].append(serial_warning)
        result["serial_check_required"] = True

    fw_version = getattr(router, "stock_firmware_version", "")
    if fw_version and serial_warning:
        # Parse version like "V2.00(AAHI.2)" -> extract major.minor
        ver_m = re.match(r"V(\d+)\.(\d+)", fw_version)
        if ver_m:
            major, minor = int(ver_m.group(1)), int(ver_m.group(2))
            if major < 2 or (major == 2 and minor < 70):
                result["issues"].append(
                    f"Stock firmware {fw_version} is below recommended v2.70 — "
                    f"must update stock firmware before flashing (PoE safety)"
                )

    if getattr(router, "web_ui_type", "") == "zyxel_stock" and stock_creds:
        result["ready"] = True
        result["flash_method"] = "oem-http"
    elif getattr(router, "ssh_available", False):
        result["ready"] = True
        result["flash_method"] = "sysupgrade"
    elif flash_methods:
        result["ready"] = True
        result["flash_method"] = list(flash_methods.keys())[0]

    return result
