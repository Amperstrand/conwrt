"""Pre-flight validation checks before flashing a router."""
from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from types import SimpleNamespace

from platform_utils import detect_platform


@dataclass
class PreflightResult:
    """Result of a single pre-flight check."""

    name: str
    status: str  # "pass", "warn", "fail"
    message: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_interface_ips(interface: str) -> list[str]:
    """Return all IPv4 addresses currently assigned to *interface*."""
    plat = detect_platform()
    try:
        if plat == "darwin":
            r = subprocess.run(
                ["ifconfig", interface],
                capture_output=True, text=True, check=False,
            )
        else:
            r = subprocess.run(
                ["ip", "addr", "show", interface],
                capture_output=True, text=True, check=False,
            )
    except FileNotFoundError:
        return []

    if r.returncode != 0:
        return []

    # Match "inet A.B.C.D/prefix" lines — works for both ifconfig and ip output.
    return re.findall(r"inet\s+(\d+\.\d+\.\d+\.\d+)", r.stdout)


def is_default_route(interface: str) -> bool:
    """Return True if *interface* carries the system default route."""
    plat = detect_platform()
    try:
        if plat == "darwin":
            r = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True, text=True, check=False,
            )
            return bool(re.search(r"interface:\s+" + re.escape(interface), r.stdout))
        else:
            r = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True, text=True, check=False,
            )
            return bool(re.search(r"dev\s+" + re.escape(interface) + r"\b", r.stdout))
    except FileNotFoundError:
        return False


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _check_stale_ip(interface: str, profile: SimpleNamespace) -> PreflightResult:
    """Fail if client IPs are already assigned to the interface."""
    existing = get_interface_ips(interface)
    conflicts: list[str] = []
    for attr in ("client_ip", "openwrt_client_ip"):
        ip = getattr(profile, attr, "")
        if ip and ip in existing:
            conflicts.append(ip)
    if conflicts:
        ips_str = " and ".join(conflicts)
        return PreflightResult(
            name="stale_ip",
            status="fail",
            message=f"{ips_str} already assigned to {interface} -- remove stale alias before flashing",
        )
    return PreflightResult(name="stale_ip", status="pass", message="No stale IP aliases on interface")


def _check_default_route(interface: str) -> PreflightResult:
    """Warn if the flash interface carries the default route."""
    if is_default_route(interface):
        return PreflightResult(
            name="default_route",
            status="warn",
            message=f"{interface} is the default route -- reconfiguring it may disrupt network connectivity",
        )
    return PreflightResult(name="default_route", status="pass", message="Interface is not the default route")


def _check_ssh_key(ssh_key_path: str | None, request_image: bool) -> PreflightResult:
    """Check SSH key file exists. Fail for request-image mode, warn otherwise."""
    if not ssh_key_path:
        severity = "fail" if request_image else "warn"
        return PreflightResult(
            name="ssh_key",
            status=severity,
            message="No SSH key path provided",
        )
    if not os.path.isfile(ssh_key_path):
        severity = "fail" if request_image else "warn"
        return PreflightResult(
            name="ssh_key",
            status=severity,
            message=f"SSH key file not found: {ssh_key_path}",
        )
    return PreflightResult(name="ssh_key", status="pass", message=f"SSH key found: {ssh_key_path}")


def _check_image(image_path: str) -> PreflightResult:
    """Fail if firmware image is missing, empty, or suspiciously small."""
    if not os.path.isfile(image_path):
        return PreflightResult(
            name="image",
            status="fail",
            message=f"Firmware image not found: {image_path}",
        )
    size = os.path.getsize(image_path)
    if size == 0:
        return PreflightResult(
            name="image",
            status="fail",
            message=f"Firmware image is empty: {image_path}",
        )
    one_mb = 1 * 1024 * 1024
    if size < one_mb:
        return PreflightResult(
            name="image",
            status="fail",
            message=f"Firmware image is suspiciously small ({size} bytes < 1 MB): {image_path}",
        )
    return PreflightResult(name="image", status="pass", message=f"Firmware image OK ({size} bytes)")


def _check_subnet_consistency(profile: SimpleNamespace) -> list[PreflightResult]:
    """Warn if profile IPs are not on consistent /24 subnets."""
    results: list[PreflightResult] = []

    client_ip = getattr(profile, "client_ip", "")
    recovery_ip = getattr(profile, "recovery_ip", "")
    if client_ip and recovery_ip:
        if client_ip.rsplit(".", 1)[0] != recovery_ip.rsplit(".", 1)[0]:
            results.append(PreflightResult(
                name="subnet_consistency",
                status="warn",
                message=f"client_ip ({client_ip}) and recovery_ip ({recovery_ip}) are on different /24 subnets -- routing may not work",
            ))
        else:
            results.append(PreflightResult(
                name="subnet_consistency",
                status="pass",
                message="client_ip and recovery_ip on same /24 subnet",
            ))
    else:
        results.append(PreflightResult(
            name="subnet_consistency",
            status="pass",
            message="Skipped (no client_ip or recovery_ip to check)",
        ))

    openwrt_client_ip = getattr(profile, "openwrt_client_ip", "")
    openwrt_ip = getattr(profile, "openwrt_ip", "")
    if openwrt_client_ip and openwrt_ip:
        if openwrt_client_ip.rsplit(".", 1)[0] != openwrt_ip.rsplit(".", 1)[0]:
            results.append(PreflightResult(
                name="openwrt_subnet_consistency",
                status="warn",
                message=f"openwrt_client_ip ({openwrt_client_ip}) and openwrt_ip ({openwrt_ip}) are on different /24 subnets -- routing may not work",
            ))
        else:
            results.append(PreflightResult(
                name="openwrt_subnet_consistency",
                status="pass",
                message="openwrt_client_ip and openwrt_ip on same /24 subnet",
            ))

    return results


def _check_profile_completeness(profile: SimpleNamespace) -> list[PreflightResult]:
    """Warn if profile is missing important fields."""
    results: list[PreflightResult] = []
    required_fields = ["recovery_ip", "flash_method", "name"]
    missing = [f for f in required_fields if not getattr(profile, f, "")]
    if missing:
        results.append(PreflightResult(
            name="profile_completeness",
            status="warn",
            message=f"Profile missing fields: {', '.join(missing)}",
        ))
    else:
        results.append(PreflightResult(
            name="profile_completeness",
            status="pass",
            message="Profile has all required fields",
        ))
    return results


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_preflight_checks(
    interface: str,
    profile: SimpleNamespace,
    image_path: str,
    ssh_key_path: str | None = None,
    boot_state: str = "",
    use_sysupgrade: bool = False,
    request_image: bool = False,
) -> list[PreflightResult]:
    """Run all pre-flight checks and return results in order.

    Any result with status "fail" should abort the flash.
    """
    results: list[PreflightResult] = []

    # Check 1: stale IP aliases
    results.append(_check_stale_ip(interface, profile))

    # Check 2: default route
    results.append(_check_default_route(interface))

    # Check 3: SSH key
    results.append(_check_ssh_key(ssh_key_path, request_image))

    # Check 4: firmware image sanity
    results.append(_check_image(image_path))

    # Check 5: subnet consistency (may produce multiple results)
    results.extend(_check_subnet_consistency(profile))

    # Check 6: profile completeness (may produce multiple results)
    results.extend(_check_profile_completeness(profile))

    return results
