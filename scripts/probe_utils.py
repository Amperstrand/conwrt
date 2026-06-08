"""probe_utils — shared network probe primitives for conwrt."""

import subprocess

from platform_utils import detect_platform


def curl_get(url: str, timeout: int = 3) -> tuple[int, str, str]:
    """HTTP GET via curl. Returns (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", str(timeout), url],
            capture_output=True, text=True, timeout=timeout + 2, check=False,
        )
        return r.returncode, r.stdout, r.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return -1, "", "curl failed"


def curl_head(url: str, timeout: int = 3) -> tuple[int, str, str]:
    """HTTP HEAD via curl. Returns (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(
            ["curl", "-sI", "--max-time", str(timeout), url],
            capture_output=True, text=True, timeout=timeout + 2, check=False,
        )
        return r.returncode, r.stdout, r.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return -1, "", "curl head failed"


def ping_host(ip: str, timeout: int = 2) -> bool:
    """Ping a host. Returns True if reachable."""
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
