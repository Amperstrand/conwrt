#!/usr/bin/env python3
"""firmware-manager -- CLI tool for requesting, caching, and managing OpenWrt
firmware images via the ASU (Attended SysUpgrade) API.

Subcommands:
    request   Submit a firmware build request to ASU and download the result.
    list      Show all cached firmware images.
    show      Display full metadata for a specific firmware.
    find      Print the path to the latest cached firmware (for scripting).
"""

import argparse
import base64
import hashlib
import json
import logging
import sys
import textwrap
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from model_loader import load_model
from config import load_config as _load_config, _strip_key_comment

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
IMAGES_DIR = REPO_ROOT / "images"

ASU_BASE = "https://sysupgrade.openwrt.org"
ASU_BUILD_URL = f"{ASU_BASE}/api/v1/build"
ASU_STORE_URL = f"{ASU_BASE}/store"

POLL_INTERVAL = 10
POLL_TIMEOUT = 600

logger = logging.getLogger("conwrt.firmware")

# ---------------------------------------------------------------------------
# HTTP helpers (stdlib only)
# ---------------------------------------------------------------------------


def _http_get_json(url: str, timeout: int = 30) -> dict[str, Any]:
    """GET a URL and return parsed JSON. Raises on non-200."""
    logger.debug("GET %s", url)
    req = urllib.request.Request(url, headers={"User-Agent": "conwrt-firmware-manager/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode()
        return json.loads(body)


def _http_post_json(url: str, data: dict[str, Any], timeout: int = 30) -> dict[str, Any]:
    """POST JSON to a URL and return parsed response."""
    payload = json.dumps(data).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "conwrt-firmware-manager/1.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode()
        return json.loads(body)


# ---------------------------------------------------------------------------
# SHA-256 helpers
# ---------------------------------------------------------------------------


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# SSH key handling
# ---------------------------------------------------------------------------


def _read_ssh_pubkey(path: str) -> tuple[str, str]:
    """Read a public SSH key file and return (stripped_key, source_filename).

    Strips the comment (user@host) from the key so no personal data leaks
    into metadata or the defaults script.
    """
    key_path = Path(path).expanduser()
    raw = key_path.read_text().strip()
    # Keep only key type + base64 blob (strip comment after second space)
    parts = raw.split()
    if len(parts) >= 2:
        cleaned = f"{parts[0]} {parts[1]}"
    else:
        cleaned = raw
    return cleaned, key_path.name


# ---------------------------------------------------------------------------
# Defaults script builder
# ---------------------------------------------------------------------------


def build_mgmt_wifi_script(txpower: Optional[int] = None) -> str:
    base = textwrap.dedent(
        """\
        # --- management WiFi setup ---
        # Do NOT use 'set -eu' — radio/wifi subsystem may not be fully
        # initialised at first-boot; we handle errors explicitly instead.
        RADIO_2G=""
        for radio in $(uci show wireless 2>/dev/null | grep "=wifi-device" | cut -d. -f2 | cut -d= -f1 || true); do
            band=$(uci -q get wireless.$radio.band || true)
            hwmode=$(uci -q get wireless.$radio.hwmode || true)
            case "$band" in
                2g|2.4g|2ghz|2.4ghz)
                    RADIO_2G="$radio"
                    break
                    ;;
            esac
            case "$hwmode" in
                11g|11ng|11axg|11bg|11b)
                    RADIO_2G="$radio"
                    break
                    ;;
            esac
        done
        if [ -z "$RADIO_2G" ]; then
            printf 'conwrt-mgmt-wifi: No 2.4GHz radio found, skipping\\n' >&2
            exit 0
        fi
        # --- Determine MAC for SSID (retry: br-lan may not exist at first boot) ---
        MAC=""
        for _ in $(seq 1 30); do
            MAC=$(cat /sys/class/net/br-lan/address 2>/dev/null || true)
            [ -n "$MAC" ] && break
            sleep 1
        done
        if [ -z "$MAC" ]; then
            MAC=$(jsonfilter -e '@.network.lan.macaddr' < /etc/board.json 2>/dev/null || true)
        fi
        if [ -z "$MAC" ]; then
            MAC=$(uci -q get wireless.$RADIO_2G.macaddr || true)
        fi
        if [ -z "$MAC" ]; then
            for iface in /sys/class/net/eth*/address /sys/class/net/*/address; do
                case "$iface" in */lo/address) continue ;; esac
                MAC=$(cat "$iface" 2>/dev/null || true)
                [ -n "$MAC" ] && break
            done
        fi
        if [ -z "$MAC" ]; then
            printf 'conwrt-mgmt-wifi: Could not determine MAC address, skipping\\n' >&2
            exit 0
        fi
        SSID="MGMT-$(printf '%s' "$MAC" | tr -d ':' | tr '[:lower:]' '[:upper:]')"

        # --- Enable the 2.4GHz radio ---
        uci set wireless.$RADIO_2G.disabled=0
        uci -q delete wireless.$RADIO_2G.country || true
"""
    )
    if txpower is not None:
        base += f"        uci set wireless.$RADIO_2G.txpower='{txpower}'\n"

    base += textwrap.dedent(
        """\
        # --- Idempotent cleanup: remove all existing wifi-ifaces and mgmt remnants ---
        uci -q delete network.mgmt_dev
        uci -q delete network.mgmt
        uci -q delete dhcp.mgmt
        idx=0
        while uci -q get wireless.@wifi-iface[$idx] >/dev/null 2>&1; do
            uci delete wireless.@wifi-iface[$idx]
        done
        for zone in $(uci show firewall 2>/dev/null | grep "=zone" | cut -d. -f2 | cut -d= -f1 || true); do
            name=$(uci -q get firewall.$zone.name || true)
            if [ "$name" = "mgmt" ]; then
                uci delete firewall.$zone
            fi
        done

        # --- Create management network bridge ---
        uci set network.mgmt_dev=device
        uci set network.mgmt_dev.type='bridge'
        uci set network.mgmt_dev.name='br-mgmt'
        uci set network.mgmt=interface
        uci set network.mgmt.device='br-mgmt'
        uci set network.mgmt.proto='static'
        uci set network.mgmt.ipaddr='172.16.0.1'
        uci set network.mgmt.netmask='255.255.255.0'

        # --- Create management WiFi AP on 2.4GHz radio ---
        uci add wireless wifi-iface
        uci set wireless.@wifi-iface[-1].device="$RADIO_2G"
        uci set wireless.@wifi-iface[-1].network='mgmt'
        uci set wireless.@wifi-iface[-1].mode='ap'
        uci set wireless.@wifi-iface[-1].ssid="$SSID"
        uci set wireless.@wifi-iface[-1].hidden='1'
        uci set wireless.@wifi-iface[-1].encryption='none'
        uci set wireless.@wifi-iface[-1].disabled='0'

        # --- Isolated firewall zone (no forwarding to/from other zones) ---
        uci add firewall zone
        uci set firewall.@zone[-1].name='mgmt'
        uci add_list firewall.@zone[-1].network='mgmt'
        uci set firewall.@zone[-1].input='ACCEPT'
        uci set firewall.@zone[-1].output='ACCEPT'
        uci set firewall.@zone[-1].forward='REJECT'

        # --- DHCP on management subnet ---
        uci set dhcp.mgmt=dhcp
        uci set dhcp.mgmt.interface='mgmt'
        uci set dhcp.mgmt.ignore='0'
        uci set dhcp.mgmt.start='10'
        uci set dhcp.mgmt.limit='21'
        uci set dhcp.mgmt.leasetime='12h'

        # --- Commit and apply ---
        uci commit network
        uci commit wireless
        uci commit firewall
        uci commit dhcp
        /etc/init.d/network reload >/dev/null 2>&1 || true
        wifi reload >/dev/null 2>&1 || wifi >/dev/null 2>&1 || true
        /etc/init.d/firewall restart >/dev/null 2>&1 || true
        /etc/init.d/dnsmasq restart >/dev/null 2>&1 || true
        printf 'MGMT_WIFI_SSID=%s\\n' "$SSID"
        printf 'MGMT_WIFI_RADIO=%s\\n' "$RADIO_2G"
        """
    )
    return base


def _build_defaults(
    ssh_key_path: Optional[str],
    password: Optional[str],
    wan_ssh: bool,
    extra_pub_keys: Optional[list[str]] = None,
    mgmt_wifi: bool = False,
    mgmt_wifi_txpower: Optional[int] = None,
) -> tuple[str, Optional[str], Optional[str]]:
    """Build the shell defaults script for first-boot customization.

    Returns (script_text, ssh_key_cleaned_or_None, ssh_key_source_or_None).
    """
    lines: list[str] = []
    ssh_key_cleaned: Optional[str] = None
    ssh_key_source: Optional[str] = None

    all_keys: list[str] = []
    if ssh_key_path:
        ssh_key_cleaned, ssh_key_source = _read_ssh_pubkey(ssh_key_path)
        all_keys.append(ssh_key_cleaned)
    if extra_pub_keys:
        for k in extra_pub_keys:
            stripped = _strip_key_comment(k.strip())
            if stripped and stripped not in all_keys:
                all_keys.append(stripped)

    if all_keys:
        lines.append("mkdir -p /etc/dropbear")
        for i, key in enumerate(all_keys):
            op = ">" if i == 0 else ">>"
            lines.append(f"echo '{key}' {op} /etc/dropbear/authorized_keys")
        lines.append("chmod 600 /etc/dropbear/authorized_keys")

    if password:
        pw_b64 = base64.b64encode(password.encode()).decode()
        lines.append(f"printf '%s\\n%s\\n' \"$(echo '{pw_b64}' | base64 -d)\" \"$(echo '{pw_b64}' | base64 -d)\" | passwd root")

    if wan_ssh:
        lines.extend([
            "uci add firewall rule",
            "uci set firewall.@rule[-1].name='Allow-SSH-WAN'",
            "uci set firewall.@rule[-1].src='wan'",
            "uci set firewall.@rule[-1].dest_port='22'",
            "uci set firewall.@rule[-1].proto='tcp'",
            "uci set firewall.@rule[-1].target='ACCEPT'",
            "uci commit firewall",
        ])

    if mgmt_wifi:
        lines.append(build_mgmt_wifi_script(txpower=mgmt_wifi_txpower).rstrip())

    return "\n".join(lines), ssh_key_cleaned, ssh_key_source


# ---------------------------------------------------------------------------
# Metadata helpers
# ---------------------------------------------------------------------------


def _metadata_path(profile: str, request_hash: str) -> Path:
    return IMAGES_DIR / profile / request_hash / "build.metadata.json"


def _read_metadata(profile: str, request_hash: str) -> Optional[dict[str, Any]]:
    path = _metadata_path(profile, request_hash)
    if not path.exists():
        legacy_path = IMAGES_DIR / profile / request_hash / f"{request_hash}.metadata.json"
        if not legacy_path.exists():
            return None
        path = legacy_path
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _find_cached_firmware(profile: str, request_hash: str) -> Optional[Path]:
    """Check if a firmware is already cached and verified."""
    meta = _read_metadata(profile, request_hash)
    if meta is None:
        return None
    images = meta.get("images", [])
    for img in images:
        if not img.get("verified"):
            return None
    hash_dir = IMAGES_DIR / profile / request_hash
    if hash_dir.exists():
        return hash_dir
    return None


# ---------------------------------------------------------------------------
# ASU query: default packages
# ---------------------------------------------------------------------------



def _compute_cache_key(
    distro: str,
    version: str,
    target: str,
    profile: str,
    packages: Optional[list[str]],
    defaults_script: Optional[str],
) -> str:
    payload = (
        f"{distro}\n{version}\n{target}\n{profile}\n"
        f"{':'.join(sorted(packages or []))}\n{defaults_script or ''}"
    )
    return hashlib.sha256(payload.encode()).hexdigest()


# ---------------------------------------------------------------------------
# request subcommand
# ---------------------------------------------------------------------------


def cmd_request(args: argparse.Namespace) -> int:
    profile: str = args.profile
    version: str = args.version
    target: Optional[str] = args.target
    packages_str: Optional[str] = args.packages
    ssh_key_path: Optional[str] = args.ssh_key
    password: Optional[str] = args.password
    wan_ssh: bool = args.wan_ssh

    cfg = _load_config()

    if not ssh_key_path:
        if cfg.ssh_public_key_path:
            ssh_key_path = cfg.ssh_public_key_path

    extra_pub_keys = cfg.ssh_all_keys[1:] if len(cfg.ssh_all_keys) > 1 else None

    if not target:
        model_id = profile.replace("_", "-")

        try:
            model = load_model(model_id)
            target = model["openwrt"]["target"]
            logger.info(
                "resolved target=%s from model %s",
                target,
                model.get("vendor", model_id),
            )
        except FileNotFoundError as exc:
            logger.error(
                "unknown profile '%s': %s",
                profile,
                exc,
            )
            return 1

    if not target:
        logger.error("could not resolve target for profile '%s'", profile)
        return 1

    defaults_script, ssh_key_cleaned, ssh_key_source = _build_defaults(
        ssh_key_path,
        password,
        wan_ssh,
        extra_pub_keys=extra_pub_keys,
        mgmt_wifi=cfg.mgmt_wifi,
        mgmt_wifi_txpower=cfg.mgmt_wifi_txpower,
    )

    if defaults_script:
        logger.info(
            "defaults script: %d lines%s",
            len(defaults_script.splitlines()),
            " (includes SSH key)" if ssh_key_cleaned else "",
        )

    # Collect extra packages to ADD on top of the ImageBuilder's profile defaults.
    # With diff_packages=false (the default), ASU includes the profile's
    # default_packages and device_packages automatically — we only need to
    # specify what we want ON TOP of those.
    packages_to_send: Optional[list[str]] = None
    extras = list(cfg.extra_packages)
    if packages_str:
        extras += [p.strip() for p in packages_str.split(",") if p.strip()]
    if extras:
        packages_to_send = list(dict.fromkeys(extras))
        logger.info("extra packages (%d): %s", len(packages_to_send), packages_to_send)

    cache_key = _compute_cache_key(
        "openwrt",
        version,
        target,
        profile,
        packages_to_send,
        defaults_script,
    )

    cached = _find_cached_firmware(profile, cache_key)
    if cached:
        logger.info("firmware already cached at %s (cache key=%s)", cached, cache_key[:12])
        print(str(cached))
        return 0

    build_request: dict[str, Any] = {
        "distro": "openwrt",
        "version": version,
        "target": target,
        "profile": profile,
    }
    if packages_to_send:
        build_request["packages"] = packages_to_send
    if defaults_script:
        build_request["defaults"] = defaults_script

    logger.info("submitting build request to ASU...")
    try:
        build_response = _http_post_json(ASU_BUILD_URL, build_request, timeout=30)
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode()
        except Exception:
            pass
        logger.error("ASU build request failed (HTTP %d): %s", exc.code, body)
        return 1
    except Exception as exc:
        logger.error("ASU build request failed: %s", exc)
        return 1

    request_hash = build_response.get("request_hash")
    if not request_hash:
        logger.error("ASU did not return a request_hash: %s", build_response)
        return 1

    logger.info("build enqueued, request_hash=%s", request_hash)

    status_url = f"{ASU_BUILD_URL}/{request_hash}"
    deadline = time.time() + POLL_TIMEOUT
    status_data: dict[str, Any] = {}

    while time.time() < deadline:
        try:
            status_data = _http_get_json(status_url, timeout=15)
        except Exception as exc:
            logger.warning("poll error: %s", exc)
            time.sleep(POLL_INTERVAL)
            continue

        status = status_data.get("status", "")
        if status in ("pending", "building", 202):
            logger.info("build status: %s, polling in %ds...", status, POLL_INTERVAL)
            time.sleep(POLL_INTERVAL)
            continue

        break
    else:
        logger.error("build timed out after %ds", POLL_TIMEOUT)
        return 1

    if status_data.get("status") not in ("done", 200):
        logger.error(
            "build failed: status=%s detail=%s message=%s",
            status_data.get("status"),
            status_data.get("detail", ""),
            status_data.get("message", ""),
        )
        return 1

    logger.info("build complete: %s", status_data.get("build_at", "unknown"))

    bin_dir = status_data.get("bin_dir", request_hash)
    image_list = status_data.get("images", [])
    if not image_list:
        logger.error("ASU response contains no images")
        return 1

    hash_dir = IMAGES_DIR / profile / cache_key
    hash_dir.mkdir(parents=True, exist_ok=True)

    downloaded_images: list[dict[str, Any]] = []

    for img_info in image_list:
        filename = img_info.get("name", "")
        expected_sha = img_info.get("sha256", "")
        size = img_info.get("size", 0)

        if not filename:
            logger.warning("skipping image entry with no filename")
            continue

        download_url = f"{ASU_STORE_URL}/{bin_dir}/{filename}"
        dest_path = hash_dir / filename

        logger.info("downloading %s (%d bytes)...", filename, size)
        try:
            req = urllib.request.Request(
                download_url,
                headers={"User-Agent": "conwrt-firmware-manager/1.0"},
            )
            with urllib.request.urlopen(req, timeout=120) as resp:
                with open(dest_path, "wb") as f:
                    while True:
                        chunk = resp.read(1 << 20)
                        if not chunk:
                            break
                        f.write(chunk)
        except Exception as exc:
            logger.error("download failed for %s: %s", filename, exc)
            dest_path.unlink(missing_ok=True)
            return 1

        actual_sha = _sha256_file(dest_path)
        if expected_sha and actual_sha != expected_sha:
            logger.error(
                "SHA-256 mismatch for %s: expected %s, got %s",
                filename,
                expected_sha,
                actual_sha,
            )
            dest_path.unlink(missing_ok=True)
            return 1

        logger.info("verified %s (sha256: %s)", filename, actual_sha[:16] + "...")

        img_type = "unknown"
        if "sysupgrade" in filename:
            img_type = "sysupgrade"
        elif "factory" in filename:
            img_type = "factory"
        elif "recovery" in filename:
            img_type = "recovery"

        downloaded_images.append({
            "type": img_type,
            "name": filename,
            "sha256": actual_sha,
            "size_bytes": dest_path.stat().st_size,
            "verified": True,
        })

    metadata: dict[str, Any] = {
        "cache_key": cache_key,
        "request_hash": request_hash,
        "distro": status_data.get("distro", "openwrt"),
        "version": status_data.get("version", version),
        "version_code": status_data.get("version_code", ""),
        "target": status_data.get("target", target),
        "profile": status_data.get("profile", profile),
        "packages": packages_to_send or [],
        "packages_all": status_data.get("packages", {}),
        "defaults": defaults_script if defaults_script else None,
        "ssh_key_source": ssh_key_source,
        "images": downloaded_images,
        "linux_kernel": status_data.get("linux_kernel", {}),
        "build_at": status_data.get("build_at", ""),
        "enqueued_at": status_data.get("enqueued_at", ""),
        "downloaded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"),
    }

    meta_path = hash_dir / "build.metadata.json"
    meta_path.write_text(json.dumps(metadata, indent=2) + "\n")
    logger.info("metadata written to %s", meta_path)

    logger.info("=" * 60)
    logger.info("firmware cached at: %s", hash_dir)
    for img in downloaded_images:
        logger.info(
            "  [%s] %s (sha256: %s..., %d bytes)",
            img["type"],
            img["name"],
            img["sha256"][:16],
            img["size_bytes"],
        )
    logger.info("=" * 60)

    print(str(hash_dir))
    return 0


# ---------------------------------------------------------------------------
# list subcommand
# ---------------------------------------------------------------------------


def cmd_list(args: argparse.Namespace) -> int:
    profile_filter: Optional[str] = args.profile

    if not IMAGES_DIR.exists():
        logger.info("no cached firmware (images directory does not exist)")
        return 0

    entries: list[dict[str, Any]] = []

    profile_dirs = sorted(IMAGES_DIR.iterdir()) if IMAGES_DIR.exists() else []
    for profile_dir in profile_dirs:
        if not profile_dir.is_dir():
            continue
        profile = profile_dir.name
        if profile_filter and profile != profile_filter:
            continue

        for hash_dir in sorted(profile_dir.iterdir()):
            if not hash_dir.is_dir():
                continue
            cache_key = hash_dir.name
            meta = _read_metadata(profile, cache_key)
            if meta is None:
                entries.append({
                    "profile": profile,
                    "hash": cache_key[:12],
                    "version": "?",
                    "build_date": "?",
                    "types": "?",
                })
                continue

            image_types = sorted(set(
                img.get("type", "?") for img in meta.get("images", [])
            ))
            entries.append({
                "profile": profile,
                "hash": cache_key[:12],
                "version": meta.get("version", "?"),
                "build_date": meta.get("build_at", "?")[:19],
                "types": ", ".join(image_types) if image_types else "none",
            })

    if not entries:
        if profile_filter:
            logger.info("no cached firmware for profile '%s'", profile_filter)
        else:
            logger.info("no cached firmware")
        return 0

    col_widths = {
        "profile": max(len("PROFILE"), max(len(e["profile"]) for e in entries)),
        "hash": max(len("CACHE KEY"), max(len(e["hash"]) for e in entries)),
        "version": max(len("VERSION"), max(len(e["version"]) for e in entries)),
        "build_date": max(len("BUILD DATE"), max(len(str(e["build_date"])) for e in entries)),
        "types": max(len("TYPES"), max(len(e["types"]) for e in entries)),
    }

    header = (
        f"{'PROFILE':<{col_widths['profile']}}  "
        f"{'CACHE KEY':<{col_widths['hash']}}  "
        f"{'VERSION':<{col_widths['version']}}  "
        f"{'BUILD DATE':<{col_widths['build_date']}}  "
        f"{'TYPES':<{col_widths['types']}}"
    )
    print(header)
    print("  ".join("-" * w for w in col_widths.values()))

    for e in entries:
        print(
            f"{e['profile']:<{col_widths['profile']}}  "
            f"{e['hash']:<{col_widths['hash']}}  "
            f"{e['version']:<{col_widths['version']}}  "
            f"{str(e['build_date']):<{col_widths['build_date']}}  "
            f"{e['types']:<{col_widths['types']}}"
        )

    return 0


# ---------------------------------------------------------------------------
# show subcommand
# ---------------------------------------------------------------------------


def cmd_show(args: argparse.Namespace) -> int:
    profile: str = args.profile
    cache_key: str = args.hash

    meta = _read_metadata(profile, cache_key)
    if meta is None:
        profile_dir = IMAGES_DIR / profile
        if profile_dir.exists():
            for d in profile_dir.iterdir():
                if d.is_dir() and d.name.startswith(cache_key):
                    meta = _read_metadata(profile, d.name)
                    cache_key = d.name
                    break

    if meta is None:
        logger.error(
            "no metadata found for profile='%s' hash='%s'",
            profile,
            cache_key,
        )
        return 1

    print(json.dumps(meta, indent=2))
    return 0


# ---------------------------------------------------------------------------
# find subcommand
# ---------------------------------------------------------------------------


def cmd_find(args: argparse.Namespace) -> int:
    profile: str = args.profile
    image_type: Optional[str] = args.type

    profile_dir = IMAGES_DIR / profile
    if not profile_dir.exists():
        logger.error("no cached firmware for profile '%s'", profile)
        return 1

    candidates: list[tuple[str, str, dict[str, Any]]] = []

    for hash_dir in profile_dir.iterdir():
        if not hash_dir.is_dir():
            continue
        cache_key = hash_dir.name
        meta = _read_metadata(profile, cache_key)
        if meta is None:
            continue

        images = meta.get("images", [])
        if image_type:
            images = [img for img in images if img.get("type") == image_type]

        if not images:
            continue

        enqueued = meta.get("enqueued_at", "")
        candidates.append((enqueued, cache_key, meta))

    if not candidates:
        if image_type:
            logger.error(
                "no cached firmware found for profile='%s' type='%s'",
                profile,
                image_type,
            )
        else:
            logger.error("no cached firmware found for profile='%s'", profile)
        return 1

    candidates.sort(key=lambda x: x[0], reverse=True)
    newest_cache_key = candidates[0][1]
    newest_meta = candidates[0][2]

    hash_dir = IMAGES_DIR / profile / newest_cache_key

    for img in newest_meta.get("images", []):
        if image_type and img.get("type") != image_type:
            continue
        img_path = hash_dir / img["name"]
        if img_path.exists():
            print(str(img_path))
            return 0

    if hash_dir.exists():
        print(str(hash_dir))
        return 0

    logger.error("metadata found but image files missing for profile='%s'", profile)
    return 1


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _ensure_gitignore() -> None:
    """Append 'images/' to .gitignore if not already present."""
    gitignore_path = REPO_ROOT / ".gitignore"
    if not gitignore_path.exists():
        return

    content = gitignore_path.read_text()
    for line in content.splitlines():
        if line.strip() == "images/":
            return

    if not content.endswith("\n"):
        content += "\n"
    content += "# --- Firmware image cache ---\nimages/\n"
    gitignore_path.write_text(content)
    logger.debug("added 'images/' to .gitignore")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Manage OpenWrt firmware images via the ASU API",
    )
    parser.set_defaults(func=None)

    subparsers = parser.add_subparsers(
        title="subcommands",
        dest="command",
    )

    # -- request --
    p_request = subparsers.add_parser(
        "request",
        help="Request a firmware build from ASU and download the result",
    )
    p_request.add_argument(
        "--profile", required=True,
        help="ASU device profile (e.g. dlink_covr-x1860-a1)",
    )
    p_request.add_argument(
        "--version", default="24.10.1",
        help="OpenWrt version (default: 24.10.1)",
    )
    p_request.add_argument(
        "--target", default=None,
        help="Target subtarget (e.g. ramips/mt7621). Auto-resolved from profile if omitted.",
    )
    p_request.add_argument(
        "--packages", default=None,
        help="Comma-separated list of extra packages to include",
    )
    p_request.add_argument(
        "--ssh-key", default=None,
        help="Path to SSH public key (default: [ssh].key from config.toml, then ~/.ssh/id_ed25519.pub)",
    )
    p_request.add_argument(
        "--password", default=None,
        help="Root password to set on first boot",
    )
    p_request.add_argument(
        "--wan-ssh", action="store_true",
        help="Add firewall rule to allow SSH on WAN interface",
    )
    p_request.set_defaults(func=cmd_request)

    # -- list --
    p_list = subparsers.add_parser(
        "list",
        help="List cached firmware images",
    )
    p_list.add_argument(
        "--profile", default=None,
        help="Filter by device profile",
    )
    p_list.set_defaults(func=cmd_list)

    # -- show --
    p_show = subparsers.add_parser(
        "show",
        help="Show full metadata for a cached firmware",
    )
    p_show.add_argument(
        "--profile", required=True,
        help="Device profile name",
    )
    p_show.add_argument(
        "--hash", required=True,
        help="Cache key (full or prefix)",
    )
    p_show.set_defaults(func=cmd_show)

    # -- find --
    p_find = subparsers.add_parser(
        "find",
        help="Find the latest cached firmware for a profile (for scripting)",
    )
    p_find.add_argument(
        "--profile", required=True,
        help="Device profile name",
    )
    p_find.add_argument(
        "--type", default=None,
        choices=["recovery", "factory", "sysupgrade"],
        help="Filter by image type",
    )
    p_find.set_defaults(func=cmd_find)

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    _ensure_gitignore()

    if args.func is None:
        parser.print_help(sys.stderr)
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
