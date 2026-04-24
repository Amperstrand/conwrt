#!/usr/bin/env python3
"""auto-flash — autonomous OpenWrt device migration.

Monitors ethernet for factory-reset devices, identifies them via JNAP,
downloads firmware, flashes, configures, and verifies.
"""

import argparse
import hashlib
import json
import logging
import os
import re
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, TypedDict
from urllib.parse import urlparse
from urllib.request import urlretrieve

logger = logging.getLogger("conwrt")


class ModelInfo(TypedDict):
    openwrt_device: str
    flash_type: str
    description: str
    firmware_filename: str
    mac_oui: list[str]
    boot_wait: str
    vendor: str
    openwrt_target: str
    default_ip: str
    wifi_radio: str
    wifi_sta_interface: str


KNOWN_MODELS: dict[str, dict[str, ModelInfo]] = {
    "WHW03": {
        "1": {
            "openwrt_device": "linksys_whw03",
            "flash_type": "eMMC (4GB)",
            "description": "Velop Tri-Band V1",
            "firmware_filename": "openwrt-{version}-ipq40xx-generic-linksys_whw03-squashfs-factory.bin",
            "mac_oui": ["14:91:82"],
            "boot_wait": "300",
            "vendor": "Linksys",
            "openwrt_target": "ipq40xx/generic",
            "default_ip": "192.168.1.1",
            "wifi_radio": "radio1",
            "wifi_sta_interface": "phy1-sta0",
        },
        "2": {
            "openwrt_device": "linksys_whw03v2",
            "flash_type": "NAND (512MB)",
            "description": "Velop Tri-Band V2",
            "firmware_filename": "openwrt-{version}-ipq40xx-generic-linksys_whw03v2-squashfs-factory.bin",
            "mac_oui": ["E8:9F:80"],
            "boot_wait": "180",
            "vendor": "Linksys",
            "openwrt_target": "ipq40xx/generic",
            "default_ip": "192.168.1.1",
            "wifi_radio": "radio1",
            "wifi_sta_interface": "phy1-sta0",
        },
    },
    "AR150": {
        "1": {
            "openwrt_device": "glinet_gl-ar150",
            "flash_type": "NOR (16MB)",
            "description": "AR150 Mini Router (all variants)",
            "firmware_filename": "openwrt-{version}-ath79-generic-glinet_gl-ar150-squashfs-sysupgrade.bin",
            "mac_oui": ["94:83:C4"],
            "boot_wait": "90",
            "vendor": "GL.iNet",
            "openwrt_target": "ath79/generic",
            "default_ip": "192.168.8.1",
            "wifi_radio": "radio0",
            "wifi_sta_interface": "phy0-sta0",
        },
    },
    "AR300M": {
        "lite": {
            "openwrt_device": "glinet_gl-ar300m-lite",
            "flash_type": "NOR (16MB)",
            "description": "AR300M-Lite / AR300M16 / AR300M16-Ext (NOR only)",
            "firmware_filename": "openwrt-{version}-ath79-generic-glinet_gl-ar300m-lite-squashfs-sysupgrade.bin",
            "mac_oui": ["94:83:C4"],
            "boot_wait": "90",
            "vendor": "GL.iNet",
            "openwrt_target": "ath79/generic",
            "default_ip": "192.168.8.1",
            "wifi_radio": "radio0",
            "wifi_sta_interface": "phy0-sta0",
        },
        "nand": {
            "openwrt_device": "glinet_gl-ar300m-nand",
            "flash_type": "NAND (128MB) + NOR (16MB)",
            "description": "AR300M / AR300M-Ext / AR300MD (NAND boot)",
            "firmware_filename": "openwrt-{version}-ath79-nand-glinet_gl-ar300m-nand-squashfs-sysupgrade.bin",
            "mac_oui": ["94:83:C4"],
            "boot_wait": "120",
            "vendor": "GL.iNet",
            "openwrt_target": "ath79/nand",
            "default_ip": "192.168.8.1",
            "wifi_radio": "radio0",
            "wifi_sta_interface": "phy0-sta0",
        },
        "nor": {
            "openwrt_device": "glinet_gl-ar300m-nor",
            "flash_type": "NOR (16MB) + NAND (128MB)",
            "description": "AR300M / AR300M-Ext (NOR boot, NAND-aware)",
            "firmware_filename": "openwrt-{version}-ath79-nand-glinet_gl-ar300m-nor-squashfs-sysupgrade.bin",
            "mac_oui": ["94:83:C4"],
            "boot_wait": "120",
            "vendor": "GL.iNet",
            "openwrt_target": "ath79/nand",
            "default_ip": "192.168.8.1",
            "wifi_radio": "radio0",
            "wifi_sta_interface": "phy0-sta0",
        },
    },
    "MT3000": {
        "1": {
            "openwrt_device": "glinet_gl-mt3000",
            "flash_type": "NAND (128MB)",
            "description": "Beryl AX (GL-MT3000) WiFi 6 travel router",
            "firmware_filename": "openwrt-{version}-mediatek-filogic-glinet_gl-mt3000-squashfs-sysupgrade.bin",
            "mac_oui": ["94:83:C4"],
            "boot_wait": "120",
            "vendor": "GL.iNet",
            "openwrt_target": "mediatek/filogic",
            "default_ip": "192.168.1.1",
            "wifi_radio": "radio0",
            "wifi_sta_interface": "phy0-sta0",
        },
    },
}

FIRMWARE_BASE_URL_TEMPLATE = (
    "https://downloads.openwrt.org/releases/{version}/targets/{target}/{filename}"
)


@dataclass
class Config:
    interface: str = "enp5s0"
    device_ip: str = "192.168.1.1"
    openwrt_version: str = "24.10.6"
    model: str = ""
    wifi_ssid: str = ""
    wifi_password: str = ""
    ssh_key_path: str = ""
    firmware_dir: Path = Path(__file__).resolve().parent.parent / "data" / "firmware"
    inventory_path: Path = Path(__file__).resolve().parent.parent / "data" / "inventory" / "devices.json"
    log_dir: Path = Path(__file__).resolve().parent.parent / "data" / "logs"
    capture_timeout: int = 120
    flash_timeout: int = 300
    boot_wait: int = 120
    stock_ready_wait: int = 240
    sta_connect_wait: int = 20
    max_retries: int = 3
    no_passive: bool = False
    no_flash: bool = False


def load_env(env_path: Path) -> dict[str, str]:
    env = {}
    if not env_path.exists():
        return env
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, value = line.split("=", 1)
                env[key.strip()] = value.strip()
    return env


def build_config(args: argparse.Namespace) -> Config:
    project_root = Path(__file__).resolve().parent.parent
    env = load_env(project_root / ".env")

    cfg = Config(
        interface=args.interface,
        device_ip=args.device_ip,
        openwrt_version=args.version,
        model=args.model or "",
        max_retries=args.max_retries,
        no_passive=args.no_passive,
        no_flash=args.no_flash,
        wifi_ssid=env.get("CONWRT_WIFI_SSID", ""),
        wifi_password=env.get("CONWRT_WIFI_PASSWORD", ""),
    )
    return cfg


def hostname_for_mac(mac: str) -> str:
    return hashlib.sha256(mac.upper().encode()).hexdigest()[:12]


def read_ssh_pubkey(path: str) -> str:
    with open(path) as f:
        return f.read().strip()


def get_mac_from_arp(ip: str) -> str:
    try:
        run_cmd(["ping", "-c", "1", "-W", "1", ip], timeout=3, check=False)
        time.sleep(1)
    except Exception:
        pass
    try:
        r = run_cmd(["arp", "-an"], timeout=5, check=False)
        for line in r.stdout.splitlines():
            if f"({ip})" in line:
                match = re.search(r"at ([0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})", line)
                if match:
                    return match.group(1).upper()
    except Exception:
        pass
    return ""


def model_boot_wait(cfg: Config, device_info: dict[str, Any]) -> int:
    model = device_info.get("model", "")
    hardware_version = device_info.get("hardware_version", "")
    model_info = get_model_info(model, hardware_version)
    if model_info is None:
        return cfg.boot_wait
    return int(model_info["boot_wait"])


def get_model_info(model: str, hardware_version: str) -> Optional[ModelInfo]:
    versions = KNOWN_MODELS.get(model)
    if versions is None:
        return None
    return versions.get(hardware_version)


def build_device_info(
    model: str,
    hardware_version: str,
    *,
    manufacturer: str | None = None,
    serial_number: str = "",
    original_firmware: str = "",
    mac_address: str = "",
) -> Optional[dict[str, Any]]:
    model_info = get_model_info(model, hardware_version)
    if model_info is None:
        return None
    return {
        "manufacturer": manufacturer or model_info["vendor"],
        "model": model,
        "hardware_version": hardware_version,
        "serial_number": serial_number,
        "original_firmware": original_firmware,
        "mac_address": mac_address,
        "openwrt_device": model_info["openwrt_device"],
        "flash_type": model_info["flash_type"],
        "description": model_info["description"],
    }


def get_wan_ip(cfg: Config, device_info: dict[str, Any]) -> str:
    model_info = get_model_info(device_info["model"], device_info["hardware_version"])
    wifi_sta_if = "phy1-sta0"
    if model_info is not None:
        wifi_sta_if = model_info["wifi_sta_interface"]
    for command in [
        "ifstatus wan",
        "ubus call network.interface.wan status",
        f"ifconfig {wifi_sta_if} 2>/dev/null",
        f"ip -4 addr show dev {wifi_sta_if} 2>/dev/null",
    ]:
        result = ssh_cmd(cfg, command, timeout=10)
        if result.returncode == 0:
            address = parse_ipv4_from_text(result.stdout)
            if address:
                return address
    return ""


def parse_ipv4_from_text(text: str) -> str:
    match = re.search(r'"address"\s*:\s*"(\d+\.\d+\.\d+\.\d+)"', text)
    if match:
        return match.group(1)
    match = re.search(r"inet addr:(\d+\.\d+\.\d+\.\d+)", text)
    if match:
        return match.group(1)
    match = re.search(r"\b(\d+\.\d+\.\d+\.\d+)\b", text)
    if match:
        return match.group(1)
    return ""


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


def ssh_cmd(
    cfg: Config,
    *args: str,
    timeout: int = 15,
    device_ip: str | None = None,
) -> subprocess.CompletedProcess[str]:
    ip = device_ip or cfg.device_ip
    cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=5",
        "-o", "LogLevel=ERROR",
        f"root@{ip}",
        *args,
    ]
    return run_cmd(cmd, timeout=timeout, check=False)


def ssh_shell(
    cfg: Config,
    script: str,
    timeout: int = 30,
    device_ip: str | None = None,
) -> subprocess.CompletedProcess[str]:
    ip = device_ip or cfg.device_ip
    cmd = [
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=5",
        "-o", "LogLevel=ERROR",
        f"root@{ip}",
        script,
    ]
    return run_cmd(cmd, timeout=timeout, check=False)


# ---------------------------------------------------------------------------
# Phase 1: Passive detection (scapy)
# ---------------------------------------------------------------------------


def passive_detect(cfg: Config) -> dict[str, Any]:
    try:
        from scapy.all import sniff, DHCP, DNS, Ether, conf  # type: ignore[attr-defined]
        from scapy.contrib.lldp import LLDPDU
    except ImportError:
        logger.warning("scapy not available, skipping passive detection")
        return {}

    logger.info("passive: sniffing %s for %ds...", cfg.interface, cfg.capture_timeout)

    discovered: dict[str, Any] = {
        "mac": None,
        "oui": None,
        "lldp": {},
        "dhcp": {},
        "mdns": [],
    }

    def _parse_packet(pkt) -> None:  # type: ignore[no-untyped-def]
        if pkt.haslayer(LLDPDU):
            try:
                payload = bytes(pkt[LLDPDU])
                decoded = payload.decode("ascii", errors="replace")
                if "Velop" in decoded:
                    discovered["lldp"]["system_name"] = "Velop"
                if "nodes" in decoded:
                    discovered["lldp"]["chassis"] = "nodes"
                if "192.168.1.1" in decoded:
                    discovered["lldp"]["management_ip"] = "192.168.1.1"
                if "eth1" in decoded:
                    discovered["lldp"]["port"] = "eth1"
                if "Linux" in decoded:
                    match = re.search(r"Linux [^\x00]+", decoded)
                    if match:
                        discovered["lldp"]["os"] = match.group().strip()
            except Exception:
                pass

        if pkt.haslayer(Ether):
            mac = pkt[Ether].src
            if mac and mac != "ff:ff:ff:ff:ff:ff" and not mac.startswith("01:00:5e"):
                discovered["mac"] = mac
                discovered["oui"] = mac[:8].upper()

        if pkt.haslayer(DHCP):
            try:
                dhcp = pkt[DHCP]
                if discovered["mac"] is None and pkt.haslayer(Ether):
                    discovered["mac"] = pkt[Ether].src
                    discovered["oui"] = pkt[Ether].src[:8].upper()
                discovered["dhcp"]["seen"] = True
            except Exception:
                pass

        # mDNS
        if pkt.haslayer(DNS):
            try:
                dns = pkt[DNS]
                if dns.rrcount > 0 or dns.qdcount > 0:
                    payload = bytes(dns)
                    decoded = payload.decode("ascii", errors="replace")
                    if "_http" in decoded or "_linksys" in decoded:
                        discovered["mdns"].append(decoded[:200])
            except Exception:
                pass

    conf.verb = 0
    try:
        sniff(
            iface=cfg.interface,
            prn=_parse_packet,
            timeout=cfg.capture_timeout,
            store=False,
        )
    except PermissionError:
        logger.error("passive: need root/capabilities for sniffing. Try: sudo ...")
        return {}
    except Exception as exc:
        logger.warning("passive: sniffing failed: %s", exc)
        return {}

    oui = discovered.get("oui")
    if oui:
        logger.info("passive: MAC=%s OUI=%s", discovered["mac"], oui)
        for model_name, versions in KNOWN_MODELS.items():
            for ver, info in versions.items():
                if oui.upper() in [o.upper() for o in info.get("mac_oui", [])]:
                    logger.info("passive: OUI match → %s V%s", model_name, ver)
                    discovered["guessed_model"] = model_name
                    discovered["guessed_version"] = ver

    if discovered["lldp"]:
        logger.info("passive: LLDP data=%s", discovered["lldp"])
    if not discovered["mac"]:
        logger.info("passive: no device detected")

    return discovered


def jnap_get_device_info(device_ip: str) -> Optional[dict[str, Any]]:
    import http.client

    headers = {
        "Content-Type": "application/json; charset=UTF-8",
        "X-JNAP-Action": "http://linksys.com/jnap/core/GetDeviceInfo",
    }
    for use_https in [False, True]:
        proto = "HTTPS" if use_https else "HTTP"
        try:
            if use_https:
                conn = http.client.HTTPSConnection(device_ip, timeout=10, context=__import__("ssl")._create_unverified_context())
            else:
                conn = http.client.HTTPConnection(device_ip, timeout=10)
            conn.request("POST", "/JNAP/", body="{}", headers=headers)
            resp = conn.getresponse()
            body = resp.read().decode()
            conn.close()
            data = json.loads(body)
            if data.get("result") == "OK":
                logger.info("jnap: identified via %s", proto)
                return data.get("output", {})
            logger.warning("jnap: %s result=%s", proto, data.get("result"))
        except Exception as exc:
            logger.debug("jnap: %s failed: %s", proto, exc)
    return None


def _is_openwrt(device_ip: str) -> bool:
    try:
        r = run_cmd(
            ["curl", "-sk", "--max-time", "3", f"http://{device_ip}/"],
            check=False,
        )
        if "LuCI" in r.stdout or "openwrt" in r.stdout.lower():
            return True
    except Exception:
        pass
    try:
        r = run_cmd(
            ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
             "-o", "ConnectTimeout=3", "-o", "LogLevel=ERROR",
             f"root@{device_ip}", "cat /etc/openwrt_release"],
            timeout=5, check=False,
        )
        if r.returncode == 0 and "OPENWRT" in r.stdout.upper():
            return True
    except Exception:
        pass
    return False


def _is_uboot(device_ip: str) -> bool:
    try:
        r = run_cmd(
            ["curl", "-s", "--max-time", "3", f"http://{device_ip}/"],
            check=False,
        )
        if "FIRMWARE UPDATE" in r.stdout or "firmware" in r.stdout.lower():
            return True
        if "uIP" in r.stdout:
            return True
    except Exception:
        pass
    try:
        r = run_cmd(
            ["curl", "-sI", "--max-time", "3", f"http://{device_ip}/"],
            check=False,
        )
        if "uIP" in r.stdout:
            return True
    except Exception:
        pass
    return False


def _is_glinet_stock(device_ip: str) -> bool:
    try:
        r = run_cmd(
            ["curl", "-sk", "--max-time", "3", "-o", "/dev/null", "-w", "%{http_code}", f"http://{device_ip}/"],
            check=False,
        )
        if r.stdout.strip() == "200":
            r2 = run_cmd(
                ["curl", "-sk", "--max-time", "3", f"http://{device_ip}/cgi-bin/luci"],
                check=False,
            )
            if r2.returncode == 0 and len(r2.stdout) > 100:
                return True
    except Exception:
        pass
    return False


def detect_boot_state(cfg: Config) -> str:
    if _is_uboot("192.168.1.1"):
        logger.info("detect: U-Boot safe mode detected at 192.168.1.1")
        return "uboot"

    if _is_openwrt("192.168.1.1"):
        logger.info("detect: OpenWrt detected at 192.168.1.1")
        return "openwrt"

    if _is_glinet_stock("192.168.8.1"):
        logger.info("detect: GL.iNet stock firmware detected at 192.168.8.1")
        return "glinet_stock"

    info = jnap_get_device_info(cfg.device_ip)
    if info:
        logger.info("detect: Linksys stock firmware detected via JNAP")
        return "linksys_stock"

    return "unknown"


def identify_glinet(cfg: Config, device_ip: str) -> Optional[dict[str, Any]]:
    logger.info("glinet: identifying device at %s...", device_ip)

    r = run_cmd(
        [
            "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR",
            f"root@{device_ip}", "cat /tmp/sysinfo/board_name 2>/dev/null || echo unknown",
        ],
        timeout=10,
        check=False,
    )
    board_name = r.stdout.strip().splitlines()[0] if r.stdout.strip() else "unknown"

    r2 = run_cmd(
        [
            "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR",
            f"root@{device_ip}", "cat /tmp/sysinfo/model 2>/dev/null || echo unknown",
        ],
        timeout=10,
        check=False,
    )
    model_name = r2.stdout.strip().splitlines()[0] if r2.stdout.strip() else "unknown"

    r_mtd = run_cmd(
        [
            "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR",
            f"root@{device_ip}", "cat /proc/mtd 2>/dev/null || echo unknown",
        ],
        timeout=10,
        check=False,
    )
    mtd_text = r_mtd.stdout

    r_ports = run_cmd(
        [
            "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR",
            f"root@{device_ip}", "ls /sys/class/net/ 2>/dev/null | grep '^eth' | wc -l",
        ],
        timeout=10,
        check=False,
    )
    port_count = 0
    if r_ports.stdout.strip().isdigit():
        port_count = int(r_ports.stdout.strip())

    mac = ""
    r3 = run_cmd(
        [
            "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR",
            f"root@{device_ip}", "cat /sys/class/net/eth0/address 2>/dev/null || echo unknown",
        ],
        timeout=10,
        check=False,
    )
    if r3.returncode == 0 and ":" in r3.stdout:
        mac = r3.stdout.strip().upper()

    if not mac:
        mac = get_mac_from_arp(device_ip)

    if not mac:
        logger.error("glinet: could not determine MAC address")
        return None

    for model_key, versions in KNOWN_MODELS.items():
        for ver_key, info in versions.items():
            if info["vendor"] != "GL.iNet":
                continue
            normalized = info["openwrt_device"].replace("_", "-").replace("glinet-", "glinet,")
            if normalized in board_name:
                logger.info("glinet: identified as %s (%s) via board_name=%s", model_key, ver_key, board_name)
                return {
                    "manufacturer": "GL.iNet",
                    "model": model_key,
                    "hardware_version": ver_key,
                    "serial_number": "",
                    "original_firmware": model_name,
                    "mac_address": mac,
                    "openwrt_device": info["openwrt_device"],
                    "flash_type": info["flash_type"],
                    "description": info["description"],
                }

    if "glinet,gl-ar300m" in board_name or "AR300M" in model_name.upper():
        variant = "lite"
        if '"kernel"' in mtd_text and '"ubi"' in mtd_text:
            variant = "nand"
        elif port_count <= 1:
            variant = "lite"
        logger.info(
            "glinet: inferred AR300M (%s) via board_name=%s mtd=%s ports=%d",
            variant,
            board_name,
            "dual-flash" if '"kernel"' in mtd_text and '"ubi"' in mtd_text else "nor-only",
            port_count,
        )
        info = KNOWN_MODELS["AR300M"][variant]
        return {
            "manufacturer": "GL.iNet",
            "model": "AR300M",
            "hardware_version": variant,
            "serial_number": "",
            "original_firmware": model_name,
            "mac_address": mac,
            "openwrt_device": info["openwrt_device"],
            "flash_type": info["flash_type"],
            "description": info["description"],
        }

    if "glinet,gl-ar150" in board_name or "AR150" in model_name.upper():
        info = KNOWN_MODELS["AR150"]["1"]
        logger.info("glinet: inferred AR150 via board_name=%s", board_name)
        return {
            "manufacturer": "GL.iNet",
            "model": "AR150",
            "hardware_version": "1",
            "serial_number": "",
            "original_firmware": model_name,
            "mac_address": mac,
            "openwrt_device": info["openwrt_device"],
            "flash_type": info["flash_type"],
            "description": info["description"],
        }

    oui = mac[:8].upper()
    for model_key, versions in KNOWN_MODELS.items():
        for ver_key, info in versions.items():
            if info["vendor"] != "GL.iNet":
                continue
            if oui in [o.upper() for o in info["mac_oui"]]:
                logger.info("glinet: identified as %s (%s) via OUI fallback", model_key, ver_key)
                return {
                    "manufacturer": "GL.iNet",
                    "model": model_key,
                    "hardware_version": ver_key,
                    "serial_number": "",
                    "original_firmware": model_name,
                    "mac_address": mac,
                    "openwrt_device": info["openwrt_device"],
                    "flash_type": info["flash_type"],
                    "description": info["description"],
                }

    logger.error("glinet: could not match board_name=%s to any known model", board_name)
    return None


def wait_for_stock_ready(cfg: Config) -> Optional[dict[str, Any]]:
    logger.info("stock: waiting for stock services on %s...", cfg.device_ip)
    deadline = time.time() + cfg.stock_ready_wait
    last_error = ""

    while time.time() < deadline:
        try:
            run_cmd(["ping", "-c", "1", "-W", "2", cfg.device_ip], timeout=5, check=True)
        except Exception:
            time.sleep(5)
            continue

        # Check if this is already OpenWrt — skip stock detection entirely
        if _is_openwrt(cfg.device_ip):
            logger.info("stock: device is already running OpenWrt, skipping stock detection")
            return {"_already_openwrt": True}

        info = jnap_get_device_info(cfg.device_ip)
        if info:
            return info

        try:
            http_code = run_cmd(
                [
                    "curl",
                    "-sk",
                    "--max-time",
                    "5",
                    "-o",
                    "/dev/null",
                    "-w",
                    "%{http_code}",
                    "-u",
                    "admin:admin",
                    f"http://{cfg.device_ip}/fwupdate.html",
                ],
                check=False,
            )
            if http_code.stdout.strip() == "200":
                logger.info("stock: fwupdate.html is ready")
                return {"_stock_ready": True}
            last_error = f"fwupdate_http={http_code.stdout.strip()}"
        except Exception as exc:
            last_error = str(exc)

        logger.debug("stock: services not ready yet (%s)", last_error)
        time.sleep(5)

    logger.error("stock: services did not become ready within %ds", cfg.stock_ready_wait)
    return None


def active_identify(cfg: Config, info: Optional[dict[str, Any]] = None) -> Optional[dict[str, Any]]:
    logger.info("active: probing %s...", cfg.device_ip)
    if info is None:
        info = jnap_get_device_info(cfg.device_ip)
    if not info:
        logger.error("active: could not reach device at %s", cfg.device_ip)
        return None

    manufacturer = info.get("manufacturer", "")
    model = info.get("modelNumber", "")
    hwver = str(info.get("hardwareVersion", ""))
    serial = info.get("serialNumber", "")
    firmware = info.get("firmwareVersion", "")
    macs = info.get("macAddresses", [])

    logger.info("active: %s %s V%s serial=%s fw=%s", manufacturer, model, hwver, serial, firmware)
    if macs:
        logger.info("active: MAC addresses: %s", macs)

    if model not in KNOWN_MODELS:
        logger.error("active: unsupported model '%s'. Aborting.", model)
        return None

    if hwver not in KNOWN_MODELS[model]:
        logger.error("active: unsupported hardware version '%s' for %s. Aborting.", hwver, model)
        return None

    model_info = KNOWN_MODELS[model][hwver]
    mac = macs[0] if macs else ""

    if not mac:
        mac = get_mac_from_arp(cfg.device_ip)
        if mac:
            logger.info("active: MAC from ARP: %s", mac)

    return {
        "manufacturer": manufacturer,
        "model": model,
        "hardware_version": hwver,
        "serial_number": serial,
        "original_firmware": firmware,
        "mac_address": mac,
        "openwrt_device": model_info["openwrt_device"],
        "flash_type": model_info["flash_type"],
        "description": model_info["description"],
    }


def verify_default_creds(device_ip: str) -> bool:
    for use_https in [False, True]:
        proto = "HTTPS" if use_https else "HTTP"
        try:
            r = run_cmd(
                ["curl", "-sk", "--max-time", "5", "-o", "/dev/null", "-w", "%{http_code}",
                 "-u", "admin:admin",
                 f"{'https' if use_https else 'http'}://{device_ip}/fwupdate.html"],
                check=False,
            )
            if r.stdout.strip() == "200":
                logger.info("creds: admin:admin accepted via %s", proto)
                return True
        except Exception:
            pass
    logger.warning("creds: admin:admin rejected on /fwupdate.html — will try /jcgi/ directly")
    return True


def ensure_firmware(cfg: Config, device_info: dict[str, Any]) -> Optional[Path]:
    model_info = KNOWN_MODELS[device_info["model"]][device_info["hardware_version"]]
    filename = model_info["firmware_filename"].format(version=cfg.openwrt_version)
    local_path = cfg.firmware_dir / filename

    if local_path.exists() and local_path.stat().st_size > 1_000_000:
        size_mb = local_path.stat().st_size / (1024 * 1024)
        logger.info("firmware: cached %s (%.1f MB)", filename, size_mb)
        return local_path

    target = model_info["openwrt_target"]
    url = FIRMWARE_BASE_URL_TEMPLATE.format(
        version=cfg.openwrt_version,
        target=target,
        filename=filename,
    )
    logger.info("firmware: downloading %s", url)
    cfg.firmware_dir.mkdir(parents=True, exist_ok=True)

    try:
        tmp_path = local_path.with_suffix(".tmp")
        urlretrieve(url, tmp_path)
        tmp_path.rename(local_path)
        size_mb = local_path.stat().st_size / (1024 * 1024)
        logger.info("firmware: downloaded %.1f MB", size_mb)
        return local_path
    except Exception as exc:
        logger.error("firmware: download failed: %s", exc)
        for p in [local_path, local_path.with_suffix(".tmp")]:
            p.unlink(missing_ok=True)
        return None


def flash_firmware(cfg: Config, firmware_path: Path) -> bool:
    logger.info("flash: uploading %s to %s...", firmware_path.name, cfg.device_ip)

    attempts = [
        (True, "admin:admin", "YWRtaW46YWRtaW4="),
        (False, "admin:admin", "YWRtaW46YWRtaW4="),
    ]

    for use_https, basic_auth, jnap_auth in attempts:
        proto = "HTTPS" if use_https else "HTTP"
        url = f"{'https' if use_https else 'http'}://{cfg.device_ip}/jcgi/"
        try:
            r = run_cmd(
                [
                    "curl", "-sk",
                    "--max-time", str(cfg.flash_timeout),
                    "-u", basic_auth,
                    "-F", "X-JNAP-Action=updatefirmware",
                    "-F", f"X-JNAP-Authorization=Basic {jnap_auth}",
                    f"-F", f"upload=@{firmware_path};type=application/octet-stream",
                    url,
                ],
                timeout=cfg.flash_timeout + 30,
                check=False,
            )
            body = r.stdout.strip()
            logger.debug("flash: %s response: %s", proto, body)
            try:
                result = json.loads(body)
                if result.get("result") == "OK":
                    logger.info("flash: upload accepted via %s", proto)
                    return True
            except json.JSONDecodeError:
                pass
            logger.warning("flash: %s response not OK: %s", proto, body)
        except subprocess.TimeoutExpired:
            logger.warning("flash: %s timed out", proto)
        except Exception as exc:
            logger.warning("flash: %s failed: %s", proto, exc)

    logger.error("flash: upload failed on both HTTP and HTTPS")
    return False


def flash_via_uboot(device_ip: str, firmware_path: Path) -> bool:
    logger.info("uboot: uploading %s to %s via HTTP...", firmware_path.name, device_ip)
    try:
        r = run_cmd(
            [
                "curl", "-sk",
                "--max-time", "300",
                "-F", f"firmware=@{firmware_path};type=application/octet-stream",
                f"http://{device_ip}/",
            ],
            timeout=330,
            check=False,
        )
        if r.returncode == 0:
            logger.info("uboot: firmware uploaded, waiting for device to flash and reboot...")
            return True
        logger.error("uboot: upload failed: %s", r.stderr)
    except Exception as exc:
        logger.error("uboot: upload failed: %s", exc)
    return False


def flash_via_sysupgrade(cfg: Config, device_ip: str, firmware_path: Path) -> bool:
    logger.info("sysupgrade: uploading %s to %s...", firmware_path.name, device_ip)

    scp_cmd = [
        "scp", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR",
        str(firmware_path), f"root@{device_ip}:/tmp/firmware.bin",
    ]
    try:
        r = run_cmd(scp_cmd, timeout=120, check=False)
        if r.returncode != 0:
            logger.error("sysupgrade: scp failed: %s", r.stderr)
            return False
    except Exception as exc:
        logger.error("sysupgrade: scp failed: %s", exc)
        return False

    logger.info("sysupgrade: running sysupgrade -n...")
    time.sleep(2)
    r = run_cmd(
        [
            "ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            f"root@{device_ip}", "sysupgrade -n /tmp/firmware.bin",
        ],
        timeout=60,
        check=False,
    )
    if r.returncode == 0 or "Rebooting" in r.stdout or "reboot" in r.stdout.lower():
        logger.info("sysupgrade: firmware upgrade initiated, device rebooting...")
        return True

    logger.info("sysupgrade: command executed (session may have been killed by reboot)")
    return True


def wait_for_boot(cfg: Config, device_info: dict[str, Any], device_ip: str | None = None) -> bool:
    ip = device_ip or cfg.device_ip
    boot_wait = model_boot_wait(cfg, device_info)
    logger.info("boot: waiting up to %ds for device to come up...", boot_wait)
    deadline = time.time() + boot_wait

    while time.time() < deadline:
        remaining = int(deadline - time.time())
        try:
            run_cmd(["ping", "-c", "1", "-W", "2", ip], timeout=5, check=True)
        except Exception:
            logger.debug("boot: no ping yet (%ds remaining)", remaining)
            time.sleep(5)
            continue

        try:
            r = run_cmd(
                ["curl", "-sk", "--max-time", "3", f"http://{ip}/"],
                check=False,
            )
            if "LuCI" in r.stdout or "openwrt" in r.stdout.lower():
                logger.info("boot: OpenWrt web interface detected")
                return True
        except Exception:
            pass

        try:
            r = ssh_cmd(cfg, "true", timeout=5, device_ip=ip)
            if r.returncode == 0:
                logger.info("boot: SSH available")
                return True
        except Exception:
            pass

        logger.debug("boot: ping OK but OpenWrt not ready (%ds remaining)", remaining)
        time.sleep(5)

    logger.error("boot: device did not come back within %ds", boot_wait)
    return False


def configure_device(cfg: Config, device_info: dict[str, Any]) -> Optional[str]:
    mac = device_info["mac_address"]
    model_info = KNOWN_MODELS.get(device_info["model"], {}).get(device_info["hardware_version"])
    hostname = hostname_for_mac(mac)
    ssh_pubkey = read_ssh_pubkey(cfg.ssh_key_path)
    wifi_ssid = cfg.wifi_ssid
    wifi_pass = cfg.wifi_password
    wifi_radio = model_info["wifi_radio"] if model_info is not None else "radio1"
    wifi_sta_if = model_info["wifi_sta_interface"] if model_info is not None else "phy1-sta0"

    if not wifi_ssid or not wifi_pass:
        logger.error("config: WiFi credentials not set (check .env)")
        return None

    logger.info("config: hostname=%s mac=%s", hostname, mac)

    # Step 1: hostname + SSH key
    setup_script = (
        f"uci set system.@system[0].hostname='{hostname}' && "
        f"uci commit system && "
        f"echo '{hostname}' > /proc/sys/kernel/hostname && "
        f"mkdir -p /etc/dropbear && "
        f"echo '{ssh_pubkey}' > /etc/dropbear/authorized_keys && "
        f"chmod 600 /etc/dropbear/authorized_keys"
    )
    r = ssh_shell(cfg, setup_script, timeout=15)
    if r.returncode != 0:
        logger.error("config: hostname/SSH key failed: %s", r.stderr)
        return None
    logger.info("config: hostname and SSH key set")

    # Step 2: WiFi STA + network + firewall + dropbear (all UCI, no restarts yet)
    uci_script = (
        f"uci set wireless.{wifi_radio}.disabled='0' && "
        f"uci set wireless.{wifi_radio}.channel='auto' && "
        f"uci set wireless.default_{wifi_radio}.mode='sta' && "
        f"uci set wireless.default_{wifi_radio}.ssid='{wifi_ssid}' && "
        f"uci set wireless.default_{wifi_radio}.encryption='psk2' && "
        f"uci set wireless.default_{wifi_radio}.key='{wifi_pass}' && "
        f"uci set wireless.default_{wifi_radio}.network='wan' && "
        f"uci set network.wan.device='{wifi_sta_if}' && "
        f"uci set network.wan.proto='dhcp' && "
        f"uci commit network && "
        f"uci commit wireless && "
        f"uci set firewall.@zone[1].input='ACCEPT' && "
        f"uci commit firewall && "
        f"uci set dropbear.main.PasswordAuth='off' && "
        f"uci set dropbear.main.RootPasswordAuth='off' && "
        f"uci commit dropbear && "
        f"wifi reload"
    )
    r = ssh_shell(cfg, uci_script, timeout=30)
    if r.returncode != 0:
        logger.error("config: UCI/wifi setup failed: %s", r.stderr)
        return None
    logger.info("config: UCI committed, wifi reload issued")

    # Step 3: Wait for STA to connect
    logger.info("config: waiting %ds for WiFi STA to connect...", cfg.sta_connect_wait)
    time.sleep(cfg.sta_connect_wait)

    # Step 4: Restart dropbear in separate SSH session
    r = ssh_cmd(cfg, "/etc/init.d/dropbear restart", timeout=10)
    if r.returncode != 0:
        logger.warning("config: dropbear restart returned non-zero (may be OK if session died): %s", r.stderr)
    else:
        logger.info("config: dropbear restarted")

    # Step 5: Get WAN IP
    time.sleep(3)
    wan_ip = get_wan_ip(cfg, device_info)

    if wan_ip:
        logger.info("config: WAN IP = %s", wan_ip)
    else:
        logger.warning("config: could not determine WAN IP via LAN")

    return wan_ip or None


def verify_device(cfg: Config, wan_ip: str, device_info: dict[str, Any]) -> bool:
    mac = device_info["mac_address"]
    expected_hostname = hostname_for_mac(mac)
    all_ok = True

    if not wan_ip:
        logger.warning("verify: no WAN IP, verification limited to LAN")
        target = cfg.device_ip
    else:
        target = wan_ip

    ssh_opts = [
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        "-o", "LogLevel=ERROR",
    ]

    logger.info("verify: testing SSH key auth to %s...", target)
    try:
        r = run_cmd(
            ["ssh", *ssh_opts, "-o", "PasswordAuthentication=no",
             f"root@{target}", "echo SSH_KEY_OK"],
            timeout=15, check=False,
        )
        if "SSH_KEY_OK" in r.stdout:
            logger.info("verify: SSH key auth works")
        else:
            logger.error("verify: SSH key auth failed: %s", r.stderr)
            all_ok = False
    except Exception as exc:
        logger.error("verify: SSH key auth failed: %s", exc)
        all_ok = False

    if wan_ip:
        logger.info("verify: testing that password auth is rejected...")
        try:
            r = run_cmd(
                ["ssh", *ssh_opts,
                 "-o", "PasswordAuthentication=yes",
                 "-o", "PreferredAuthentications=password",
                 f"root@{target}", "echo PASSWORD_BAD"],
                timeout=10, check=False,
            )
            if "PASSWORD_BAD" in r.stdout:
                logger.error("verify: password auth STILL WORKS (should be disabled!)")
                all_ok = False
            else:
                logger.info("verify: password auth correctly rejected")
        except Exception:
            logger.info("verify: password auth correctly rejected (connection failed)")

    if wan_ip or target == cfg.device_ip:
        try:
            r = run_cmd(
                [
                    "ssh",
                    *ssh_opts,
                    "-o",
                    "PasswordAuthentication=no",
                    f"root@{target}",
                    "sh -c 'uci get system.@system[0].hostname 2>/dev/null || cat /proc/sys/kernel/hostname'",
                ],
                timeout=10,
                check=False,
            )
            actual_hostname = r.stdout.strip().splitlines()[0] if r.stdout.strip() else ""
            if actual_hostname == expected_hostname:
                logger.info("verify: hostname=%s (correct)", actual_hostname)
            else:
                logger.error("verify: hostname=%s expected=%s", actual_hostname, expected_hostname)
                all_ok = False
        except Exception as exc:
            logger.error("verify: hostname check failed: %s", exc)
            all_ok = False

    return all_ok


def update_inventory(cfg: Config, device_info: dict[str, Any], wan_ip: str) -> None:
    mac = device_info["mac_address"]
    hwver = device_info["hardware_version"]
    model_info = KNOWN_MODELS[device_info["model"]][hwver]
    vendor_slug = model_info.get("vendor", "unknown").lower().replace(".", "")
    model_slug = device_info["model"].lower()

    cfg.inventory_path.parent.mkdir(parents=True, exist_ok=True)

    inventory: list[dict] = []
    if cfg.inventory_path.exists():
        try:
            with open(cfg.inventory_path) as f:
                inventory = json.load(f)
        except json.JSONDecodeError:
            logger.warning("inventory: corrupted, starting fresh")
            inventory = []

    for existing in inventory:
        if existing.get("mac_address") == mac:
            existing.update(
                {
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "serial_number": device_info["serial_number"],
                    "original_firmware": device_info["original_firmware"],
                    "flashed_firmware": f"OpenWrt {cfg.openwrt_version}",
                    "hostname": hostname_for_mac(mac),
                    "wan_ip": wan_ip or existing.get("wan_ip", "unknown"),
                    "ssh_key_auth": True,
                    "password_auth": False,
                    "notes": "Auto-provisioned by auto-flash.py",
                }
            )
            with open(cfg.inventory_path, "w") as f:
                json.dump(inventory, f, indent=2)
                f.write("\n")
            logger.info("inventory: updated existing entry for %s", mac)
            return

    existing_v = sum(
        1 for d in inventory
        if d.get("model") == device_info["model"] and d.get("hardware_version") == hwver
    )
    seq = existing_v + 1

    entry = {
        "id": f"{vendor_slug}-{model_slug}-{hwver}-{seq:03d}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "manufacturer": device_info["manufacturer"],
        "model": device_info["model"],
        "hardware_version": hwver,
        "flash_type": model_info["flash_type"],
        "description": model_info["description"],
        "mac_address": mac,
        "serial_number": device_info["serial_number"],
        "original_firmware": device_info["original_firmware"],
        "flashed_firmware": f"OpenWrt {cfg.openwrt_version}",
        "openwrt_target": model_info["openwrt_target"],
        "openwrt_device": model_info["openwrt_device"],
        "hostname": hostname_for_mac(mac),
        "lan_ip": cfg.device_ip,
        "wan_type": "wifi-sta",
        "wan_ssid": cfg.wifi_ssid,
        "wan_ip": wan_ip or "unknown",
        "ssh_key_auth": True,
        "password_auth": False,
        "recipe": f"recipes/{vendor_slug}/{model_slug}/",
        "notes": "Auto-provisioned by auto-flash.py",
    }

    inventory.append(entry)
    with open(cfg.inventory_path, "w") as f:
        json.dump(inventory, f, indent=2)
        f.write("\n")

    logger.info("inventory: updated (%d devices total)", len(inventory))


_interrupted = False


def _handle_signal(signum: int, frame: Any) -> None:
    global _interrupted
    _interrupted = True
    logger.info("interrupted, exiting...")
    sys.exit(1)


def _pipeline_finish(cfg: Config, device_info: dict[str, Any]) -> bool:
    wan_ip = configure_device(cfg, device_info)
    if not wan_ip:
        logger.warning("config: completed but WAN IP unknown, verification will be limited")

    if not verify_device(cfg, wan_ip or "", device_info):
        logger.error("verification failed")
        return False

    update_inventory(cfg, device_info, wan_ip or "unknown")

    logger.info(
        "SUCCESS: %s %s V%s → %s (hostname=%s, wan=%s)",
        device_info["manufacturer"],
        device_info["model"],
        device_info["hardware_version"],
        f"OpenWrt {cfg.openwrt_version}",
        hostname_for_mac(device_info["mac_address"]),
        wan_ip or "?",
    )
    return True


def _pipeline_existing_openwrt_whw03(cfg: Config) -> bool:
    logger.info("device already running OpenWrt — attempting configuration only")
    mac = get_mac_from_arp(cfg.device_ip) or ""
    if not mac:
        logger.error("aborting: cannot determine MAC of existing OpenWrt device")
        return False
    device_info = {
        "manufacturer": "Linksys",
        "model": "WHW03",
        "hardware_version": "1",
        "serial_number": "",
        "original_firmware": "",
        "mac_address": mac,
        "openwrt_device": "linksys_whw03",
        "flash_type": "eMMC/NAND",
        "description": "Velop Tri-Band (already on OpenWrt)",
    }
    wan_ip = configure_device(cfg, device_info)
    if not wan_ip:
        logger.warning("config: completed but WAN IP unknown")
    if not verify_device(cfg, wan_ip or "", device_info):
        logger.error("verification failed")
        return False
    update_inventory(cfg, device_info, wan_ip or "unknown")
    logger.info("SUCCESS: re-configured existing OpenWrt device (hostname=%s)", hostname_for_mac(mac))
    return True


def _resolve_model_override(model_arg: str) -> Optional[tuple[str, str]]:
    value = model_arg.strip().upper()
    if not value:
        return None
    if value == "AR150":
        return ("AR150", "1")
    if value in {"AR300M/LITE", "AR300M16", "AR300M16-EXT", "AR300M-LITE"}:
        return ("AR300M", "lite")
    if value in {"AR300M/NAND", "AR300M", "AR300M-EXT", "AR300MD"}:
        return ("AR300M", "nand")
    if value == "AR300M/NOR":
        return ("AR300M", "nor")
    if value == "MT3000":
        return ("MT3000", "1")
    return None


def _log_glinet_oui_matches() -> None:
    matches: list[str] = []
    for model, versions in KNOWN_MODELS.items():
        for hwver, info in versions.items():
            if info["vendor"] == "GL.iNet":
                matches.append(f"{model}/{hwver}")
    logger.info("uboot: GL.iNet OUI matches known models: %s", ", ".join(matches))


def _pipeline_uboot(cfg: Config) -> bool:
    if not cfg.model:
        _log_glinet_oui_matches()
        logger.error("uboot: --model is required in U-Boot mode")
        return False

    resolved = _resolve_model_override(cfg.model)
    if resolved is None:
        logger.error("uboot: unsupported --model value '%s'", cfg.model)
        return False

    device_info = build_device_info(*resolved, manufacturer="GL.iNet")
    if device_info is None:
        logger.error("uboot: could not map model '%s'", cfg.model)
        return False

    if cfg.no_flash:
        logger.info("dry run: stopping after identification (--no-flash)")
        print(json.dumps(device_info, indent=2))
        return True

    firmware_path = ensure_firmware(cfg, device_info)
    if not firmware_path:
        logger.error("aborting: firmware not available")
        return False

    if not flash_via_uboot("192.168.1.1", firmware_path):
        logger.error("aborting: firmware upload failed")
        return False

    if not wait_for_boot(cfg, device_info, device_ip="192.168.1.1"):
        logger.error("aborting: device did not boot OpenWrt")
        return False

    identified = identify_glinet(cfg, "192.168.1.1")
    if identified is None:
        logger.error("aborting: could not identify flashed GL.iNet device")
        return False

    return _pipeline_finish(cfg, identified)


def _pipeline_glinet_stock(cfg: Config) -> bool:
    device_info = identify_glinet(cfg, "192.168.8.1")
    if not device_info:
        logger.error("aborting: could not identify GL.iNet device")
        return False

    logger.info(
        "identified: %s %s V%s (%s) MAC=%s",
        device_info["manufacturer"],
        device_info["model"],
        device_info["hardware_version"],
        device_info["flash_type"],
        device_info["mac_address"],
    )

    if cfg.no_flash:
        logger.info("dry run: stopping after identification (--no-flash)")
        print(json.dumps(device_info, indent=2))
        return True

    firmware_path = ensure_firmware(cfg, device_info)
    if not firmware_path:
        logger.error("aborting: firmware not available")
        return False

    if not flash_via_sysupgrade(cfg, "192.168.8.1", firmware_path):
        logger.error("aborting: firmware upload failed")
        return False

    if not wait_for_boot(cfg, device_info, device_ip="192.168.1.1"):
        logger.error("aborting: device did not boot OpenWrt")
        return False

    identified = identify_glinet(cfg, "192.168.1.1")
    if identified is None:
        logger.error("aborting: could not identify OpenWrt device after sysupgrade")
        return False

    return _pipeline_finish(cfg, identified)


def _pipeline_openwrt(cfg: Config) -> bool:
    device_info = identify_glinet(cfg, "192.168.1.1")
    if device_info is not None:
        logger.info(
            "identified: %s %s V%s (%s) MAC=%s",
            device_info["manufacturer"],
            device_info["model"],
            device_info["hardware_version"],
            device_info["flash_type"],
            device_info["mac_address"],
        )
        if cfg.no_flash:
            logger.info("dry run: stopping after identification (--no-flash)")
            print(json.dumps(device_info, indent=2))
            return True
        return _pipeline_finish(cfg, device_info)

    return _pipeline_existing_openwrt_whw03(cfg)


def _pipeline_linksys_stock(cfg: Config) -> bool:
    stock_info = wait_for_stock_ready(cfg)
    if stock_info is None:
        logger.error("aborting: stock device never became ready for identification")
        return False

    if stock_info.get("_already_openwrt"):
        return _pipeline_existing_openwrt_whw03(cfg)

    device_info = active_identify(cfg, None if stock_info.get("_stock_ready") else stock_info)
    if not device_info:
        logger.error("aborting: could not identify device")
        return False

    logger.info(
        "identified: %s %s V%s (%s) MAC=%s",
        device_info["manufacturer"],
        device_info["model"],
        device_info["hardware_version"],
        device_info["flash_type"],
        device_info["mac_address"],
    )

    if cfg.no_flash:
        logger.info("dry run: stopping after identification (--no-flash)")
        print(json.dumps(device_info, indent=2))
        return True

    if not verify_default_creds(cfg.device_ip):
        logger.error("aborting: default credentials rejected")
        return False

    firmware_path = ensure_firmware(cfg, device_info)
    if not firmware_path:
        logger.error("aborting: firmware not available")
        return False

    if not flash_firmware(cfg, firmware_path):
        logger.error("aborting: firmware upload failed")
        return False

    if not wait_for_boot(cfg, device_info):
        logger.error("aborting: device did not boot OpenWrt")
        return False

    return _pipeline_finish(cfg, device_info)


def run_pipeline(cfg: Config) -> bool:

    if not cfg.no_passive:
        passive_info = passive_detect(cfg)
        if passive_info.get("mac"):
            logger.info(
                "passive: detected MAC=%s (model guess: %s V%s)",
                passive_info["mac"],
                passive_info.get("guessed_model", "?"),
                passive_info.get("guessed_version", "?"),
            )
        else:
            logger.info("passive: no device detected, proceeding to active probe")

    boot_state = detect_boot_state(cfg)
    if boot_state == "uboot":
        return _pipeline_uboot(cfg)
    if boot_state == "glinet_stock":
        return _pipeline_glinet_stock(cfg)
    if boot_state == "openwrt":
        return _pipeline_openwrt(cfg)
    if boot_state == "linksys_stock":
        return _pipeline_linksys_stock(cfg)

    logger.error("aborting: could not detect device boot state")
    return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="conwrt auto-flash — autonomous OpenWrt device migration",
    )
    parser.add_argument("--interface", default="enp5s0", help="Wired ethernet interface (default: enp5s0)")
    parser.add_argument("--device-ip", default="192.168.1.1", help="Target device IP (default: 192.168.1.1)")
    parser.add_argument("--version", default="24.10.6", help="OpenWrt version (default: 24.10.6)")
    parser.add_argument("--max-retries", type=int, default=3, help="Max restart attempts on error (default: 3)")
    parser.add_argument("--model", help="Specify model for U-Boot mode (e.g. AR150, AR300M/lite, AR300M/nand)")
    parser.add_argument("--no-passive", action="store_true", help="Skip passive detection")
    parser.add_argument("--no-flash", action="store_true", help="Identify only, don't flash (dry run)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging on console")
    args = parser.parse_args()

    cfg = build_config(args)

    log_format = "[%(asctime)s] %(levelname)s %(message)s"
    log_datefmt = "%H:%M:%S"
    level = logging.DEBUG if args.verbose else logging.INFO

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(logging.Formatter(log_format, log_datefmt))
    logger.addHandler(console_handler)

    cfg.log_dir.mkdir(parents=True, exist_ok=True)
    log_ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    file_handler = logging.FileHandler(cfg.log_dir / f"auto-flash-{log_ts}.log")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(log_format, log_datefmt))
    logger.addHandler(file_handler)
    logger.setLevel(logging.DEBUG)

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    logger.info("conwrt auto-flash starting (interface=%s, version=%s)", cfg.interface, cfg.openwrt_version)

    for attempt in range(1, cfg.max_retries + 1):
        try:
            if run_pipeline(cfg):
                sys.exit(0)
            logger.error("attempt %d/%d failed", attempt, cfg.max_retries)
        except KeyboardInterrupt:
            sys.exit(1)
        except SystemExit:
            raise
        except Exception as exc:
            logger.exception("attempt %d/%d crashed: %s", attempt, cfg.max_retries, exc)

        if attempt < cfg.max_retries:
            logger.info("restarting in 5s...")
            time.sleep(5)

    logger.error("all %d attempts failed", cfg.max_retries)
    sys.exit(1)


if __name__ == "__main__":
    main()
