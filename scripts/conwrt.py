#!/usr/bin/env python3
"""conwrt — OpenWrt flasher with auto-detection, pcap monitoring, and ASU integration.

Reads device profiles from conwrt model JSON files via model_loader.
Auto-detects device state (OpenWrt running, U-Boot recovery, or offline) and
picks the appropriate flash method (SSH sysupgrade or U-Boot HTTP upload).

Usage:
    # Flash (auto-detects method):
    conwrt --request-image --wan-ssh
    conwrt flash --model-id dlink-covr-x1860-a1 --request-image --force-uboot

    # List supported models:
    conwrt list

    # Manage cached firmware:
    conwrt cache list
    conwrt cache clean --keep-latest
    conwrt cache clean --model-id dlink-covr-x1860-a1
"""

import argparse
import hashlib
import io
import json
import os
import queue
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from contextlib import redirect_stdout
from enum import Enum, auto
from pathlib import Path
from types import SimpleNamespace
from typing import Optional

# model_loader is in the same directory
sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import load_config as _load_config
from model_loader import load_model, list_models
import importlib
_firmware_manager = importlib.import_module("firmware-manager")
firmware_request = _firmware_manager.cmd_request
firmware_find = _firmware_manager.cmd_find
IMAGES_DIR = _firmware_manager.IMAGES_DIR
_router_fingerprint = importlib.import_module("router-fingerprint")
fingerprint_router = _router_fingerprint.fingerprint_router
save_fingerprint = _router_fingerprint.save_fingerprint


DEFAULT_IP = "192.168.1.1"
REBOOT_TIMEOUT = 360
SILENCE_TIMEOUT_DEFAULT = 30


def _find_recovery_flash_method(model: dict, method_hint: str = "") -> tuple[str, dict]:
    methods = model.get("flash_methods", {})
    if method_hint and method_hint in methods:
        return method_hint, methods[method_hint]
    for method_name, method_cfg in methods.items():
        if "recovery_ip" in method_cfg:
            return method_name, method_cfg
    available = list(methods.keys())
    serial_methods = [m for m in available if m.startswith("serial-tftp-")]
    if serial_methods and not method_hint:
        raise ValueError(
            f"Model '{model.get('id', '?')}' has no HTTP recovery method. "
            f"Use --serial-method to select a serial flash method. "
            f"Available serial methods: {serial_methods}"
        )
    raise ValueError(
        f"No HTTP recovery flash method found in model '{model.get('id', '?')}'. "
        f"Available methods: {available}"
    )


def _build_profile_from_model(model_id: str, serial_method: str = "") -> SimpleNamespace:
    """Load a model and build a runtime profile namespace for the recovery script.

    Returns a SimpleNamespace with the same attributes that DeviceProfile used to have,
    so the rest of the state machine code works unchanged.
    """
    model = load_model(model_id)
    method_hint = f"serial-tftp-{serial_method}" if serial_method else ""
    method_name, fm = _find_recovery_flash_method(model, method_hint)

    is_serial_tftp = method_name.startswith("serial-tftp")

    if is_serial_tftp:
        client_ip = fm.get("tftp_server_ip", "192.168.1.254")
        recovery_ip = fm.get("tftp_router_ip", "192.168.1.1")
    else:
        client_ip = fm["client_ip"]
        recovery_ip = fm["recovery_ip"]

    return SimpleNamespace(
        name=model["id"],
        vendor=model["vendor"],
        description=model["description"],
        flash_method=method_name,
        recovery_ip=recovery_ip,
        client_ip=client_ip,
        client_subnet=fm.get("client_subnet", "255.255.255.0"),
        reset_instructions=fm.get("reset_instructions", ""),
        led_pattern=fm.get("led_pattern", ""),
        upload_endpoint=fm.get("upload_endpoint", ""),
        upload_field=fm.get("upload_field", ""),
        trigger_flash_endpoint=fm.get("trigger_flash_endpoint", ""),
        flash_time_seconds=fm.get("flash_time_seconds", 120),
        silence_timeout=fm.get("silence_timeout", 30),
        openwrt_ip=model["openwrt"]["default_ip"],
        openwrt_client_ip=fm.get("openwrt_client_ip", client_ip),
        is_serial_tftp=is_serial_tftp,
        serial_baud=fm.get("serial_baud", 115200),
        bootmenu_timeout=fm.get("bootmenu_timeout_seconds", 30),
        bootmenu_interrupt=fm.get("bootmenu_interrupt", "ctrl-c"),
        bootmenu_select_console=fm.get("bootmenu_select_console", "0"),
        tftp_server_ip=fm.get("tftp_server_ip", ""),
        lan_port=fm.get("lan_port", ""),
        uboot_commands=fm.get("uboot_commands", []),
        images=fm.get("images", {}),
        eth_prime=fm.get("eth_prime", ""),
    )


def _setup_interface_ips(interface: str, profile: SimpleNamespace) -> None:
    existing = subprocess.run(
        ["ifconfig", interface], capture_output=True, text=True, check=False,
    ).stdout

    if profile.client_ip not in existing:
        result = subprocess.run(
            ["ifconfig", interface, profile.client_ip, "netmask", profile.client_subnet, "up"],
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            print(f"ERROR: need sudo to configure {interface}: {result.stderr.strip()}", file=sys.stderr)
            print(f"  sudo ifconfig {interface} {profile.client_ip} netmask {profile.client_subnet} up", file=sys.stderr)
            sys.exit(1)
        log(f"Configured {interface}: {profile.client_ip}/{profile.client_subnet}")
    else:
        log(f"Interface {interface} already has {profile.client_ip}")

    openwrt_client = profile.openwrt_client_ip
    if openwrt_client and openwrt_client != profile.client_ip and openwrt_client not in existing:
        result = subprocess.run(
            ["ifconfig", interface, openwrt_client, "netmask", "255.255.255.0", "alias"],
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            log(f"WARNING: could not add alias {openwrt_client}: {result.stderr.strip()}")
        else:
            log(f"Added alias {interface}: {openwrt_client}/255.255.255.0")


def _detect_boot_state(interface: str, profile: Optional[SimpleNamespace] = None, timeout: int = 10) -> str:
    """Probe the device to determine its current state.

    Returns: "openwrt", "uboot", or "unknown"
    """
    openwrt_ip = profile.openwrt_ip if profile else "192.168.1.1"
    recovery_ip = profile.recovery_ip if profile else "192.168.0.1"

    try:
        if check_ssh(openwrt_ip):
            log(f"SSH reachable at {openwrt_ip} — device is running OpenWrt")
            return "openwrt"
    except Exception as e:
        log(f"SSH probe failed for {openwrt_ip}: {e}")

    try:
        found, detail = detect_uboot_http(recovery_ip)
        if found:
            log(f"Recovery HTTP at {recovery_ip} — device is in U-Boot mode ({detail})")
            return "uboot"
    except Exception as e:
        log(f"U-Boot HTTP probe failed for {recovery_ip}: {e}")

    if profile and profile.openwrt_ip and profile.recovery_ip:
        if profile.openwrt_ip != "192.168.1.1" or profile.recovery_ip != "192.168.0.1":
            log("No SSH or recovery HTTP detected on profile IPs — device may be on a different subnet")
        else:
            log("No SSH or recovery HTTP detected — device state unknown")
    else:
        log("No SSH or recovery HTTP detected — device state unknown")
    return "unknown"


def _flash_via_sysupgrade(device_ip: str, firmware_path: str, ssh_key: Optional[str] = None) -> bool:
    """Upload firmware via SCP and run sysupgrade -n."""
    firmware_name = os.path.basename(firmware_path)
    remote_path = f"/tmp/{firmware_name}"

    scp_cmd = ["scp", "-o", "StrictHostKeyChecking=no",
               "-o", "UserKnownHostsFile=/dev/null",
               "-o", "ConnectTimeout=10"]
    if ssh_key:
        scp_cmd.extend(["-i", ssh_key])
    scp_cmd.extend([firmware_path, f"root@{device_ip}:{remote_path}"])

    size_mb = os.path.getsize(firmware_path) / 1024 / 1024
    log(f"Uploading {firmware_name} ({size_mb:.1f} MB) via SCP to {device_ip}...")
    try:
        r = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=120, check=False)
        if r.returncode != 0:
            stderr_hint = r.stderr[:300] if r.stderr else "(no stderr)"
            if "permission denied" in stderr_hint.lower():
                log(f"SCP failed (exit {r.returncode}): {stderr_hint}")
                log("Hint: check SSH key authentication — ensure the key is authorized on the device")
            else:
                log(f"SCP failed (exit {r.returncode}): {stderr_hint}")
            return False
    except subprocess.TimeoutExpired:
        log("SCP upload timed out.")
        return False
    except Exception as e:
        log(f"SCP error: {e}")
        return False

    log(f"Firmware uploaded. Running sysupgrade -n {remote_path}...")
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no",
               "-o", "UserKnownHostsFile=/dev/null",
               "-o", "ConnectTimeout=10"]
    if ssh_key:
        ssh_cmd.extend(["-i", ssh_key])
    ssh_cmd.extend([f"root@{device_ip}", f"sysupgrade -n {remote_path}"])

    try:
        r = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30, check=False)
        if r.returncode == 0 or "Upgrading" in r.stdout or "Rebooting" in r.stdout:
            log("sysupgrade initiated successfully.")
            return True
        if r.returncode != 0 and not r.stdout and not r.stderr:
            log("sysupgrade initiated (connection closed by remote — expected).")
            return True
        if "Connection refused" in r.stderr or "Connection timed out" in r.stderr:
            log(f"SSH connection failed during sysupgrade: {r.stderr[:200]}")
            log("Hint: device may have rejected the firmware or SSH is not available")
            return False
        if r.returncode != 0 and "Rebooting" not in r.stdout and "Upgrading" not in r.stdout:
            log(f"WARNING: sysupgrade returned exit {r.returncode}")
            log(f"  stdout: {r.stdout[:300]}")
            log(f"  stderr: {r.stderr[:300]}")
        log(f"sysupgrade returned {r.returncode}: {r.stdout[:200]} {r.stderr[:200]}")
        return r.returncode == 0 or r.returncode == 255
    except subprocess.TimeoutExpired:
        log("sysupgrade command timed out (may have started reboot).")
        return True
    except Exception as e:
        log(f"sysupgrade error: {e}")
        return False


def _wait_for_sysupgrade_reboot(device_ip: str, timeout: int = 180) -> bool:
    """Wait for device to come back after sysupgrade reboot."""
    log(f"Waiting for device to reboot and SSH to come back at {device_ip}...")
    start = ts()
    while ts() - start < timeout:
        if check_ssh(device_ip):
            return True
        time.sleep(10)
    log(f"Device did not come back at {device_ip} within {timeout}s")
    log("Hint: the firmware may be incompatible with this device, or the device booted on a different subnet")
    return False


def _find_model_id_by_board(board_name: str) -> Optional[str]:
    """Search models/*.json for a matching board name in openwrt.device."""
    if not board_name:
        return None
    try:
        for model_info in list_models():
            model = load_model(model_info["id"])
            device = model.get("openwrt", {}).get("device", "")
            if device == board_name:
                return model_info["id"]
    except Exception:
        pass
    return None


 def _detect_ssh_key_path() -> str:
    cfg = _load_config()
    return cfg.ssh_private_key_path


def _arp_target_for_profile(profile: SimpleNamespace) -> str:
    parts = profile.recovery_ip.rsplit(".", 1)
    return f"{parts[0]}.2"


class Event(Enum):
    LINK_DOWN = auto()
    LINK_UP = auto()
    UBOOT_HTTP = auto()
    UBOOT_ARP_192_168_1_2 = auto()
    ICMPV6_FROM_ROUTER = auto()
    SSH_UP = auto()
    FAILSAFE_BROADCAST = auto()
    NO_PACKETS_FOR_N_SECONDS = auto()
    UPLOAD_COMPLETE = auto()
    FLASH_TRIGGERED = auto()
    SERIAL_UBOOT_READY = auto()
    SERIAL_COMMAND_DONE = auto()
    SERIAL_ALL_DONE = auto()


class State(Enum):
    DETECTING = auto()
    SYSUPGRADE_UPLOADING = auto()
    SYSUPGRADE_FLASHING = auto()
    SYSUPGRADE_REBOOTING = auto()
    SYSUPGRADE_BOOTING = auto()
    WAITING_FOR_POWER_OFF = auto()
    WAITING_FOR_UBOOT = auto()
    UBOOT_UPLOADING = auto()
    UBOOT_FLASHING = auto()
    SERIAL_WAITING_FOR_BOOTMENU = auto()
    SERIAL_UBOOT_INTERACTING = auto()
    SERIAL_TFTP_FLASHING = auto()
    REBOOTING = auto()
    OPENWRT_BOOTING = auto()
    COMPLETE = auto()
    FAILED = auto()


@dataclass
class Timeline:
    power_off: Optional[float] = None
    link_up: Optional[float] = None
    uboot_http_first: Optional[float] = None
    upload_start: Optional[float] = None
    upload_complete: Optional[float] = None
    flash_triggered: Optional[float] = None
    flash_complete: Optional[float] = None
    first_openwrt_packet: Optional[float] = None
    ssh_available: Optional[float] = None
    recovery_start: Optional[float] = None


@dataclass
class PcapMonitorConfig:
    interface: str
    pcap_path: str
    recovery_ip: str = DEFAULT_IP
    router_mac_openwrt: str = ""
    router_mac_uboot: str = ""
    uboot_ip: str = DEFAULT_IP
    silence_timeout: int = SILENCE_TIMEOUT_DEFAULT


def ts() -> float:
    return time.time()


def ts_str(t: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(t))


def say(msg: str) -> None:
    try:
        subprocess.run(["say", "-v", "Samantha", msg], check=False, timeout=30)
    except subprocess.TimeoutExpired:
        pass


def log(msg: str) -> None:
    t = time.strftime("%H:%M:%S")
    print(f"  [{t}] {msg}")
    sys.stdout.flush()


def get_link_state(interface: str) -> bool:
    r = subprocess.run(
        ["ifconfig", interface],
        capture_output=True, text=True, timeout=5, check=False,
    )
    return "status: active" in r.stdout.lower()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def detect_uboot_http(recovery_ip: str = DEFAULT_IP) -> tuple[bool, str]:
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", "2", f"http://{recovery_ip}/"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if "FIRMWARE UPDATE" in r.stdout or "firmware" in r.stdout.lower():
            return True, "firmware page"
        if r.stdout.strip().startswith("<!DOCTYPE"):
            return True, "HTML response"
        return False, r.stdout[:100] if r.stdout.strip() else "no response"
    except Exception as e:
        return False, str(e)[:80]


def upload_firmware(image_path: str, profile: SimpleNamespace, timeout: int = 300) -> tuple[bool, str]:
    size_mb = os.path.getsize(image_path) / 1024 / 1024
    endpoint = f"http://{profile.recovery_ip}{profile.upload_endpoint}"
    log(f"Uploading {os.path.basename(image_path)} ({size_mb:.1f} MB) to {profile.upload_endpoint}...")
    try:
        r = subprocess.run(
            [
                "curl", "-sk", "--show-error",
                "--max-time", str(timeout),
                "-F", f"{profile.upload_field}=@{image_path};type=application/octet-stream",
                endpoint,
            ],
            capture_output=True, text=True, timeout=timeout + 30, check=False,
        )
        if r.returncode == 0 and r.stdout.strip():
            response_text = r.stdout.strip()
            # D-Link and similar routers return HTML instead of "size md5hash"
            if response_text.lower().startswith("<!doctype") or response_text.lower().startswith("<html"):
                log("Upload accepted (HTML response)")
                return True, response_text[:200]
            # GL.iNet format: "size md5hash"
            parts = response_text.split()
            uboot_md5 = parts[1] if len(parts) > 1 else "?"
            log(f"Upload accepted: size={parts[0]} bytes, uboot_md5={uboot_md5}")
            return True, response_text
        log(f"Upload failed (exit {r.returncode}): {r.stderr[:300]}")
        return False, r.stderr[:300]
    except subprocess.TimeoutExpired:
        log("Upload timed out.")
        return False, "timeout"
    except Exception as e:
        log(f"Upload error: {e}")
        return False, str(e)


def trigger_flash(profile: SimpleNamespace) -> bool:
    if not profile.trigger_flash_endpoint:
        return True
    endpoint = profile.trigger_flash_endpoint
    # GL.iNet U-Boot uses /result which blocks until flash completes.
    # Allow up to flash_time_seconds + 60s for the response.
    flash_timeout = profile.flash_time_seconds + 60
    log(f"Triggering flash via {endpoint} (timeout: {flash_timeout}s)...")
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", str(flash_timeout),
             f"http://{profile.recovery_ip}{endpoint}"],
            capture_output=True, text=True, timeout=flash_timeout + 30, check=False,
        )
        response = r.stdout.strip()
        if response == "success":
            log(f"Flash completed successfully ({endpoint} returned 'success').")
            return True
        if "Update in progress" in r.stdout:
            log("Flash triggered — 'Update in progress' page returned.")
            return True
        if response:
            log(f"Flash response: {response[:100]}")
            if "success" in response.lower():
                return True
        else:
            log(f"Empty response from {endpoint} — flash may have been consumed already.")
            return True
    except subprocess.TimeoutExpired:
        log(f"Flash trigger timed out after {flash_timeout}s — flash may still be in progress.")
        return True
    except Exception as e:
        log(f"Flash trigger error: {e}")
    return False


def check_ssh(ip: str = DEFAULT_IP) -> bool:
    try:
        r = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null",
             "-o", "ConnectTimeout=3",
             "-o", "PasswordAuthentication=no",
             f"root@{ip}", "echo SSH_OK"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        return "SSH_OK" in r.stdout
    except Exception:
        return False


def verify_router(ip: str = DEFAULT_IP) -> list[tuple[str, str]]:
    log("Verifying router state...")
    checks: list[tuple[str, str]] = []
    try:
        r = subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null",
             "-o", "ConnectTimeout=5",
             "-o", "PasswordAuthentication=no",
             f"root@{ip}",
             "echo hostname=$(cat /proc/sys/kernel/hostname); "
             "echo board=$(cat /etc/board.json | jsonfilter -e '@.model.id' 2>/dev/null || echo unknown); "
             "echo kernel=$(uname -r); "
             "echo sshkey_size=$(wc -c < /etc/dropbear/authorized_keys 2>/dev/null || echo 0); "
             "echo wan_ssh=$(uci show firewall 2>/dev/null | grep Allow-SSH-WAN | wc -l); "
             "echo uci_defaults=$(ls /etc/uci-defaults/ 2>/dev/null | wc -l); "
             "echo mac_brlan=$(cat /sys/class/net/br-lan/address 2>/dev/null || echo ''); "
             "echo mac_eth0=$(cat /sys/class/net/eth0/address 2>/dev/null || echo ''); "
             "echo ping_ok=$(ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 && echo yes || echo no)"],
            capture_output=True, text=True, timeout=20, check=False,
        )
        for line in r.stdout.strip().split('\n'):
            if '=' in line:
                key, val = line.split('=', 1)
                checks.append((key, val))
                log(f"  verify: {key}: {val}")
        uci_defaults = dict(checks).get("uci_defaults", "?")
        if uci_defaults == "0":
            log("  verify OK: no uci-defaults remaining (first boot completed)")
        else:
            log(f"  verify WARN: {uci_defaults} uci-defaults remaining")
        ping_ok = dict(checks).get("ping_ok", "no")
        if ping_ok == "yes":
            log("  verify OK: network connectivity confirmed (ping 8.8.8.8)")
        else:
            log("  verify WARN: no network connectivity")
    except Exception as e:
        log(f"Verification failed: {e}")
    return checks


def probe_router_info(ip: str = DEFAULT_IP) -> Optional[dict]:
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from router_probe import probe_router as _probe_router
        result = _probe_router(ip=ip)
        return {
            "model": result.model,
            "vendor": result.vendor,
            "firmware_version": result.firmware_version,
            "mac": result.mac,
            "ssh_key_count": result.ssh_key_count,
            "state": result.state,
        }
    except Exception as e:
        log(f"Router probe failed: {e}")
        return None


class PcapMonitor:
    """Background thread that captures packets and emits events to a queue.

    Uses two subprocess.Popen instances:
    1. Writer: sudo tcpdump -i <iface> -w <path> -n -U --immediate-mode
       This process may die when the USB ethernet adapter disconnects on reboot.
       The monitor watches it and restarts when the interface comes back.
    2. Reader: tcpdump -r <path> -nn -l (reads the growing pcap file in real-time)
       Parses packets and emits events.
    """

    def __init__(self, config: PcapMonitorConfig, event_queue: queue.Queue):
        self.config = config
        self.event_queue = event_queue
        self._stop = threading.Event()
        self._last_packet_time: float = ts()
        self._silence_timeout = config.silence_timeout
        self._writer_proc: Optional[subprocess.Popen] = None
        self._reader_proc: Optional[subprocess.Popen] = None
        self._known_uboot_macs: set[str] = set()

    def stop(self) -> None:
        self._stop.set()

    def _start_writer(self) -> Optional[subprocess.Popen]:
        try:
            proc = subprocess.Popen(
                ["sudo", "-n", "tcpdump", "-i", self.config.interface,
                 "-w", self.config.pcap_path, "-n", "-U", "--immediate-mode",
                 "--buffer-size=16384"],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            time.sleep(0.5)
            if proc.poll() is not None:
                err = proc.stderr.read().decode(errors="replace")
                log(f"tcpdump writer failed: {err.strip()}")
                return None
            return proc
        except FileNotFoundError:
            log("tcpdump not found")
            return None

    def _start_reader(self) -> Optional[subprocess.Popen]:
        if not os.path.isfile(self.config.pcap_path):
            return None
        try:
            proc = subprocess.Popen(
                ["tcpdump", "-r", self.config.pcap_path, "-nn", "-l"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            )
            return proc
        except FileNotFoundError:
            return None

    def _restart_writer(self) -> None:
        if self._writer_proc and self._writer_proc.poll() is None:
            self._writer_proc.terminate()
            try:
                self._writer_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._writer_proc.kill()
        time.sleep(2)
        new_proc = self._start_writer()
        if new_proc:
            self._writer_proc = new_proc
            log("tcpdump writer restarted")

    def _emit(self, event: Event, detail: str = "") -> None:
        self._last_packet_time = ts()
        self.event_queue.put((event, ts(), detail))

    def _parse_line(self, line: str) -> None:
        line = line.strip()
        if not line:
            return

        lower = line.lower()
        recovery_ip = self.config.recovery_ip
        arp_target = recovery_ip.rsplit(".", 1)[0] + ".2"

        if "http" in lower and recovery_ip in lower:
            if "length" in lower:
                self._emit(Event.UBOOT_HTTP, line[:120])

        if "arp" in lower and f"who-has {arp_target}" in lower:
            mac_match = re.search(
                r'([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:'
                r'[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})', line,
            )
            if mac_match:
                src_mac = mac_match.group(1).lower()
                if self.config.router_mac_openwrt and src_mac != self.config.router_mac_openwrt.lower():
                    self._emit(Event.UBOOT_ARP_192_168_1_2, f"src_mac={src_mac}")
                    return
            self._emit(Event.UBOOT_ARP_192_168_1_2, line[:120])

        # ICMPv6 from router's real MAC (OpenWrt booting — uses different MAC than U-Boot)
        if "icmp6" in lower and self.config.router_mac_openwrt:
            router_mac = self.config.router_mac_openwrt.lower()
            if router_mac in lower:
                self._emit(Event.ICMPV6_FROM_ROUTER, line[:120])

        # Failsafe broadcast (UDP 4919)
        if "udp" in lower and "4919" in lower:
            self._emit(Event.FAILSAFE_BROADCAST, line[:120])

    def run(self) -> None:
        log(f"Pcap monitor starting: iface={self.config.interface} pcap={self.config.pcap_path}")

        self._writer_proc = self._start_writer()

        # Wait for pcap file header to be written
        time.sleep(1)

        self._reader_proc = self._start_reader()

        silence_check_interval = 5
        last_silence_check = ts()

        while not self._stop.is_set():
            # tcpdump writer dies when USB ethernet adapter disconnects on reboot
            if self._writer_proc and self._writer_proc.poll() is not None:
                log("tcpdump writer died (interface gone?), will restart when link returns")
                time.sleep(3)
                if get_link_state(self.config.interface):
                    self._restart_writer()
                    # pcap file has a gap after writer restart, restart reader
                    if self._reader_proc and self._reader_proc.poll() is None:
                        self._reader_proc.terminate()
                        self._reader_proc.wait(timeout=3)
                    time.sleep(1)
                    self._reader_proc = self._start_reader()

            if self._reader_proc and self._reader_proc.poll() is None:
                try:
                    import selectors
                    sel = selectors.DefaultSelector()
                    sel.register(self._reader_proc.stdout, selectors.EVENT_READ)
                    ready = sel.select(timeout=0.1)
                    sel.close()
                    if ready:
                        raw_line = self._reader_proc.stdout.readline()
                        if raw_line:
                            self._parse_line(raw_line.decode(errors="replace"))
                except Exception:
                    pass
            else:
                if self._reader_proc:
                    time.sleep(1)
                    self._reader_proc = self._start_reader()
                time.sleep(0.2)

            now = ts()
            if now - last_silence_check >= silence_check_interval:
                last_silence_check = now
                if now - self._last_packet_time >= self._silence_timeout:
                    self.event_queue.put((
                        Event.NO_PACKETS_FOR_N_SECONDS, now,
                        f"no packets for {int(now - self._last_packet_time)}s",
                    ))
                    self._last_packet_time = now

        if self._reader_proc and self._reader_proc.poll() is None:
            self._reader_proc.terminate()
            try:
                self._reader_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._reader_proc.kill()

        if self._writer_proc and self._writer_proc.poll() is None:
            self._writer_proc.terminate()
            try:
                self._writer_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self._writer_proc.kill()

        log("Pcap monitor stopped")


class LinkMonitor:
    """Polls link state in a background thread and emits LINK_UP/LINK_DOWN events."""

    def __init__(self, interface: str, event_queue: queue.Queue, poll_interval: float = 0.5):
        self.interface = interface
        self.event_queue = event_queue
        self._stop = threading.Event()
        self._poll_interval = poll_interval
        self._last_state: Optional[bool] = None

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                current = get_link_state(self.interface)
                if self._last_state is not None and current != self._last_state:
                    if current:
                        self.event_queue.put((Event.LINK_UP, ts(), ""))
                    else:
                        self.event_queue.put((Event.LINK_DOWN, ts(), ""))
                self._last_state = current
            except Exception:
                pass
            self._stop.wait(self._poll_interval)


class SSHMonitor:
    """Polls SSH availability in background and emits SSH_UP event."""

    def __init__(self, ip: str, event_queue: queue.Queue, poll_interval: float = 5.0):
        self.ip = ip
        self.event_queue = event_queue
        self._stop = threading.Event()
        self._poll_interval = poll_interval

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                if check_ssh(self.ip):
                    self.event_queue.put((Event.SSH_UP, ts(), ""))
                    return
            except Exception:
                pass
            self._stop.wait(self._poll_interval)


def _auto_detect_serial_port() -> str:
    import glob as globmod
    candidates = sorted(globmod.glob("/dev/cu.usbserial*") + globmod.glob("/dev/cu.SLAB_USBtoUART*"))
    if candidates:
        return candidates[0]
    raise FileNotFoundError(
        "No serial adapter found. Checked /dev/cu.usbserial* and /dev/cu.SLAB_USBtoUART*. "
        "Use --serial-port to specify manually."
    )


class TFTPServerManager:
    def __init__(self, tftp_root: str):
        self.tftp_root = tftp_root
        self._proc: Optional[subprocess.Popen] = None

    def start(self) -> bool:
        if not os.path.isdir(self.tftp_root):
            log(f"ERROR: TFTP root directory not found: {self.tftp_root}")
            return False

        tftp_script = os.path.join(os.path.dirname(__file__), "..", "..", "jtag", "tftp-server.py")
        if not os.path.isfile(tftp_script):
            tftp_script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tftp-server.py")

        tftp_cmd = None
        if os.path.isfile(tftp_script):
            tftp_cmd = [sys.executable, tftp_script, self.tftp_root]
        else:
            import shutil
            dnsmasq = shutil.which("dnsmasq")
            if dnsmasq:
                tftp_cmd = [dnsmasq, f"--tftp-root={self.tftp_root}", "--no-daemon", "--port=0"]

        if not tftp_cmd:
            log("WARNING: No TFTP server script found. U-Boot TFTP commands may fail.")
            log("  Expected: jtag/tftp-server.py or scripts/tftp-server.py")
            return False

        log(f"Starting TFTP server: {' '.join(tftp_cmd)}")
        try:
            self._proc = subprocess.Popen(
                tftp_cmd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            time.sleep(1)
            if self._proc.poll() is not None:
                err = self._proc.stderr.read().decode(errors="replace")
                log(f"TFTP server failed to start: {err.strip()}")
                self._proc = None
                return False
            log(f"TFTP server serving {self.tftp_root} on port 69 (PID {self._proc.pid})")
            return True
        except Exception as e:
            log(f"TFTP server error: {e}")
            self._proc = None
            return False

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            log("TFTP server stopped")

    @property
    def is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None


class SerialUBootDriver:
    ERROR_STRINGS = ["ERROR:", "not found", "Bad CRC", "usage:", "Unknown command"]

    def __init__(self, port: str, baud: int = 115200, timeout: float = 0.1):
        try:
            import serial as _serial
        except ImportError:
            print("ERROR: pyserial is required for serial-tftp flash method.", file=sys.stderr)
            print("  Install with: pip install pyserial", file=sys.stderr)
            sys.exit(1)
        self._serial_mod = _serial
        self.ser = _serial.Serial(port, baud, timeout=timeout)
        self.port = port
        self.baud = baud

    def _drain(self, timeout: float = 0.5) -> bytes:
        time.sleep(timeout)
        data = b""
        while True:
            chunk = self.ser.read(4096)
            if not chunk:
                break
            data += chunk
        return data

    def wait_for_bootmenu(self, timeout: float = 60, interrupt: str = "ctrl-c",
                          console_option: str = "0", say_fn=None) -> bool:
        buf = b""
        start = time.time()
        while time.time() - start < timeout:
            chunk = self.ser.read(4096)
            if chunk:
                buf += chunk
                text = chunk.decode("ascii", errors="replace")
                for line in text.split("\n"):
                    clean = line.strip()
                    if clean:
                        log(f"  [serial] {clean}")

                full_text = buf.decode("ascii", errors="replace")

                if "Hit any key" in full_text or "stop autoboot" in full_text.lower():
                    log("Bootmenu countdown detected — entering U-Boot console")
                    if say_fn:
                        say_fn("Bootmenu detected. Entering U-Boot console.")
                    time.sleep(0.5)
                    self.ser.write(b"\x03")
                    time.sleep(0.3)
                    self.ser.write((console_option + "\r\n").encode())
                    time.sleep(2)
                    remaining = self._drain(2)
                    full_text += remaining.decode("ascii", errors="replace")

                if "=>" in full_text:
                    log("Got U-Boot prompt")
                    self._drain(0.5)
                    return True

                if "login:" in full_text or "init:" in full_text:
                    log("ERROR: Linux already booting — too late to interrupt")
                    return False

        log("ERROR: Timed out waiting for U-Boot bootmenu")
        return False

    def send_command(self, cmd: str, wait: float = 3) -> tuple[bool, str]:
        self._drain(0.2)
        self.ser.write((cmd + "\r\n").encode())
        time.sleep(wait)
        data = self._drain(0.5)
        text = data.decode("ascii", errors="replace")

        output_lines = []
        for line in text.strip().split("\n"):
            clean = line.strip()
            if clean and clean != cmd:
                output_lines.append(clean)

        has_error = any(err in text for err in self.ERROR_STRINGS)

        if "tftpboot" in cmd and "Bytes transferred" not in text and "LOAD ERROR" not in text.upper():
            if "ERROR" in text.upper() or "Retry count exceeded" in text:
                has_error = True

        return has_error, "\n".join(output_lines)

    def run_commands(self, commands: list[str], event_queue: queue.Queue,
                     say_fn=None, flash_time_seconds: int = 120) -> bool:
        total = len(commands)
        for i, cmd in enumerate(commands):
            progress = f"[{i+1}/{total}]"
            log(f"{progress} U-Boot: {cmd}")

            cmd_lower = cmd.lower()

            if "tftpboot" in cmd_lower:
                wait = 15
                if ".bin" in cmd_lower:
                    fn_match = re.search(r'tftpboot\s+\S+\s+(\S+)', cmd)
                    if fn_match:
                        fn = fn_match.group(1)
                        if "chunk" in fn:
                            wait = 300
                say_msg = f"Transferring file {i+1} of {total}"
            elif "nand erase" in cmd_lower or "mtd erase" in cmd_lower:
                wait = 30
                say_msg = f"Erasing flash partition {i+1} of {total}"
            elif "nand write" in cmd_lower or "mtd write" in cmd_lower:
                wait = 30
                say_msg = f"Writing flash partition {i+1} of {total}"
            elif "ubi create" in cmd_lower:
                wait = 5
                say_msg = f"Creating UBI volume {i+1} of {total}"
            elif "reset" in cmd_lower:
                wait = 2
                say_msg = "Rebooting router"
            else:
                wait = 3
                say_msg = ""

            if say_fn and say_msg:
                say_fn(say_msg)

            has_error, output = self.send_command(cmd, wait)

            if output:
                for line in output.split("\n")[:10]:
                    log(f"  {line}")

            if has_error and "reset" not in cmd_lower:
                log(f"ERROR: Command failed: {cmd}")
                log(f"  Output: {output[:300]}")
                event_queue.put((Event.SERIAL_COMMAND_DONE, ts(), f"ERROR: {cmd}"))
                return False

            event_queue.put((Event.SERIAL_COMMAND_DONE, ts(), cmd))

        event_queue.put((Event.SERIAL_ALL_DONE, ts(), ""))
        return True

    def close(self):
        if self.ser and self.ser.is_open:
            self.ser.close()
            log(f"Serial port {self.port} closed")


@dataclass
class RecoveryContext:
    profile: object  # SimpleNamespace loaded from model JSON via model_loader
    image_path: str
    interface: str
    pcap_path: str
    no_upload: bool = False
    no_voice: bool = False
    router_mac_openwrt: str = ""
    router_mac_uboot: str = ""
    timeline: Timeline = field(default_factory=Timeline)
    state: State = State.WAITING_FOR_POWER_OFF
    sha256_before: str = ""
    sha256_after: str = ""
    generated_password: str = ""
    password_set: bool = False
    auth_type: str = ""          # "key-and-password", "key-only", or "password-only"
    wan_ssh_enabled: bool = False
    force_uboot: bool = False
    boot_state: str = "unknown"
    ssh_key_path: str = ""
    serial_port: str = ""
    serial_method: str = ""
    serial_baud: int = 115200
    tftp_root: str = ""
    uboot_commands: list = field(default_factory=list)
    _say_fn: object = field(default=None, repr=False)

    def __post_init__(self):
        if self._say_fn is None:
            self._say_fn = say


def _generate_random_password() -> str:
    password = secrets.token_urlsafe(16)
    print()
    print("=" * 60)
    print(f"  Generated random password: {password}")
    print("=" * 60)
    print()
    return password


def _validate_args(args: argparse.Namespace) -> Optional[str]:
    if not args.image and not args.request_image:
        return "One of --image or --request-image is required."

    if args.image and args.request_image:
        return "--image and --request-image are mutually exclusive."

    if args.image:
        image_only_flags = []
        if args.ssh_key:
            image_only_flags.append("--ssh-key")
        if args.password:
            image_only_flags.append("--password")
        if args.no_password:
            image_only_flags.append("--no-password")
        if args.wan_ssh:
            image_only_flags.append("--wan-ssh")
        if image_only_flags:
            return (
                f"{', '.join(image_only_flags)} only valid with --request-image, "
                f"not with --image."
            )

    return None


def _resolve_asu_profile(model_id: str) -> str:
    try:
        model = load_model(model_id)
        profile = model.get("openwrt", {}).get("profile", "")
        if profile:
            return profile
        # Model JSON "id" field uses ASU profile naming (e.g. "dlink_covr-x1860-a1")
        return model.get("id", model_id)
    except FileNotFoundError:
        return model_id


def _request_custom_image(
    model_id: str,
    ssh_key_path: Optional[str],
    password: Optional[str],
    wan_ssh: bool,
    flash_method: str,
    say_fn,
) -> Optional[str]:
    asu_profile = _resolve_asu_profile(model_id)
    say_fn("Requesting custom firmware image from ASU...")
    log(f"ASU profile: {asu_profile}")

    model = load_model(model_id)
    target = model.get("openwrt", {}).get("target", "")
    version = model.get("openwrt", {}).get("version", "24.10.1")

    request_args = argparse.Namespace(
        profile=asu_profile,
        version=version,
        target=target or None,
        packages=None,
        ssh_key=ssh_key_path,
        password=password,
        wan_ssh=wan_ssh,
    )

    request_buf = io.StringIO()
    with redirect_stdout(request_buf):
        rc = firmware_request(request_args)
    if rc != 0:
        log("ERROR: ASU firmware request failed.")
        return None

    recovery_methods = {"recovery-http", "uboot-http", "uboot-tftp"}
    if flash_method in recovery_methods:
        preferred_types = ["recovery", "factory"]
    else:
        preferred_types = ["sysupgrade"]

    image_path = None
    for img_type in preferred_types:
        find_args = argparse.Namespace(
            profile=asu_profile,
            type=img_type,
        )
        find_buf = io.StringIO()
        with redirect_stdout(find_buf):
            firmware_find(find_args)
        candidate = find_buf.getvalue().strip()
        if candidate and os.path.isfile(candidate):
            image_path = candidate
            break

    if not image_path:
        find_args = argparse.Namespace(
            profile=asu_profile,
            type=None,
        )
        find_buf = io.StringIO()
        with redirect_stdout(find_buf):
            firmware_find(find_args)
        image_path = find_buf.getvalue().strip()

    if not image_path or not os.path.isfile(image_path):
        profile_dir = IMAGES_DIR / asu_profile
        if profile_dir.exists():
            for hash_dir in sorted(profile_dir.iterdir(), reverse=True):
                if not hash_dir.is_dir():
                    continue
                for f in sorted(hash_dir.iterdir()):
                    if f.is_file() and f.suffix in (".bin", ".img", ".tar"):
                        image_path = str(f)
                        break
                if image_path and os.path.isfile(image_path):
                    break

    if not image_path or not os.path.isfile(image_path):
        log("ERROR: No firmware image file found after ASU request.")
        return None

    log(f"Firmware image: {image_path}")
    return image_path


def _run_state_machine(
    ctx: RecoveryContext,
    event_queue: queue.Queue,
    pcap_monitor: PcapMonitor,
    link_monitor: LinkMonitor,
) -> int:
    ctx.timeline.recovery_start = ts()

    while ctx.state not in (State.COMPLETE, State.FAILED):
        if ctx.state == State.DETECTING:
            _handle_detecting(ctx, event_queue)
        elif ctx.state == State.SYSUPGRADE_UPLOADING:
            _handle_sysupgrade_uploading(ctx, event_queue)
        elif ctx.state == State.SYSUPGRADE_REBOOTING:
            _handle_sysupgrade_rebooting(ctx, event_queue)
        elif ctx.state == State.SYSUPGRADE_BOOTING:
            _handle_sysupgrade_booting(ctx, event_queue)
        elif ctx.state == State.WAITING_FOR_POWER_OFF:
            _handle_waiting_for_power_off(ctx, event_queue)
        elif ctx.state == State.WAITING_FOR_UBOOT:
            _handle_waiting_for_uboot(ctx, event_queue, link_monitor)
        elif ctx.state == State.UBOOT_UPLOADING:
            _handle_uboot_uploading(ctx, event_queue)
        elif ctx.state == State.UBOOT_FLASHING:
            _handle_uboot_flashing(ctx, event_queue, pcap_monitor)
        elif ctx.state == State.SERIAL_WAITING_FOR_BOOTMENU:
            _handle_serial_waiting_for_bootmenu(ctx, event_queue)
        elif ctx.state == State.SERIAL_UBOOT_INTERACTING:
            _handle_serial_uboot_interacting(ctx, event_queue)
        elif ctx.state == State.REBOOTING:
            _handle_rebooting(ctx, event_queue)
        elif ctx.state == State.OPENWRT_BOOTING:
            _handle_openwrt_booting(ctx, event_queue)
        else:
            log(f"Unknown state: {ctx.state}")
            ctx.state = State.FAILED

    if ctx.state == State.COMPLETE:
        _print_timeline(ctx)
        _record_inventory(ctx)
        return 0
    return 1


def _handle_detecting(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    boot_state = _detect_boot_state(ctx.interface, ctx.profile)
    ctx.boot_state = boot_state
    if boot_state == "openwrt" and not ctx.force_uboot:
        ctx._say_fn("OpenWrt detected. Using sysupgrade for faster re-flash.")
        log("Boot state: OpenWrt — using sysupgrade path")
        ctx.state = State.SYSUPGRADE_UPLOADING
    else:
        if boot_state == "uboot":
            log("Boot state: U-Boot recovery mode detected")
        elif ctx.force_uboot:
            log("Boot state: forced to U-Boot recovery (--force-uboot)")
        else:
            log("Boot state: unknown — proceeding with U-Boot recovery")
        ctx.state = State.WAITING_FOR_POWER_OFF


def _handle_sysupgrade_uploading(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    openwrt_ip = ctx.profile.openwrt_ip
    success = _flash_via_sysupgrade(openwrt_ip, ctx.image_path, ctx.ssh_key_path or None)
    if success:
        ctx.sha256_before = sha256_file(ctx.image_path)
        ctx.state = State.SYSUPGRADE_REBOOTING
    else:
        log("sysupgrade upload failed.")
        ctx.state = State.FAILED


def _handle_sysupgrade_rebooting(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    ctx._say_fn("Firmware flashing via sysupgrade. Do not unplug.")
    log("sysupgrade: device is rebooting")
    ctx.state = State.SYSUPGRADE_BOOTING


def _handle_sysupgrade_booting(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    openwrt_ip = ctx.profile.openwrt_ip
    if _wait_for_sysupgrade_reboot(openwrt_ip):
        ctx.timeline.ssh_available = ts()
        ctx._say_fn("Recovery complete! Router is back online.")
        log("SUCCESS — sysupgrade recovery complete.")
        verify_router(openwrt_ip)
        ctx.state = State.COMPLETE
    else:
        ctx._say_fn("Device did not come back after sysupgrade.")
        log("FAIL: SSH not available after sysupgrade reboot.")
        ctx.state = State.FAILED


def _handle_waiting_for_power_off(ctx: RecoveryContext, eq: queue.Queue) -> None:
    link_up = get_link_state(ctx.interface)
    if link_up:
        ctx._say_fn("Ready. Please unplug the power cable from the router now.")
        log("STEP 1: Unplug power (keep ethernet in LAN port)")

        _wait_for_event_or_timeout(
            eq, timeout=300,
            target_events={Event.LINK_DOWN},
            success_state=State.WAITING_FOR_UBOOT,
            fail_message="Timed out waiting for power off.",
            fail_say="Timed out. Please unplug the power cable from the router.",
            ctx=ctx,
        )
        if ctx.state == State.WAITING_FOR_UBOOT:
            ctx._say_fn("Power disconnected. Good.")
            ctx.timeline.power_off = ts()
    else:
        log("Router already powered off.")
        ctx._say_fn("Router is off. Good.")
        ctx.timeline.power_off = ts()
        ctx.state = State.WAITING_FOR_UBOOT


def _handle_waiting_for_uboot(ctx: RecoveryContext, eq: queue.Queue, link_monitor: LinkMonitor) -> None:
    print()
    profile = ctx.profile
    ctx._say_fn(profile.reset_instructions)
    log(f"STEP 2: {profile.reset_instructions}")
    time.sleep(4)

    ctx._say_fn("While still holding reset, plug in the power cable.")
    log("STEP 3: Plug in power WHILE STILL HOLDING reset")
    time.sleep(2)

    ctx._say_fn(
        f"Watch the LED. {profile.led_pattern}. "
        "Release reset when the LED shows the recovery pattern."
    )
    log(f"Waiting for recovery LED pattern: {profile.led_pattern}")
    print()

    got_link_up = _wait_for_event_or_timeout(
        eq, timeout=30,
        target_events={Event.LINK_UP},
        success_state=None,
        fail_message="Ethernet link did not come up.",
        fail_say="Ethernet link did not come up. Check the cable is in the LAN port.",
        ctx=ctx,
    )
    if got_link_up is None:
        ctx.state = State.FAILED
        return

    ctx.timeline.link_up = ts()
    ctx._say_fn("Link detected. Waiting for recovery mode.")
    log(f"Link up — waiting for recovery HTTP: {profile.led_pattern}")
    time.sleep(8)

    log("Scanning for recovery HTTP server...")
    uboot_found = False
    probe_start = ts()
    probe_timeout = 90

    while ts() - probe_start < probe_timeout:
        found, detail = detect_uboot_http(profile.recovery_ip)
        if found:
            log(f"Recovery mode detected: {detail}")
            ctx.timeline.uboot_http_first = ts()
            ctx._say_fn("Recovery mode detected. You can release the button now.")
            ctx.state = State.UBOOT_UPLOADING
            uboot_found = True
            break

        _drain_events(eq, ctx)

        time.sleep(1)

    if not uboot_found:
        ctx._say_fn(f"Recovery mode not found. Check the LED pattern: {profile.led_pattern}")
        log("FAIL: Recovery HTTP server not detected.")
        ctx.state = State.FAILED


def _handle_uboot_uploading(ctx: RecoveryContext, eq: queue.Queue) -> None:
    profile = ctx.profile
    if ctx.no_upload:
        ctx._say_fn("Dry run. Recovery server is ready but not uploading.")
        log(f"DRY RUN: Recovery server ready at http://{profile.recovery_ip}")
        log(f"  Upload: curl -F {profile.upload_field}=@{ctx.image_path} http://{profile.recovery_ip}{profile.upload_endpoint}")
        if profile.trigger_flash_endpoint:
            log(f"  Flash:  curl http://{profile.recovery_ip}{profile.trigger_flash_endpoint}")
        ctx.state = State.COMPLETE
        return

    ctx.sha256_before = sha256_file(ctx.image_path)
    log(f"SHA-256 (before upload): {ctx.sha256_before}")

    ctx.timeline.upload_start = ts()
    ok, response = upload_firmware(ctx.image_path, profile)
    if not ok:
        ctx._say_fn(f"Upload failed. Try a browser at http://{profile.recovery_ip} instead.")
        ctx.state = State.FAILED
        return

    ctx.timeline.upload_complete = ts()
    eq.put((Event.UPLOAD_COMPLETE, ts(), response))

    ctx.sha256_after = sha256_file(ctx.image_path)
    if ctx.sha256_after != ctx.sha256_before:
        log("WARNING: SHA-256 mismatch! File may have been modified on disk during upload.")
    else:
        log(f"SHA-256 verified (after upload): {ctx.sha256_after}")

    if trigger_flash(profile):
        ctx.timeline.flash_triggered = ts()
        eq.put((Event.FLASH_TRIGGERED, ts(), ""))
    else:
        log("Flash trigger may have failed. Router may still flash on its own.")
        ctx.timeline.flash_triggered = ts()

    ctx._say_fn("Firmware flashing. Do not unplug.")
    ctx.state = State.UBOOT_FLASHING


def _handle_uboot_flashing(ctx: RecoveryContext, eq: queue.Queue, pcap_monitor: PcapMonitor) -> None:
    profile = ctx.profile
    timeout = profile.flash_time_seconds + 120
    result = _wait_for_event_or_timeout(
        eq, timeout=timeout,
        target_events={Event.UBOOT_ARP_192_168_1_2, Event.LINK_DOWN},
        success_state=State.REBOOTING,
        fail_message=f"Flash did not complete within {timeout}s.",
        fail_say="Flash is taking too long. Something went wrong.",
        ctx=ctx,
    )
    if result is None:
        ctx.state = State.FAILED
        return

    ctx.timeline.flash_complete = ts()
    log(f"Flash complete (event: {result})")
    if result == Event.LINK_DOWN:
        ctx._say_fn("Link down. Router is rebooting.")
    elif result == Event.UBOOT_ARP_192_168_1_2:
        ctx._say_fn("Firmware uploaded. Flashing in progress. Do not unplug.")


def _handle_serial_waiting_for_bootmenu(ctx: RecoveryContext, eq: queue.Queue) -> None:
    profile = ctx.profile
    port = ctx.serial_port
    baud = ctx.serial_baud

    if not port:
        try:
            port = _auto_detect_serial_port()
            log(f"Auto-detected serial port: {port}")
        except FileNotFoundError as e:
            log(f"ERROR: {e}")
            ctx.state = State.FAILED
            return

    ctx._say_fn("Connect serial adapter and Ethernet cable to LAN2.")
    if profile.lan_port:
        log(f"IMPORTANT: Connect Ethernet cable to {profile.lan_port} port")
    log(f"Serial port: {port} at {baud} baud")

    ctx._say_fn("Power cycle the router now.")
    log("Power cycle the router now. Watching for U-Boot bootmenu...")

    driver = SerialUBootDriver(port, baud)
    ctx._serial_driver = driver

    got_prompt = driver.wait_for_bootmenu(
        timeout=profile.bootmenu_timeout,
        interrupt=profile.bootmenu_interrupt,
        console_option=profile.bootmenu_select_console,
        say_fn=ctx._say_fn,
    )

    if not got_prompt:
        ctx._say_fn("Failed to get U-Boot prompt. Check serial connection and try again.")
        driver.close()
        ctx.state = State.FAILED
        return

    eq.put((Event.SERIAL_UBOOT_READY, ts(), ""))
    ctx.timeline.uboot_http_first = ts()
    ctx.state = State.SERIAL_UBOOT_INTERACTING


def _handle_serial_uboot_interacting(ctx: RecoveryContext, eq: queue.Queue) -> None:
    profile = ctx.profile
    driver: SerialUBootDriver = ctx._serial_driver

    tftp_root = ctx.tftp_root
    if not tftp_root:
        tftp_root = os.path.join(os.path.dirname(ctx.image_path), "tftpboot")
        if not os.path.isdir(tftp_root):
            tftp_root = os.path.dirname(ctx.image_path)

    tftp_mgr = TFTPServerManager(tftp_root)
    ctx._tftp_manager = tftp_mgr

    if not tftp_mgr.start():
        log("WARNING: TFTP server not available — commands may fail")

    ctx._say_fn("Setting up network and starting flash process.")

    setup_interface_for_serial(ctx)

    commands = ctx.uboot_commands
    if not commands:
        commands = profile.uboot_commands

    if not commands:
        log("ERROR: No U-Boot commands defined in model JSON")
        ctx.state = State.FAILED
        tftp_mgr.stop()
        driver.close()
        return

    ctx.timeline.upload_start = ts()
    ctx.sha256_before = sha256_file(ctx.image_path) if ctx.image_path else ""

    success = driver.run_commands(
        commands, eq,
        say_fn=ctx._say_fn,
        flash_time_seconds=profile.flash_time_seconds,
    )

    tftp_mgr.stop()

    if success:
        ctx.timeline.flash_complete = ts()
        ctx.timeline.upload_complete = ts()
        log("All U-Boot commands executed successfully")
        ctx.state = State.REBOOTING
        driver.close()
    else:
        ctx._say_fn("Flash failed. Check serial output for details.")
        ctx.state = State.FAILED
        driver.close()


def setup_interface_for_serial(ctx: RecoveryContext) -> None:
    profile = ctx.profile
    interface = ctx.interface
    if not interface:
        return

    existing = subprocess.run(
        ["ifconfig", interface], capture_output=True, text=True, check=False,
    ).stdout

    if profile.client_ip and profile.client_ip not in existing:
        result = subprocess.run(
            ["ifconfig", interface, profile.client_ip,
             "netmask", profile.client_subnet, "up"],
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            log(f"ERROR: need sudo to configure {interface}: {result.stderr.strip()}")
            log(f"  sudo ifconfig {interface} {profile.client_ip} netmask {profile.client_subnet} up")
        else:
            log(f"Configured {interface}: {profile.client_ip}/{profile.client_subnet}")
    else:
        log(f"Interface {interface} already has {profile.client_ip}")


def _handle_rebooting(ctx: RecoveryContext, eq: queue.Queue) -> None:
    ctx._say_fn("Router is rebooting. Waiting for it to come back online.")

    # Phase 1: Wait for link to come back up (pcap may be dead, but LinkMonitor still works)
    link_result = _wait_for_event_or_timeout(
        eq, timeout=REBOOT_TIMEOUT,
        target_events={Event.LINK_UP},
        success_state=None,
        fail_message="Link did not come back up after reboot.",
        fail_say="Link did not come back up. Check the ethernet cable.",
        ctx=ctx,
    )
    if link_result is None:
        ctx.state = State.FAILED
        return

    ctx._say_fn("Link detected. Waiting for OpenWrt to boot.")
    log("Link up after reboot — waiting for OpenWrt")

    # Phase 2: Wait for ICMPv6 (OpenWrt booting) or SSH with generous timeout
    timeout_after_link = 180
    result = _wait_for_event_or_timeout(
        eq, timeout=timeout_after_link,
        target_events={Event.ICMPV6_FROM_ROUTER, Event.SSH_UP},
        success_state=State.OPENWRT_BOOTING,
        fail_message=f"OpenWrt did not appear within {timeout_after_link}s after link up.",
        fail_say="OpenWrt is taking longer than expected. Check the router.",
        ctx=ctx,
    )
    if result is None:
        ctx.state = State.FAILED
        return

    if result == Event.ICMPV6_FROM_ROUTER:
        ctx.timeline.first_openwrt_packet = ts()
        ctx._say_fn("OpenWrt is booting.")
        log("ICMPv6 from router MAC detected — OpenWrt is booting")
    elif result == Event.SSH_UP:
        ctx.timeline.ssh_available = ts()
        ctx._say_fn("Recovery complete! Router is back online.")
        log("SUCCESS — router recovered (SSH detected during reboot phase).")
        openwrt_ip = ctx.profile.openwrt_ip or ctx.profile.recovery_ip
        verify_router(openwrt_ip)
        ctx.state = State.COMPLETE


def _handle_openwrt_booting(ctx: RecoveryContext, eq: queue.Queue) -> None:
    openwrt_ip = ctx.profile.openwrt_ip or ctx.profile.recovery_ip
    ssh_monitor = SSHMonitor(openwrt_ip, eq, poll_interval=5.0)
    ssh_thread = threading.Thread(target=ssh_monitor.run, daemon=True)
    ssh_thread.start()

    timeout = 120
    result = _wait_for_event_or_timeout(
        eq, timeout=timeout,
        target_events={Event.SSH_UP, Event.LINK_UP},
        success_state=None,
        fail_message=f"SSH not available within {timeout}s.",
        fail_say="Router is taking longer than expected. Check SSH in a few minutes.",
        ctx=ctx,
    )

    ssh_monitor.stop()

    if result == Event.SSH_UP:
        ctx.timeline.ssh_available = ts()
        ctx._say_fn("Recovery complete! Router is back online.")
        log("SUCCESS — router recovered.")
        verify_router(openwrt_ip)
        ctx.state = State.COMPLETE
    else:
        if check_ssh(openwrt_ip):
            ctx.timeline.ssh_available = ts()
            ctx._say_fn("Recovery complete! Router is back online.")
            log("SUCCESS — router recovered (SSH fallback check).")
            verify_router(openwrt_ip)
            ctx.state = State.COMPLETE
        else:
            ctx.state = State.FAILED


def _wait_for_event_or_timeout(
    eq: queue.Queue,
    timeout: int,
    target_events: set[Event],
    success_state: Optional[State],
    fail_message: str,
    fail_say: str,
    ctx: RecoveryContext,
) -> Optional[Event]:
    """Wait for one of the target events or timeout.

    Returns the Event that was found, or None on timeout.
    Sets ctx.state to success_state on success, or State.FAILED on timeout.
    """
    start = ts()
    while ts() - start < timeout:
        try:
            event, event_ts, detail = eq.get(timeout=1.0)

            if event in target_events:
                if success_state is not None:
                    ctx.state = success_state
                return event

            if event == Event.LINK_UP and ctx.timeline.link_up is None:
                ctx.timeline.link_up = event_ts
                if ctx.state in (State.REBOOTING, State.OPENWRT_BOOTING):
                    ctx._say_fn("Link up. Waiting for OpenWrt to boot.")
            elif event == Event.LINK_DOWN and ctx.timeline.power_off is None:
                ctx.timeline.power_off = event_ts
            elif event == Event.ICMPV6_FROM_ROUTER and ctx.timeline.first_openwrt_packet is None:
                ctx.timeline.first_openwrt_packet = event_ts
                ctx._say_fn("OpenWrt is booting.")
            elif event == Event.SSH_UP:
                ctx.timeline.ssh_available = event_ts
                if success_state is not None:
                    ctx.state = success_state
                return event
            elif event == Event.UBOOT_HTTP and ctx.timeline.uboot_http_first is None:
                ctx.timeline.uboot_http_first = event_ts

        except queue.Empty:
            pass

    log(fail_message)
    ctx._say_fn(fail_say)
    if success_state is not None:
        ctx.state = State.FAILED
    return None


def _drain_events(eq: queue.Queue, ctx: RecoveryContext) -> None:
    """Non-blocking drain of any pending events to update timeline."""
    while True:
        try:
            event, event_ts, detail = eq.get_nowait()
            if event == Event.LINK_UP and ctx.timeline.link_up is None:
                ctx.timeline.link_up = event_ts
            elif event == Event.LINK_DOWN and ctx.timeline.power_off is None:
                ctx.timeline.power_off = event_ts
            elif event == Event.UBOOT_HTTP and ctx.timeline.uboot_http_first is None:
                ctx.timeline.uboot_http_first = event_ts
        except queue.Empty:
            break


def _print_timeline(ctx: RecoveryContext) -> None:
    print()
    log("=" * 50)
    log("RECOVERY TIMELINE")
    log("=" * 50)

    tl = ctx.timeline
    start = tl.recovery_start or tl.power_off or ts()

    def elapsed(t: Optional[float]) -> str:
        if t is None:
            return "N/A"
        return f"+{int(t - start)}s ({ts_str(t)})"

    log(f"  Recovery start:    {ts_str(start)}")
    log(f"  Power off:         {elapsed(tl.power_off)}")
    log(f"  Link up:           {elapsed(tl.link_up)}")
    log(f"  U-Boot HTTP:       {elapsed(tl.uboot_http_first)}")
    log(f"  Upload start:      {elapsed(tl.upload_start)}")
    log(f"  Upload complete:   {elapsed(tl.upload_complete)}")
    log(f"  Flash triggered:   {elapsed(tl.flash_triggered)}")
    log(f"  Flash complete:    {elapsed(tl.flash_complete)}")
    log(f"  First OpenWrt pkt: {elapsed(tl.first_openwrt_packet)}")
    log(f"  SSH available:     {elapsed(tl.ssh_available)}")

    if tl.ssh_available and start:
        total = int(tl.ssh_available - start)
        log(f"  TOTAL TIME:        {total}s ({total // 60}m {total % 60}s)")

    log(f"  SHA-256:           {ctx.sha256_before}")
    log("=" * 50)

    if ctx.pcap_path and os.path.isfile(ctx.pcap_path):
        size_kb = os.path.getsize(ctx.pcap_path) / 1024
        log(f"  Pcap: {ctx.pcap_path} ({size_kb:.1f} KB)")


def _record_inventory(ctx: RecoveryContext) -> None:
    ip = ctx.profile.openwrt_ip or ctx.profile.recovery_ip

    fp = fingerprint_router(ip)
    if not fp:
        log("Could not fingerprint router for inventory.")
        return

    ident = fp.get("identity", {})
    fw = fp.get("firmware", {})
    net = fp.get("network", {})
    sec = fp.get("security", {})
    diag = fp.get("diagnostics", {})
    macs = net.get("macs", {})

    for key in ["hostname", "board", "serial"]:
        val = ident.get(key, "")
        if val:
            log(f"  inventory: {key}={val}")
    for key in ["mac_brlan", "mac_eth0"]:
        iface = key.replace("mac_", "")
        val = macs.get(iface, "")
        if val:
            log(f"  inventory: {key}={val}")

    tl = ctx.timeline
    start = tl.recovery_start or ts()
    timeline_durations = {}
    if tl.power_off:
        timeline_durations["power_off"] = int(tl.power_off - start)
    if tl.link_up:
        timeline_durations["link_up"] = int(tl.link_up - start)
    if tl.uboot_http_first:
        timeline_durations["uboot_http"] = int(tl.uboot_http_first - start)
    if tl.upload_start:
        timeline_durations["upload_start"] = int(tl.upload_start - start)
    if tl.upload_complete:
        timeline_durations["upload_complete"] = int(tl.upload_complete - start)
    if tl.flash_triggered:
        timeline_durations["flash_triggered"] = int(tl.flash_triggered - start)
    if tl.flash_complete:
        timeline_durations["flash_complete"] = int(tl.flash_complete - start)
    if tl.first_openwrt_packet:
        timeline_durations["first_openwrt_packet"] = int(tl.first_openwrt_packet - start)
    if tl.ssh_available:
        timeline_durations["ssh_available"] = int(tl.ssh_available - start)
        timeline_durations["total_seconds"] = int(tl.ssh_available - start)

    model_id = getattr(ctx.profile, 'name', '')
    openwrt_target = ""
    try:
        model = load_model(model_id)
        openwrt_target = model.get("openwrt", {}).get("target", "")
    except Exception:
        pass

    board = ident.get("board", "")
    fp_path = save_fingerprint(fp, board_id=board)

    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "device_serial": ident.get("serial", ""),
        "model": ident.get("model", ""),
        "model_id": model_id,
        "vendor": fp.get("firmware", {}).get("DISTRIB_ID", "").strip("'\"") or ident.get("vendor", ""),
        "firmware_version": fw.get("version", "").strip("'\""),
        "openwrt_target": openwrt_target,
        "hostname": ident.get("hostname", ""),
        "board": board,
        "kernel": fw.get("kernel", ""),
        "mac_addresses": list(filter(None, [
            macs.get("br-lan", ""),
            macs.get("eth0", ""),
        ])),
        "ssh_key_fingerprint": sec.get("ssh_fingerprint", ""),
        "ssh_key_count": sec.get("ssh_key_count", 0),
        "wan_ssh_rules": sec.get("wan_ssh_rules", 0),
        "packages_installed": sec.get("packages_installed", 0),
        "password_set": ctx.password_set,
        "auth_type": ctx.auth_type,
        "wan_ssh_enabled": ctx.wan_ssh_enabled,
        "sha256_firmware": ctx.sha256_before,
        "flashed_by": os.environ.get("USER", ""),
        "timeline": timeline_durations,
        "fingerprint_file": str(fp_path) if fp_path else "",
        "notes": "Flashed via conwrt",
    }

    inventory_path = Path(__file__).resolve().parent.parent / "data" / "inventory.jsonl"
    try:
        inventory_path.parent.mkdir(parents=True, exist_ok=True)
        with open(inventory_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
        log(f"Inventory entry appended to {inventory_path}")
    except Exception as e:
        log(f"Failed to write inventory: {e}")


def auto_detect_interface(subnet_prefix: str = "") -> Optional[str]:
    """Find the single active physical ethernet interface.

    Skips en0 (WiFi), Thunderbolt bridge members, and Thunderbolt bridge
    virtual interfaces (mtu 16000). Asserts exactly one candidate exists.
    """
    bridge_members = set()
    br_r = subprocess.run(["ifconfig", "bridge0"], capture_output=True, text=True, check=False)
    for line in br_r.stdout.splitlines():
        if "member:" in line.lower():
            bridge_members.add(line.strip().split()[1])

    candidates = []
    for n in range(1, 21):
        iface = f"en{n}"
        r = subprocess.run(
            ["ifconfig", iface], capture_output=True, text=True, check=False,
        )
        if r.returncode != 0:
            continue
        if "status: active" not in r.stdout.lower():
            continue
        if iface in bridge_members:
            continue
        if "mtu 16000" in r.stdout:  # Thunderbolt bridge
            continue
        if "base" not in r.stdout or "duplex" not in r.stdout:
            continue
        candidates.append(iface)

    if len(candidates) == 0:
        return None
    if len(candidates) > 1:
        log(f"WARNING: multiple ethernet interfaces active: {candidates}, using first")
    return candidates[0]


def _build_parser() -> argparse.ArgumentParser:
    try:
        available_ids = [m["id"] for m in list_models()]
    except Exception:
        available_ids = []

    parser = argparse.ArgumentParser(
        description="conwrt — flash OpenWrt firmware to routers",
    )
    subparsers = parser.add_subparsers(dest="command")

    flash_parser = subparsers.add_parser("flash",
        help="Flash firmware to device (default if no subcommand given)")
    flash_parser.add_argument("--model-id", required=False,
                        help=f"Model ID from models/ directory (e.g. glinet-mt3000, dlink-covr-x1860-a1). "
                             f"Auto-detected if device is running OpenWrt. "
                             f"Use 'conwrt list' to see all available. "
                             f"Known: {', '.join(sorted(available_ids)) or 'none loaded'}")

    firmware_group = flash_parser.add_mutually_exclusive_group()
    firmware_group.add_argument("--image", default=None,
                                help="Path to firmware image (vanilla or custom)")
    firmware_group.add_argument("--request-image", action="store_true",
                                help="Request custom image from ASU with baked-in settings")

    flash_parser.add_argument("--ssh-key", default=None,
                        help="SSH public key to install (default: first found of ~/.ssh/id_ed25519.pub, id_rsa.pub)")
    flash_parser.add_argument("--password", default=None,
                        help="Set root password (default: random, printed once)")
    flash_parser.add_argument("--no-password", action="store_true",
                        help="Skip password (key-only auth)")
    flash_parser.add_argument("--wan-ssh", action="store_true",
                        help="Open SSH on WAN port (disables password login on WAN)")
    flash_parser.add_argument("--interface", default=None,
                        help="Ethernet interface (auto-detected if omitted)")
    flash_parser.add_argument("--no-voice", action="store_true", help="Disable voice guidance")
    flash_parser.add_argument("--no-upload", action="store_true",
                        help="Stop after detecting U-Boot (dry run)")
    flash_parser.add_argument("--force-uboot", action="store_true",
                        help="Force U-Boot recovery mode even if OpenWrt is detected")
    flash_parser.add_argument("--capture", default=None,
                        help="Save pcap capture to file (requires sudo)")
    flash_parser.add_argument("--router-mac", default="",
                        help="Router's OpenWrt MAC address (for ICMPv6 detection)")
    flash_parser.add_argument("--uboot-mac", default="",
                        help="Router's U-Boot MAC address (for ARP detection)")
    flash_parser.add_argument("--silence-timeout", type=int, default=SILENCE_TIMEOUT_DEFAULT,
                        help="Seconds of no packets before silence event")
    flash_parser.add_argument("--serial-port", default=None,
                        help="Serial port for serial-tftp method (e.g. /dev/cu.usbserial-A50285BI). "
                             "Auto-detected if omitted.")
    flash_parser.add_argument("--serial-method", default=None,
                        help="Serial flash method variant (e.g. openwrt-flash, stock-restore). "
                             "Selects the serial-tftp-{method} flash_method from model JSON.")
    flash_parser.add_argument("--serial-baud", type=int, default=115200,
                        help="Serial baud rate (default: 115200)")
    flash_parser.add_argument("--tftp-root", default=None,
                        help="TFTP server root directory. Defaults to image directory.")

    subparsers.add_parser("list", help="List available device models")

    cache_parser = subparsers.add_parser("cache", help="Manage cached firmware images")
    cache_sub = cache_parser.add_subparsers(dest="cache_command")
    cache_sub.add_parser("list", help="List cached firmware images")
    cache_clean = cache_sub.add_parser("clean", help="Remove cached firmware images")
    cache_clean.add_argument("--model-id", default=None,
                        help="Only clean images for this model")
    cache_clean.add_argument("--keep-latest", action="store_true",
                        help="Keep only the latest build per model")
    cache_clean.add_argument("--yes", action="store_true",
                        help="Skip confirmation prompt")

    return parser


def cmd_list(args: argparse.Namespace) -> int:
    models = list_models()
    if not models:
        print("No models found in models/ directory.", file=sys.stderr)
        return 1

    print(f"{'Model ID':<40s}  {'Vendor':<12s}  {'Target':<22s}  {'Flash Methods':<20s}  Description")
    print("-" * 140)
    for model in models:
        model_id = model.get("id", "?")
        vendor = model.get("vendor", "?")
        target = model.get("openwrt", {}).get("target", "?")
        methods = ", ".join(model.get("flash_methods", {}).keys()) or "none"
        desc = model.get("description", "")
        print(f"{model_id:<40s}  {vendor:<12s}  {target:<22s}  [{methods}]  {desc}")
    return 0


def cmd_cache(args: argparse.Namespace) -> int:
    images_dir = Path(__file__).resolve().parent.parent / "images"

    if args.cache_command == "list":
        return _cache_list(images_dir)
    elif args.cache_command == "clean":
        return _cache_clean(images_dir, args)
    else:
        print("Usage: conwrt cache <list|clean>", file=sys.stderr)
        return 1


def _cache_list(images_dir: Path) -> int:
    if not images_dir.is_dir():
        print("No images/ directory found.", file=sys.stderr)
        return 1

    entries = []
    for model_dir in sorted(images_dir.iterdir()):
        if not model_dir.is_dir():
            continue
        for hash_dir in sorted(model_dir.iterdir()):
            if not hash_dir.is_dir():
                continue
            model_id = model_dir.name
            request_hash = hash_dir.name
            metadata_files = list(hash_dir.glob("*.metadata.json"))
            metadata = {}
            if metadata_files:
                try:
                    with open(metadata_files[0]) as f:
                        metadata = json.load(f)
                except (json.JSONDecodeError, OSError):
                    pass

            bin_files = list(hash_dir.glob("*.bin"))
            image_types = []
            total_size = 0
            for bf in bin_files:
                if "sysupgrade" in bf.name:
                    image_types.append("sysupgrade")
                elif "recovery" in bf.name:
                    image_types.append("recovery")
                elif "factory" in bf.name:
                    image_types.append("factory")
                else:
                    image_types.append(bf.stem)
                total_size += bf.stat().st_size

            build_info = metadata.get("version", "?")
            if metadata.get("version_code"):
                build_info += f" ({metadata.get('version_code', '')[:20]})"

            entries.append({
                "model": model_id,
                "hash": request_hash[:12],
                "version": build_info,
                "types": ", ".join(sorted(set(image_types))) or "none",
                "size_mb": f"{total_size / 1024 / 1024:.1f}",
            })

    if not entries:
        print("No cached firmware images found.")
        return 0

    print(f"{'Model':<30s}  {'Hash':<14s}  {'Version':<35s}  {'Types':<30s}  {'Size':>8s}")
    print("-" * 130)
    for e in entries:
        print(f"{e['model']:<30s}  {e['hash']:<14s}  {e['version']:<35s}  {e['types']:<30s}  {e['size_mb']:>7s} MB")
    print(f"\nTotal: {len(entries)} cached build(s)")
    return 0


def _cache_clean(images_dir: Path, args: argparse.Namespace) -> int:
    if not images_dir.is_dir():
        print("No images/ directory found.", file=sys.stderr)
        return 1

    targets = []
    for model_dir in sorted(images_dir.iterdir()):
        if not model_dir.is_dir():
            continue
        if args.model_id and model_dir.name != args.model_id and model_dir.name != args.model_id.replace("-", "_"):
            continue

        hash_dirs = sorted(model_dir.iterdir(), key=lambda d: d.stat().st_mtime)
        hash_dirs = [h for h in hash_dirs if h.is_dir()]

        if args.keep_latest and len(hash_dirs) > 1:
            targets.extend(hash_dirs[:-1])
        elif not args.keep_latest:
            targets.extend(hash_dirs)

    if not targets:
        if args.model_id:
            print(f"No cached images found for model '{args.model_id}'.")
        else:
            print("No cached images found.")
        return 0

    total_size = sum(
        f.stat().st_size
        for d in targets
        for f in d.iterdir()
        if f.is_file()
    )
    print(f"Will remove {len(targets)} cached build(s) ({total_size / 1024 / 1024:.1f} MB):")
    for d in targets:
        print(f"  {d.parent.name}/{d.name[:12]}...")

    if not args.yes:
        try:
            response = input("Continue? [y/N] ")
            if response.lower() not in ("y", "yes"):
                print("Cancelled.")
                return 0
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

    removed = 0
    for d in targets:
        shutil.rmtree(d)
        removed += 1

    print(f"Removed {removed} cached build(s) ({total_size / 1024 / 1024:.1f} MB freed).")
    return 0


def cmd_flash(args: argparse.Namespace) -> int:
    parser = _build_parser()
    validation_error = _validate_args(args)
    if validation_error:
        parser.error(validation_error)

    if args.request_image and not args.ssh_key:
        cfg = _load_config()
        if cfg.ssh_public_key_path:
            args.ssh_key = cfg.ssh_public_key_path
        else:
            parser.error("No SSH public key found. Set [ssh].key in config.toml or use --ssh-key.")

    _say_fn = (lambda m: None) if args.no_voice else say

    ssh_key_path = _detect_ssh_key_path()

    if not args.model_id:
        for probe_ip in ["192.168.1.1", "192.168.0.1"]:
            fp = fingerprint_router(probe_ip)
            if fp:
                board = fp.get("identity", {}).get("board", "")
                if board:
                    detected_id = _find_model_id_by_board(board)
                    if detected_id:
                        args.model_id = detected_id
                        log(f"Auto-detected model: {detected_id} (board={board})")
                        break
        if not args.model_id:
            parser.error("--model-id is required when device is not reachable via SSH.")

    try:
        profile = _build_profile_from_model(args.model_id, serial_method=args.serial_method or "")
    except (FileNotFoundError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    is_serial_tftp = getattr(profile, 'is_serial_tftp', False)

    if is_serial_tftp and not args.serial_method:
        serial_methods = [k for k in load_model(args.model_id).get("flash_methods", {}).keys()
                          if k.startswith("serial-tftp-")]
        if len(serial_methods) == 1:
            method_suffix = serial_methods[0].replace("serial-tftp-", "")
            profile = _build_profile_from_model(args.model_id, serial_method=method_suffix)
            log(f"Auto-selected serial method: {serial_methods[0]}")
        elif len(serial_methods) > 1:
            print(f"ERROR: Multiple serial methods available: {serial_methods}. "
                  f"Use --serial-method to select one.", file=sys.stderr)
            return 1

    openwrt_ip = profile.openwrt_ip or profile.recovery_ip

    if is_serial_tftp:
        boot_state = "unknown"
        use_sysupgrade = False
    else:
        boot_state = _detect_boot_state("", profile)
        use_sysupgrade = boot_state == "openwrt" and not args.force_uboot

    generated_password = ""
    password_set = False
    auth_type = ""
    wan_ssh_enabled = False
    image_path = args.image

    if args.request_image:
        cfg = _load_config()
        password = args.password
        if not args.no_password and not args.password:
            if cfg.password_is_key_only:
                password = None
                password_set = False
                auth_type = "key-only"
            elif cfg.password_is_random:
                generated_password = _generate_random_password()
                _say_fn("Random password generated. Check the console.")
                password = generated_password
                password_set = True
                auth_type = "key-and-password"
            elif cfg.password_literal:
                password = cfg.password_literal
                password_set = True
                auth_type = "key-and-password"
        elif args.password:
            password_set = True
            auth_type = "key-and-password"
        elif args.no_password:
            password_set = False
            auth_type = "key-only"

        wan_ssh_enabled = args.wan_ssh or cfg.wan_ssh

        image_path = _request_custom_image(
            model_id=args.model_id,
            ssh_key_path=args.ssh_key,
            password=password,
            wan_ssh=wan_ssh_enabled,
            flash_method="sysupgrade" if use_sysupgrade else profile.flash_method,
            say_fn=_say_fn,
        )
        if not image_path:
            print("ERROR: Failed to obtain firmware image.", file=sys.stderr)
            return 1

    if not image_path:
        parser.error("One of --image or --request-image is required.")

    if not os.path.isfile(image_path):
        print(f"ERROR: image not found: {image_path}", file=sys.stderr)
        return 1

    interface = args.interface or auto_detect_interface()
    if not interface:
        print("ERROR: no active ethernet interface found. Use --interface.", file=sys.stderr)
        return 1

    if args.capture:
        pcap_path = args.capture
    else:
        captures_dir = Path(__file__).resolve().parent.parent / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d-%H%M%S")
        pcap_path = str(captures_dir / f"{args.model_id}-{ts}.pcap")

    log(f"{profile.description} Recovery")
    log(f"Model:      {profile.name} ({profile.vendor})")
    log(f"Image:      {image_path}")
    log(f"Interface:  {interface}")
    log(f"Pcap:       {pcap_path}")
    log(f"Boot state: {boot_state}")
    if is_serial_tftp:
        log(f"Flash path: serial-tftp ({profile.flash_method})")
        log(f"Serial:     {args.serial_port or 'auto-detect'} @ {getattr(profile, 'serial_baud', 115200)} baud")
        if getattr(profile, 'lan_port', ''):
            log(f"LAN port:   {profile.lan_port} (for TFTP)")
    else:
        log(f"Flash path: {'sysupgrade' if use_sysupgrade else 'U-Boot recovery'}")
    if not use_sysupgrade and not is_serial_tftp:
        log(f"LED signal: {profile.led_pattern}")
    if args.request_image:
        log(f"Auth type:  {auth_type}")
        log(f"WAN SSH:    {wan_ssh_enabled}")
    print()

    fp = fingerprint_router(openwrt_ip)
    if fp:
        ident = fp.get("identity", {})
        fw = fp.get("firmware", {})
        hw = fp.get("hardware", {})
        net = fp.get("network", {})
        sec = fp.get("security", {})
        log(f"Detected:   {ident.get('model', '?')} (board={ident.get('board', '?')})")
        log(f"Firmware:   {fw.get('version', '?')} {fw.get('target', '')}")
        log(f"Kernel:     {fw.get('kernel', '?')}")
        br_mac = net.get("macs", {}).get("br-lan", "")
        if br_mac:
            log(f"MAC:        {br_mac}")
            if not args.router_mac:
                args.router_mac = br_mac
        mem = hw.get("memory_mb", {})
        if mem:
            log(f"Memory:     {mem.get('total', '?')} kB total, {mem.get('free', '?')} kB free")
        pkgs = sec.get("packages_installed", 0)
        if pkgs:
            log(f"Packages:   {pkgs} installed")
        uptime = fp.get("diagnostics", {}).get("uptime", "")
        if uptime:
            log(f"Uptime:     {uptime}")
        print()
    else:
        log("No running router detected at this IP (expected — device needs recovery)")
        print()

    if is_serial_tftp:
        initial_state = State.SERIAL_WAITING_FOR_BOOTMENU
    elif use_sysupgrade:
        initial_state = State.SYSUPGRADE_UPLOADING
    else:
        initial_state = State.WAITING_FOR_POWER_OFF

    ctx = RecoveryContext(
        profile=profile,
        image_path=image_path,
        interface=interface,
        pcap_path=pcap_path,
        no_upload=args.no_upload,
        no_voice=args.no_voice,
        router_mac_openwrt=args.router_mac,
        router_mac_uboot=args.uboot_mac,
        generated_password=generated_password,
        password_set=password_set,
        auth_type=auth_type,
        wan_ssh_enabled=wan_ssh_enabled,
        force_uboot=args.force_uboot,
        boot_state=boot_state,
        ssh_key_path=ssh_key_path,
        serial_port=args.serial_port or "",
        serial_method=args.serial_method or "",
        serial_baud=args.serial_baud or getattr(profile, 'serial_baud', 115200),
        tftp_root=args.tftp_root or "",
        uboot_commands=getattr(profile, 'uboot_commands', []),
        _say_fn=_say_fn,
        state=initial_state,
    )

    event_queue: queue.Queue = queue.Queue()

    if use_sysupgrade:
        _say_fn(f"Starting {profile.description} sysupgrade recovery.")
        try:
            rc = _run_state_machine(ctx, event_queue, None, None)
        except KeyboardInterrupt:
            log("Interrupted by user.")
            rc = 1
        return rc

    if is_serial_tftp:
        _say_fn(f"Starting {profile.description} serial recovery.")
        if getattr(profile, 'lan_port', ''):
            log(f"IMPORTANT: Connect Ethernet cable to {profile.lan_port} port")
        try:
            rc = _run_state_machine(ctx, event_queue, None, None)
        except KeyboardInterrupt:
            log("Interrupted by user.")
            rc = 1
        finally:
            driver = getattr(ctx, '_serial_driver', None)
            if driver:
                driver.close()
            tftp_mgr = getattr(ctx, '_tftp_manager', None)
            if tftp_mgr:
                tftp_mgr.stop()
        return rc

    _setup_interface_ips(interface, profile)

    monitor_config = PcapMonitorConfig(
        interface=interface,
        pcap_path=pcap_path,
        recovery_ip=profile.recovery_ip,
        router_mac_openwrt=args.router_mac,
        router_mac_uboot=args.uboot_mac,
        silence_timeout=args.silence_timeout,
    )

    pcap_monitor = PcapMonitor(monitor_config, event_queue)
    link_monitor = LinkMonitor(interface, event_queue)

    pcap_thread = threading.Thread(target=pcap_monitor.run, daemon=True)
    link_thread = threading.Thread(target=link_monitor.run, daemon=True)
    pcap_thread.start()
    link_thread.start()

    _say_fn(f"Starting {profile.description} recovery. Listen for instructions.")

    try:
        rc = _run_state_machine(ctx, event_queue, pcap_monitor, link_monitor)
    except KeyboardInterrupt:
        log("Interrupted by user.")
        rc = 1
    finally:
        pcap_monitor.stop()
        link_monitor.stop()
        pcap_thread.join(timeout=5)

    return rc


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] not in ("flash", "list", "cache", "-h", "--help"):
        sys.argv.insert(1, "flash")

    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "list":
        return cmd_list(args)
    elif args.command == "cache":
        return cmd_cache(args)
    else:
        return cmd_flash(args)


if __name__ == "__main__":
    sys.exit(main())
