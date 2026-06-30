import hashlib
import importlib
import os
import subprocess
import time
from pathlib import Path
from typing import Optional

from config import load_config as _load_config
from flash.context import log, ts, ts_str
from inventory import append_to_inventory as _append_to_inventory
from model_loader import load_model
from platform_utils import detect_platform
from conwrt.infrastructure import RecoveryContext

_router_fingerprint = importlib.import_module("router-fingerprint")
fingerprint_router = _router_fingerprint.fingerprint_router
save_fingerprint = _router_fingerprint.save_fingerprint


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
    cfg = _load_config()

    fp = fingerprint_router(ip)
    if not fp:
        log("Could not fingerprint router for inventory.")
        return

    ident = fp.get("identity", {})
    fw = fp.get("firmware", {})
    net = fp.get("network", {})
    sec = fp.get("security", {})
    fp.get("diagnostics", {})
    macs = net.get("macs", {})

    for key in ["hostname", "board", "serial"]:
        val = ident.get(key, "")
        if val:
            log(f"  inventory: {key}={val}")
    for iface, mac in sorted(macs.items()):
        if iface != "lo" and mac:
            log(f"  inventory: mac_{iface}={mac}")

    modem_data = fp.get("modem", {})
    if modem_data:
        for key in ["model", "firmware", "imei", "iccid"]:
            val = modem_data.get(key, "")
            if val:
                log(f"  inventory: modem_{key}={val}")

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
    except (OSError, ValueError):
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
        "mac_addresses": {k: v for k, v in macs.items() if v and k != "lo"},
        "ssh_key_fingerprint": sec.get("ssh_fingerprint", ""),
        "ssh_key_count": sec.get("ssh_key_count", 0),
        "wan_ssh_rules": sec.get("wan_ssh_rules", 0),
        "packages_installed": sec.get("packages_installed", 0),
        "request_hash": ctx.request_hash or "",
        "cache_key": ctx.cache_key or "",
        "packages": ctx.packages or [],
        "defaults_script_hash": hashlib.sha256(ctx.defaults_script.encode()).hexdigest()[:16] if ctx.defaults_script else "",
        "ssh_keys_installed": len(cfg.ssh_all_keys) if cfg else 0,
        "password_set": ctx.password_set,
        "auth_type": ctx.auth_type,
        "wan_ssh_enabled": ctx.wan_ssh_enabled,
        "wireguard_pubkey": ctx.wireguard_pubkey,
        "sha256_firmware": ctx.sha256_before,
        "flashed_by": os.environ.get("USER", ""),
        "timeline": timeline_durations,
        "fingerprint_file": str(fp_path) if fp_path else "",
        "notes": "Flashed via conwrt",
    }
    if modem_data:
        entry["modem"] = modem_data

    inventory_path = Path(__file__).resolve().parent.parent / "data" / "inventory.jsonl"
    try:
        _append_to_inventory(entry, str(inventory_path))
        log(f"Inventory entry appended to {inventory_path}")
    except (OSError, TypeError) as e:
        log(f"Failed to write inventory: {e}")


def auto_detect_interface(subnet_prefix: str = "") -> Optional[str]:
    """Find the single active physical ethernet interface.

    On OpenWrt, returns br-lan directly (all LAN ports are bridged).
    On Linux, looks for enp*/eth*/en* interfaces with carrier UP.
    On macOS, scans en1..en20 skipping WiFi/Thunderbolt.
    """
    import platform
    if platform.system() == "Linux":
        # On OpenWrt, all LAN ports are bridged under br-lan
        if detect_platform() == "openwrt":
            if (Path("/sys/class/net/br-lan")).exists():
                log("OpenWrt detected — using br-lan as default interface")
                return "br-lan"
        candidates = []
        iface_dir = Path("/sys/class/net")
        if iface_dir.exists():
            for iface_path in sorted(iface_dir.iterdir()):
                name = iface_path.name
                if name.startswith(("lo", "wl", "docker", "br-", "virbr", "veth")):
                    continue
                if not name.startswith(("en", "eth")):
                    continue
                try:
                    carrier = (iface_path / "carrier").read_text().strip()
                    operstate = (iface_path / "operstate").read_text().strip()
                    if carrier == "1" and operstate == "up":
                        candidates.append(name)
                except (OSError, PermissionError):
                    continue
        if len(candidates) == 0:
            relaxed = []
            for iface_path in sorted(iface_dir.iterdir()):
                name = iface_path.name
                if name.startswith(("lo", "wl", "docker", "br-", "virbr", "veth")):
                    continue
                if not name.startswith(("en", "eth")):
                    continue
                relaxed.append(name)
            if len(relaxed) == 1:
                log(f"No carrier on {relaxed[0]}, but it's the only ethernet interface — using it")
                return relaxed[0]
            return None
        if len(candidates) > 1:
            log(f"WARNING: multiple ethernet interfaces active: {candidates}, using first")
        return candidates[0]
    else:
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
            if "mtu 16000" in r.stdout:
                continue
            if "base" not in r.stdout or "duplex" not in r.stdout:
                continue
            candidates.append(iface)

        if len(candidates) == 0:
            return None
        if len(candidates) > 1:
            log(f"WARNING: multiple ethernet interfaces active: {candidates}, using first")
        return candidates[0]
