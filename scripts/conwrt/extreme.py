# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false
import os
import queue
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Optional

from flash.context import Event, State, log, say, ts
from flash.context import sha256_file
from ssh_utils import ssh_cmd, scp_cmd
from platform_utils import configure_interface_ip
from conwrt.infrastructure import TFTPServerManager, RecoveryContext
from conwrt.monitors import check_ssh


def _setup_interface_ips(interface: str, profile: SimpleNamespace) -> None:
    if profile.client_ip:
        configure_interface_ip(interface, profile.client_ip, "24")
    openwrt_client = profile.openwrt_client_ip
    if openwrt_client and openwrt_client != profile.client_ip:
        configure_interface_ip(interface, openwrt_client, "24")


def _generate_zyxel_password(serial: str) -> Optional[str]:
    import shutil
    pwgen = shutil.which("zyxel_pwgen")
    if not pwgen:
        return None
    try:
        result = subprocess.run(
            [pwgen, serial],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split("\n")[-1].strip()
    except Exception:
        pass
    return None


def _ssh_with_password(ip: str, user: str, password: str, command: str,
                        timeout: int = 30, *, extra_ssh_options: list[str] | None = None) -> subprocess.CompletedProcess:
    import shutil
    sshpass = shutil.which("sshpass")
    if not sshpass:
        return subprocess.CompletedProcess(
            args=[], returncode=127,
            stdout="", stderr="sshpass not found. Install with: brew install hudochenkov/sshpass/sshpass",
        )
    cmd = [
        sshpass, "-p", password,
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", f"ConnectTimeout=10",
        *(extra_ssh_options or []),
        f"{user}@{ip}",
        command,
    ]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def _scp_with_password(ip: str, user: str, password: str,
                       remote_src: str, local_dst: str,
                       timeout: int = 120, *, extra_ssh_options: list[str] | None = None) -> subprocess.CompletedProcess:
    import shutil
    sshpass = shutil.which("sshpass")
    if not sshpass:
        return subprocess.CompletedProcess(
            args=[], returncode=127,
            stdout="", stderr="sshpass not found.",
        )
    cmd = [
        sshpass, "-p", password,
        "scp", "-O",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        *(extra_ssh_options or []),
        f"{user}@{ip}:{remote_src}",
        local_dst,
    ]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def _parse_key_value_lines(output: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def _sanitize_filename_part(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip())
    return cleaned.strip("-._") or "unknown"


def _extreme_tftp_server_ip(profile: SimpleNamespace) -> str:
    return getattr(profile, "openwrt_client_ip", "") or getattr(profile, "client_ip", "") or ""


def _extreme_stock_ssh_options(profile: SimpleNamespace) -> list[str]:
    return list(getattr(profile, "stock_legacy_ssh_options", []) or [])


def _resolve_extreme_uboot_value(profile: SimpleNamespace, value: str) -> str:
    if value == "<CONWRT_TFTP_SERVER_IP>":
        return _extreme_tftp_server_ip(profile)
    return value


def _ensure_extreme_backup_dir(ctx: RecoveryContext, preflight_data: Optional[dict] = None) -> Path:
    existing = getattr(ctx, "_extreme_backup_dir", "")
    if existing:
        backup_dir = Path(existing)
        backup_dir.mkdir(parents=True, exist_ok=True)
        return backup_dir

    device_id = "unknown-device"
    if preflight_data:
        for candidate in (
            preflight_data.get("serial", ""),
            preflight_data.get("hostname", ""),
            preflight_data.get("primary_mac", ""),
        ):
            if candidate:
                device_id = _sanitize_filename_part(candidate)
                break
    base = Path(__file__).resolve().parent.parent / "data" / "backups" / ctx.profile.name / device_id
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    backup_dir = base / timestamp
    backup_dir.mkdir(parents=True, exist_ok=True)
    ctx._extreme_backup_dir = str(backup_dir)
    ctx._extreme_device_id = device_id
    return backup_dir


def _extreme_confirm_or_fail(ctx: RecoveryContext, prompt: str) -> bool:
    if ctx.no_upload:
        return True
    if ctx.assume_yes:
        return True
    print()
    try:
        response = input(f"{prompt} [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        log("Cancelled before destructive Extreme flash step.")
        ctx.state = State.FAILED
        return False
    if response not in ("y", "yes"):
        log("Cancelled. Re-run with --yes to allow destructive Extreme flash steps.")
        ctx.state = State.FAILED
        return False
    return True


def _extreme_openwrt_ssh(ctx: RecoveryContext, command: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """SSH to OpenWrt initramfs (root, no password). Uses sshpass for reliability."""
    import shutil

    sshpass = shutil.which("sshpass")
    if not sshpass:
        return subprocess.run(
            ssh_cmd(ctx.profile.openwrt_ip, command, key=ctx.ssh_key_path or None, connect_timeout=10),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    return subprocess.run(
        [
            sshpass,
            "-p",
            "",
            "ssh",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=10",
            f"root@{ctx.profile.openwrt_ip}",
            command,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _extreme_openwrt_scp_from_remote(ctx: RecoveryContext, remote_src: str, local_dst: str,
                                     timeout: int = 120) -> subprocess.CompletedProcess:
    """SCP from OpenWrt initramfs (root, no password)."""
    import shutil

    sshpass = shutil.which("sshpass")
    if not sshpass:
        return subprocess.run(
            scp_cmd(
                ctx.profile.openwrt_ip,
                f"root@{ctx.profile.openwrt_ip}:{remote_src}",
                local_dst,
                key=ctx.ssh_key_path or None,
                connect_timeout=10,
            ),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    return subprocess.run(
        [
            sshpass,
            "-p",
            "",
            "scp",
            "-O",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=10",
            f"root@{ctx.profile.openwrt_ip}:{remote_src}",
            local_dst,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _extreme_openwrt_scp_to_remote(ctx: RecoveryContext, local_src: str, remote_dst: str,
                                    timeout: int = 120) -> subprocess.CompletedProcess:
    """SCP to OpenWrt initramfs (root, no password)."""
    import shutil

    sshpass = shutil.which("sshpass")
    if not sshpass:
        return subprocess.run(
            scp_cmd(
                ctx.profile.openwrt_ip,
                local_src,
                f"root@{ctx.profile.openwrt_ip}:{remote_dst}",
                key=ctx.ssh_key_path or None,
                connect_timeout=10,
            ),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    return subprocess.run(
        [
            sshpass,
            "-p",
            "",
            "scp",
            "-O",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=10",
            local_src,
            f"root@{ctx.profile.openwrt_ip}:{remote_dst}",
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _write_json_file(path: Path, data: object) -> None:
    import json
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def _prepare_extreme_tftp_root(ctx: RecoveryContext) -> tuple[Optional[Path], Optional[Path]]:
    initramfs_path = ctx.initramfs_path
    if not initramfs_path or not os.path.isfile(initramfs_path):
        log(f"ERROR: initramfs image not found: {initramfs_path}")
        return None, None

    temp_root = Path(tempfile.mkdtemp(prefix="conwrt-extreme-tftp-"))
    primary_name = ctx.profile.initramfs_tftp_name
    primary_path = temp_root / primary_name
    try:
        os.symlink(os.path.abspath(initramfs_path), primary_path)
    except OSError:
        shutil.copy2(initramfs_path, primary_path)

    alt_name = getattr(ctx.profile, "optional_alt_tftp_name", "")
    if alt_name and alt_name != primary_name:
        alt_path = temp_root / alt_name
        try:
            os.symlink(os.path.abspath(initramfs_path), alt_path)
        except OSError:
            shutil.copy2(initramfs_path, alt_path)

    return temp_root, primary_path


def _cleanup_extreme_tftp_assets(ctx: RecoveryContext) -> None:
    tftp_mgr = getattr(ctx, "_extreme_tftp_manager", None)
    if tftp_mgr:
        tftp_mgr.stop()
        ctx._extreme_tftp_manager = None
    tftp_root = getattr(ctx, "_extreme_tftp_root", "")
    if tftp_root:
        shutil.rmtree(tftp_root, ignore_errors=True)
        ctx._extreme_tftp_root = ""


def _handle_extreme_stock_preflight(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    profile = ctx.profile
    stock_ip = profile.stock_default_ip
    stock_user = profile.stock_default_user
    stock_password = profile.stock_default_password
    stock_ssh_options = _extreme_stock_ssh_options(profile)

    if not _extreme_confirm_or_fail(ctx, "Extreme flash will modify U-Boot variables and reboot the AP. Continue?"):
        return

    import shutil as _shutil_dep

    missing_deps = []
    if not _shutil_dep.which("sshpass"):
        missing_deps.append("sshpass (required for stock firmware SSH and initramfs access)")
    if not ctx.initramfs_path or not os.path.isfile(ctx.initramfs_path):
        missing_deps.append(f"initramfs image not found: {ctx.initramfs_path}")
    if not ctx.image_path or not os.path.isfile(ctx.image_path):
        missing_deps.append(f"sysupgrade image not found: {ctx.image_path}")
    if missing_deps:
        for dep in missing_deps:
            log(f"MISSING: {dep}")
        log("Cannot proceed without required dependencies.")
        ctx.state = State.FAILED
        return

    which_result = _ssh_with_password(
        stock_ip,
        stock_user,
        stock_password,
        f"which {shlex.quote(profile.rdwr_boot_cfg_binary)}",
        timeout=15,
        extra_ssh_options=stock_ssh_options,
    )
    if which_result.returncode != 0:
        log(f"ERROR: {profile.rdwr_boot_cfg_binary} not found on stock firmware: {which_result.stderr[:300]}")
        ctx.state = State.FAILED
        return

    read_all_result = _ssh_with_password(
        stock_ip,
        stock_user,
        stock_password,
        f"{shlex.quote(profile.rdwr_boot_cfg_binary)} read_all",
        timeout=30,
        extra_ssh_options=stock_ssh_options,
    )
    if read_all_result.returncode != 0 or not read_all_result.stdout.strip():
        log(f"WARNING: rdwr_boot_cfg read_all failed (exit {read_all_result.returncode}): {(read_all_result.stderr or read_all_result.stdout)[:400]}")
        log("Will attempt raw MTD config block write as fallback.")
        ctx._extreme_rdwr_broken = True
        read_all_output = ""
    else:
        ctx._extreme_rdwr_broken = False
        read_all_output = read_all_result.stdout

    info_commands = {
        "hostname": "hostname",
        "mac_addresses": "for f in /sys/class/net/*/address; do printf '%s=%s\\n' $(basename $(dirname \"$f\")) $(cat \"$f\" 2>/dev/null); done",
        "serial": "cat /sys/devices/platform/qca-ssdk.0/serial_number 2>/dev/null || cat /proc/device-tree/serial-number 2>/dev/null || getserialno 2>/dev/null || echo ''",
        "firmware_version": "cat /etc/version 2>/dev/null || cat /etc/banner 2>/dev/null || echo ''",
        "uname": "uname -a",
        "mount": "mount",
        "proc_mtd": "cat /proc/mtd",
        "dmesg_tail": "dmesg | tail -n 200",
    }
    collected: dict[str, str] = {}
    for name, command in info_commands.items():
        result = _ssh_with_password(
            stock_ip, stock_user, stock_password, command, timeout=30,
            extra_ssh_options=stock_ssh_options,
        )
        collected[name] = (result.stdout or "").strip()

    mac_lines = _parse_key_value_lines(collected.get("mac_addresses", ""))
    preflight_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "stock_ip": stock_ip,
        "hostname": collected.get("hostname", "").strip(),
        "serial": collected.get("serial", "").strip(),
        "primary_mac": next(iter(mac_lines.values()), ""),
        "mac_addresses": mac_lines,
        "firmware_version": collected.get("firmware_version", "").strip(),
        "uname": collected.get("uname", "").strip(),
        "mount": collected.get("mount", ""),
        "proc_mtd": collected.get("proc_mtd", ""),
        "dmesg_tail": collected.get("dmesg_tail", ""),
        "rdwr_boot_cfg_read_all": read_all_output,
        "initramfs_path": ctx.initramfs_path,
    }
    backup_dir = _ensure_extreme_backup_dir(ctx, preflight_data)
    _write_json_file(backup_dir / "preflight.json", preflight_data)
    event_queue.put((Event.EXTREME_UBOOT_ENV_SAVED, ts(), str(backup_dir / "preflight.json")))

    if ctx.no_upload:
        log("DRY RUN: Extreme stock firmware reachable and preflight data saved.")
        log(f"  Backup dir: {backup_dir}")
        log(f"  Initramfs:  {ctx.initramfs_path}")
        log(f"  Sysupgrade: {ctx.image_path}")
        ctx.state = State.COMPLETE
        return

    _setup_interface_ips(ctx.interface, profile)
    tftp_ip = _extreme_tftp_server_ip(profile)
    if not tftp_ip:
        log("ERROR: No local TFTP server IP configured in profile.")
        ctx.state = State.FAILED
        return
    if not configure_interface_ip(ctx.interface, tftp_ip, "24"):
        log(f"ERROR: failed to configure {tftp_ip}/24 on {ctx.interface}")
        ctx.state = State.FAILED
        return

    for disable_cmd in getattr(profile, "stock_ssh_timeout_disable_commands", []):
        result = _ssh_with_password(
            stock_ip, stock_user, stock_password, disable_cmd, timeout=20,
            extra_ssh_options=stock_ssh_options,
        )
        if result.returncode != 0:
            log(f"ERROR: failed to run stock timeout-disable command '{disable_cmd}': {result.stderr[:300]}")
            ctx.state = State.FAILED
            return

    tftp_root, _ = _prepare_extreme_tftp_root(ctx)
    if tftp_root is None:
        ctx.state = State.FAILED
        return
    tftp_mgr = TFTPServerManager(str(tftp_root), bind_ip=tftp_ip)
    if not tftp_mgr.start():
        shutil.rmtree(tftp_root, ignore_errors=True)
        ctx.state = State.FAILED
        return
    tftp_test_file = tftp_root / profile.initramfs_tftp_name
    if not tftp_test_file.exists():
        log(f"ERROR: TFTP root does not contain {profile.initramfs_tftp_name}")
        log(f"  TFTP root contents: {list(tftp_root.iterdir()) if tftp_root.exists() else '(missing)'}")
        tftp_mgr.stop()
        shutil.rmtree(tftp_root, ignore_errors=True)
        ctx.state = State.FAILED
        return
    log(f"TFTP verified: {profile.initramfs_tftp_name} ({tftp_test_file.stat().st_size} bytes)")
    ctx._extreme_tftp_manager = tftp_mgr
    ctx._extreme_tftp_root = str(tftp_root)
    event_queue.put((Event.EXTREME_TFTP_INITRAMFS_READY, ts(), tftp_ip))
    log(f"Extreme preflight complete. TFTP serving {profile.initramfs_tftp_name} from {tftp_ip}.")
    ctx.state = State.EXTREME_STOCK_WRITING_UBOOT


def _handle_extreme_stock_writing_uboot(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    profile = ctx.profile
    stock_ip = profile.stock_default_ip
    stock_user = profile.stock_default_user
    stock_password = profile.stock_default_password
    tftp_ip = _extreme_tftp_server_ip(profile)
    ap_ip = profile.stock_default_ip
    stock_ssh_options = _extreme_stock_ssh_options(profile)

    if not _extreme_confirm_or_fail(ctx, "Write temporary Extreme U-Boot variables now?"):
        return

    vars_to_write: dict[str, str] = {}
    for key, value in profile.required_uboot_vars.items():
        resolved = _resolve_extreme_uboot_value(profile, value)
        if value == "<TEMP_AP_IP>":
            resolved = ap_ip
        vars_to_write[key] = resolved

    rdwr_broken = getattr(ctx, "_extreme_rdwr_broken", False)

    if not rdwr_broken:
        log("WARNING: Stock firmware reboots every ~5 minutes without a controller.")
        log("Writing all U-Boot variables in a single batch to minimize time window.")
        log("If the AP reboots during this step, serial console may be required for recovery.")
        write_commands = []
        for key, value in vars_to_write.items():
            write_commands.append(f"{shlex.quote(profile.rdwr_boot_cfg_binary)} write_var {shlex.quote(f'{key}={value}')}")
        batch_script = " && ".join(write_commands)
        log(f"Writing {len(vars_to_write)} U-Boot variables in single batch...")
        batch_result = _ssh_with_password(
            stock_ip, stock_user, stock_password, batch_script, timeout=30,
            extra_ssh_options=stock_ssh_options,
        )
        if batch_result.returncode != 0:
            log(f"WARNING: rdwr_boot_cfg write_var batch failed: {batch_result.stderr[:500]}")
            rdwr_broken = True

    if rdwr_broken:
        log("Attempting individual write_var calls as fallback...")
        individual_ok = True
        for key, value in vars_to_write.items():
            result = _ssh_with_password(
                stock_ip,
                stock_user,
                stock_password,
                f"{shlex.quote(profile.rdwr_boot_cfg_binary)} write_var {shlex.quote(f'{key}={value}')}",
                timeout=15,
                extra_ssh_options=stock_ssh_options,
            )
            if result.returncode != 0:
                log(f"WARNING: write_var failed for {key}={value}: {result.stderr[:200]}")
                individual_ok = False
            else:
                log(f"Wrote {key}={value} via write_var")
        if not individual_ok:
            log("ERROR: rdwr_boot_cfg is broken on this firmware. Cannot write U-Boot variables.")
            log("RECOVERY OPTIONS:")
            log("  1. Connect serial console and set U-Boot variables manually:")
            for key, value in vars_to_write.items():
                log(f"     setenv {key} {value}")
            log("     saveenv")
            log("  2. Try a different firmware version where rdwr_boot_cfg works")
            ctx.state = State.FAILED
            return
    ctx._extreme_rdwr_broken = rdwr_broken

    verify_result = _ssh_with_password(
        stock_ip,
        stock_user,
        stock_password,
        f"{shlex.quote(profile.rdwr_boot_cfg_binary)} read_all",
        timeout=20,
        extra_ssh_options=stock_ssh_options,
    )
    if verify_result.returncode != 0 or not verify_result.stdout.strip():
        log("WARNING: Cannot verify written variables (rdwr_boot_cfg read_all broken).")
        log("Proceeding anyway — variables were written without error.")
    else:
        parsed = _parse_key_value_lines((verify_result.stdout or "") + "\n" + (verify_result.stderr or ""))
        for key, value in vars_to_write.items():
            if parsed.get(key) != value:
                log(f"ERROR: verification failed for {key}: expected {value!r}, got {parsed.get(key)!r}")
                ctx.state = State.FAILED
                return
            log(f"Verified stock U-Boot var {key}={value}")

    final_vars_to_write: dict[str, str] = {}
    for key, value in profile.final_uboot_vars.items():
        resolved = _resolve_extreme_uboot_value(profile, value)
        final_vars_to_write[key] = resolved

    if not rdwr_broken:
        final_write_commands = []
        for key, value in final_vars_to_write.items():
            final_write_commands.append(f"{shlex.quote(profile.rdwr_boot_cfg_binary)} write_var {shlex.quote(f'{key}={value}')}")
        if final_write_commands:
            final_batch_script = " && ".join(final_write_commands)
            log(f"Writing {len(final_vars_to_write)} final U-Boot variables for permanent OpenWrt boot...")
            final_result = _ssh_with_password(
                stock_ip, stock_user, stock_password, final_batch_script, timeout=30,
                extra_ssh_options=stock_ssh_options,
            )
            if final_result.returncode == 0:
                ctx._extreme_final_vars_written = True
                log("Final U-Boot vars written successfully.")
            else:
                log(f"WARNING: Failed to write final U-Boot vars: {final_result.stderr[:400]}")
                log("AP will use TFTP boot as fallback. Permanent boot must be set manually later.")
    else:
        final_ok = True
        for key, value in final_vars_to_write.items():
            result = _ssh_with_password(
                stock_ip, stock_user, stock_password,
                f"{shlex.quote(profile.rdwr_boot_cfg_binary)} write_var {shlex.quote(f'{key}={value}')}",
                timeout=15,
                extra_ssh_options=stock_ssh_options,
            )
            if result.returncode != 0:
                final_ok = False
        if final_ok:
            ctx._extreme_final_vars_written = True

    ctx.state = State.EXTREME_STOCK_REBOOTING


def _handle_extreme_stock_rebooting(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    profile = ctx.profile
    stock_ssh_options = _extreme_stock_ssh_options(profile)
    log("Rebooting AP to TFTP boot OpenWrt initramfs...")
    try:
        _ssh_with_password(
            profile.stock_default_ip,
            profile.stock_default_user,
            profile.stock_default_password,
            "reboot",
            timeout=10,
            extra_ssh_options=stock_ssh_options,
        )
    except Exception:
        pass
    ctx._say_fn("AP rebooting. Waiting for OpenWrt initramfs. This takes about 90 seconds.")
    time.sleep(10)
    ctx.state = State.EXTREME_OPENWRT_INITRAMFS_WAITING


def _handle_extreme_openwrt_initramfs_waiting(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    openwrt_ip = ctx.profile.openwrt_ip
    timeout = ctx.profile.flash_time_seconds
    start = ts()
    while ts() - start < timeout:
        if check_ssh(openwrt_ip):
            verify = _extreme_openwrt_ssh(ctx, "test -f /etc/openwrt_release && cat /proc/mtd", timeout=20)
            if verify.returncode == 0:
                ctx.timeline.ssh_available = ts()
                log(f"SSH available at {openwrt_ip} — OpenWrt initramfs booted.")
                ctx._say_fn("OpenWrt initramfs booted. Starting backup.")
                ctx.state = State.EXTREME_OPENWRT_BACKUP
                return
        time.sleep(5)
    log(f"FAIL: OpenWrt initramfs SSH not available at {openwrt_ip} after {timeout}s.")
    ctx.state = State.FAILED


def _handle_extreme_openwrt_backup(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    backup_dir = _ensure_extreme_backup_dir(ctx)
    info_result = _extreme_openwrt_ssh(ctx, "cat /proc/mtd", timeout=20)
    if info_result.returncode != 0 or not info_result.stdout.strip():
        log(f"ERROR: failed to read /proc/mtd from initramfs: {info_result.stderr[:300]}")
        ctx.state = State.FAILED
        return

    mtd_parts: list[tuple[str, str]] = []
    for line in info_result.stdout.splitlines():
        match = re.match(r"^(mtd\d+):\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+\"([^\"]+)\"", line.strip())
        if match:
            mtd_parts.append((match.group(1), _sanitize_filename_part(match.group(2))))

    commands = [
        "rm -rf /tmp/conwrt-backup /tmp/conwrt-backup.tar.gz",
        "mkdir -p /tmp/conwrt-backup",
        "cat /proc/mtd > /tmp/conwrt-backup/proc_mtd.txt",
        "dmesg > /tmp/conwrt-backup/dmesg.txt",
        "mount > /tmp/conwrt-backup/mount.txt",
        "ubus call system board > /tmp/conwrt-backup/system_board.json 2>/dev/null || true",
        "fw_printenv > /tmp/conwrt-backup/fw_printenv.txt 2>/dev/null || true",
    ]
    for mtd_name, label in mtd_parts:
        commands.append(
            f"dd if=/dev/{mtd_name} of=/tmp/conwrt-backup/{mtd_name}_{label}.bin bs=64k"
        )
    commands.extend([
        "(cd /tmp/conwrt-backup && sha256sum * > SHA256SUMS.txt)",
        "tar czf /tmp/conwrt-backup.tar.gz -C /tmp conwrt-backup",
    ])
    script = "set -e; " + "; ".join(commands)
    backup_result = _extreme_openwrt_ssh(ctx, script, timeout=max(120, len(mtd_parts) * 45))
    if backup_result.returncode != 0:
        log(f"ERROR: failed creating Extreme backup on initramfs: {(backup_result.stderr or backup_result.stdout)[:500]}")
        ctx.state = State.FAILED
        return

    local_tar = backup_dir / "conwrt-backup.tar.gz"
    scp_result = _extreme_openwrt_scp_from_remote(ctx, "/tmp/conwrt-backup.tar.gz", str(local_tar), timeout=180)
    if scp_result.returncode != 0:
        log(f"ERROR: failed downloading Extreme backup tarball: {scp_result.stderr[:300]}")
        ctx.state = State.FAILED
        return
    if not local_tar.is_file() or local_tar.stat().st_size == 0:
        log(f"ERROR: local backup tarball missing or empty: {local_tar}")
        ctx.state = State.FAILED
        return

    extracted_dir = backup_dir / "files"
    extracted_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(local_tar, "r:gz") as tar:
        tar.extractall(extracted_dir)

    extracted_root = extracted_dir / "conwrt-backup"
    hashes: dict[str, str] = {}
    sha_file = extracted_root / "SHA256SUMS.txt"
    if sha_file.is_file():
        for line in sha_file.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                hashes[parts[1].lstrip("*./")] = parts[0]
    _write_json_file(
        backup_dir / "backup-manifest.json",
        {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "tarball": str(local_tar),
            "tarball_sha256": sha256_file(str(local_tar)),
            "hashes": hashes,
            "mtd_partitions": [mtd for mtd, _ in mtd_parts],
        },
    )
    event_queue.put((Event.EXTREME_BACKUP_COMPLETE, ts(), str(local_tar)))
    ctx.state = State.EXTREME_BOOTCMD_RESTORE


def _handle_extreme_bootcmd_restore(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    final_vars_written = getattr(ctx, "_extreme_final_vars_written", False)
    if final_vars_written:
        log("Final U-Boot vars already written from stock firmware.")
        event_queue.put((Event.EXTREME_BOOTCMD_RESTORED, ts(), "stock_rdwr"))
    else:
        log("WARNING: Final U-Boot vars were NOT written during stock phase.")
        log("The AP will boot from TFTP (run boot_net) on every reboot.")
        log("To set permanent boot from flash, SSH to stock firmware and run:")
        for key, value in ctx.profile.final_uboot_vars.items():
            resolved = _resolve_extreme_uboot_value(ctx.profile, value)
            log(f"  rdwr_boot_cfg write_var {key}={resolved}")

    _cleanup_extreme_tftp_assets(ctx)
    ctx.state = State.EXTREME_SYSUPGRADE_UPLOADING


def _handle_extreme_sysupgrade_uploading(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    image_path = ctx.image_path
    if not image_path or not os.path.isfile(image_path):
        log(f"ERROR: sysupgrade image not found: {image_path}")
        ctx.state = State.FAILED
        return

    remote_name = os.path.basename(image_path)
    remote_path = f"/tmp/{remote_name}"
    size_mb = os.path.getsize(image_path) / 1024 / 1024
    ctx.timeline.upload_start = ts()
    if not ctx.sha256_before:
        ctx.sha256_before = sha256_file(image_path)
    log(f"Uploading sysupgrade ({size_mb:.1f} MB) to initramfs at {ctx.profile.openwrt_ip}...")
    scp_result = _extreme_openwrt_scp_to_remote(ctx, image_path, remote_path, timeout=180)
    if scp_result.returncode != 0:
        log(f"ERROR: SCP to initramfs failed: {scp_result.stderr[:300]}")
        ctx.state = State.FAILED
        return

    verify_result = _extreme_openwrt_ssh(
        ctx,
        f"test -s {shlex.quote(remote_path)} && sha256sum {shlex.quote(remote_path)}",
        timeout=30,
    )
    if verify_result.returncode != 0 or not verify_result.stdout.strip():
        log(f"ERROR: remote sysupgrade verification failed: {(verify_result.stderr or verify_result.stdout)[:300]}")
        ctx.state = State.FAILED
        return
    remote_hash = verify_result.stdout.strip().split()[0]
    log(f"Remote SHA-256: {remote_hash}")
    ctx.timeline.upload_complete = ts()
    ctx.state = State.EXTREME_SYSUPGRADE_FLASHING


def _handle_extreme_sysupgrade_flashing(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    remote_name = os.path.basename(ctx.image_path)
    remote_path = f"/tmp/{remote_name}"
    ctx._say_fn("Flashing firmware. Do not unplug.")

    from platform_utils import detect_platform
    on_openwrt = detect_platform() == "openwrt"
    overlay_path = None

    if on_openwrt:
        from profile.overlay import build_overlay_tarball
        overlay_path = build_overlay_tarball(disable_dhcp=True)
        try:
            overlay_name = os.path.basename(overlay_path)
            overlay_remote = f"/tmp/{overlay_name}"
            scp_result = _extreme_openwrt_scp_to_remote(ctx, overlay_path, overlay_remote, timeout=30)
            if scp_result.returncode == 0:
                log("Post-flash overlay uploaded. Running sysupgrade -n -f ...")
                cmd = f"sysupgrade -n -f {shlex.quote(overlay_remote)} {shlex.quote(remote_path)}"
            else:
                log("Overlay upload failed, falling back to sysupgrade -n without overlay.")
                cmd = f"sysupgrade -n {shlex.quote(remote_path)}"
        except Exception:
            log("Overlay generation failed, falling back to sysupgrade -n without overlay.")
            cmd = f"sysupgrade -n {shlex.quote(remote_path)}"
        finally:
            if overlay_path:
                try:
                    os.unlink(overlay_path)
                except OSError:
                    pass
    else:
        log("Running sysupgrade -n from OpenWrt initramfs...")
        cmd = f"sysupgrade -n {shlex.quote(remote_path)}"

    try:
        result = _extreme_openwrt_ssh(ctx, cmd, timeout=60)
        combined = (result.stdout or "") + (result.stderr or "")
        if result.returncode == 0 or "Commencing upgrade" in combined or "Rebooting system" in combined:
            log("Extreme sysupgrade initiated successfully.")
        elif result.returncode != 0 and not result.stdout and not result.stderr:
            log("Extreme sysupgrade initiated (connection closed by remote — expected).")
        else:
            log(f"Extreme sysupgrade output (exit {result.returncode}): {combined[:500]}")
    except subprocess.TimeoutExpired:
        log("Extreme sysupgrade command timed out (may have started reboot).")
    ctx.timeline.flash_triggered = ts()
    _cleanup_extreme_tftp_assets(ctx)
    ctx.state = State.OPENWRT_BOOTING


def _handle_port_isolation(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    """Isolate target port into VLAN before flashing (switch-initiated flow only)."""
    if not ctx.isolate_port:
        log("No port isolation requested — skipping")
        _advance_past_port_isolation(ctx)
        return

    from platform_utils import detect_platform
    if detect_platform() != "openwrt":
        log("Port isolation requires running on OpenWrt — skipping")
        _advance_past_port_isolation(ctx)
        return

    # Check if model has port_isolation config
    model_data = {}
    profile = ctx.profile
    if hasattr(profile, "_raw_model"):
        model_data = profile._raw_model
    port_isolation_config = model_data.get("port_isolation") if isinstance(model_data, dict) else None
    if not port_isolation_config:
        log("Model does not define port_isolation — skipping")
        _advance_past_port_isolation(ctx)
        return

    from flash.port_isolator import PortIsolator
    vlan_id = port_isolation_config.get("isolation_vlan_id", 999)
    isolator = PortIsolator("127.0.0.1", ssh_key=ctx.ssh_key_path or None, vlan_id=vlan_id)
    ctx.port_isolator = isolator

    log(f"Isolating port {ctx.isolate_port} into VLAN {vlan_id}...")
    success = isolator.isolate(ctx.isolate_port)
    if success:
        log(f"Port {ctx.isolate_port} isolated successfully")
    else:
        log(f"WARNING: Port isolation failed for {ctx.isolate_port} — continuing anyway")

    _advance_past_port_isolation(ctx)


def _advance_past_port_isolation(ctx: RecoveryContext) -> None:
    """Advance state past PORT_ISOLATION to the appropriate next state."""
    flash_method = getattr(ctx.profile, "flash_method", "")
    is_extreme = flash_method == "extreme-rdwr-tftp"
    is_serial = flash_method == "serial-tftp-openwrt"
    is_zycast = flash_method == "zycast"
    is_edgeos = flash_method == "edgeos-kernel-swap"
    use_sysupgrade = getattr(ctx.profile, "use_sysupgrade", False)

    if is_extreme and not use_sysupgrade:
        boot_state = ctx.boot_state
        ctx.state = State.EXTREME_STOCK_PREFLIGHT if boot_state == "stock-extreme" else State.DETECTING
    elif is_serial:
        ctx.state = State.SERIAL_WAITING_FOR_BOOTMENU
    elif is_zycast and not use_sysupgrade:
        ctx.state = State.ZYCAST_WAITING_FOR_DEVICE
    elif is_edgeos and not use_sysupgrade:
        ctx.state = State.EDGEOS_STAGE1
    elif use_sysupgrade:
        ctx.state = State.SYSUPGRADE_UPLOADING
    else:
        ctx.state = State.WAITING_FOR_POWER_OFF


def _restore_port_isolation(ctx: RecoveryContext) -> None:
    """Restore port isolation after flash completes."""
    if not ctx.isolate_port or not ctx.port_isolator:
        return
    from flash.port_isolator import PortIsolator
    isolator = ctx.port_isolator
    if not isinstance(isolator, PortIsolator):
        return
    log(f"Restoring port {ctx.isolate_port} from isolation...")
    try:
        isolator.restore(ctx.isolate_port)
    except Exception as e:
        log(f"WARNING: Port restoration failed: {e}")
