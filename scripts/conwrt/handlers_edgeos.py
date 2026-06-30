# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false
import os
import queue
import subprocess
import time

from flash.context import Event, State, DEFAULT_IP, log, ts, sha256_file, poll_until
from ssh_utils import ssh_cmd, scp_cmd
from ssh_utils import check_ssh
from conwrt.infrastructure import RecoveryContext
from conwrt.extreme_helpers import _ssh_with_password


def _handle_edgeos_stage1(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    """Stage 1: SSH to EdgeOS, swap boot kernel with OpenWrt initramfs."""
    import shutil as _shutil
    profile = ctx.profile
    edgeos_ip = profile.edgeos_ip
    edgeos_user = profile.edgeos_user
    edgeos_password = profile.edgeos_password
    initramfs_path = ctx.initramfs_path

    if not initramfs_path or not os.path.isfile(initramfs_path):
        log(f"ERROR: initramfs image not found: {initramfs_path}")
        ctx.state = State.FAILED
        return

    size_mb = os.path.getsize(initramfs_path) / 1024 / 1024
    log(f"Stage 1: Uploading initramfs ({size_mb:.1f} MB) to EdgeOS at {edgeos_ip}...")

    # SCP initramfs to EdgeOS /tmp (upload: local → remote with password auth)
    sshpass_bin = _shutil.which("sshpass")
    if not sshpass_bin:
        log("ERROR: sshpass not found. Install with: brew install hudochenkov/sshpass/sshpass")
        ctx.state = State.FAILED
        return

    remote_name = os.path.basename(initramfs_path)
    scp_upload_cmd = [
        sshpass_bin, "-p", edgeos_password,
        "scp", "-O",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        initramfs_path,
        f"{edgeos_user}@{edgeos_ip}:/tmp/{remote_name}",
    ]
    try:
        scp_result = subprocess.run(scp_upload_cmd, capture_output=True, text=True, timeout=120, check=False)
    except subprocess.TimeoutExpired:
        log("SCP to EdgeOS timed out.")
        ctx.state = State.FAILED
        return
    if scp_result.returncode != 0:
        log(f"SCP to EdgeOS failed (exit {scp_result.returncode}): {scp_result.stderr[:300]}")
        ctx.state = State.FAILED
        return

    log("Initramfs uploaded. Swapping boot kernel...")

    # Build the kernel swap script — must use sudo on EdgeOS
    boot_partition = profile.boot_partition
    kernel_path = profile.kernel_path
    md5_path = profile.md5_path
    swap_script = (
        f"set -ex; "
        f"mkdir -p /tmp/boot; "
        f"sudo mount -t vfat {boot_partition} /tmp/boot; "
        f"test -f /tmp/boot{kernel_path} || {{ echo 'ERROR: kernel not found'; exit 1; }}; "
        f"cp -a /tmp/boot{kernel_path} /tmp/boot{kernel_path}.bak; "
        f"cp -a /tmp/boot{md5_path} /tmp/boot{md5_path}.bak; "
        f"cp /tmp/{remote_name} /tmp/boot{kernel_path}; "
        f"md5sum /tmp/boot{kernel_path} | cut -d ' ' -f1 > /tmp/boot{md5_path}; "
        f"sync; "
        f"sudo umount /tmp/boot; "
        f"echo 'Kernel swap complete'; "
        f"sudo reboot"
    )
    ssh_result = _ssh_with_password(
        edgeos_ip, edgeos_user, edgeos_password,
        f"bash -c '{swap_script}'",
        timeout=60,
    )
    if ssh_result.returncode != 0:
        combined = (ssh_result.stdout or "") + (ssh_result.stderr or "")
        if "Kernel swap complete" in combined or "Connection closed" in combined:
            log("Kernel swap completed (connection closed during reboot — expected).")
        else:
            log(f"Kernel swap failed (exit {ssh_result.returncode}): {combined[:500]}")
            ctx.state = State.FAILED
            return

    ctx.sha256_before = sha256_file(ctx.image_path)
    ctx.timeline.upload_start = ts()
    ctx._say_fn("Stage 1 complete. Device rebooting into OpenWrt initramfs.")
    log("Stage 1 complete — EdgeOS rebooting into OpenWrt initramfs.")
    ctx.state = State.EDGEOS_STAGE1_REBOOTING


def _handle_edgeos_stage1_rebooting(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    """Wait for EdgeOS to reboot into OpenWrt initramfs."""
    ctx._say_fn("Waiting for device to reboot. This takes about 90 seconds.")
    log("Waiting for initramfs boot (~90 seconds)...")
    time.sleep(10)

    if ctx.profile.port_swap_required:
        ctx.state = State.EDGEOS_PORT_SWAP
    else:
        ctx.state = State.EDGEOS_STAGE2_UPLOADING


def _handle_edgeos_port_swap(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    """Prompt user to move cable from eth0 (WAN) to eth1+ (LAN)."""
    port_note = ctx.profile.port_swap_note or "Move the ethernet cable to a LAN port."
    ctx._say_fn(f"Important! {port_note}")
    log(f"PORT SWAP: {port_note}")
    log(f"Waiting for SSH on {DEFAULT_IP}...")

    openwrt_ip = ctx.profile.openwrt_ip or DEFAULT_IP
    timeout = 120
    if poll_until(lambda: check_ssh(openwrt_ip), timeout=timeout, interval=5):
        ctx.timeline.ssh_available = ts()
        log(f"SSH available at {openwrt_ip} — initramfs booted successfully.")
        ctx._say_fn("Initramfs is up. Starting stage 2.")
        event_queue.put((Event.EDGEOS_PORT_SWAP_DONE, ts(), ""))
        ctx.state = State.EDGEOS_STAGE2_UPLOADING
        return

    ctx._say_fn("Timed out waiting for initramfs SSH.")
    log(f"FAIL: SSH not available at {openwrt_ip} after {timeout}s.")
    ctx.state = State.FAILED


def _handle_edgeos_stage2_uploading(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    """Stage 2a: Upload sysupgrade.tar to OpenWrt initramfs."""
    openwrt_ip = ctx.profile.openwrt_ip or DEFAULT_IP
    image_path = ctx.image_path

    if not image_path or not os.path.isfile(image_path):
        log(f"ERROR: sysupgrade.tar not found: {image_path}")
        ctx.state = State.FAILED
        return

    size_mb = os.path.getsize(image_path) / 1024 / 1024
    log(f"Stage 2: Uploading sysupgrade.tar ({size_mb:.1f} MB) to initramfs at {openwrt_ip}...")

    remote_path = "/tmp/sysupgrade.tar"
    scp_command = scp_cmd(openwrt_ip, image_path, f"root@{openwrt_ip}:{remote_path}",
                          key=ctx.ssh_key_path or None, connect_timeout=10)
    try:
        r = subprocess.run(scp_command, capture_output=True, text=True, timeout=120, check=False)
        if r.returncode != 0:
            log(f"SCP to initramfs failed (exit {r.returncode}): {r.stderr[:300]}")
            ctx.state = State.FAILED
            return
    except subprocess.TimeoutExpired:
        log("SCP upload to initramfs timed out.")
        ctx.state = State.FAILED
        return

    log("sysupgrade.tar uploaded. Verifying...")
    # Verify upload via remote md5sum
    ssh_command = ssh_cmd(openwrt_ip,
                          f"md5sum {remote_path}",
                          key=ctx.ssh_key_path or None, connect_timeout=10)
    try:
        r = subprocess.run(ssh_command, capture_output=True, text=True, timeout=15, check=False)
        if r.returncode == 0 and r.stdout.strip():
            remote_hash = r.stdout.strip().split()[0]
            log(f"Remote MD5: {remote_hash}")
        else:
            log(f"Could not verify remote file: {r.stderr[:200]}")
    except (subprocess.SubprocessError, OSError) as e:
        log(f"WARNING: upload verification failed: {e}")

    ctx.timeline.upload_complete = ts()
    ctx._say_fn("Upload complete. Flashing firmware.")
    log("sysupgrade.tar uploaded successfully. Proceeding to flash.")
    ctx.state = State.EDGEOS_STAGE2_FLASHING


def _handle_edgeos_stage2_flashing(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    """Stage 2b: Manual dd — extract kernel+rootfs from tar and write to eMMC."""
    openwrt_ip = ctx.profile.openwrt_ip or DEFAULT_IP
    profile = ctx.profile
    model_id = profile.name

    # Build the device-specific tar member paths
    # OpenWrt tar structure: sysupgrade-DEVICE_NAME/kernel and sysupgrade-DEVICE_NAME/root
    # Device name uses underscores: ubnt_edgerouter-6p
    device_name = model_id.replace("-", "_")
    kernel_member = f"sysupgrade-{device_name}/kernel"
    root_member = f"sysupgrade-{device_name}/root"
    boot_partition = profile.boot_partition
    kernel_path = profile.kernel_path
    md5_path = profile.md5_path

    # The flash script — uses sh (not bash — initramfs only has ash)
    flash_script = (
        f"set -ex; "
        f"tar tf /tmp/sysupgrade.tar | head -5; "
        f"mkdir -p /boot; "
        f"mount -t vfat {boot_partition} /boot; "
        f"[ -f /boot{kernel_path} ] && mv /boot{kernel_path} /boot{kernel_path}.previous; "
        f"[ -f /boot{md5_path} ] && mv /boot{md5_path} /boot{md5_path}.previous; "
        f"tar xf /tmp/sysupgrade.tar {kernel_member} -O > /boot{kernel_path}; "
        f"md5sum /boot{kernel_path} | cut -f1 -d ' ' > /boot{md5_path}; "
        f"echo 'Kernel size:'; "
        f"ls -la /boot{kernel_path}; "
        f"echo 'Flashing rootfs to /dev/mmcblk0p2...'; "
        f"tar xf /tmp/sysupgrade.tar {root_member} -O | dd of=/dev/mmcblk0p2 bs=4096; "
        f"sync; "
        f"umount /boot; "
        f"echo 'Flash complete. Rebooting into permanent OpenWrt...'; "
        f"reboot -f"
    )

    log("Stage 2: Flashing squashfs kernel + rootfs to eMMC...")
    ctx._say_fn("Flashing firmware. Do not unplug.")

    ssh_command = ssh_cmd(openwrt_ip,
                          f"sh -c '{flash_script}'",
                          key=ctx.ssh_key_path or None, connect_timeout=10)
    try:
        r = subprocess.run(ssh_command, capture_output=True, text=True, timeout=120, check=False)
        combined = (r.stdout or "") + (r.stderr or "")
        if "Flash complete" in combined:
            log("Flash completed successfully.")
        elif r.returncode != 0 and not r.stdout and not r.stderr:
            log("Flash command sent (connection closed by remote during reboot — expected).")
        else:
            log(f"Flash output (exit {r.returncode}): {combined[:500]}")
    except subprocess.TimeoutExpired:
        log("Flash command timed out (may have started reboot).")

    ctx.timeline.flash_triggered = ts()
    ctx.state = State.OPENWRT_BOOTING
