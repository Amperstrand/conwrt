# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import time

from flash.context import Event, State, log, say, ts
from flash.context import DEFAULT_IP, sha256_file, poll_until
from flash.oem_handlers import (
    oem_http_accept_reboot, oem_http_change_password, oem_http_login,
    oem_http_upload, oem_ftp_enable_service, oem_ftp_login, oem_ftp_upload,
    oem_has_prepare_step, oem_reboot_wait_and_install, get_oem_install_fn,
)
from model_loader import load_model
from conwrt.infrastructure import RecoveryContext


def _handle_oem_login(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    profile = ctx.profile
    method = profile.flash_method
    stock_ip = profile.stock_default_ip
    username = profile.stock_default_user
    password = profile.stock_default_password

    if not password:
        model_data = load_model(profile.name)
        creds = model_data.get("stock_default_creds", {})
        username = creds.get("username", "admin")
        password = creds.get("password", "1234")

    if not ctx.initramfs_path or not os.path.isfile(ctx.initramfs_path):
        log(f"ERROR: initramfs image not found: {ctx.initramfs_path}")
        ctx.state = State.FAILED
        return

    if method == "oem-http":
        log(f"Logging into ZyXEL OEM web UI at {stock_ip} (user={username})...")
        success, cookie = oem_http_login(stock_ip, username, password)
        if not success:
            log(f"ERROR: OEM HTTP login failed: {cookie}")
            ctx.state = State.FAILED
            return

        try:
            r_dash = subprocess.run(
                ["curl", "-s", "--max-time", "10", "-b", cookie, "-L",
                 f"http://{stock_ip}/cgi-bin/dispatcher.cgi?cmd=4"],
                capture_output=True, text=True, timeout=15, check=False,
            )
            if "cmd=30" in r_dash.stdout or ("Password" in r_dash.stdout and "Change" in r_dash.stdout):
                new_password = "Zyxel2026!"
                log(f"Mandatory password change detected, changing to '{new_password}'...")
                pw_ok, pw_msg = oem_http_change_password(stock_ip, username, password, new_password, cookie)
                if pw_ok:
                    log(pw_msg)
                    success, cookie = oem_http_login(stock_ip, username, new_password)
                    if not success:
                        log(f"ERROR: Re-login after password change failed: {cookie}")
                        ctx.state = State.FAILED
                        return
                    password = new_password
                else:
                    log(f"WARNING: Password change failed: {pw_msg}")
        except (subprocess.SubprocessError, OSError) as e:
            log(f"WARNING: Password change check failed: {e}")

        ctx.oem_state["cookie"] = cookie
        ctx.oem_state["password"] = password
        log("OEM HTTP login successful")

    elif method == "oem-ftp":
        log(f"Logging into GS1920-24 OEM web UI at {stock_ip} (user={username})...")
        success, cookie_file = oem_ftp_login(stock_ip, username, password)
        if not success:
            log(f"ERROR: OEM FTP login failed: {cookie_file}")
            ctx.state = State.FAILED
            return
        ctx.oem_state["cookie_file"] = cookie_file
        ctx.oem_state["password"] = password
        log("OEM FTP login successful")

    else:
        log(f"ERROR: Unknown OEM method: {method}")
        ctx.state = State.FAILED
        return

    if oem_has_prepare_step(method):
        ctx.state = State.OEM_PREPARE
    else:
        ctx.state = State.OEM_UPLOADING


def _handle_oem_prepare(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    profile = ctx.profile
    method = profile.flash_method
    stock_ip = profile.stock_default_ip

    if method == "oem-ftp":
        cookie_file = ctx.oem_state.get("cookie_file", "")
        log("Enabling FTP service on device...")
        success, msg = oem_ftp_enable_service(stock_ip, cookie_file)
        if not success:
            log(f"ERROR: FTP service enable failed: {msg}")
            ctx.state = State.FAILED
            return
        log("FTP service enabled")

    ctx.state = State.OEM_UPLOADING


def _handle_oem_uploading(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    profile = ctx.profile
    method = profile.flash_method
    stock_ip = profile.stock_default_ip
    initramfs_path = ctx.initramfs_path

    if method == "oem-http":
        cookie = ctx.oem_state.get("cookie", "")
        upload_endpoint = profile.oem_http_upload_endpoint

        filename = os.path.basename(initramfs_path)
        upload_path = initramfs_path
        temp_copy = False
        if len(filename) > 64:
            upload_path = os.path.join(tempfile.gettempdir(), "openwrt-initramfs.bin")
            shutil.copy2(initramfs_path, upload_path)
            temp_copy = True
            log(f"Renamed initramps (>{len(filename)} chars) to {os.path.basename(upload_path)} for v2.90 compatibility")

        try:
            timeout = profile.flash_time_seconds + 60
            success, response = oem_http_upload(stock_ip, cookie, upload_path, upload_endpoint, timeout=timeout)
        finally:
            if temp_copy and os.path.exists(upload_path):
                os.unlink(upload_path)

        if not success:
            log(f"ERROR: OEM HTTP upload failed: {response}")
            ctx.state = State.FAILED
            return

        ctx.timeline.upload_start = ts()
        ctx.timeline.upload_complete = ts()
        log("Firmware uploaded. Accepting reboot dialog...")
        oem_http_accept_reboot(stock_ip, cookie)

    elif method == "oem-ftp":
        username = profile.stock_default_user
        password = ctx.oem_state.get("password", profile.stock_default_password)
        client_ip = profile.client_ip
        target = profile.oem_ftp_target

        success, response = oem_ftp_upload(stock_ip, username, password,
                                           initramfs_path, target=target,
                                           client_ip=client_ip)
        if not success:
            log(f"ERROR: OEM FTP upload failed: {response}")
            ctx.state = State.FAILED
            return

        ctx.timeline.upload_start = ts()
        ctx.timeline.upload_complete = ts()
        log("Firmware uploaded via FTP. Device will reboot...")

    else:
        log(f"ERROR: Unknown OEM method for upload: {method}")
        ctx.state = State.FAILED
        return

    ctx.timeline.flash_triggered = ts()
    ctx._say_fn("Firmware uploaded. Waiting for device to reboot.")
    ctx.state = State.OEM_REBOOTING


def _handle_oem_rebooting(ctx: RecoveryContext, event_queue: queue.Queue) -> None:
    profile = ctx.profile
    openwrt_ip = profile.openwrt_ip or DEFAULT_IP

    ctx._say_fn("Device is rebooting into OpenWrt initramfs.")
    install_fn = get_oem_install_fn(profile.flash_method)

    result = oem_reboot_wait_and_install(ctx, openwrt_ip, install_fn)
    if result is not None:
        ctx.state = result
