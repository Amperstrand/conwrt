# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false
import os
import queue
import subprocess

try:
    from serial import SerialException as _SerialException
except ImportError:
    _SerialException = OSError  # type: ignore[misc, assignment]

from flash.context import Event, State, log, say, ts, sha256_file
from platform_utils import configure_interface_ip
from conwrt.infrastructure import RecoveryContext, TFTPServerManager, SerialUBootDriver, _auto_detect_serial_port


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

    try:
        got_prompt = driver.wait_for_bootmenu(
            timeout=profile.bootmenu_timeout,
            interrupt=profile.bootmenu_interrupt,
            console_option=profile.bootmenu_select_console,
            say_fn=ctx._say_fn,
        )
    except (_SerialException, OSError):
        log(f"ERROR: Serial communication failed during bootmenu wait")
        driver.close()
        ctx.state = State.FAILED
        return

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

    try:
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
    except (_SerialException, OSError, subprocess.SubprocessError):
        log("ERROR: Serial operation failed")
        tftp_mgr.stop()
        driver.close()
        ctx.state = State.FAILED
        return

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

    if profile.client_ip:
        configure_interface_ip(interface, profile.client_ip, "24")
