# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false
import queue
import subprocess

from flash.context import Event, State, log, ts, sha256_file
from zycast import run_zycast_auto
from conwrt.infrastructure import RecoveryContext
from conwrt.handlers_uboot import _drain_events


def _handle_zycast_waiting(ctx: RecoveryContext, eq: queue.Queue) -> None:
    profile = ctx.profile
    ctx._say_fn("Power cycle the router now. Multicast flash will start automatically.")
    log("Waiting for ZyXEL Multiboot multicast packets...")

    getattr(profile, 'zycast_multicast_group', '225.0.0.0')
    getattr(profile, 'zycast_multicast_port', 5631)
    probe_timeout = 120
    probe_start = ts()

    while ts() - probe_start < probe_timeout:
        try:
            event, event_ts, detail = eq.get(timeout=1.0)
            if event == Event.ZYCAST_MULTICAST_DETECTED:
                ctx.timeline.uboot_http_first = ts()
                log(f"ZyXEL Multiboot detected: {detail}")
                ctx._say_fn("Multiboot detected. Starting multicast flash.")
                ctx.state = State.ZYCAST_SENDING
                return
            if event == Event.LINK_UP and ctx.timeline.link_up is None:
                ctx.timeline.link_up = event_ts
                log("Link up — watching for multicast")
            elif event == Event.LINK_DOWN and ctx.timeline.power_off is None:
                ctx.timeline.power_off = event_ts
        except queue.Empty:
            pass

        _drain_events(eq, ctx)

    ctx._say_fn("No Multiboot detected. Check that the router is powered on.")
    log(f"FAIL: No multicast packets from ZyXEL bootloader within {probe_timeout}s")
    ctx.state = State.FAILED


def _handle_zycast_sending(ctx: RecoveryContext, eq: queue.Queue) -> None:
    if ctx.no_upload:
        ctx._say_fn("Dry run. Multiboot detected but not flashing.")
        log("DRY RUN: Would flash via zycast multicast")
        ctx.state = State.COMPLETE
        return

    profile = ctx.profile
    ctx.sha256_before = sha256_file(ctx.image_path)
    log(f"SHA-256 (before zycast): {ctx.sha256_before}")

    multicast_group = getattr(profile, 'zycast_multicast_group', '225.0.0.0')
    multicast_port = getattr(profile, 'zycast_multicast_port', 5631)
    image_type = getattr(profile, 'zycast_image_type', 'ras')

    ctx.timeline.upload_start = ts()
    ctx._say_fn("Sending firmware via multicast. Do not unplug.")
    log(f"Starting zycast: {ctx.image_path} -> {multicast_group}:{multicast_port}")

    try:
        proc = run_zycast_auto(
            image_path=ctx.image_path,
            interface=ctx.interface,
            multicast_group=multicast_group,
            multicast_port=multicast_port,
            image_type=image_type,
        )
    except (subprocess.SubprocessError, OSError) as e:
        log(f"ERROR: Failed to start zycast: {e}")
        ctx.state = State.FAILED
        return

    ctx._zycast_proc = proc

    flash_timeout = getattr(profile, 'flash_time_seconds', 180) + 60
    start = ts()
    while ts() - start < flash_timeout:
        retcode = proc.poll()
        if retcode is not None:
            break
        try:
            event, event_ts, detail = eq.get(timeout=2.0)
            if event == Event.ZYCAST_MULTICAST_DETECTED:
                log(f"  multicast activity: {detail[:80]}")
        except queue.Empty:
            pass

    if proc.poll() is None:
        log("zycast still running after timeout — terminating")
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    stdout_data = proc.stdout.read() if proc.stdout else ""
    stderr_data = proc.stderr.read() if proc.stderr else ""

    if stdout_data:
        for line in stdout_data.strip().split("\n")[:10]:
            log(f"  [zycast stdout] {line}")
    if stderr_data:
        for line in stderr_data.strip().split("\n")[:10]:
            log(f"  [zycast stderr] {line}")

    retcode = proc.returncode
    if retcode == 0:
        ctx.timeline.upload_complete = ts()
        ctx.timeline.flash_complete = ts()
        ctx.timeline.flash_triggered = ts()
        log("zycast completed successfully")
        ctx._say_fn("Multicast flash complete. Waiting for router to reboot.")
        ctx.state = State.REBOOTING
    else:
        log(f"zycast exited with code {retcode}")
        ctx._say_fn("Multicast flash may have failed. Check the console output.")
        ctx.timeline.flash_complete = ts()
        ctx.state = State.REBOOTING
