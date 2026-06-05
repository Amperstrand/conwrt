# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false
import os
import queue
import time
from typing import Optional

from flash.context import Event, State, log, say, ts, wait_for_event
from flash.context import get_link_state, sha256_file
from flash.upload import detect_uboot_http, upload_firmware, trigger_flash
from flash.hnap import _flash_via_dlink_hnap
from conwrt.infrastructure import RecoveryContext
from conwrt.monitors import PcapMonitor, LinkMonitor

_wait_for_event_or_timeout = wait_for_event


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

    if profile.flash_method == "dlink-hnap":
        ok, response = _flash_via_dlink_hnap(ctx.image_path, profile)
    else:
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

    if profile.flash_method != "dlink-hnap" and trigger_flash(profile):
        ctx.timeline.flash_triggered = ts()
        eq.put((Event.FLASH_TRIGGERED, ts(), ""))
    else:
        log("Flash trigger may have failed. Router may still flash on its own.")
        ctx.timeline.flash_triggered = ts()

    ctx._say_fn("Firmware flashing. Do not unplug.")
    ctx.state = State.UBOOT_FLASHING


def _handle_uboot_flashing(ctx: RecoveryContext, eq: queue.Queue, pcap_monitor: Optional[PcapMonitor]) -> None:
    if pcap_monitor is None:
        timeout = ctx.profile.flash_time_seconds + 30
        log(f"Waiting {timeout}s for flash to complete (polling-only mode)...")
        time.sleep(timeout)
        ctx.timeline.flash_complete = ts()
        ctx.state = State.REBOOTING
        return

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
