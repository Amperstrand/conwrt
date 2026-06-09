import queue
import sys
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from flash.context import Event, RecoveryContext, State, Timeline
from conwrt.handlers_uboot import (
    _drain_events,
    _handle_waiting_for_power_off,
    _handle_waiting_for_uboot,
    _handle_uboot_uploading,
    _handle_uboot_flashing,
)


def _make_ctx(**overrides):
    profile = MagicMock()
    profile.reset_instructions = overrides.pop("reset_instructions", "Hold reset for 10 seconds")
    profile.led_pattern = overrides.pop("led_pattern", "Solid red")
    profile.recovery_ip = overrides.pop("recovery_ip", "192.168.0.1")
    profile.upload_field = overrides.pop("upload_field", "file")
    profile.upload_endpoint = overrides.pop("upload_endpoint", "/upload")
    profile.trigger_flash_endpoint = overrides.pop("trigger_flash_endpoint", "/flash")
    profile.flash_method = overrides.pop("flash_method", "recovery-http")
    profile.flash_time_seconds = overrides.pop("flash_time_seconds", 60)
    defaults = {
        "profile": profile,
        "image_path": "/tmp/fw.bin",
        "interface": "en0",
        "pcap_path": "/tmp/cap.pcap",
        "state": State.WAITING_FOR_POWER_OFF,
        "timeline": Timeline(),
        "_say_fn": MagicMock(),
    }
    defaults.update(overrides)
    return RecoveryContext(**defaults)


class TestDrainEventsEmptyQueue(TestCase):
    def test_returns_immediately_on_empty_queue(self):
        ctx = _make_ctx()
        eq = queue.Queue()
        _drain_events(eq, ctx)
        self.assertIsNone(ctx.timeline.link_up)
        self.assertIsNone(ctx.timeline.power_off)
        self.assertIsNone(ctx.timeline.uboot_http_first)


class TestDrainEventsLinkUp(TestCase):
    def test_sets_timeline_link_up_when_unset(self):
        ctx = _make_ctx()
        eq = queue.Queue()
        eq.put((Event.LINK_UP, 100.5, ""))
        _drain_events(eq, ctx)
        self.assertEqual(ctx.timeline.link_up, 100.5)

    def test_does_not_overwrite_existing_link_up(self):
        ctx = _make_ctx()
        ctx.timeline.link_up = 50.0
        eq = queue.Queue()
        eq.put((Event.LINK_UP, 200.0, ""))
        _drain_events(eq, ctx)
        self.assertEqual(ctx.timeline.link_up, 50.0)


class TestDrainEventsLinkDown(TestCase):
    def test_sets_timeline_power_off_when_unset(self):
        ctx = _make_ctx()
        eq = queue.Queue()
        eq.put((Event.LINK_DOWN, 75.0, ""))
        _drain_events(eq, ctx)
        self.assertEqual(ctx.timeline.power_off, 75.0)

    def test_does_not_overwrite_existing_power_off(self):
        ctx = _make_ctx()
        ctx.timeline.power_off = 10.0
        eq = queue.Queue()
        eq.put((Event.LINK_DOWN, 99.0, ""))
        _drain_events(eq, ctx)
        self.assertEqual(ctx.timeline.power_off, 10.0)


class TestDrainEventsUbootHttp(TestCase):
    def test_sets_timeline_uboot_http_first_when_unset(self):
        ctx = _make_ctx()
        eq = queue.Queue()
        eq.put((Event.UBOOT_HTTP, 123.0, "200 OK"))
        _drain_events(eq, ctx)
        self.assertEqual(ctx.timeline.uboot_http_first, 123.0)

    def test_does_not_overwrite_existing_uboot_http(self):
        ctx = _make_ctx()
        ctx.timeline.uboot_http_first = 5.0
        eq = queue.Queue()
        eq.put((Event.UBOOT_HTTP, 88.0, ""))
        _drain_events(eq, ctx)
        self.assertEqual(ctx.timeline.uboot_http_first, 5.0)


class TestDrainEventsMixed(TestCase):
    def test_processes_all_queued_events_until_empty(self):
        ctx = _make_ctx()
        eq = queue.Queue()
        eq.put((Event.LINK_UP, 1.0, ""))
        eq.put((Event.LINK_DOWN, 2.0, ""))
        eq.put((Event.UBOOT_HTTP, 3.0, ""))
        _drain_events(eq, ctx)
        self.assertEqual(ctx.timeline.link_up, 1.0)
        self.assertEqual(ctx.timeline.power_off, 2.0)
        self.assertEqual(ctx.timeline.uboot_http_first, 3.0)

    def test_ignores_unrelated_event_types(self):
        ctx = _make_ctx()
        eq = queue.Queue()
        eq.put((Event.SSH_UP, 50.0, ""))
        eq.put((Event.UPLOAD_COMPLETE, 60.0, ""))
        _drain_events(eq, ctx)
        self.assertIsNone(ctx.timeline.link_up)
        self.assertIsNone(ctx.timeline.power_off)
        self.assertIsNone(ctx.timeline.uboot_http_first)


class TestHandleWaitingForPowerOffAlreadyOff(TestCase):
    @patch("conwrt.handlers_uboot.get_link_state", return_value=False)
    @patch("conwrt.handlers_uboot.ts", return_value=1234.0)
    def test_no_link_marks_router_off_and_advances(self, mock_ts, mock_link):
        ctx = _make_ctx()
        eq = queue.Queue()
        _handle_waiting_for_power_off(ctx, eq)
        self.assertEqual(ctx.state, State.WAITING_FOR_UBOOT)
        self.assertEqual(ctx.timeline.power_off, 1234.0)
        ctx._say_fn.assert_called_with("Router is off. Good.")


class TestHandleWaitingForPowerOffWithLink(TestCase):
    @patch("conwrt.handlers_uboot.get_link_state", return_value=True)
    @patch("conwrt.handlers_uboot._wait_for_event_or_timeout")
    @patch("conwrt.handlers_uboot.ts", return_value=2000.0)
    def test_link_up_waits_and_advances_on_success(self, mock_ts, mock_wait, mock_link):
        ctx = _make_ctx()
        eq = queue.Queue()

        def side_effect(eq, **kwargs):
            ctx.state = State.WAITING_FOR_UBOOT
            return Event.LINK_DOWN
        mock_wait.side_effect = side_effect

        _handle_waiting_for_power_off(ctx, eq)
        self.assertEqual(ctx.state, State.WAITING_FOR_UBOOT)
        self.assertEqual(ctx.timeline.power_off, 2000.0)
        ctx._say_fn.assert_any_call("Ready. Please unplug the power cable from the router now.")
        ctx._say_fn.assert_any_call("Power disconnected. Good.")

    @patch("conwrt.handlers_uboot.get_link_state", return_value=True)
    @patch("conwrt.handlers_uboot._wait_for_event_or_timeout")
    def test_link_up_no_state_change_on_timeout(self, mock_wait, mock_link):
        ctx = _make_ctx()
        eq = queue.Queue()
        mock_wait.return_value = None
        _handle_waiting_for_power_off(ctx, eq)
        self.assertEqual(ctx.state, State.WAITING_FOR_POWER_OFF)
        self.assertIsNone(ctx.timeline.power_off)


class TestHandleWaitingForUbootLinkFails(TestCase):
    @patch("conwrt.handlers_uboot._wait_for_event_or_timeout", return_value=None)
    @patch("conwrt.handlers_uboot.time.sleep")
    def test_link_up_timeout_sets_failed(self, mock_sleep, mock_wait):
        ctx = _make_ctx()
        eq = queue.Queue()
        link_monitor = MagicMock()
        _handle_waiting_for_uboot(ctx, eq, link_monitor)
        self.assertEqual(ctx.state, State.FAILED)


class TestHandleWaitingForUbootRecoveryFound(TestCase):
    @patch("conwrt.handlers_uboot._wait_for_event_or_timeout", return_value=Event.LINK_UP)
    @patch("conwrt.handlers_uboot.detect_uboot_http", return_value=(True, "200 OK"))
    @patch("conwrt.handlers_uboot.time.sleep")
    @patch("conwrt.handlers_uboot.ts", return_value=500.0)
    def test_recovery_detected_advances_to_uploading(self, mock_ts, mock_sleep, mock_detect, mock_wait):
        ctx = _make_ctx()
        eq = queue.Queue()
        link_monitor = MagicMock()
        _handle_waiting_for_uboot(ctx, eq, link_monitor)
        self.assertEqual(ctx.state, State.UBOOT_UPLOADING)
        self.assertEqual(ctx.timeline.uboot_http_first, 500.0)
        ctx._say_fn.assert_any_call("Recovery mode detected. You can release the button now.")


class TestHandleWaitingForUbootRecoveryNotFound(TestCase):
    @patch("conwrt.handlers_uboot._wait_for_event_or_timeout", return_value=Event.LINK_UP)
    @patch("conwrt.handlers_uboot.detect_uboot_http", return_value=(False, ""))
    @patch("conwrt.handlers_uboot.time.sleep")
    @patch("conwrt.handlers_uboot.ts")
    def test_recovery_timeout_sets_failed(self, mock_ts, mock_sleep, mock_detect, mock_wait):
        # ts() increments past probe_timeout (90s) on each call
        mock_ts.side_effect = [100.0, 100.0, 200.0]
        ctx = _make_ctx()
        eq = queue.Queue()
        link_monitor = MagicMock()
        _handle_waiting_for_uboot(ctx, eq, link_monitor)
        self.assertEqual(ctx.state, State.FAILED)


class TestHandleUbootUploadingDryRun(TestCase):
    def test_no_upload_skips_to_complete(self):
        ctx = _make_ctx(no_upload=True)
        eq = queue.Queue()
        _handle_uboot_uploading(ctx, eq)
        self.assertEqual(ctx.state, State.COMPLETE)
        ctx._say_fn.assert_called_with("Dry run. Recovery server is ready but not uploading.")

    def test_no_upload_without_trigger_endpoint(self):
        ctx = _make_ctx(no_upload=True, trigger_flash_endpoint=None)
        eq = queue.Queue()
        _handle_uboot_uploading(ctx, eq)
        self.assertEqual(ctx.state, State.COMPLETE)


class TestHandleUbootUploadingSuccess(TestCase):
    @patch("conwrt.handlers_uboot.sha256_file", return_value="abc123")
    @patch("conwrt.handlers_uboot.upload_firmware", return_value=(True, "response-body"))
    @patch("conwrt.handlers_uboot.trigger_flash", return_value=True)
    @patch("conwrt.handlers_uboot.ts", return_value=999.0)
    def test_recovery_http_uploads_triggers_advances(self, mock_ts, mock_trigger, mock_upload, mock_sha):
        ctx = _make_ctx()
        eq = queue.Queue()
        _handle_uboot_uploading(ctx, eq)
        self.assertEqual(ctx.state, State.UBOOT_FLASHING)
        self.assertEqual(ctx.sha256_before, "abc123")
        self.assertEqual(ctx.sha256_after, "abc123")
        self.assertEqual(ctx.timeline.upload_start, 999.0)
        self.assertEqual(ctx.timeline.upload_complete, 999.0)
        self.assertEqual(ctx.timeline.flash_triggered, 999.0)
        ctx._say_fn.assert_any_call("Firmware flashing. Do not unplug.")


class TestHandleUbootUploadingFailure(TestCase):
    @patch("conwrt.handlers_uboot.sha256_file", return_value="abc")
    @patch("conwrt.handlers_uboot.upload_firmware", return_value=(False, "error"))
    def test_upload_failure_sets_failed(self, mock_upload, mock_sha):
        ctx = _make_ctx()
        eq = queue.Queue()
        _handle_uboot_uploading(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)


class TestHandleUbootUploadingShaMismatch(TestCase):
    @patch("conwrt.handlers_uboot.sha256_file")
    @patch("conwrt.handlers_uboot.upload_firmware", return_value=(True, ""))
    @patch("conwrt.handlers_uboot.trigger_flash", return_value=True)
    def test_sha_mismatch_logged_but_continues(self, mock_trigger, mock_upload, mock_sha):
        mock_sha.side_effect = ["before-hash", "after-hash"]
        ctx = _make_ctx()
        eq = queue.Queue()
        _handle_uboot_uploading(ctx, eq)
        self.assertEqual(ctx.sha256_before, "before-hash")
        self.assertEqual(ctx.sha256_after, "after-hash")
        self.assertEqual(ctx.state, State.UBOOT_FLASHING)


class TestHandleUbootUploadingTriggerFailure(TestCase):
    @patch("conwrt.handlers_uboot.sha256_file", return_value="x")
    @patch("conwrt.handlers_uboot.upload_firmware", return_value=(True, ""))
    @patch("conwrt.handlers_uboot.trigger_flash", return_value=False)
    @patch("conwrt.handlers_uboot.ts", return_value=42.0)
    def test_trigger_failure_still_advances(self, mock_ts, mock_trigger, mock_upload, mock_sha):
        ctx = _make_ctx()
        eq = queue.Queue()
        _handle_uboot_uploading(ctx, eq)
        self.assertEqual(ctx.state, State.UBOOT_FLASHING)
        self.assertEqual(ctx.timeline.flash_triggered, 42.0)


class TestHandleUbootUploadingHnap(TestCase):
    @patch("conwrt.handlers_uboot.sha256_file", return_value="hnap-hash")
    @patch("conwrt.handlers_uboot._flash_via_dlink_hnap", return_value=(True, "ok"))
    @patch("conwrt.handlers_uboot.trigger_flash")
    @patch("conwrt.handlers_uboot.upload_firmware")
    @patch("conwrt.handlers_uboot.ts", return_value=300.0)
    def test_hnap_method_uses_hnap_flash_and_skips_trigger(
        self, mock_ts, mock_upload, mock_trigger, mock_hnap, mock_sha
    ):
        ctx = _make_ctx(flash_method="dlink-hnap")
        eq = queue.Queue()
        _handle_uboot_uploading(ctx, eq)
        mock_hnap.assert_called_once()
        mock_upload.assert_not_called()
        mock_trigger.assert_not_called()
        self.assertEqual(ctx.state, State.UBOOT_FLASHING)
        self.assertEqual(ctx.timeline.flash_triggered, 300.0)

    @patch("conwrt.handlers_uboot.sha256_file", return_value="hnap-hash")
    @patch("conwrt.handlers_uboot._flash_via_dlink_hnap", return_value=(False, "auth-failed"))
    def test_hnap_failure_sets_failed(self, mock_hnap, mock_sha):
        ctx = _make_ctx(flash_method="dlink-hnap")
        eq = queue.Queue()
        _handle_uboot_uploading(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)


class TestHandleUbootFlashingNoPcap(TestCase):
    @patch("conwrt.handlers_uboot.time.sleep")
    @patch("conwrt.handlers_uboot.ts", return_value=777.0)
    def test_polling_mode_sleeps_and_advances(self, mock_ts, mock_sleep):
        ctx = _make_ctx()
        eq = queue.Queue()
        _handle_uboot_flashing(ctx, eq, pcap_monitor=None)
        self.assertEqual(ctx.state, State.REBOOTING)
        self.assertEqual(ctx.timeline.flash_complete, 777.0)
        mock_sleep.assert_called_once()


class TestHandleUbootFlashingWithPcap(TestCase):
    @patch("conwrt.handlers_uboot._wait_for_event_or_timeout", return_value=Event.UBOOT_ARP_192_168_1_2)
    @patch("conwrt.handlers_uboot.ts", return_value=888.0)
    def test_arp_event_advances_to_rebooting(self, mock_ts, mock_wait):
        ctx = _make_ctx()
        eq = queue.Queue()
        pcap_monitor = MagicMock()
        _handle_uboot_flashing(ctx, eq, pcap_monitor)
        self.assertEqual(ctx.timeline.flash_complete, 888.0)
        ctx._say_fn.assert_any_call("Firmware uploaded. Flashing in progress. Do not unplug.")

    @patch("conwrt.handlers_uboot._wait_for_event_or_timeout", return_value=Event.LINK_DOWN)
    @patch("conwrt.handlers_uboot.ts", return_value=999.0)
    def test_link_down_event_advances_to_rebooting(self, mock_ts, mock_wait):
        ctx = _make_ctx()
        eq = queue.Queue()
        pcap_monitor = MagicMock()
        _handle_uboot_flashing(ctx, eq, pcap_monitor)
        self.assertEqual(ctx.timeline.flash_complete, 999.0)
        ctx._say_fn.assert_any_call("Link down. Router is rebooting.")

    @patch("conwrt.handlers_uboot._wait_for_event_or_timeout", return_value=None)
    def test_timeout_sets_failed(self, mock_wait):
        ctx = _make_ctx()
        eq = queue.Queue()
        pcap_monitor = MagicMock()
        _handle_uboot_flashing(ctx, eq, pcap_monitor)
        self.assertEqual(ctx.state, State.FAILED)
