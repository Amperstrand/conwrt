import queue
import sys
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from flash.context import Event, RecoveryContext, State, Timeline
from conwrt.handlers_zycast import _handle_zycast_sending, _handle_zycast_waiting


def _make_ctx(**overrides):
    profile = MagicMock()
    profile.flash_time_seconds = overrides.pop("flash_time_seconds", 90)
    profile.zycast_multicast_group = overrides.pop("zycast_multicast_group", "225.0.0.0")
    profile.zycast_multicast_port = overrides.pop("zycast_multicast_port", 5631)
    profile.zycast_image_type = overrides.pop("zycast_image_type", "ras")
    defaults = {
        "profile": profile,
        "image_path": "/tmp/fw.bin",
        "interface": "en0",
        "pcap_path": "/tmp/cap.pcap",
        "initramfs_path": "",
        "state": State.ZYCAST_WAITING_FOR_DEVICE,
        "timeline": Timeline(),
        "_say_fn": MagicMock(),
    }
    defaults.update(overrides)
    ctx = RecoveryContext(**defaults)
    return ctx


class TestHandleZycastWaitingDetectsMulticast(TestCase):
    @patch("conwrt.handlers_zycast._drain_events")
    @patch("conwrt.handlers_zycast.ts", side_effect=[0, 0, 1])
    @patch("conwrt.handlers_zycast.log")
    def test_transitions_to_sending_on_multicast(self, mock_log, mock_ts, mock_drain):
        ctx = _make_ctx(state=State.ZYCAST_WAITING_FOR_DEVICE)
        eq = queue.Queue()
        eq.put((Event.ZYCAST_MULTICAST_DETECTED, 1.0, "multicast from bootloader"))
        _handle_zycast_waiting(ctx, eq)
        self.assertEqual(ctx.state, State.ZYCAST_SENDING)
        self.assertIsNotNone(ctx.timeline.uboot_http_first)


class TestHandleZycastWaitingRecordsLinkUp(TestCase):
    @patch("conwrt.handlers_zycast._drain_events")
    @patch("conwrt.handlers_zycast.ts", side_effect=[0, 0, 0, 0, 200])
    @patch("conwrt.handlers_zycast.log")
    def test_link_up_event_sets_timeline(self, mock_log, mock_ts, mock_drain):
        ctx = _make_ctx(state=State.ZYCAST_WAITING_FOR_DEVICE)
        eq = queue.Queue()
        eq.put((Event.LINK_UP, 5.0, "en0 up"))
        _handle_zycast_waiting(ctx, eq)
        self.assertEqual(ctx.timeline.link_up, 5.0)


class TestHandleZycastWaitingRecordsPowerOff(TestCase):
    @patch("conwrt.handlers_zycast._drain_events")
    @patch("conwrt.handlers_zycast.ts", side_effect=[0, 0, 0, 0, 200])
    @patch("conwrt.handlers_zycast.log")
    def test_link_down_sets_power_off(self, mock_log, mock_ts, mock_drain):
        ctx = _make_ctx(state=State.ZYCAST_WAITING_FOR_DEVICE)
        eq = queue.Queue()
        eq.put((Event.LINK_DOWN, 3.0, "en0 down"))
        _handle_zycast_waiting(ctx, eq)
        self.assertEqual(ctx.timeline.power_off, 3.0)


class TestHandleZycastWaitingTimeout(TestCase):
    @patch("conwrt.handlers_zycast._drain_events")
    @patch("conwrt.handlers_zycast.ts", side_effect=[0, 200])
    @patch("conwrt.handlers_zycast.log")
    def test_timeout_goes_to_failed(self, mock_log, mock_ts, mock_drain):
        ctx = _make_ctx(state=State.ZYCAST_WAITING_FOR_DEVICE)
        eq = queue.Queue()
        _handle_zycast_waiting(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)


class TestHandleZycastSendingDryRun(TestCase):
    @patch("conwrt.handlers_zycast.log")
    def test_no_upload_sets_complete(self, mock_log):
        ctx = _make_ctx(state=State.ZYCAST_SENDING, no_upload=True)
        eq = queue.Queue()
        _handle_zycast_sending(ctx, eq)
        self.assertEqual(ctx.state, State.COMPLETE)


class TestHandleZycastSendingSuccess(TestCase):
    @patch("conwrt.handlers_zycast.sha256_file", return_value="abc123")
    @patch("conwrt.handlers_zycast.log")
    @patch("conwrt.handlers_zycast.ts", side_effect=[0, 0, 0, 1, 2, 3, 4, 5])
    def test_success_sets_rebooting(self, mock_ts, mock_log, mock_sha):
        proc = MagicMock()
        proc.poll.return_value = 0
        proc.returncode = 0
        proc.stdout = MagicMock()
        proc.stdout.read.return_value = "done"
        proc.stderr = MagicMock()
        proc.stderr.read.return_value = ""
        with patch("conwrt.handlers_zycast.run_zycast_auto", return_value=proc):
            ctx = _make_ctx(state=State.ZYCAST_SENDING)
            eq = queue.Queue()
            _handle_zycast_sending(ctx, eq)
        self.assertEqual(ctx.state, State.REBOOTING)
        self.assertEqual(ctx.sha256_before, "abc123")
        self.assertIsNotNone(ctx.timeline.upload_complete)


class TestHandleZycastSendingNonZeroExit(TestCase):
    @patch("conwrt.handlers_zycast.sha256_file", return_value="abc123")
    @patch("conwrt.handlers_zycast.log")
    @patch("conwrt.handlers_zycast.ts", side_effect=[0, 0, 0, 1, 2, 3, 4, 5])
    def test_nonzero_exit_still_rebooting(self, mock_ts, mock_log, mock_sha):
        proc = MagicMock()
        proc.poll.return_value = 1
        proc.returncode = 1
        proc.stdout = MagicMock()
        proc.stdout.read.return_value = ""
        proc.stderr = MagicMock()
        proc.stderr.read.return_value = "error"
        with patch("conwrt.handlers_zycast.run_zycast_auto", return_value=proc):
            ctx = _make_ctx(state=State.ZYCAST_SENDING)
            eq = queue.Queue()
            _handle_zycast_sending(ctx, eq)
        self.assertEqual(ctx.state, State.REBOOTING)


class TestHandleZycastSendingException(TestCase):
    @patch("conwrt.handlers_zycast.sha256_file", return_value="abc123")
    @patch("conwrt.handlers_zycast.log")
    @patch("conwrt.handlers_zycast.ts", side_effect=[0, 0, 0, 1])
    def test_run_zycast_exception_goes_to_failed(self, mock_ts, mock_log, mock_sha):
        with patch("conwrt.handlers_zycast.run_zycast_auto", side_effect=OSError("boom")):
            ctx = _make_ctx(state=State.ZYCAST_SENDING)
            eq = queue.Queue()
            _handle_zycast_sending(ctx, eq)
        self.assertEqual(ctx.state, State.FAILED)


class TestHandleZycastSendingTimeoutTerminate(TestCase):
    @patch("conwrt.handlers_zycast.sha256_file", return_value="abc123")
    @patch("conwrt.handlers_zycast.log")
    @patch("conwrt.handlers_zycast.ts", side_effect=[0, 0, 0, 50, 150, 250, 260, 270, 280])
    def test_proc_terminated_after_timeout(self, mock_ts, mock_log, mock_sha):
        poll_count = iter([None, None, None, 0])
        proc = MagicMock()
        proc.poll.side_effect = lambda: next(poll_count)
        proc.returncode = 0
        proc.stdout = MagicMock()
        proc.stdout.read.return_value = ""
        proc.stderr = MagicMock()
        proc.stderr.read.return_value = ""
        with patch("conwrt.handlers_zycast.run_zycast_auto", return_value=proc):
            ctx = _make_ctx(state=State.ZYCAST_SENDING, flash_time_seconds=10)
            eq = queue.Queue()
            _handle_zycast_sending(ctx, eq)
        proc.terminate.assert_called_once()


class TestHandleZycastSendingProfileAttrs(TestCase):
    @patch("conwrt.handlers_zycast.sha256_file", return_value="deadbeef")
    @patch("conwrt.handlers_zycast.log")
    @patch("conwrt.handlers_zycast.ts", side_effect=[0, 0, 0, 1, 2, 3, 4, 5])
    def test_custom_profile_attrs_passed(self, mock_ts, mock_log, mock_sha):
        proc = MagicMock()
        proc.poll.return_value = 0
        proc.returncode = 0
        proc.stdout = MagicMock()
        proc.stdout.read.return_value = ""
        proc.stderr = MagicMock()
        proc.stderr.read.return_value = ""
        with patch("conwrt.handlers_zycast.run_zycast_auto", return_value=proc) as mock_run:
            ctx = _make_ctx(
                state=State.ZYCAST_SENDING,
                zycast_multicast_group="239.1.1.1",
                zycast_multicast_port=9000,
                zycast_image_type="trx",
            )
            eq = queue.Queue()
            _handle_zycast_sending(ctx, eq)
        mock_run.assert_called_once_with(
            image_path="/tmp/fw.bin",
            interface="en0",
            multicast_group="239.1.1.1",
            multicast_port=9000,
            image_type="trx",
        )
