import os
import queue
import sys
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from flash.context import Event, RecoveryContext, State, Timeline
from conwrt.handlers_serial import (
    _handle_serial_waiting_for_bootmenu,
    _handle_serial_uboot_interacting,
    setup_interface_for_serial,
)


def _make_ctx(**overrides):
    profile = MagicMock()
    profile.bootmenu_timeout = overrides.pop("bootmenu_timeout", 30)
    profile.bootmenu_interrupt = overrides.pop("bootmenu_interrupt", "ctrl-c")
    profile.bootmenu_select_console = overrides.pop("bootmenu_select_console", "0")
    profile.lan_port = overrides.pop("lan_port", "LAN2")
    profile.flash_time_seconds = overrides.pop("flash_time_seconds", 120)
    profile.uboot_commands = overrides.pop("uboot_commands", ["boot"])
    profile.client_ip = overrides.pop("client_ip", "192.168.1.2")
    defaults = {
        "profile": profile,
        "image_path": "/tmp/fw.bin",
        "interface": "en0",
        "pcap_path": "/tmp/cap.pcap",
        "state": State.SERIAL_WAITING_FOR_BOOTMENU,
        "serial_port": "/dev/cu.usbserial-110",
        "serial_baud": 115200,
        "timeline": Timeline(),
        "_say_fn": MagicMock(),
        "tftp_root": "/tmp/tftpboot",
        "uboot_commands": [],
    }
    defaults.update(overrides)
    ctx = RecoveryContext(**defaults)
    return ctx


class TestSetupInterfaceForSerialNoInterface(TestCase):
    def test_no_interface_returns_early(self):
        ctx = _make_ctx(interface="")
        with patch("conwrt.handlers_serial.configure_interface_ip") as mock_cfg:
            setup_interface_for_serial(ctx)
            mock_cfg.assert_not_called()


class TestSetupInterfaceForSerialNoClientIp(TestCase):
    def test_no_client_ip_returns_early(self):
        profile = MagicMock()
        profile.client_ip = ""
        ctx = _make_ctx(interface="en0")
        ctx.profile = profile
        with patch("conwrt.handlers_serial.configure_interface_ip") as mock_cfg:
            setup_interface_for_serial(ctx)
            mock_cfg.assert_not_called()


class TestSetupInterfaceForSerialSuccess(TestCase):
    def test_configures_interface_with_client_ip(self):
        profile = MagicMock()
        profile.client_ip = "192.168.1.100"
        ctx = _make_ctx(interface="en0")
        ctx.profile = profile
        with patch("conwrt.handlers_serial.configure_interface_ip") as mock_cfg:
            setup_interface_for_serial(ctx)
            mock_cfg.assert_called_once_with("en0", "192.168.1.100", "24")


class TestWaitingForBootmenuAutoDetect(TestCase):
    @patch("conwrt.handlers_serial.SerialUBootDriver")
    @patch("conwrt.handlers_serial._auto_detect_serial_port", return_value="/dev/cu.auto")
    def test_auto_detects_port_when_not_set(self, mock_detect, mock_driver_cls):
        ctx = _make_ctx(serial_port="")
        eq = queue.Queue()
        mock_driver = MagicMock()
        mock_driver.wait_for_bootmenu.return_value = True
        mock_driver_cls.return_value = mock_driver

        _handle_serial_waiting_for_bootmenu(ctx, eq)

        mock_detect.assert_called_once()
        self.assertEqual(ctx.state, State.SERIAL_UBOOT_INTERACTING)


class TestWaitingForBootmenuAutoDetectFails(TestCase):
    @patch("conwrt.handlers_serial._auto_detect_serial_port",
           side_effect=FileNotFoundError("No serial adapter found"))
    def test_auto_detect_failure_sets_failed(self, mock_detect):
        ctx = _make_ctx(serial_port="")
        eq = queue.Queue()

        _handle_serial_waiting_for_bootmenu(ctx, eq)

        self.assertEqual(ctx.state, State.FAILED)


class TestWaitingForBootmenuGotPrompt(TestCase):
    @patch("conwrt.handlers_serial.SerialUBootDriver")
    def test_got_prompt_sets_interacting(self, mock_driver_cls):
        ctx = _make_ctx(serial_port="/dev/cu.usbserial-110")
        eq = queue.Queue()
        mock_driver = MagicMock()
        mock_driver.wait_for_bootmenu.return_value = True
        mock_driver_cls.return_value = mock_driver

        _handle_serial_waiting_for_bootmenu(ctx, eq)

        self.assertEqual(ctx.state, State.SERIAL_UBOOT_INTERACTING)
        event, event_ts, detail = eq.get_nowait()
        self.assertEqual(event, Event.SERIAL_UBOOT_READY)
        self.assertIsNotNone(ctx.timeline.uboot_http_first)


class TestWaitingForBootmenuNoPrompt(TestCase):
    @patch("conwrt.handlers_serial.SerialUBootDriver")
    def test_no_prompt_sets_failed(self, mock_driver_cls):
        ctx = _make_ctx(serial_port="/dev/cu.usbserial-110")
        eq = queue.Queue()
        mock_driver = MagicMock()
        mock_driver.wait_for_bootmenu.return_value = False
        mock_driver_cls.return_value = mock_driver

        _handle_serial_waiting_for_bootmenu(ctx, eq)

        self.assertEqual(ctx.state, State.FAILED)
        mock_driver.close.assert_called_once()


class TestWaitingForBootmenuSerialException(TestCase):
    @patch("conwrt.handlers_serial.SerialUBootDriver")
    def test_serial_exception_sets_failed(self, mock_driver_cls):
        ctx = _make_ctx(serial_port="/dev/cu.usbserial-110")
        eq = queue.Queue()
        mock_driver = MagicMock()
        mock_driver.wait_for_bootmenu.side_effect = OSError("Port busy")
        mock_driver_cls.return_value = mock_driver

        _handle_serial_waiting_for_bootmenu(ctx, eq)

        self.assertEqual(ctx.state, State.FAILED)
        mock_driver.close.assert_called_once()


class TestUbootInteractingSuccess(TestCase):
    @patch("conwrt.handlers_serial.sha256_file", return_value="abc123")
    @patch("conwrt.handlers_serial.setup_interface_for_serial")
    @patch("conwrt.handlers_serial.TFTPServerManager")
    def test_success_sets_rebooting(self, mock_tftp_cls, mock_setup, mock_sha):
        ctx = _make_ctx(
            state=State.SERIAL_UBOOT_INTERACTING,
            serial_port="/dev/cu.usbserial-110",
        )
        mock_driver = MagicMock()
        mock_driver.run_commands.return_value = True
        ctx._serial_driver = mock_driver

        mock_tftp = MagicMock()
        mock_tftp.start.return_value = True
        mock_tftp_cls.return_value = mock_tftp

        eq = queue.Queue()

        _handle_serial_uboot_interacting(ctx, eq)

        self.assertEqual(ctx.state, State.REBOOTING)
        self.assertEqual(ctx.sha256_before, "abc123")
        mock_tftp.stop.assert_called_once()
        mock_driver.close.assert_called_once()


class TestUbootInteractingFailure(TestCase):
    @patch("conwrt.handlers_serial.setup_interface_for_serial")
    @patch("conwrt.handlers_serial.TFTPServerManager")
    def test_commands_failure_sets_failed(self, mock_tftp_cls, mock_setup):
        ctx = _make_ctx(
            state=State.SERIAL_UBOOT_INTERACTING,
            serial_port="/dev/cu.usbserial-110",
        )
        mock_driver = MagicMock()
        mock_driver.run_commands.return_value = False
        ctx._serial_driver = mock_driver

        mock_tftp = MagicMock()
        mock_tftp.start.return_value = True
        mock_tftp_cls.return_value = mock_tftp

        eq = queue.Queue()

        _handle_serial_uboot_interacting(ctx, eq)

        self.assertEqual(ctx.state, State.FAILED)
        mock_tftp.stop.assert_called_once()
        mock_driver.close.assert_called_once()


class TestUbootInteractingNoCommands(TestCase):
    @patch("conwrt.handlers_serial.setup_interface_for_serial")
    @patch("conwrt.handlers_serial.TFTPServerManager")
    def test_no_commands_sets_failed(self, mock_tftp_cls, mock_setup):
        profile = MagicMock()
        profile.uboot_commands = []
        profile.client_ip = "192.168.1.2"

        ctx = _make_ctx(
            state=State.SERIAL_UBOOT_INTERACTING,
            uboot_commands=[],
        )
        ctx.profile = profile
        mock_driver = MagicMock()
        ctx._serial_driver = mock_driver

        mock_tftp = MagicMock()
        mock_tftp.start.return_value = True
        mock_tftp_cls.return_value = mock_tftp

        eq = queue.Queue()

        _handle_serial_uboot_interacting(ctx, eq)

        self.assertEqual(ctx.state, State.FAILED)
        mock_tftp.stop.assert_called_once()
        mock_driver.close.assert_called_once()


class TestUbootInteractingException(TestCase):
    @patch("conwrt.handlers_serial.setup_interface_for_serial",
           side_effect=OSError("Interface config failed"))
    @patch("conwrt.handlers_serial.TFTPServerManager")
    def test_exception_sets_failed(self, mock_tftp_cls, mock_setup):
        ctx = _make_ctx(
            state=State.SERIAL_UBOOT_INTERACTING,
            serial_port="/dev/cu.usbserial-110",
        )
        mock_driver = MagicMock()
        ctx._serial_driver = mock_driver

        mock_tftp = MagicMock()
        mock_tftp.start.return_value = True
        mock_tftp_cls.return_value = mock_tftp

        eq = queue.Queue()

        _handle_serial_uboot_interacting(ctx, eq)

        self.assertEqual(ctx.state, State.FAILED)
        mock_tftp.stop.assert_called_once()
        mock_driver.close.assert_called_once()


class TestUbootInteractingUsesProfileCommands(TestCase):
    @patch("conwrt.handlers_serial.sha256_file", return_value="deadbeef")
    @patch("conwrt.handlers_serial.setup_interface_for_serial")
    @patch("conwrt.handlers_serial.TFTPServerManager")
    def test_uses_profile_commands_when_ctx_empty(self, mock_tftp_cls, mock_setup, mock_sha):
        profile = MagicMock()
        profile.uboot_commands = ["tftpboot 0x82000000 fw.bin", "bootm 0x82000000"]
        profile.client_ip = "192.168.1.2"
        profile.flash_time_seconds = 60

        ctx = _make_ctx(
            state=State.SERIAL_UBOOT_INTERACTING,
            uboot_commands=[],
        )
        ctx.profile = profile

        mock_driver = MagicMock()
        mock_driver.run_commands.return_value = True
        ctx._serial_driver = mock_driver

        mock_tftp = MagicMock()
        mock_tftp.start.return_value = True
        mock_tftp_cls.return_value = mock_tftp

        eq = queue.Queue()

        _handle_serial_uboot_interacting(ctx, eq)

        mock_driver.run_commands.assert_called_once_with(
            ["tftpboot 0x82000000 fw.bin", "bootm 0x82000000"],
            eq,
            say_fn=ctx._say_fn,
            flash_time_seconds=60,
        )


class TestUbootInteractingTftpStartFails(TestCase):
    @patch("conwrt.handlers_serial.sha256_file", return_value="abc")
    @patch("conwrt.handlers_serial.setup_interface_for_serial")
    @patch("conwrt.handlers_serial.TFTPServerManager")
    def test_tftp_start_fails_continues(self, mock_tftp_cls, mock_setup, mock_sha):
        ctx = _make_ctx(
            state=State.SERIAL_UBOOT_INTERACTING,
            serial_port="/dev/cu.usbserial-110",
        )
        mock_driver = MagicMock()
        mock_driver.run_commands.return_value = True
        ctx._serial_driver = mock_driver

        mock_tftp = MagicMock()
        mock_tftp.start.return_value = False
        mock_tftp_cls.return_value = mock_tftp

        eq = queue.Queue()

        _handle_serial_uboot_interacting(ctx, eq)

        self.assertEqual(ctx.state, State.REBOOTING)


class TestUbootInteractingCommandsFalse(TestCase):
    """run_commands returning False (not raising) takes the explicit failure branch."""
    @patch("conwrt.handlers_serial.sha256_file", return_value="abc")
    @patch("conwrt.handlers_serial.setup_interface_for_serial")
    @patch("conwrt.handlers_serial.TFTPServerManager")
    def test_run_commands_false_sets_failed(self, mock_tftp_cls, mock_setup, mock_sha):
        ctx = _make_ctx(
            state=State.SERIAL_UBOOT_INTERACTING,
            serial_port="/dev/cu.usbserial-110",
        )
        mock_driver = MagicMock()
        mock_driver.run_commands.return_value = False
        ctx._serial_driver = mock_driver

        mock_tftp = MagicMock()
        mock_tftp.start.return_value = True
        mock_tftp_cls.return_value = mock_tftp

        _handle_serial_uboot_interacting(ctx, queue.Queue())

        self.assertEqual(ctx.state, State.FAILED)
        mock_driver.close.assert_called_once()
        say_messages = [c[0][0] for c in ctx._say_fn.call_args_list]
        self.assertTrue(any("Flash failed" in m for m in say_messages))


class TestUbootInteractingTftpRootDefault(TestCase):
    @patch("conwrt.handlers_serial.sha256_file", return_value="abc")
    @patch("conwrt.handlers_serial.setup_interface_for_serial")
    @patch("conwrt.handlers_serial.TFTPServerManager")
    def test_empty_tftp_root_uses_image_dir(self, mock_tftp_cls, mock_setup, mock_sha):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            image = os.path.join(td, "fw.bin")
            with open(image, "wb") as f:
                f.write(b"fw")
            ctx = _make_ctx(
                state=State.SERIAL_UBOOT_INTERACTING,
                image_path=image,
                tftp_root="",
            )
            mock_driver = MagicMock()
            mock_driver.run_commands.return_value = True
            ctx._serial_driver = mock_driver
            mock_tftp_cls.return_value = MagicMock()

            _handle_serial_uboot_interacting(ctx, queue.Queue())

            mock_tftp_cls.assert_called_once_with(td)
            self.assertEqual(ctx.state, State.REBOOTING)

    @patch("conwrt.handlers_serial.sha256_file", return_value="abc")
    @patch("conwrt.handlers_serial.setup_interface_for_serial")
    @patch("conwrt.handlers_serial.TFTPServerManager")
    def test_empty_tftp_root_prefers_tftpboot_sibling(self, mock_tftp_cls, mock_setup, mock_sha):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            tftpboot = os.path.join(td, "tftpboot")
            os.makedirs(tftpboot)
            image = os.path.join(td, "fw.bin")
            with open(image, "wb") as f:
                f.write(b"fw")
            ctx = _make_ctx(
                state=State.SERIAL_UBOOT_INTERACTING,
                image_path=image,
                tftp_root="",
            )
            mock_driver = MagicMock()
            mock_driver.run_commands.return_value = True
            ctx._serial_driver = mock_driver
            mock_tftp_cls.return_value = MagicMock()

            _handle_serial_uboot_interacting(ctx, queue.Queue())

            mock_tftp_cls.assert_called_once_with(tftpboot)


class TestPyserialImportFallback(TestCase):
    def test_missing_pyserial_falls_back_to_oserror(self):
        import importlib
        import conwrt.handlers_serial as hs
        saved = sys.modules.get("serial")
        try:
            # None in sys.modules makes `from serial import ...` raise ImportError
            with patch.dict(sys.modules, {"serial": None}):
                importlib.reload(hs)
                self.assertIs(hs._SerialException, OSError)
        finally:
            sys.modules.pop("serial", None)
            if saved is not None:
                sys.modules["serial"] = saved
            importlib.reload(hs)
            self.assertIsNot(hs._SerialException, OSError)
