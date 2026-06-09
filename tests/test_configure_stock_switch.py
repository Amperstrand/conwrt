import importlib.util
import sys
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock, patch


_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS))


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "configure_stock_switch",
        _SCRIPTS / "configure-stock-switch.py",
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["configure_stock_switch"] = module
    spec.loader.exec_module(module)
    return module


css = _load_module()


def _frame(url):
    f = MagicMock()
    f.url = url
    return f


def _page(frame_urls, main_url=None):
    p = MagicMock()
    p.frames = [_frame(u) for u in frame_urls]
    main = _frame(main_url) if main_url else (p.frames[0] if p.frames else _frame(""))
    p.main_frame = main
    return p


class TestWaitForFrameUrlFound(TestCase):
    @patch("configure_stock_switch.time.sleep")
    @patch("configure_stock_switch.time.time")
    def test_returns_matching_frame(self, mock_time, mock_sleep):
        mock_time.return_value = 0.0
        page = _page(["http://x/cgi-bin/dispatcher.cgi?cmd=30"])
        result = css._wait_for_frame_url(page, "30", timeout=1)
        self.assertIsNotNone(result)
        self.assertIn("cmd=30", result.url)

    @patch("configure_stock_switch.time.sleep")
    @patch("configure_stock_switch.time.time")
    def test_returns_first_match_among_many(self, mock_time, mock_sleep):
        mock_time.return_value = 0.0
        page = _page([
            "http://x/cgi-bin/dispatcher.cgi?cmd=0",
            "http://x/cgi-bin/dispatcher.cgi?cmd=1",
            "http://x/cgi-bin/dispatcher.cgi?cmd=30",
        ])
        result = css._wait_for_frame_url(page, "1", timeout=1)
        self.assertIsNotNone(result)
        self.assertIn("cmd=1", result.url)


class TestWaitForFrameUrlTimeout(TestCase):
    @patch("configure_stock_switch.time.sleep")
    @patch("configure_stock_switch.time.time")
    def test_returns_none_when_no_match(self, mock_time, mock_sleep):
        # First call sets deadline; subsequent calls exceed it
        mock_time.side_effect = [0.0, 0.0, 100.0]
        page = _page(["http://x/cgi-bin/dispatcher.cgi?cmd=0"])
        result = css._wait_for_frame_url(page, "999", timeout=1)
        self.assertIsNone(result)

    @patch("configure_stock_switch.time.sleep")
    @patch("configure_stock_switch.time.time")
    def test_empty_frames_returns_none(self, mock_time, mock_sleep):
        mock_time.side_effect = [0.0, 0.0, 100.0]
        page = _page([])
        page.main_frame = _frame("")
        result = css._wait_for_frame_url(page, "1", timeout=1)
        self.assertIsNone(result)


class TestFindContentFrame(TestCase):
    def test_returns_frame_with_cmd_not_zero(self):
        page = _page([
            "http://x/cgi-bin/dispatcher.cgi?cmd=0",
            "http://x/cgi-bin/dispatcher.cgi?cmd=1",
            "http://x/cgi-bin/dispatcher.cgi?cmd=516",
        ])
        result = css._find_content_frame(page)
        # First matching: cmd=1
        self.assertIn("cmd=1", result.url)

    def test_single_frame_returns_main(self):
        page = MagicMock()
        single = _frame("http://x/login.html")
        page.frames = [single]
        page.main_frame = single
        result = css._find_content_frame(page)
        self.assertIs(result, single)

    def test_only_cmd_zero_frames_falls_back_to_index_1(self):
        page = _page([
            "http://x/cgi-bin/dispatcher.cgi?cmd=0",
            "http://x/cgi-bin/dispatcher.cgi?cmd=0",
        ])
        result = css._find_content_frame(page)
        self.assertIs(result, page.frames[1])

    def test_zero_frames_returns_main_frame(self):
        page = MagicMock()
        page.frames = []
        main = _frame("http://x/")
        page.main_frame = main
        result = css._find_content_frame(page)
        self.assertIs(result, main)

    def test_prefers_cmd_n_over_cmd_zero(self):
        page = _page([
            "http://x/cgi-bin/dispatcher.cgi?cmd=0",
            "http://x/cgi-bin/dispatcher.cgi?cmd=30",
        ])
        result = css._find_content_frame(page)
        self.assertIn("cmd=30", result.url)


class TestDoLogin(TestCase):
    def test_fills_username_password_and_calls_login_js(self):
        frame = MagicMock()
        username_loc = MagicMock()
        password_loc = MagicMock()
        frame.locator.side_effect = lambda sel: {
            "#username": username_loc,
            "#password": password_loc,
        }[sel]

        css._do_login(frame, "secret123")

        username_loc.fill.assert_called_once_with("admin")
        password_loc.fill.assert_called_once_with("secret123")
        frame.evaluate.assert_called_once_with("login()")

    def test_locator_called_with_id_selectors(self):
        frame = MagicMock()
        css._do_login(frame, "pw")
        selectors = [c.args[0] for c in frame.locator.call_args_list]
        self.assertIn("#username", selectors)
        self.assertIn("#password", selectors)


class TestMainArgparse(TestCase):
    """argparse defaults can be exercised without driving Playwright."""

    @patch("configure_stock_switch.sync_playwright")
    def test_unknown_flag_exits(self, mock_pw):
        argv = ["configure-stock-switch.py", "--bogus"]
        with patch.object(sys, "argv", argv):
            with self.assertRaises(SystemExit):
                css.main()


class TestMainHappyPath(TestCase):
    """Heavily mocked happy-ish path through main()."""

    @patch("configure_stock_switch.time.sleep")
    @patch("configure_stock_switch.sync_playwright")
    def test_main_runs_with_password_change_path(self, mock_pw, mock_sleep):
        # Build mock browser/page chain
        ctx = MagicMock()
        mock_pw.return_value.__enter__.return_value = ctx
        browser = MagicMock()
        ctx.chromium.launch.return_value = browser
        page = MagicMock()
        browser.new_page.return_value = page

        # Initial login frame
        login_frame = MagicMock()
        login_frame.url = "http://192.168.1.1/cgi-bin/dispatcher.cgi?cmd=0"
        page.main_frame = login_frame

        # Frames after login: include cmd=30 (password change required)
        pw_frame = MagicMock()
        pw_frame.url = "http://x/cgi-bin/dispatcher.cgi?cmd=30"
        dash_frame = MagicMock()
        dash_frame.url = "http://x/cgi-bin/dispatcher.cgi?cmd=1"
        content_frame = MagicMock()
        content_frame.url = "http://x/cgi-bin/dispatcher.cgi?cmd=516"

        # _wait_for_frame_url() iterates page.frames; provide them
        page.frames = [login_frame, pw_frame, dash_frame, content_frame]

        # Mock content frame methods used after navigation
        content_frame.content.return_value = "<html>" + "x" * 1000 + "</html>"
        ip_field_loc = MagicMock()
        ip_field_loc.count.return_value = 1
        ip_field_loc.first.input_value.return_value = "192.168.1.1"

        # Locator returns ip_field_loc for first IP name, empty for others
        def locator_side_effect(sel):
            loc = MagicMock()
            if 'sysIpAddr' in sel:
                return ip_field_loc
            elif 'input[name=' in sel:
                # Subnet/gateway fields return empty
                empty = MagicMock()
                empty.count.return_value = 0
                return empty
            # "input" generic locator
            loc.count.return_value = 0
            return loc

        content_frame.locator.side_effect = locator_side_effect

        # evaluate() is called three different ways during main()
        def evaluate_side_effect(*args, **kwargs):
            if len(args) == 1 and args[0] == "typeof submitForm":
                return "function"
            if len(args) == 1 and args[0] == "submitForm()":
                return None
            # save-command loop: arrow function + cmd int → expects dict result
            return {"status": 200, "len": 100, "text": "ok"}

        content_frame.evaluate.side_effect = evaluate_side_effect

        # File write: target /tmp
        argv = [
            "configure-stock-switch.py",
            "--ip", "192.168.1.1",
            "--password", "1234",
            "--new-password", "newpass",
            "--new-ip", "192.168.13.3",
        ]
        # Skip writing to /tmp during test
        with patch("builtins.open", create=True):
            with patch.object(sys, "argv", argv):
                # Patch _find_content_frame to return our content_frame deterministically
                with patch("configure_stock_switch._find_content_frame", return_value=content_frame):
                    # _wait_for_frame_url returns pw_frame then dash_frame
                    with patch(
                        "configure_stock_switch._wait_for_frame_url",
                        side_effect=[pw_frame, dash_frame],
                    ):
                        result = css.main()
        self.assertTrue(result)
        browser.close.assert_called_once()

    @patch("configure_stock_switch.time.sleep")
    @patch("configure_stock_switch.sync_playwright")
    def test_main_returns_false_when_no_ip_field_found(self, mock_pw, mock_sleep):
        ctx = MagicMock()
        mock_pw.return_value.__enter__.return_value = ctx
        browser = MagicMock()
        ctx.chromium.launch.return_value = browser
        page = MagicMock()
        browser.new_page.return_value = page

        login_frame = MagicMock()
        login_frame.url = "http://192.168.1.1/"
        page.main_frame = login_frame

        content_frame = MagicMock()
        content_frame.url = "http://x/cgi-bin/dispatcher.cgi?cmd=516"
        content_frame.content.return_value = "<html>" + "x" * 1000 + "</html>"
        page.frames = [login_frame, content_frame]

        # All locator queries return zero count (no IP field anywhere)
        empty_loc = MagicMock()
        empty_loc.count.return_value = 0
        content_frame.locator.return_value = empty_loc

        argv = ["configure-stock-switch.py"]
        with patch("builtins.open", create=True):
            with patch.object(sys, "argv", argv):
                with patch(
                    "configure_stock_switch._find_content_frame",
                    return_value=content_frame,
                ):
                    with patch(
                        "configure_stock_switch._wait_for_frame_url",
                        side_effect=[None, None],
                    ):
                        result = css.main()
        self.assertFalse(result)
        browser.close.assert_called_once()
