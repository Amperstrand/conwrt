"""Driver-level tests for chromium_upload.upload() (#794).

The form/classify/resolve layers are covered (test_chromium_upload.py);
this drives upload() end-to-end with an injected FAKE playwright module
(the real one is not installed on this host — and unit tests must not
launch browsers anyway). Matrix: happy accept, click-timeout PENDING,
form-never-loads WINDOW DEAD, direct-page mode, and file hygiene.
"""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

spec = importlib.util.spec_from_file_location(
    "chromium_upload", ROOT / "scripts" / "flash" / "chromium_upload.py")
cu = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cu)


class FakePlaywrightError(Exception):
    pass


class FakeTimeout(Exception):
    """Raised where the real playwright raises its TimeoutError.

    Deliberately message-less for some raises: the driver's
    transcript.append(str(e).splitlines()[0]) crashed on empty messages
    (latent bug, found by this suite) — the bare-raise case pins the fix.
    """
    def __init__(self, msg=None):
        super().__init__(msg or "")


class FakeElement:
    def __init__(self, recorder, name):
        self._r = recorder
        self._name = name

    def set_input_files(self, path):
        self._r.append(("set_input_files", self._name, path))

    def click(self, timeout=None):
        self._r.append(("click", self._name))
        if self._r.opts.get("click_times_out"):
            raise FakeTimeout()

    def query_selector(self, sel):  # page-level convenience
        return FakeElement(self._r, sel)


class FakePage:
    def __init__(self, recorder):
        self._r = recorder

    def goto(self, target, wait_until=None, timeout=None):
        self._r.append(("goto", target))
        if self._r.opts.get("goto_fails"):
            raise FakePlaywrightError("net::ERR_CONNECTION_REFUSED")

    def wait_for_selector(self, sel, timeout=None):
        if self._r.opts.get("form_never_loads"):
            raise FakeTimeout()
        return FakeElement(self._r, sel)

    def query_selector(self, sel):
        return FakeElement(self._r, sel)

    def wait_for_load_state(self, state, timeout=None):
        if self._r.opts.get("load_never_completes"):
            raise FakeTimeout("load timeout")

    def content(self):
        return self._r.opts.get("page_content", "Firmware upgrade successfully!")


class FakeBrowser:
    def __init__(self, recorder):
        self._r = recorder

    def new_page(self):
        return FakePage(self._r)

    def close(self):
        self._r.append(("browser_close",))


class Recorder:
    def __init__(self, **opts):
        self.events = []
        self.opts = opts

    def append(self, ev):
        self.events.append(ev)

    def of(self, kind):
        return [e for e in self.events if e[0] == kind]


@pytest.fixture()
def fake_pw(monkeypatch):
    """Inject a fake playwright.sync_api into sys.modules; upload() imports
    it inside the function, so the fake is picked up without the real dep."""

    def _install(**opts):
        rec = Recorder(**opts)
        sync_api = types.ModuleType("playwright.sync_api")
        sync_api.sync_playwright = lambda: _Ctx(rec)
        sync_api.TimeoutError = FakeTimeout
        # _launch_chromium also imports playwright._impl._errors.Error —
        # fake the whole package surface upload() can touch
        impl = types.ModuleType("playwright._impl")
        errors = types.ModuleType("playwright._impl._errors")
        errors.Error = FakePlaywrightError
        impl._errors = errors
        pw = types.ModuleType("playwright")
        pw.sync_api = sync_api
        pw._impl = impl
        monkeypatch.setitem(sys.modules, "playwright", pw)
        monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)
        monkeypatch.setitem(sys.modules, "playwright._impl", impl)
        monkeypatch.setitem(sys.modules, "playwright._impl._errors", errors)
        return rec

    class _Ctx:
        def __init__(self, rec):
            self._rec = rec

        def __enter__(self):
            return types.SimpleNamespace(
                chromium=types.SimpleNamespace(
                    launch=lambda **kw: FakeBrowser(self._rec)))

        def __exit__(self, *a):
            return False

    return _install


@pytest.fixture()
def image(tmp_path):
    p = tmp_path / "fw.bin"
    p.write_bytes(b"\x5A" * 512)
    return str(p)


class TestUploadDriver:
    def test_happy_path_accepted(self, fake_pw, image):
        rec = fake_pw()
        ok, verdict = cu.upload(image, "http://192.168.0.1/upload")
        assert ok, verdict
        assert "ACCEPTED" in verdict and "upgrade successfully" in verdict
        # the local-form mode navigated to a file:// URL, then submitted
        targets = [e[1] for e in rec.of("goto")]
        assert targets[0].startswith("file://")
        assert "conwrt-bundle" not in targets[0]
        # the image reached the file input; the submit button was clicked
        setf = [e for e in rec.of("set_input_files") if e[1] == "input[type=file]"]
        assert setf and setf[0][2] == image
        assert rec.of("click")
        assert rec.of("browser_close")

    def test_click_timeout_with_hung_load_is_pending(self, fake_pw, image):
        # click times out AND the page never completes loading — the
        # known-behavior hang class: PENDING, never accepted
        fake_pw(click_times_out=True, load_never_completes=True,
                page_content="")
        ok, verdict = cu.upload(image, "http://192.168.0.1/upload")
        assert not ok
        assert "PENDING" in verdict and "pending-navigation timeout" in verdict

    def test_click_timeout_with_success_page_is_accepted(self, fake_pw, image):
        # CURRENT-SEMANTICS PIN: a successful response body outranks the
        # click-timeout marker (the only in-band proof of consumption)
        fake_pw(click_times_out=True)
        ok, verdict = cu.upload(image, "http://192.168.0.1/upload")
        assert ok and "ACCEPTED" in verdict

    def test_form_never_loads_is_window_dead(self, fake_pw, image):
        fake_pw(form_never_loads=True)
        ok, verdict = cu.upload(image, "http://192.168.0.1/upload")
        assert not ok and "WINDOW DEAD" in verdict
        assert "recovery page never loaded" in verdict

    def test_direct_page_mode_targets_endpoint(self, fake_pw, image):
        rec = fake_pw()
        ok, _ = cu.upload(image, "http://192.168.0.1/upload",
                          direct_page=True)
        assert ok
        targets = [e[1] for e in rec.of("goto")]
        assert targets[0] == "http://192.168.0.1/upload"

    def test_load_timeout_falls_to_transcript(self, fake_pw, image):
        fake_pw(load_never_completes=True)
        ok, verdict = cu.upload(image, "http://192.168.0.1/upload")
        assert not ok
        # the wait failure is transcripted; the accepted marker in
        # content() is NOT reachable — pending/unknown verdict, never ok
        assert "ACCEPTED" not in verdict

    def test_form_file_is_cleaned_up(self, fake_pw, image, tmp_path):
        before = set(Path("/tmp").glob("*.html"))
        fake_pw()
        cu.upload(image, "http://192.168.0.1/upload")
        after = set(Path("/tmp").glob("*.html"))
        # no form html litter from THIS run (pre-existing files untouched)
        new = {p for p in after - before}
        assert not new, f"form file leaked: {new}"

    def test_retries_goto_then_gives_up(self, fake_pw, image):
        rec = fake_pw(goto_fails=True)
        ok, verdict = cu.upload(image, "http://192.168.0.1/upload")
        assert not ok
        # five load attempts before "recovery page never loaded"
        assert len(rec.of("goto")) == 5
