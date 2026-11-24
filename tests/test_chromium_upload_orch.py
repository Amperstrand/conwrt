"""Tests for chromium_upload's orchestration + CLI wiring (#794 lane 1).

The existing test_chromium_upload.py covers the pure helpers
(finder/form/classify); this adds the retry loop, temp-file hygiene,
and main() exit codes — via an injected fake playwright module, no
Chromium, no network, no device.
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

from flash import chromium_upload


class _FakePage:
    def __init__(self, goto_error=None):
        self._goto_error = goto_error
        self.goto_calls = 0

    def goto(self, *a, **kw):
        self.goto_calls += 1
        if self._goto_error:
            raise self._goto_error

    def wait_for_selector(self, *a, **kw):
        raise RuntimeError("no form")

    def query_selector(self, *a, **kw):
        return None

    def content(self):
        return "<html></html>"

    def wait_for_load_state(self, *a, **kw):
        return None


class _FakeBrowser:
    def __init__(self, page):
        self.page = page

    def new_page(self):
        return self.page

    def close(self):
        pass


class _FakeChromium:
    def __init__(self, page):
        self._page = page

    def launch(self, headless=True, executable_path=None):
        return _FakeBrowser(self._page)


class _FakePlaywrightCtx:
    def __init__(self, page):
        self.chromium = _FakeChromium(page)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _inject_fake_playwright(monkeypatch, page):
    """Inject a playwright module whose sync_playwright() yields the fake.

    upload() imports `playwright.sync_api` and _launch_chromium imports
    `playwright._impl._errors` INSIDE the function — both must exist in
    sys.modules before the call.
    """
    mod = types.ModuleType("playwright")
    sync_api = types.ModuleType("playwright.sync_api")
    sync_api.sync_playwright = lambda: _FakePlaywrightCtx(page)
    sync_api.TimeoutError = type("PWTimeout", (Exception,), {})
    errors = types.ModuleType("playwright._impl._errors")
    errors.Error = type("PlaywrightError", (Exception,), {})
    mod.sync_api = sync_api
    monkeypatch.setitem(sys.modules, "playwright", mod)
    monkeypatch.setitem(sys.modules, "playwright.sync_api", sync_api)
    monkeypatch.setitem(sys.modules, "playwright._impl._errors", errors)


class TestUploadRetryLoop:
    def test_page_never_loading_gives_up_after_five(self, tmp_path, monkeypatch):
        img = tmp_path / "fw.bin"
        img.write_bytes(b"IMG")
        page = _FakePage(goto_error=RuntimeError("refused"))
        _inject_fake_playwright(monkeypatch, page)
        accepted, verdict = chromium_upload.upload(str(img), "http://192.168.0.1/")
        assert not accepted
        assert page.goto_calls == 5  # the documented retry budget
        assert "never loaded" in verdict.lower() or "refused" in verdict.lower()

    def test_temp_form_file_is_cleaned_up(self, tmp_path, monkeypatch):
        img = tmp_path / "fw.bin"
        img.write_bytes(b"IMG")
        before = set(Path("/tmp").glob("*.html"))
        _inject_fake_playwright(monkeypatch, _FakePage(goto_error=RuntimeError("x")))
        chromium_upload.upload(str(img), "http://192.168.0.1/")
        after = set(Path("/tmp").glob("*.html"))
        leaked = after - before
        assert not leaked, f"temp form leaked: {leaked}"

    def test_direct_page_mode_targets_the_endpoint(self, tmp_path, monkeypatch):
        img = tmp_path / "fw.bin"
        img.write_bytes(b"IMG")
        seen = {}

        class _Page(_FakePage):
            def goto(self, target, *a, **kw):
                seen["target"] = target
                raise RuntimeError("no page")

        _inject_fake_playwright(monkeypatch, _Page(goto_error=None))
        chromium_upload.upload(str(img), "http://192.168.0.1/", direct_page=True)
        assert seen["target"] == "http://192.168.0.1/"


class TestMain:
    def test_exit_zero_on_accepted(self, monkeypatch, capsys):
        monkeypatch.setattr(chromium_upload, "upload",
                            lambda *a, **kw: (True, "accepted"))
        assert chromium_upload.main(["img.bin", "--endpoint", "http://x/"]) == 0
        assert "accepted" in capsys.readouterr().out

    def test_exit_one_on_rejected(self, monkeypatch):
        monkeypatch.setattr(chromium_upload, "upload",
                            lambda *a, **kw: (False, "pending"))
        assert chromium_upload.main(["img.bin"]) == 1

    def test_args_pass_through(self, monkeypatch):
        calls = {}

        def fake_upload(image, endpoint, field, timeout, direct_page):
            calls.update(image=image, endpoint=endpoint, field=field,
                         timeout=timeout, direct_page=direct_page)
            return True, "ok"

        monkeypatch.setattr(chromium_upload, "upload", fake_upload)
        chromium_upload.main(["fw.bin", "--endpoint", "http://192.168.0.2/",
                              "--field", "upload", "--timeout", "42",
                              "--direct-page"])
        assert calls == dict(image="fw.bin", endpoint="http://192.168.0.2/",
                             field="upload", timeout=42, direct_page=True)
