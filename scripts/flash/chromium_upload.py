# pyright: reportAttributeAccessIssue=false
"""Real-Chromium firmware upload for D-Link COVR U-Boot recovery servers.

Why a real browser: the COVR recovery httpd is a one-shot uIP server whose
NAND writer mishandles some non-browser multipart framings — the elimination
matrix in ``models/dlink-covr-x1860-a1.json`` (``bench_observations.
upload_client_sensitivity``) recorded accepted-but-never-boots uploads for
several curl variants, while Chromium-shaped uploads are the proven-accepted
client class. This module drives headless Playwright Chromium.

Two hardening decisions, both paid for on the bench (2026-10-19):

1. **Browser-cache drift is expected, not fatal.** The installed playwright
   package pins a browser build (e.g. ``chromium_headless_shell-1217``)
   while the machine's cache holds whatever another flow installed
   (``-1234``). A bare ``launch()`` then dies with "Executable doesn't
   exist" while the ~5-8 min recovery window burns. ``launch()`` failures
   are retried against the NEWEST usable Chromium in the playwright cache
   (``resolve_chromium_executable``).

2. **The POST is the device's first request.** By default the driver loads
   a LOCAL ``file://`` form whose action targets the recovery endpoint, so
   the multipart POST is the first HTTP request the device ever sees
   (DLINK-RECOVERY-FLASH-RUNBOOK, "Upload with a real Chromium"). The
   ``--direct-page`` mode GETs the device page first instead — observed
   served-and-accepted on two units on 2026-10-19 (see
   ``bench_observations.recovery_page_get_tolerance``), but kept opt-in:
   a first-request POST cannot burn a one-request window.

ARMA note: probe arming by ARP only — never curl the page to check the
window. This module performs no probes of its own.
"""
from __future__ import annotations

import argparse
import glob
import os
import re
import sys
import tempfile
from pathlib import Path

from flash.context import log

# (linux layouts first, then the macOS layouts the fleet used before the
# move to Linux bench hosts; headless-shell is playwright's "new" headless)
_CANDIDATE_GLOBS = [
    "chromium_headless_shell-*/chrome-headless-shell-linux64/chrome-headless-shell",
    "chromium-*/chrome-linux/chrome",
    "chromium_headless_shell-*/chrome-headless-shell-mac/chrome-headless-shell",
    "chromium-*/chrome-mac/Chromium.app/Contents/MacOS/Chromium",
]

_VERSION_RE = re.compile(r"-(\d+)")


def resolve_chromium_executable(cache_dir: str | Path | None = None) -> str | None:
    """Return the NEWEST usable Chromium binary in the playwright cache.

    ``cache_dir`` defaults to ``$PLAYWRIGHT_BROWSERS_PATH`` or
    ``~/.cache/ms-playwright``. "Newest" is by the numeric build suffix in
    the directory name (``chromium-1234`` > ``chromium-999``), so a stale
    pinned package falls forward to whatever the machine actually holds.
    Returns ``None`` when no candidate exists.
    """
    root = Path(cache_dir or os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
                or Path.home() / ".cache" / "ms-playwright")
    best: tuple[tuple[int, ...], str] | None = None
    for pattern in _CANDIDATE_GLOBS:
        for exe in glob.glob(str(root / pattern)):
            if not os.access(exe, os.X_OK):
                continue
            m = _VERSION_RE.search(Path(exe).parent.parent.name)
            version = (int(m.group(1)),) if m else (0,)
            if best is None or version > best[0]:
                best = (version, exe)
    return best[1] if best else None


def build_local_form(endpoint: str, field: str = "firmware") -> str:
    """Build the local HTML form whose submit POSTs to *endpoint*.

    The form lives on the bench host; the device only ever sees the
    multipart POST the browser sends when the submit button is clicked.
    """
    return (
        "<!doctype html><html><head><title>conwrt recovery upload</title></head>"
        "<body><form "
        f'action="{endpoint}" method="post" '
        f'enctype="multipart/form-data">'
        f'<input type="file" name="{field}">'
        '<input type="submit" value="Upload">'
        "</form></body></html>\n"
    )


# The device responds with "Upgrade successfully!" only when it can — most
# POSTs end mid-navigation because flashing starts immediately. A hung
# navigation is therefore NOT proof of acceptance: an idle-dead recovery
# server (window > ~5-8 min since arming) ACCEPTS THE TCP CONNECTION and
# never responds, which looks identical from the browser side (seen live
# 2026-10-19: two "page is navigating" verdicts while the recovery server
# stayed ARP-present — the POSTs never consumed). The only in-band proof
# is a real response body; everything else is PENDING until the caller
# verifies the recovery server VANISHED (ARP for the recovery IP).
_ACCEPTED_MARKERS = (
    "upgrade successfully",
)
_PENDING_MARKERS = (
    "pending-navigation timeout",
    "page is navigating",
    "net::err_aborted",  # server drops the connection once flashing starts
    "click accepted",
)
_WINDOW_DEAD_MARKERS = (
    "net::err_connection_refused",
    "net::err_connection_reset",
    "net::err_address_unreachable",
    "recovery page never loaded",
)


def classify_outcome(transcript: str) -> tuple[bool, str]:
    """Classify an upload transcript into (accepted, verdict).

    ``accepted`` is True only when the device produced a real success
    response. Hang-class endings return False with a PENDING verdict —
    the caller must confirm consumption (recovery server gone from ARP)
    before trusting the upload; an idle-dead window hangs exactly like
    an accepted POST.
    """
    lowered = transcript.lower()
    for marker in _ACCEPTED_MARKERS:
        if marker in lowered:
            return True, f"ACCEPTED ({marker})"
    for marker in _WINDOW_DEAD_MARKERS:
        if marker in lowered:
            return False, f"WINDOW DEAD ({marker})"
    for marker in _PENDING_MARKERS:
        if marker in lowered:
            return False, (
                f"PENDING ({marker}) — navigation hung; indistinguishable from an "
                "accepted POST until the recovery server vanishes. ARP-check the "
                "recovery IP: still present = NOT consumed (idle-dead window)"
            )
    return False, "UNRECOGNIZED — capture a pcap before blaming the client"


def _launch_chromium(p, headless: bool):
    """launch() with fallback to the newest cached browser on drift."""
    from playwright._impl._errors import Error as PlaywrightError
    try:
        return p.chromium.launch(headless=headless)
    except PlaywrightError as first_err:
        exe = resolve_chromium_executable()
        if exe is None:
            raise
        log(f"default browser launch failed ({str(first_err).splitlines()[0][:100]}); "
            f"falling back to cached {exe}")
        return p.chromium.launch(headless=headless, executable_path=exe)


def upload(image_path: str, endpoint: str, field: str = "firmware",
           timeout: int = 300, direct_page: bool = False,
           headless: bool = True) -> tuple[bool, str]:
    """POST *image_path* to the recovery *endpoint* via real Chromium.

    Returns ``(accepted, verdict)`` per :func:`classify_outcome`. Every step
    is logged so the console transcript is the client-side evidence to pair
    with the runbook's pcap rule.
    """
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

    transcript: list[str] = []
    size = os.path.getsize(image_path)
    log(f"Chromium upload: {os.path.basename(image_path)} ({size} bytes) -> {endpoint} "
        f"(mode: {'direct-page' if direct_page else 'local-form'})")

    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as fh:
        fh.write(build_local_form(endpoint, field))
        form_path = fh.name

    try:
        with sync_playwright() as p:
            browser = _launch_chromium(p, headless)
            page = browser.new_page()
            try:
                if direct_page:
                    target = endpoint
                else:
                    target = f"file://{form_path}"
                for attempt in range(1, 6):
                    try:
                        page.goto(target, wait_until="domcontentloaded", timeout=15000)
                        page.wait_for_selector("input[type=file]", timeout=10000)
                        log(f"attempt {attempt}: form ready ({target})")
                        break
                    except Exception as e:  # noqa: BLE001 — retry ladder is the point
                        transcript.append(str(e).splitlines()[0])
                        log(f"attempt {attempt} failed: {str(e)[:110]}")
                else:
                    transcript.append("recovery page never loaded")
                    return classify_outcome("\n".join(transcript))

                page.query_selector("input[type=file]").set_input_files(image_path)
                btn = page.query_selector("input[type=submit], button")
                try:
                    btn.click(timeout=5000)
                    transcript.append("click accepted")
                except PWTimeout:
                    transcript.append("pending-navigation timeout (known behavior)")
                try:
                    page.wait_for_load_state("load", timeout=timeout * 1000)
                    body = page.content()[:200].replace("\n", " ")
                    transcript.append(f"page: {body}")
                except Exception as e:  # noqa: BLE001 — mid-flash endings land here
                    transcript.append(f"post-upload wait: {str(e)[:110]}")
                return classify_outcome("\n".join(transcript))
            finally:
                browser.close()
    finally:
        try:
            os.unlink(form_path)
        except OSError:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("image", help="recovery/factory image to POST")
    parser.add_argument("--endpoint", default="http://192.168.0.1/upload",
                        help="recovery upload endpoint (default: %(default)s)")
    parser.add_argument("--field", default="firmware", help="file input name")
    parser.add_argument("--timeout", type=int, default=300, help="seconds for the upload+wait")
    parser.add_argument("--direct-page", action="store_true",
                        help="GET the device page first instead of a local form "
                             "(burns a request against the one-request window)")
    args = parser.parse_args(argv)
    accepted, verdict = upload(args.image, args.endpoint, args.field,
                               args.timeout, args.direct_page)
    log(f"verdict: {verdict}")
    return 0 if accepted else 1


if __name__ == "__main__":
    sys.exit(main())
