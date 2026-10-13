"""End-to-end harness for the ADB tethering hotplug loop.

Runs the exact inner loop shipped in use_cases/usb_tether.py against a
fully stubbed environment — adb, ip, logger and sleep are fakes on PATH
— so the whole method-ordered retry cycle (svc -> UI automation ->
backoff) executes in milliseconds without a phone, a router, or real
delays. The loop body is extracted verbatim from the generated hotplug
script; only the installer preamble and the backgrounding `( ... ) &`
wrapper are dropped (they write to /etc and detach — neither belongs in
a test).
"""
import os
import stat
import subprocess
import tempfile
import time
from pathlib import Path

from use_cases.usb_tether import _adb_hotplug_script

FIXTURES = Path(__file__).parent / "fixtures"

ADB_STUB = r"""#!/bin/sh
# Fake adb driven by $FAKE_ADB_DIR state files:
#   mode        "legacy" (svc enables tethering) | "ui" (only the tap does) | "dead"
#   ui.xml      the dump served for `uiautomator dump` / `cat`
#   taps.log    every `input tap X Y` (appended)
STATE="$FAKE_ADB_DIR"
MODE=$(cat "$STATE/mode" 2>/dev/null || echo ui)

if [ "$1" = "get-state" ]; then
    [ "$MODE" = "dead" ] && exit 1
    echo device
    exit 0
fi

if [ "$1" = "shell" ]; then
    CMD="$2 $3"
    case "$CMD" in
        svc*)
            # Acknowledge like a real phone; on Android 14+ it is a no-op.
            if [ "$MODE" = "legacy" ]; then
                echo enabled > "$STATE/tethered"
            fi
            echo "setCurrentFunctions opId:1"
            ;;
        uiautomator*)
            echo "UI hierarchy dumped to: /sdcard/ui.xml"
            ;;
        cat\ *)
            cat "$STATE/ui.xml"
            ;;
        am\ *|*keyevent*)
            ;;
        "input tap"*)
            echo "$4 $5" >> "$STATE/taps.log"
            # The toggle lives at the coordinates the pipeline computes.
            if [ "$4 $5" = "1005 678" ]; then
                echo enabled > "$STATE/tethered"
            fi
            ;;
    esac
    exit 0
fi
exit 0
"""

IP_STUB = r"""#!/bin/sh
# `ip addr show usb0` reports an address only once tethered (state file).
if [ "$1" = "addr" ] && [ "$3" = "usb0" ]; then
    if [ -f "$FAKE_ADB_DIR/tethered" ]; then
        echo "6: usb0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500"
        echo "    inet 192.168.42.2/24 brd 192.168.42.255 scope global usb0"
    fi
fi
exit 0
"""

LOGGER_STUB = r"""#!/bin/sh
echo "$*" >> "$FAKE_ADB_DIR/logger.log"
exit 0
"""

SLEEP_STUB = "#!/bin/sh\nexit 0\n"


def _write_stub(dirpath: Path, name: str, content: str) -> None:
    p = dirpath / name
    p.write_text(content)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)


def _hotplug_loop_body() -> str:
    src = _adb_hotplug_script()
    inner = src.split("<< 'HOTPLUG_EOF'\n", 1)[1].split("\nHOTPLUG_EOF", 1)[0]
    lines = inner.splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.strip() == "(")
    end = next(i for i, ln in enumerate(lines) if ln.strip() == ") &")
    # Drop the `(` / `) &` wrapper: run the body in the foreground.
    body = "\n".join(lines[start + 1 : end])
    assert "svc usb setFunctions" in body
    assert "uiautomator dump" in body
    return body + "\n"


def _run_hotplug(mode: str, timeout_s: float = 10.0) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="adb-harness-"))
    stubs = tmp / "stubs"
    state = tmp / "state"
    stubs.mkdir()
    state.mkdir()
    _write_stub(stubs, "adb", ADB_STUB)
    _write_stub(stubs, "ip", IP_STUB)
    _write_stub(stubs, "logger", LOGGER_STUB)
    _write_stub(stubs, "sleep", SLEEP_STUB)
    (state / "mode").write_text(mode)
    (state / "ui.xml").write_text(
        (FIXTURES / "ui_dump_tether_settings.xml").read_text()
    )
    loop = tmp / "loop.sh"
    loop.write_text(_hotplug_loop_body())

    env = dict(os.environ)
    env["PATH"] = f"{stubs}:{env['PATH']}"
    env["FAKE_ADB_DIR"] = str(state)
    env["ACTION"] = "bind"
    env["PRODUCT"] = "18d1/4ee7/5200"

    def out(name: str) -> str:
        p = state / name
        return p.read_text().strip() if p.exists() else ""

    proc = subprocess.run(
        ["/bin/sh", str(loop)], env=env, capture_output=True, text=True,
        timeout=timeout_s,
    )
    return {
        "rc": proc.returncode,
        "stderr": proc.stderr,
        "taps": out("taps.log"),
        "log": out("logger.log"),
        "tethered": out("tethered"),
    }


class TestHotplugLoop:
    def test_android15_ui_toggle_path(self):
        # svc is a no-op (Android 14+); the UI-automation tap enables usb0.
        r = _run_hotplug("ui")
        assert r["rc"] == 0, r["stderr"]
        assert r["tethered"] == "enabled"
        assert r["taps"] == "1005 678", r["taps"]
        assert "ADB UI toggle enabled tethering (attempt 1)" in r["log"]
        assert "gave up" not in r["log"]

    def test_legacy_android_svc_path(self):
        # svc works (Android <= 12): no tap, no UI automation needed.
        r = _run_hotplug("legacy")
        assert r["rc"] == 0, r["stderr"]
        assert r["tethered"] == "enabled"
        assert r["taps"] == ""
        assert "ADB svc enabled tethering (attempt 1)" in r["log"]
        assert "ADB UI toggle" not in r["log"]

    def test_gives_up_after_seven_attempts_when_device_dead(self):
        r = _run_hotplug("dead")
        assert r["rc"] == 0, r["stderr"]
        assert r["tethered"] == ""
        assert r["taps"] == ""
        assert "gave up after 7 attempts" in r["log"]
