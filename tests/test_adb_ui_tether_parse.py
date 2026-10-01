"""Behavioral tests for the ADB UI-automation parsing pipeline.

The hotplug script in use_cases/usb_tether.py extracts the tap point for
the "USB tethering" switch from a uiautomator XML dump with a pure-grep
pipeline. These tests run that exact pipeline against fixture dumps and
assert the extracted coordinates — guarding against regex drift that
marker-string tests cannot catch.

The pipeline relies on a layout invariant field-verified on Pixel 10 /
Android 15: the Switch widget's top edge sits 28px below the row text's
top edge, and its horizontal center is ~65px right of the widget's left
edge. The fixtures model that invariant plus decoy switches.
"""
import subprocess
from pathlib import Path

from use_cases.usb_tether import _adb_hotplug_script

FIXTURES = Path(__file__).parent / "fixtures"

PIPELINE = r"""
UI=$(cat "$1")
USB_ROW=$(echo "$UI" | grep -oE 'USB.tethering[^>]*bounds="\[[0-9]+,[0-9]+' | grep -oE '[0-9]+,[0-9]+' | head -1)
USB_Y=$(echo "$USB_ROW" | cut -d, -f2)
if [ -n "$USB_Y" ]; then
    USB_Y_CENTER=$((USB_Y + 28))
    SWITCH=$(echo "$UI" | grep -oE "Switch[^>]*bounds=\"\[[0-9]+,${USB_Y_CENTER}" | grep -oE '\[[0-9]+,' | grep -oE '[0-9]+' | head -1)
    if [ -n "$SWITCH" ]; then
        SWITCH_CENTER=$((SWITCH + 65))
        echo "$SWITCH_CENTER $USB_Y_CENTER"
    else
        echo "no-switch"
    fi
else
    echo "no-row"
fi
"""


def _run_pipeline(dump: str) -> str:
    proc = subprocess.run(
        ["/bin/sh", "-c", PIPELINE, "sh", dump],
        capture_output=True, text=True, timeout=10,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def _assert_pipeline_shipped():
    # The pipeline above must stay in lockstep with the generated hotplug
    # script — if the shipped greps change without updating this test
    # (or vice versa), fail loudly.
    script = _adb_hotplug_script()
    for shipped in (
        "grep -oE 'USB.tethering[^>]*bounds=\"\\[[0-9]+,[0-9]+'",
        'grep -oE "Switch[^>]*bounds=\\"\\[[0-9]+,${USB_Y_CENTER}"',
        "USB_Y_CENTER=$((USB_Y + 28))",
        "SWITCH_CENTER=$((SWITCH + 65))",
    ):
        assert shipped in script, f"pipeline drifted from hotplug script: {shipped}"


class TestUsbTetherSwitchExtraction:
    def test_tether_settings_dump_taps_the_usb_switch(self):
        _assert_pipeline_shipped()
        dump = str(FIXTURES / "ui_dump_tether_settings.xml")
        # Row text at y=650 -> tap y = 650+28 = 678; the USB switch sits at
        # x=940 (y=678), the Bluetooth switch decoy at y=533 must not match.
        assert _run_pipeline(dump) == "1005 678"

    def test_dump_without_usb_row_reports_no_row(self):
        empty = Path(subprocess.run(
            ["mktemp"], capture_output=True, text=True
        ).stdout.strip())
        try:
            empty.write_text("<hierarchy><node class='x' bounds='[0,0][10,10]'/></hierarchy>")
            assert _run_pipeline(str(empty)) == "no-row"
        finally:
            empty.unlink()

    def test_dump_without_matching_switch_reports_no_switch(self):
        # Row present but no Switch aligned at row_y+28 (the layout
        # invariant broke) — must not tap a wrong-coordinate switch.
        misaligned = Path(subprocess.run(
            ["mktemp"], capture_output=True, text=True
        ).stdout.strip())
        try:
            misaligned.write_text(
                '<node text="USB tethering" class="android.widget.TextView" bounds="[36,650][700,700]"/>'
                '<node class="android.widget.Switch" bounds="[940,700][1020,748]"/>'
            )
            assert _run_pipeline(str(misaligned)) == "no-switch"
        finally:
            misaligned.unlink()
