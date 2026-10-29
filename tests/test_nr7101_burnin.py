"""Static contract tests for the NR7101 burn-in payload.

No device, no SSH: `sh -n` parse check on the exact payload text, BusyBox
applet whitelist (the AGENTS.md on-device rules), and report-shape locks
so a payload edit cannot silently drop a section or gate.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from nr7101_burnin import BURNIN_SCRIPT, REQUIRED_KEYS  # noqa: E402

# Applets/commands that do not exist or are forbidden on the target
# (AGENTS.md: BusyBox-only, no chpasswd/hostname; no timeout/jq/od on
# the unit; md5sum banned in favor of sha256).
FORBIDDEN = ("chpasswd", "md5sum", "jq ", "timeout ", "openssl ", "hostname ", "python", "bash")


class TestBurninPayload:
    def test_parses_as_posix_sh(self):
        r = subprocess.run(["sh", "-n"], input=BURNIN_SCRIPT, capture_output=True, text=True, timeout=10)
        assert r.returncode == 0, r.stderr

    def test_no_forbidden_commands(self):
        for banned in FORBIDDEN:
            assert banned not in BURNIN_SCRIPT, f"payload uses {banned!r}"

    def test_sections_present(self):
        for marker in (
            "/dev/ttyUSB2",  # modem AT port (model JSON)
            "AT+GMR",  # modem firmware
            "AT+GSN",  # IMEI
            "AT+QCCID",  # ICCID
            "thermal_zone",  # thermal
            "/sys/class/net/eth0/speed",  # eth
            "sha256sum",  # cpu/ram/flash hashing
            "dmesg",  # health scan
        ):
            assert marker in BURNIN_SCRIPT, f"missing {marker!r}"

    def test_fail_gates_present(self):
        for gate in ("FAIL:modem-absent", "FAIL:ram-", "FAIL:flash-", "FAIL:cpu-degenerate", "FAIL:thermal-"):
            assert gate in BURNIN_SCRIPT, f"missing gate {gate!r}"

    def test_at_reads_are_bounded(self):
        # No timeout applet exists — every AT read must be the
        # background-cat + kill pattern with a bounded sleep.
        assert 'kill "$_cpid"' in BURNIN_SCRIPT
        assert "sleep 2" in BURNIN_SCRIPT
        assert BURNIN_SCRIPT.count("$(_at ") == 7  # ATI,GMR,GSN,QCCID,CSQ,COPS,usbnet

    def test_report_template_has_required_keys(self):
        for key in REQUIRED_KEYS:
            assert f'"{key}"' in BURNIN_SCRIPT, f"report template missing {key!r}"

    def test_payload_single_json_line(self):
        # The host runner parses the LAST '{' line — exactly one printf
        # emits the report.
        assert BURNIN_SCRIPT.count('printf \'{"result"') == 1
