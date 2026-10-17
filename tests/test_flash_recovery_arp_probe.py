"""flash-recovery.sh arming-detection tests (runbook §8 reg#1).

Shells the real script against a hermetic fake repo with stubbed
``ip``/``ping``/``curl``/``sudo``/``python3``/``sleep`` on PATH. The safety
contract under test: on one-request recovery servers (D-Link COVR x1860
class) the script must NEVER issue an HTTP GET — arming is detected from the
ARP neighbor table only. FORCE_HTTP_PROBE=1 (without DRY_RUN) restores the
legacy GET probe for multi-request server classes (GL.iNet).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "flash-recovery.sh"

RECOVERY_IP = "192.168.0.1"
SOFT_MAC = "3e:85:be:87:55:42"

# ip neigh states that count as armed (MAC present + live-ish state).
ARMED_STATES = ["REACHABLE", "STALE", "DELAY", "PROBE"]
NOT_ARMED_LINES = [
    f"{RECOVERY_IP} dev lo INCOMPLETE",
    f"{RECOVERY_IP} dev lo lladdr {SOFT_MAC} FAILED",
    f"{RECOVERY_IP} dev lo lladdr {SOFT_MAC} PERMANENT",  # static entry, not ARP-resolved
    "",
]

_STUBS = {
    "sudo": """#!/bin/sh
if [ "$1" = "-v" ] || { [ "$1" = "-n" ] && [ "$2" = "true" ]; }; then
  exit 0
fi
exec "$@"
""",
    "python3": """#!/bin/sh
# model_recovery / conwrt handoff — succeed with the test IPs (or py.reply content).
printf '%s\\n' "$*" >> "${STUB_LOGS}/python3.args"
if [ -s "${STUB_LOGS}/py.reply" ]; then cat "${STUB_LOGS}/py.reply"; else echo "192.168.0.1 192.168.0.10"; fi
exit 0
""",
    "ip": """#!/bin/sh
printf 'ip %s\\n' "$*" >> "${STUB_LOGS}/ip.args"
case "$*" in
  *"neigh show"*) cat "${STUB_LOGS}/neigh.reply" 2>/dev/null ;;
esac
exit 0
""",
    "ping": """#!/bin/sh
printf 'ping %s\\n' "$*" >> "${STUB_LOGS}/ping.args"
# The recovery server never answers ICMP — the ping only solicits ARP.
exit 1
""",
    "curl": """#!/bin/sh
printf 'curl %s\\n' "$*" >> "${STUB_LOGS}/curl.args"
cat "${STUB_LOGS}/curl.reply" 2>/dev/null
exit 0
""",
    "sleep": """#!/bin/sh
exit 0
""",
}

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux")
    or not Path("/sys/class/net/lo").exists()
    or not shutil.which("bash"),
    reason="needs Linux /sys/class/net and bash",
)


@pytest.fixture()
def rig(tmp_path: Path):
    """Fake conwrt checkout + stubbed binaries. Yields run()/lines()/set_neigh_reply()."""

    def set_neigh_reply(line: str) -> None:
        (tmp_path / "logs" / "neigh.reply").write_text(line + "\n" if line else "")

    def set_curl_reply(body: str) -> None:
        (tmp_path / "logs" / "curl.reply").write_text(body)

    def set_py_reply(line: str) -> None:
        # Always non-empty file (stub's -s gate) — an empty line means "no IPs".
        (tmp_path / "logs" / "py.reply").write_text(line + "\n" if line else "\n")

    fake_repo = tmp_path / "repo"
    (fake_repo / "scripts").mkdir(parents=True)
    (fake_repo / "models").mkdir()
    (fake_repo / "scripts" / "conwrt.py").touch()
    shutil.copy2(SCRIPT, fake_repo / "scripts" / "flash-recovery.sh")

    bin_dir = tmp_path / "bin"
    logs_dir = tmp_path / "logs"
    bin_dir.mkdir()
    logs_dir.mkdir()
    for name, body in _STUBS.items():
        stub = bin_dir / name
        stub.write_text(body)
        stub.chmod(0o755)
    set_neigh_reply("")

    def run(env_extra: dict[str, str], stdin: str | None = None) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "STUB_LOGS": str(logs_dir),
        }
        env.update(env_extra)
        return subprocess.run(
            ["bash", str(fake_repo / "scripts" / "flash-recovery.sh"), "test-model", "lo"],
            input=stdin if stdin is not None else "",  # EOF at any prompt — never block on a tty
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
            check=False,
        )

    def lines(log: str) -> list[str]:
        path = logs_dir / f"{log}.args"
        return path.read_text().splitlines() if path.exists() else []

    return SimpleNamespace(
        run=run, lines=lines, set_neigh_reply=set_neigh_reply,
        set_curl_reply=set_curl_reply, set_py_reply=set_py_reply,
    )


@pytest.mark.parametrize("state", ARMED_STATES)
def test_arp_armed_never_gets(rig, state):
    """ARP entry with MAC in an armed state => armed verdict, zero HTTP requests."""
    rig.set_neigh_reply(f"{RECOVERY_IP} dev lo lladdr {SOFT_MAC} {state}")
    out = rig.run({"DRY_RUN": "1"})
    assert out.returncode == 0, out.stdout + out.stderr
    assert f"Recovery server armed (ARP {state} {SOFT_MAC})" in out.stdout
    assert "DRY_RUN=1 — probe done; not flashing." in out.stdout
    assert rig.lines("curl") == []  # the one-request window is never burned
    assert rig.lines("ping"), "ARP must be solicited (ping) at least once"
    ip_calls = rig.lines("ip")
    assert any("neigh del" in c for c in ip_calls), "stale neighbor entry must be flushed first"
    del_idx = next(i for i, c in enumerate(ip_calls) if "neigh del" in c)
    show_idx = next(i for i, c in enumerate(ip_calls) if "neigh show" in c)
    assert del_idx < show_idx
    assert any("route del" in c for c in ip_calls), "net_down cleanup must run after the probe"


@pytest.mark.parametrize("neigh_line", NOT_ARMED_LINES, ids=lambda line: line or "empty")
def test_arp_not_armed_aborts_without_get(rig, neigh_line):
    """No armed ARP entry => warn + prompt; empty stdin aborts; still zero GETs."""
    rig.set_neigh_reply(neigh_line.strip())
    out = rig.run({"DRY_RUN": "1"})
    assert out.returncode == 1
    assert "Aborted — nothing was flashed." in out.stderr
    assert "may not be in recovery mode" in out.stderr
    assert rig.lines("curl") == []
    assert rig.lines("ping"), "not-armed verdict must come from an actual ARP solicitation"


def test_arp_not_armed_continue(rig):
    """Answering 'y' at the prompt continues past the warning (dry run)."""
    rig.set_neigh_reply("")
    out = rig.run({"DRY_RUN": "1"}, stdin="y\n")
    assert out.returncode == 0, out.stdout + out.stderr
    assert "DRY_RUN=1 — probe done; not flashing." in out.stdout
    assert rig.lines("curl") == []


def test_force_http_probe_gets_and_hands_off(rig):
    """FORCE_HTTP_PROBE=1 (no DRY_RUN): legacy GET fires once, flash handoff proceeds."""
    rig.set_neigh_reply(f"{RECOVERY_IP} dev lo lladdr {SOFT_MAC} REACHABLE")
    rig.set_curl_reply("<html>FIRMWARE UPDATE</html>")
    out = rig.run({"FORCE_HTTP_PROBE": "1"})
    assert out.returncode == 0, out.stdout + out.stderr
    assert "Recovery server armed (HTTP response)" in out.stdout
    gets = rig.lines("curl")
    assert len(gets) == 1 and f"http://{RECOVERY_IP}/" in gets[0]
    assert "Flash complete." in out.stdout
    py_args = "\n".join(rig.lines("python3"))
    assert "conwrt.py flash" in py_args and "--model-id" in py_args


def test_force_http_probe_with_dry_run_still_never_gets(rig):
    """DRY_RUN=1 wins over FORCE_HTTP_PROBE=1 — no HTTP request in either mode."""
    rig.set_neigh_reply(f"{RECOVERY_IP} dev lo lladdr {SOFT_MAC} REACHABLE")
    out = rig.run({"FORCE_HTTP_PROBE": "1", "DRY_RUN": "1"})
    assert out.returncode == 0, out.stdout + out.stderr
    assert "Recovery server armed (ARP REACHABLE" in out.stdout
    assert rig.lines("curl") == []
    assert rig.lines("ping")


def test_assume_yes_continues_without_prompt(rig):
    """ASSUME_YES=1 auto-continues at the not-armed prompt (bench panes)."""
    rig.set_neigh_reply("")
    out = rig.run({"DRY_RUN": "1", "ASSUME_YES": "1"})
    assert out.returncode == 0, out.stdout + out.stderr
    assert "ASSUME_YES=1 — continuing without asking." in out.stderr
    assert "DRY_RUN=1 — probe done; not flashing." in out.stdout
    assert rig.lines("curl") == []


def test_arp_attempts_tunable(rig):
    """ARP_ATTEMPTS=N bounds the poll rounds (timing knob for the bench)."""
    rig.set_neigh_reply("")  # never armed
    out = rig.run({"DRY_RUN": "1", "ASSUME_YES": "1", "ARP_ATTEMPTS": "2"})
    assert out.returncode == 0, out.stdout + out.stderr
    assert len(rig.lines("ping")) == 2


def test_arp_attempts_garbage_clamps_to_default(rig):
    """Non-numeric ARP_ATTEMPTS must not collapse the wait window to zero."""
    rig.set_neigh_reply("")  # never armed
    out = rig.run({"DRY_RUN": "1", "ASSUME_YES": "1", "ARP_ATTEMPTS": "abc"})
    assert out.returncode == 0, out.stdout + out.stderr
    assert "ARP_ATTEMPTS='abc' is not a positive integer — using 5." in out.stderr
    assert len(rig.lines("ping")) == 5  # default window, not zero rounds


def test_model_without_recovery_ip_warns(rig):
    """A model yielding no recovery IPs skips the probe — but never silently."""
    rig.set_py_reply("")  # empty recovery_ip + client_ip
    out = rig.run({"DRY_RUN": "1"})
    assert out.returncode == 0, out.stdout + out.stderr
    assert "exposes no recovery_ip — no arming detection will run." in out.stderr
    assert "Waiting for ARP" not in out.stdout
    assert rig.lines("curl") == [] and rig.lines("ping") == []
