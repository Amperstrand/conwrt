"""Regression tests for conwrt_serial_bridge's REMOTE_SH (#763 P1).

The console-safety tool exists to leave the listener's getty intact on
every exit route — a regression there strands consoles (the exact
failure class the tool prevents, #279). These tests run the REAL remote
script bytes on this host against a fake inittab / fake ps / fake tty,
parameterized through the script's env-default seams (CONWRT_BRIDGE_*),
and pin the restore contract on EVERY exit route:

- STOP token (bridge stopping deliberately) -> getty RESTORED
- stdin EOF (ssh stream drop)             -> restore SKIPPED (spec: the
  reconnect's free_tty must not race the respawned getty — the
  2026-09-23 wedge lesson)
- SIGTERM                                 -> getty RESTORED

Plus the free_tty invariants the 2026-09-23 fix established: the
column-0 [^#]* match actually comments the getty line, and the inittab
backup is taken exactly once (idempotent across bridge restarts).
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from conwrt_serial_bridge import REMOTE_SH  # type: ignore[import-not-found]

GETTY_DEV = "ttyMSM0"
UNRELATED_LINE = "::sysinit:/etc/init.d/rcS S boot"


class FakeEnv:
    """Fake inittab + ps + tty; the real script runs against them."""

    def __init__(self, root: Path, extra_ps_lines: list[str] | None = None):
        self.root = root
        self.tty = root / "ttyMSM0"
        self.tty.write_bytes(b"")
        self.inittab = root / "inittab"
        # The script greps for TTYID (= $TTY minus any /dev/ prefix); with a
        # fixture tty outside /dev, TTYID is the full path — so the fixture
        # getty line references the full path (mechanics stay identical).
        self.getty_line = f"::respawn:/sbin/getty -L {self.tty} 115200 vt100"
        self.inittab.write_text("\n".join([self.getty_line, UNRELATED_LINE]) + "\n")
        self.tty = root / "ttyMSM0"
        self.tty.write_bytes(b"")
        # A process we own standing in for PID 1 (HUP target): prove the
        # HUP actually fires without signaling the host's init.
        self.init_proc = subprocess.Popen(["sleep", "300"])
        # fake ps: only fixture lines, never the host's real process table
        self.ps = root / "fake-ps.sh"
        lines = ["PID CMD", f"1234 /bin/login ", "1235 grep getty (must be skipped)"]
        lines += extra_ps_lines or []
        self.ps.write_text(
            "#!/bin/sh\n" + "\n".join(f'echo "{ln}"' for ln in lines) + "\n"
        )
        self.ps.chmod(0o755)
        self.log = root / "bridge-target.log"

    def env(self) -> dict[str, str]:
        e = os.environ.copy()
        e.update({
            "CONWRT_BRIDGE_INITTAB": str(self.inittab),
            "CONWRT_BRIDGE_INITTAB_BAK": str(self.root / "inittab.bak-conwrt"),
            "CONWRT_BRIDGE_PS": str(self.ps),
            "CONWRT_BRIDGE_HUP_TARGET": str(self.init_proc.pid),
            "CONWRT_BRIDGE_SLEEP": "0",
        })
        return e

    def run(self, stdin_lines: list[str] | None, wait: float = 3.0) -> subprocess.CompletedProcess[bytes]:
        # Exactly the production delivery shape (SSHStream.start): the
        # script goes on stdin FIRST — `sh -s` parses incrementally, so the
        # while-read loop then consumes the subsequent lines as console data.
        p = subprocess.Popen(
            ["sh", "-s", "--", str(self.tty), str(self.log)],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=self.env(),
        )
        assert p.stdin is not None
        p.stdin.write(REMOTE_SH.encode())
        p.stdin.flush()
        time.sleep(0.3)  # parse separation: sh -s read-ahead must not slurp
                         # script+data in one block (production has the same
                         # timing gap between script push and first pump byte)
        if stdin_lines is None:
            p.stdin.close()  # stream drop: EOF immediately
        else:
            for ln in stdin_lines:
                p.stdin.write(ln.encode() + b"\n")
            p.stdin.flush()
            p.stdin.close()
        try:
            rc = p.wait(timeout=wait)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
            rc = -999
        return subprocess.CompletedProcess(args=[], returncode=rc, stdout=b"", stderr=b"")

    def getty_commented(self) -> bool:
        return any(
            ln.startswith("#") and "respawn" in ln
            for ln in self.inittab.read_text().splitlines()
        )

    def teardown(self) -> None:
        if self.init_proc.poll() is None:
            self.init_proc.kill()
            self.init_proc.wait()


@pytest.fixture()
def fake(tmp_path: Path):
    env = FakeEnv(tmp_path)
    yield env
    env.teardown()


class TestStopTokenRestores:
    def test_stop_token_restores_getty(self, fake):
        out = fake.run(["___CONWRT-BRIDGE-STOP___"])
        assert out.returncode == 0
        assert not fake.getty_commented(), "STOP token must restore the inittab"
        assert fake.getty_line in fake.inittab.read_text()

    def test_other_lines_do_not_restore(self, fake):
        # Non-token input then EOF: stream-drop semantics (no restore).
        fake.run(["some console input", "AT", ""])
        assert fake.getty_commented(), "plain lines + EOF must NOT restore"


class TestStreamDropSkipsRestore:
    def test_eof_leaves_getty_commented(self, fake):
        out = fake.run(None)
        assert out.returncode == 0
        assert fake.getty_commented(), (
            "stream drop must NOT restore — the auto-reconnect's free_tty "
            "would race the respawned getty (2026-09-23 wedge)"
        )
        assert UNRELATED_LINE in fake.inittab.read_text()


class TestSignalTerminationRestores:
    def test_sigterm_restores_getty(self, fake):
        p = subprocess.Popen(
            ["sh", "-s", "--", str(fake.tty), str(fake.log)],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=fake.env(),
        )
        assert p.stdin is not None
        p.stdin.write(REMOTE_SH.encode())
        p.stdin.flush()  # keep stdin open: the loop waits for data
        time.sleep(0.4)  # let free_tty + cats come up
        p.send_signal(signal.SIGTERM)
        rc = p.wait(timeout=5)
        assert rc == 0 or rc == -signal.SIGTERM
        assert not fake.getty_commented(), "SIGTERM must restore the inittab"


class TestFreeTtyInvariants:
    def test_getty_line_actually_commented_column_zero(self, fake):
        # The 2026-09-23 bug: [^#].* never matched, getty never freed.
        fake.run(None)
        text = fake.inittab.read_text()
        commented = [ln for ln in text.splitlines() if ln.startswith("#") and "respawn" in ln]
        assert commented, "the getty line must end up commented out"
        assert UNRELATED_LINE in text, "unrelated lines untouched"

    def test_backup_taken_exactly_once(self, fake):
        fake.run(None)  # first session: creates the backup
        bak = fake.root / "inittab.bak-conwrt"
        assert bak.exists()
        first = bak.read_text()
        # mutate the live inittab between sessions; the backup must NOT be
        # clobbered by a second bridge start (idempotent free_tty)
        fake.inittab.write_text(fake.getty_line + "\n" + UNRELATED_LINE + "\nEXTRA=later\n")
        fake.run(None)
        assert bak.read_text() == first, "second bridge start must not re-backup"

    def test_dev_prefix_strip_and_basename_match(self, tmp_path):
        # The 2026-09-23 fix: on-device TTY=/dev/ttyMSM0 must reduce to the
        # BASENAME for the inittab match. STOP-token route only (the fifo
        # write path would block with no readable tty — the token check
        # happens before any fifo write).
        import os as _os
        inittab = tmp_path / "inittab"
        inittab.write_text("::respawn:/sbin/getty -L ttyMSM0 115200 vt100\n")
        ps = tmp_path / "fake-ps.sh"
        ps.write_text("#!/bin/sh\necho 'PID CMD'\n")
        ps.chmod(0o755)
        init = subprocess.Popen(["sleep", "300"])
        e = _os.environ.copy()
        e.update({"CONWRT_BRIDGE_INITTAB": str(inittab),
                  "CONWRT_BRIDGE_INITTAB_BAK": str(tmp_path / "bak"),
                  "CONWRT_BRIDGE_PS": str(ps),
                  "CONWRT_BRIDGE_HUP_TARGET": str(init.pid),
                  "CONWRT_BRIDGE_SLEEP": "0"})
        try:
            p = subprocess.Popen(["sh", "-s", "--", "/dev/ttyMSM0", str(tmp_path / "log")],
                                 stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, env=e)
            p.stdin.write(REMOTE_SH.encode())
            p.stdin.flush()
            time.sleep(0.3)
            p.stdin.write(b"___CONWRT-BRIDGE-STOP___\n")
            p.stdin.flush(); p.stdin.close()
            assert p.wait(timeout=5) == 0
            # STOP restores the inittab, so the proof the MATCH worked is the
            # backup: free_tty only creates it when the grep hit — and it hit
            # only if "/dev/ttyMSM0" stripped to the BusyBox id "ttyMSM0".
            bak = tmp_path / "bak"
            assert bak.exists(), (
                "/dev/ prefix must strip to the BusyBox id for the inittab match")
            assert "ttyMSM0" in bak.read_text() and not any(
                ln.startswith("#") for ln in bak.read_text().splitlines())
        finally:
            if init.poll() is None:
                init.kill(); init.wait()

    def test_hup_actually_sent_to_target(self, fake):
        fake.run(None)
        # HUP_TARGET (our stand-in init) must have been signaled.
        assert fake.init_proc.poll() is not None, "kill -HUP must reach the init target"


class TestScriptHygiene:
    def test_remote_sh_shellcheck_clean(self):
        shellcheck = shutil.which("shellcheck")
        if shellcheck is None:
            pytest.skip("shellcheck not installed (CI installs it)")
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
            f.write("# shellcheck shell=sh\n")
            f.write(REMOTE_SH)
            path = f.name
        try:
            r = subprocess.run([shellcheck, "--severity=error", path],
                               capture_output=True, text=True)
            assert r.returncode == 0, f"REMOTE_SH shellcheck findings:\n{r.stdout}"
        finally:
            os.unlink(path)

    def test_stop_sent_before_terminate_in_sshstream_stop(self):
        # Source contract: SSHStream.stop() must send the STOP token and only
        # fall back to terminate() — a bare terminate leaves the getty
        # stranded (#279). We pin the ordering on the code as shipped.
        import inspect
        import conwrt_serial_bridge as mod
        src = inspect.getsource(mod.SSHStream.stop)
        assert "___CONWRT-BRIDGE-STOP___" in src
        terminate_idx = src.index("self.proc.terminate()")
        stop_idx = src.index("___CONWRT-BRIDGE-STOP___")
        assert stop_idx < terminate_idx, "STOP token must be tried before terminate()"
