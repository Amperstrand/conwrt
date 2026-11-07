"""End-to-end tests for scripts/zte-blankdl-flashd.py against the mock
ZTE blank-download bootloader (tests/fixtures/zte_blankdl/mock_bootloader.py).

Every test runs the real daemon as a subprocess (with --bind override to
127.0.0.1 — the daemon prints its rehearsal warning, by design) and drives
it with a mock bootloader client personality.

Red/green contract: these tests FAIL against the original #649 daemon for
    * test_plain_512_full_transfer_rollover  (block rollover struct.error)
    * test_rfc_client_no_block_skip          (eager DATA(1) + ACK(0) skip)
    * test_oversize_blksize_clamped          (wrong clamp constant)
and PASS against the hardened daemon in this branch.
"""
import hashlib
import importlib.util
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

HERE = Path(__file__).parent
SCRIPTS = HERE.parent / "scripts"
DAEMON = SCRIPTS / "zte-blankdl-flashd.py"
MOCK = HERE / "fixtures" / "zte_blankdl" / "mock_bootloader.py"

spec = importlib.util.spec_from_file_location("mock_bootloader", MOCK)
mock_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mock_mod)


def make_image(size, fill=b"Z"):
    fd, path = tempfile.mkstemp(suffix=".root_uImage")
    with os.fdopen(fd, "wb") as f:
        f.write((fill * size)[:size])
    return path, hashlib.sha256(open(path, "rb").read()).hexdigest()


class Daemon:
    def __init__(self, image, sha, port, extra=()):
        self.logdir = tempfile.mkdtemp(prefix="blankdl-run-")
        self.proc = subprocess.Popen(
            [sys.executable, str(DAEMON), "--image", f"{image}#sha256:{sha}",
             "--bind", "127.0.0.1", "--port", str(port),
             "--timeout", "25", "--log-dir", self.logdir, *extra],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        time.sleep(0.7)  # bind + image pin

    def stop(self):
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
        try:
            self.out = self.proc.communicate(timeout=5)[0]
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.out = self.proc.communicate()[0]
        run = Path(self.logdir) / "run.json"
        self.run = json.loads(run.read_text()) if run.exists() else {}
        return self

    def wait(self, timeout=60):
        try:
            self.out = self.proc.communicate(timeout=timeout)[0]
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.out = self.proc.communicate()[0]
        run = Path(self.logdir) / "run.json"
        self.run = json.loads(run.read_text()) if run.exists() else {}
        return self


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_live_client_full_transfer_and_fin():
    """The observed real-bootloader flow: blksize 1468, no ACK(0), fin packet."""
    image, sha = make_image(38797312)
    port = free_port()
    d = Daemon(image, sha, port)
    try:
        rc, blob = mock_mod.MockBootloader("127.0.0.1", port, "live",
                                           image_size=38797312).run()
        d.wait()
    finally:
        d.stop()
    assert rc == 0
    assert len(blob) == 38797312
    assert hashlib.sha256(blob).hexdigest() == sha
    assert d.run.get("fin") is True
    assert d.proc.returncode == 0


def test_rfc_client_no_block_skip():
    """RFC-strict client ACKs block 0 after OACK — no data block may be skipped."""
    image, sha = make_image(1468 * 40)  # small: skip bugs show as missing bytes
    port = free_port()
    d = Daemon(image, sha, port)
    try:
        rc, blob = mock_mod.MockBootloader("127.0.0.1", port, "rfc",
                                           image_size=len(open(image, "rb").read())).run()
        d.wait()
    finally:
        d.stop()
    assert rc == 0, "rfc client failed or hung"
    assert hashlib.sha256(blob).hexdigest() == sha, "received bytes != image (block skip)"


def test_oversize_blksize_clamped():
    """Client asking blksize=65535 must be clamped to the 1468 protocol max."""
    image, sha = make_image(1468 * 3)
    port = free_port()
    d = Daemon(image, sha, port)
    try:
        rc, blob = mock_mod.MockBootloader("127.0.0.1", port, "live",
                                           image_size=1468 * 3, blksize=65535).run()
        d.wait()
    finally:
        d.stop()
    assert rc == 0
    assert hashlib.sha256(blob).hexdigest() == sha
    # the daemon must clamp to the 1468 protocol max and say so
    assert "blksize=1468" in (d.out or ""), "oversize blksize not clamped in OACK"


def test_plain_512_full_transfer_rollover():
    """Option-less 512-byte client on a >32MiB image: block rollover must not crash."""
    size = 512 * 65536 + 512  # one block past the 16-bit wrap point
    image, sha = make_image(size)
    port = free_port()
    d = Daemon(image, sha, port)
    try:
        rc, blob = mock_mod.MockBootloader("127.0.0.1", port, "plain",
                                           image_size=size).run(deadline=180)
        d.wait(timeout=180)
    finally:
        d.stop()
    assert rc == 0, "transfer failed (daemon crash on block rollover?)"
    assert len(blob) == size
    assert hashlib.sha256(blob).hexdigest() == sha


def test_exact_multiple_image_uses_eof_block():
    """Exact-multiple images (no short final block) must terminate via the
    empty EOF block instead of stalling."""
    size = 1468 * 4  # exact multiple
    image, sha = make_image(size)
    port = free_port()
    d = Daemon(image, sha, port)
    try:
        rc, blob = mock_mod.MockBootloader("127.0.0.1", port, "live",
                                           image_size=size).run(deadline=30)
        d.wait(timeout=40)
    finally:
        d.stop()
    assert rc == 0
    assert hashlib.sha256(blob).hexdigest() == sha
    assert d.run.get("fin") is True


def test_unpinned_image_refused():
    image, sha = make_image(1024)
    p = subprocess.run([sys.executable, str(DAEMON), "--image", image,
                        "--bind", "127.0.0.1", "--port", str(free_port())],
                       capture_output=True, text=True, timeout=15)
    assert p.returncode != 0
    assert "refusing" in (p.stdout + p.stderr).lower()


def test_wrong_sha_refused():
    image, _ = make_image(1024)
    p = subprocess.run([sys.executable, str(DAEMON), "--image", image,
                        "--expect-sha256", "0" * 64,
                        "--bind", "127.0.0.1", "--port", str(free_port())],
                       capture_output=True, text=True, timeout=15)
    assert p.returncode != 0
    assert "REFUSING" in (p.stdout + p.stderr)


def test_dry_run_never_answers():
    image, sha = make_image(2048)
    port = free_port()
    d = Daemon(image, sha, port, extra=("--dry-run", "--timeout", "8"))
    try:
        rc, blob = mock_mod.MockBootloader("127.0.0.1", port, "live",
                                           image_size=2048).run(deadline=8)
        d.wait(timeout=10)
    finally:
        d.stop()
    assert rc != 0  # client got nothing
    assert len(d.run.get("rrqs", [])) >= 1  # RRQ retries observed+logged
    assert "transferred" not in d.run
