"""conwrt#228 — trust-on-first-boot host-side tests (ADR-0013)."""
from __future__ import annotations

import base64
import hashlib
import struct
import subprocess

import pytest

from tofb import (
    CODE_DIGITS,
    ENDPOINT_FAILURES_LIMIT,
    enrollment_url,
    led_sequence,
    tofb_code,
)

@pytest.fixture(scope="module")
def pubkey_line(tmp_path_factory):
    """A real throwaway ed25519 key (ssh-keygen), like ssh-keyscan returns."""
    key = tmp_path_factory.mktemp("tofb") / "t"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-q", "-f", str(key)],
        check=True, capture_output=True,
    )
    return key.with_suffix(".pub").read_text().strip()


def _blob(line: str) -> bytes:
    return base64.b64decode(line.split()[1], validate=True)


class TestTofbCode:
    def test_six_zero_padded_digits(self, pubkey_line):
        code = tofb_code(pubkey_line)
        assert len(code) == CODE_DIGITS
        assert code.isdigit()
        assert code == code.zfill(CODE_DIGITS)

    def test_deterministic(self, pubkey_line):
        assert tofb_code(pubkey_line) == tofb_code(pubkey_line)

    def test_matches_independent_reference(self, pubkey_line):
        # Reference computed straight from hashlib, not via tofb.py, so a
        # bug in the module cannot satisfy its own test.
        digest = hashlib.sha256(_blob(pubkey_line)).digest()
        expected = str(struct.unpack(">Q", digest[:8])[0] % 10**CODE_DIGITS)
        assert tofb_code(pubkey_line) == expected.zfill(CODE_DIGITS)

    def test_mutated_blob_changes_code(self, pubkey_line):
        codes = {tofb_code(pubkey_line), tofb_code(_mutate_blob(pubkey_line))}
        assert len(codes) == 2

    def test_rejects_garbage_closed(self):
        for bad in ("", "notakey", "ssh-ed25519 !!!not-base64!!!", "ssh-ed25519"):
            with pytest.raises(ValueError):
                tofb_code(bad)


def _mutate_blob(line: str) -> str:
    blob = bytearray(_blob(line))
    blob[-1] ^= 0xFF
    return "ssh-ed25519 " + base64.b64encode(bytes(blob)).decode()


class TestLedSequence:
    def test_six_groups_color_cycle(self):
        seq = led_sequence("012345")
        assert len(seq) == 6
        assert [c for c, _ in seq] == ["red", "orange", "white", "red", "orange", "white"]

    def test_digit_is_blink_count(self):
        seq = led_sequence("123456")
        assert [b for _, b in seq] == [1, 2, 3, 4, 5, 6]

    def test_zero_is_blink_count_zero(self):
        assert led_sequence("000000")[0][1] == 0

    def test_rejects_bad_code(self):
        for bad in ("12345", "1234567", "12345a", "12 456"):
            with pytest.raises(ValueError):
                led_sequence(bad)


class TestEnrollmentUrl:
    def test_scoped_link_local(self):
        url = enrollment_url("fe80::1", "switch.100X")
        assert url == "http://[fe80::1%25switch.100X]/tofb-enroll"

    def test_unscoped(self):
        assert enrollment_url("fe80::1") == "http://[fe80::1]/tofb-enroll"

    def test_rejects_non_link_local_closed(self):
        with pytest.raises(ValueError):
            enrollment_url("192.168.1.1")
        with pytest.raises(ValueError):
            enrollment_url("2001:db8::1")


class TestDeviceScriptContract:
    """Static contract checks on the device-side script (ADR-0013)."""

    SCRIPT = "scripts/tofb-device.sh"

    def read(self) -> str:
        with open(self.SCRIPT) as fh:
            return fh.read()

    def test_entropy_gate_precedes_keygen(self):
        s = self.read()
        assert s.index("/dev/random") < s.index("dropbearkey -t")

    def test_code_derivation_uses_busybox_primitives(self):
        s = self.read()
        assert "base64 -d" in s and "sha256sum" in s
        assert "md5sum" not in s

    def test_verify_gate_precedes_hardening(self):
        # The #229/#235 discipline: authorized_keys write verified BEFORE
        # PasswordAuth hardening and BEFORE the done-marker.
        s = self.read()
        write = s.index(">> \"$AUTH_KEYS\"")
        verify = s.index("grep -qF")
        harden = s.index("PasswordAuth='off'")
        done = s.index('date > "$TOFB_DONE"')
        assert write < verify < harden < done

    def test_done_marker_short_circuits(self):
        assert "[ -e \"$TOFB_DONE\" ] && exit 0" in self.read()

    def test_endpoint_failure_limit_matches_host_constant(self):
        s = self.read()
        assert f"FAILURES_LIMIT={ENDPOINT_FAILURES_LIMIT}" in s

    def test_digest_width_matches_host(self):
        # Cross-implementation consistency: the device takes 16 hex chars
        # (8 bytes big-endian) — the same width tofb.py hashes to.
        s = self.read()
        assert "cut -c1-16" in s
        assert "cut -c1-8)" not in s

    def test_shell_syntax(self):
        proc = subprocess.run(["sh", "-n", self.SCRIPT], capture_output=True)
        assert proc.returncode == 0, proc.stderr.decode()


class TestCli:
    def test_code_from_stdin(self, pubkey_line):
        proc = subprocess.run(
            ["python3", "scripts/tofb.py", "code", "-"],
            input=pubkey_line + "\n", capture_output=True, text=True,
        )
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == tofb_code(pubkey_line)

    def test_led_plan(self):
        proc = subprocess.run(
            ["python3", "scripts/tofb.py", "led", "012345"],
            capture_output=True, text=True,
        )
        assert proc.returncode == 0
        assert "long blink" in proc.stdout
        assert "5 blinks" in proc.stdout
