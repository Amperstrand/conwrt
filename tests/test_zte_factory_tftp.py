"""Tests for zte_factory_tftp (#763 P1 — last item).

The module's own --selftest covers the happy path (RRQ → OACK → full
transfer). These tests pin the classes that bite in the field, against
the REAL server over loopback (house style: loopback-only networking):

- security: path-traversal RRQs are refused with ERROR, never served
- missing file -> ERROR(1) 'File not found'
- WRQ -> ERROR (server is read-only by design)
- RFC2347 negotiation: blksize clamped into [8, 1468]; OACK echoes
  blksize/timeout/tsize but never windowsize (window=1 contract)
- looks_tftp classification incl. the Sahara-passthrough boundary
"""
from __future__ import annotations

import socket
import struct
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import zte_factory_tftp as tftp  # noqa: E402

PORT = 11069


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    root = tmp_path_factory.mktemp("tftproot")
    (root / "armprg.bin").write_bytes(b"\xA5" * 5000)
    secret = tmp_path_factory.mktemp("outside")
    (secret / "secret.bin").write_bytes(b"TOPSECRET")
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    thread = threading.Thread(target=tftp.watcher, args=(srv, str(root)), daemon=True)
    thread.start()
    time.sleep(0.2)
    yield {"root": root, "outside": secret, "sock": srv}
    srv.close()


def rrq(fname: bytes, opts: dict[bytes, bytes] | None = None) -> bytes:
    pkt = struct.pack("!H", 1) + fname + b"\x00octet\x00"
    for k, v in (opts or {}).items():
        pkt += k + b"\x00" + v + b"\x00"
    return pkt


def client() -> socket.socket:
    c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    c.settimeout(3)
    return c


def recv_op(c: socket.socket) -> tuple[int, bytes]:
    data, _ = c.recvfrom(2048)
    return struct.unpack("!H", data[:2])[0], data


def abort(c: socket.socket) -> None:
    """Tear down a transfer we deliberately left unfinished.

    The watcher is single-threaded: a client that walks away after the
    OACK leaves the server parked in its retry loop and every later RRQ
    starves behind it. A client-side ERROR (the TFTP abort) releases it
    immediately — both in the OACK-wait loop and inside Transfer.run.
    """
    try:
        c.sendto(struct.pack("!HH", 5, 0) + b"test-done\x00", ("127.0.0.1", PORT))
        time.sleep(0.05)
    except OSError:
        pass


class TestSecurity:
    @pytest.mark.parametrize("fname", [
        b"../outside/secret.bin",
        b"..\\outside\\secret.bin",
        b"../../etc/passwd",
        b"sub/../../armprg.bin",
    ])
    def test_traversal_refused(self, server, fname):
        c = client()
        c.sendto(rrq(fname), ("127.0.0.1", PORT))
        op, data = recv_op(c)
        assert op == 5, f"traversal RRQ must get ERROR, got op {op}"
        assert struct.unpack("!H", data[2:4])[0] == 1
        assert b"TOPSECRET" not in data
        c.close()

    def test_missing_file_is_error_not_crash(self, server):
        c = client()
        c.sendto(rrq(b"nope.bin"), ("127.0.0.1", PORT))
        op, data = recv_op(c)
        assert op == 5 and b"not found" in data[4:].lower()
        c.close()

    def test_server_alive_after_bad_rrqs(self, server):
        # the watcher must survive every refusal (it catches per-RRQ)
        c = client()
        c.sendto(rrq(b"armprg.bin", {b"blksize": b"512"}), ("127.0.0.1", PORT))
        op, _ = recv_op(c)
        assert op == 6, "server must still answer good RRQs after bad ones"
        abort(c)
        c.close()


class TestNegotiation:
    def test_oack_shape_no_windowsize(self, server):
        c = client()
        c.sendto(rrq(b"armprg.bin", {b"blksize": b"1024", b"tsize": b"0",
                                     b"windowsize": b"8"}), ("127.0.0.1", PORT))
        op, data = recv_op(c)
        assert op == 6
        body = data[2:].split(b"\x00")
        assert b"blksize" in body and b"1024" in body
        assert b"windowsize" not in body, "window=1 server must not echo windowsize"
        abort(c)
        c.close()

    @pytest.mark.parametrize("ask,expect", [(b"4", b"8"), (b"99999", b"1468"), (b"100", b"100")])
    def test_blksize_clamped(self, server, ask, expect):
        c = client()
        c.sendto(rrq(b"armprg.bin", {b"blksize": ask}), ("127.0.0.1", PORT))
        op, data = recv_op(c)
        assert op == 6
        body = data[2:].split(b"\x00")
        assert expect in body, f"blksize {ask!r} must clamp to {expect!r}: {body}"
        abort(c)
        c.close()

    def test_full_transfer_after_oack(self, server):
        c = client()
        c.sendto(rrq(b"armprg.bin", {b"blksize": b"1500"}), ("127.0.0.1", PORT))
        op, _ = recv_op(c)
        assert op == 6
        c.sendto(struct.pack("!HH", 4, 0), ("127.0.0.1", PORT))  # ACK the OACK
        data, blk = b"", 0
        while True:
            pkt, _ = c.recvfrom(2048)
            op, b = struct.unpack("!HH", pkt[:4])
            assert op == 3
            if b == blk + 1:
                data += pkt[4:]
                blk = b
            c.sendto(struct.pack("!HH", 4, b), ("127.0.0.1", PORT))
            if len(pkt) < 4 + 1468:
                break
        assert data == (server["root"] / "armprg.bin").read_bytes()
        c.close()


class TestReadOnly:
    def test_wrq_refused(self, server):
        c = client()
        c.sendto(struct.pack("!H", 2) + b"evil.bin\x00octet\x00", ("127.0.0.1", PORT))
        op, data = recv_op(c)
        assert op == 5 and b"wrq" in data[4:].lower()
        c.close()


class TestLooksTftp:
    @pytest.mark.parametrize("pkt,expect", [
        (struct.pack("!H", 1) + b"f\x00octet\x00", True),   # RRQ
        (struct.pack("!H", 4) + b"\x00\x01", True),          # ACK
        (struct.pack("!H", 6) + b"blksize\x001024\x00", True),  # OACK
        (b"\x01\x01\x01\x01\x00\x00\x00\x01", False),       # Sahara HELLO
        (b"\x00", False),                                    # too short
        (b"", False),
    ])
    def test_classification(self, pkt, expect):
        assert tftp.looks_tftp(pkt) is expect
