#!/usr/bin/env python3
"""Mock ZTE ipq40xx blank-download bootloader (the `lr` recovery client).

Implements the device side of the blank-download TFTP flow so the flash
daemon (scripts/zte-blankdl-flashd.py) can be tested end-to-end without
hardware. Client personalities:

  live  — behavior observed from the real stock U-Boot: RRQ with options
          blksize=1468 + timeout=5, ACKs every data block, NO block-0
          ACK after OACK, sends the ASCII fin packet on completion.
  rfc   — RFC 2347/2348 strict: ACK(0) after OACK, then per-block ACKs.
  plain — no options (512-byte blocks): reproduces the block-rollover
          class of bugs on >32 MiB images.

Usage (library or CLI):
    python3 mock_bootloader.py --image-size 38797312 --mode live \
        --server 127.0.0.1 --port 1069 [--fin] [--no-verify-sha]
Exit 0 on complete transfer (and fin if requested).
"""
import argparse
import hashlib
import socket
import struct
import sys
import time

OP_RRQ, OP_WRQ, OP_DATA, OP_ACK, OP_ERROR, OP_OACK = 1, 2, 3, 4, 5, 6
FIN_STRING = b"OK:zte blank download is done"


class MockBootloader:
    def __init__(self, server, port, mode="live", image_size=38797312,
                 blksize=1468, timeout_opt=5, send_fin=True, verbose=False):
        self.server, self.port = server, port
        self.mode = mode
        self.image_size = image_size
        self.want_blksize = blksize
        self.timeout_opt = timeout_opt
        self.send_fin = send_fin
        self.verbose = verbose
        self.received = bytearray()

    def log(self, *a):
        if self.verbose:
            print("[mock-bl]", *a, file=sys.stderr)

    def run(self, deadline=120.0):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2.0)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        end = time.time() + deadline

        name = "root_uImage"
        if self.mode == "live":
            # the real client derives a per-boot 4-hex name
            name = "%04x" % (int(time.time()) & 0xFFFF)
        opts = b""
        if self.mode != "plain":
            opts = b"blksize\x00" + str(self.want_blksize).encode() + b"\x00timeout\x00" + str(self.timeout_opt).encode() + b"\x00"
        rrq = struct.pack("!H", OP_RRQ) + name.encode() + b"\x00octet\x00" + opts
        s.sendto(rrq, (self.server, self.port))

        blksize = 512
        block = 0
        acked_oack = False
        fin_sent = False
        last = None
        while time.time() < end:
            try:
                data, _ = s.recvfrom(66000)
            except socket.timeout:
                if last:
                    s.sendto(last, (self.server, self.port))  # re-ACK
                else:
                    s.sendto(rrq, (self.server, self.port))   # retry the RRQ
                    self.log("RRQ retry")
                continue
            op = struct.unpack("!H", data[:2])[0] if len(data) >= 2 else 0

            if op == OP_OACK:
                # parse negotiated options
                parts = data[2:].split(b"\x00")
                for i in range(0, len(parts) - 1, 2):
                    if parts[i].lower() == b"blksize":
                        blksize = int(parts[i + 1])
                self.log("OACK blksize", blksize)
                if self.mode == "rfc":
                    last = struct.pack("!HH", OP_ACK, 0)
                    s.sendto(last, (self.server, self.port))
                    acked_oack = True
                continue

            if op == OP_DATA:
                b = struct.unpack("!H", data[2:4])[0]
                if self.mode == "rfc" and not acked_oack:
                    self.log("DATA before OACK-ACK — strict client rejects")
                    continue
                expected = (block + 1) % 65536  # TFTP block rollover
                if b == expected or (block == 0 and not self.received):
                    block = b
                    self.received += data[4:]
                elif b == block:
                    pass  # resend of current block, do not double-append
                else:
                    self.log("out-of-order block", b, "expected", block + 1)
                last = struct.pack("!HH", OP_ACK, block)
                s.sendto(last, (self.server, self.port))
                if len(data) == 4 or len(data) - 4 < blksize:
                    # zero-length EOF block (exact-multiple images) or short block
                    self.log("last block", block, "total", len(self.received))
                    if self.send_fin:
                        time.sleep(0.2)
                        s.sendto(FIN_STRING, (self.server, self.port))
                        fin_sent = True
                    break
                continue

            if op == OP_ERROR:
                self.log("server ERROR:", data)
                return 1, self.received
        s.close()
        ok = len(self.received) == self.image_size and (fin_sent or not self.send_fin)
        return (0 if ok else 1), self.received


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1069)
    ap.add_argument("--mode", choices=["live", "rfc", "plain"], default="live")
    ap.add_argument("--image-size", type=int, default=38797312)
    ap.add_argument("--no-fin", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()
    mb = MockBootloader(a.server, a.port, a.mode, a.image_size,
                        send_fin=not a.no_fin, verbose=a.verbose)
    rc, blob = mb.run()
    print(f"mock rc={rc} bytes={len(blob)} sha256={hashlib.sha256(blob).hexdigest()}")
    sys.exit(rc)
