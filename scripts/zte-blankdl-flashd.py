#!/usr/bin/env python3
"""zte-blankdl-flashd — hardened TFTP flash daemon for ZTE ipq40xx blank-download.

Serves ONE pinned image to the stock bootloader's blank-download flow
(U-Boot `lr`: pulls `root_uImage` from 192.0.0.1:69, rewrites web+rootfs
NAND regions, sends an ASCII fin packet back to :69 on success).

Safety model (deliberately rigid):
  * binds 192.0.0.1:69 only — the protocol's fixed server address. Override
    exists for dress rehearsals but prints a loud warning.
  * the image sha256 MUST be pinned before the flash window (--expect-sha256,
    or an inline sha256:... arg to --image). The daemon refuses to serve
    anything unpinned; there is no --force.
  * serves ANY requested filename, aliased to the pinned image — the
    bootloader may derive a per-boot 4-hex-digit name (zdu no-bootfile path).
    Every RRQ name + client address is logged.
  * non-TFTP UDP payloads to :69 are inspected: the ASCII fin string
    `OK:zte blank download is done` ends the run with success.
  * dry-run mode answers nothing; it only logs what it saw.

Hardening (this branch; all fixes covered by tests/test_zte_blankdl.py):
  * TFTP block-number rollover handled after 65535 blocks (option-less
    512-byte clients transfer >32 MiB without struct errors)
  * OACK/DATA(1) ordering tolerant of both client personalities: the eager
    live client (no block-0 ACK) and the RFC-strict client (ACK(0) after
    OACK) — ACK(0) resends block 1, never skips
  * blksize clamped to the protocol max (1468) — not the 16-bit block max
  * per-block resend with real retries (the old loop was dead code)
  * no per-ACK sleep (the vestigial 10 ms sleep cost ~4 min per flash)

Usage:
    python3 zte-blankdl-flashd.py --image root_uImage#sha256:<hex> [--dry-run]

Exit codes: 0 = fin packet seen (flash complete); 1 = error; 2 = timeout
without fin (transfer may still have completed — check the device).
"""
import argparse
import hashlib
import json
import logging
import os
import socket
import struct
import sys
import time

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [zte-blankdl] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("zte-blankdl")

PROTO_BIND_IP = "192.0.0.1"
PROTO_PORT = 69
FIN_STRING = b"OK:zte blank download is done"
OP_RRQ, OP_WRQ, OP_DATA, OP_ACK, OP_ERROR, OP_OACK = 1, 2, 3, 4, 5, 6
BLOCK_MOD = 65536
DEFAULT_BLKSIZE = 512
MIN_BLKSIZE = 8
MAX_BLKSIZE = 1468  # largest the stock client asks for
RETRIES = 8
RX_TIMEOUT = 10.0
ACK_DEADLINE = 1.0  # resend the in-flight block after this long


def parse_opts(data):
    """Parse RRQ mode + RFC2347 options. Returns (mode, opts dict)."""
    parts = data.split(b"\x00")
    mode = parts[1].decode(errors="replace").lower() if len(parts) > 1 else ""
    opts = {}
    i = 2
    while i + 1 < len(parts):
        k = parts[i].decode(errors="replace").lower()
        v = parts[i + 1].decode(errors="replace")
        if not k:
            break
        opts[k] = v
        i += 2
    return mode, opts


def clamp_blksize(raw):
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_BLKSIZE
    return max(MIN_BLKSIZE, min(v, MAX_BLKSIZE))


class Transfer:
    def __init__(self, addr, image, blksize, interval):
        self.addr = addr
        self.image = image
        self.blksize = blksize
        self.interval = interval
        self.block = 0          # last block number SENT
        self.acked = -1
        self.sent_pkt = None    # current in-flight packet (for resends)
        self.resends = 0
        self.deadline = time.time() + 900.0  # 38MB @ ~4MB/s worst case
        self.bytes_sent = 0
        self.completed = False
        self.eof_sent = False

    def _data_pkt(self, block, chunk):
        return struct.pack("!HH", OP_DATA, block) + chunk

    def start(self):
        """First DATA packet (block 1), sent eagerly with the OACK so both
        the live client (no ACK(0)) and strict clients can proceed."""
        return self.advance()

    def advance(self):
        """Prepare the next DATA packet; complete (None) when the image is
        exhausted. An empty EOF block is sent ONLY for exact-multiple images
        (a short final block already terminates the stream)."""
        if self.completed:
            return None
        off = self.block * self.blksize if self.block else 0
        if self.block and self.bytes_sent >= len(self.image):
            if len(self.image) % self.blksize == 0 and not self.eof_sent:
                # exact-multiple: no short block will occur — signal EOF
                self.block = (self.block + 1) % BLOCK_MOD
                self.sent_pkt = struct.pack("!HH", OP_DATA, self.block)
                self.resends = 0
                self.eof_sent = True
                return self.sent_pkt
            self.completed = True
            return None
        self.block = (self.block + 1) % BLOCK_MOD  # RFC rollover after 65535
        chunk = self.image[off:off + self.blksize]
        self.bytes_sent += len(chunk)
        self.sent_pkt = self._data_pkt(self.block, chunk)
        self.resends = 0
        return self.sent_pkt

    def resend(self):
        self.resends += 1
        return self.sent_pkt

    def packet_for(self, block_no):
        """Rebuild any already-started block's DATA packet for retransmit.
        TFTP blocks are 1-indexed: block N carries image[(N-1)*blksize : N*blksize).
        (An earlier version used N*blksize — off by one block — which corrupted
        resends; caught by the campaign rehearsal loopback, 2026-11-08.)"""
        off = (block_no - 1) * self.blksize
        if off >= len(self.image):
            return struct.pack("!HH", OP_DATA, block_no)  # EOF block
        return self._data_pkt(block_no, self.image[off:off + self.blksize])

    def on_ack(self, acked_block):
        """Classic single-window TFTP state machine.

        State: block c sent, awaiting ACK(c).
          ACK(c)  -> advance to c+1 (or complete on the EOF block)
          other   -> the client is behind: rewind to acked+1 and retransmit
                     exactly that block (lost-packet recovery). The stream
                     position NEVER runs ahead of the client's ACKs.
        """
        self.acked = acked_block
        if self.completed:
            return None, False
        if acked_block == 0 and self.block == 1 and not self.eof_sent:
            return self.resend(), False       # strict client accepts OACK
        if acked_block == self.block:
            if self.eof_sent:
                self.completed = True
                return None, False
            return self.advance(), False
        # stale/duplicate/behind ACK — rewind to the client's position
        want = (acked_block + 1) % BLOCK_MOD
        self.block = want
        self.eof_sent = want * self.blksize >= len(self.image) and \
            self.bytes_sent >= len(self.image)
        return self.packet_for(want), True


def load_image(path, expect_sha):
    with open(path, "rb") as f:
        image = f.read()
    sha = hashlib.sha256(image).hexdigest()
    if expect_sha and sha != expect_sha.lower():
        raise SystemExit(f"REFUSING: image sha256 {sha} != pinned {expect_sha}")
    log.info("image pinned: %s (%d bytes, sha256 %s)", path, len(image), sha)
    return image, sha


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--image", required=True, help="image path, optionally path#sha256:<hex>")
    ap.add_argument("--expect-sha256", help="pinned sha256 (required unless the path carries #sha256:<hex>)")
    ap.add_argument("--bind", default=PROTO_BIND_IP, help=f"bind address (default {PROTO_BIND_IP}; overriding is for rehearsals only)")
    ap.add_argument("--port", type=int, default=PROTO_PORT)
    ap.add_argument("--timeout", type=float, default=600.0, help="give up after N seconds without a fin packet")
    ap.add_argument("--dry-run", action="store_true", help="log only, never answer")
    ap.add_argument("--log-dir", help="write run.json + transfer log here")
    args = ap.parse_args()

    import signal

    def on_term(signum, frame):
        raise KeyboardInterrupt  # unwind to the common run.json writer below
    signal.signal(signal.SIGTERM, on_term)

    path = args.image
    inline_sha = None
    if "#sha256:" in path:
        path, inline_sha = path.split("#sha256:", 1)
    expect = args.expect_sha256 or inline_sha
    if not expect:
        ap.error("refusing to serve unpinned image: pass --expect-sha256 or path#sha256:<hex>")

    if args.bind != PROTO_BIND_IP:
        log.warning("NON-STANDARD BIND %s — real blank-download clients only talk to %s",
                    args.bind, PROTO_BIND_IP)

    image, sha = load_image(path, expect)

    if args.log_dir:
        os.makedirs(args.log_dir, exist_ok=True)
        fh = logging.FileHandler(os.path.join(args.log_dir, "flash.log"))
        fh.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        logging.getLogger().addHandler(fh)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.5)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.bind((args.bind, args.port))
    log.info("listening on %s:%d%s", args.bind, args.port, " (dry-run)" if args.dry_run else "")

    xfer = None
    result = {"image": path, "sha256": sha, "bytes": len(image), "fin": False,
              "rrqs": [], "started": time.time()}
    deadline = time.time() + args.timeout
    exit_code = 2
    last_activity = time.time()

    try:
        while time.time() < deadline:
        # block-level resend timer
            if xfer and not xfer.completed and xfer.sent_pkt \
                    and time.time() - last_activity > ACK_DEADLINE:
                if xfer.resends >= RETRIES:
                    log.error("block %d resent %d times without ACK — giving up",
                              xfer.block, xfer.resends)
                    break
                sock.sendto(xfer.resend(), xfer.addr)
                last_activity = time.time()
                continue

            try:
                data, addr = sock.recvfrom(2048)
            except socket.timeout:
                if xfer and time.time() > xfer.deadline:
                    log.error("transfer stalled past hard deadline")
                    break
                continue
            last_activity = time.time()

            # the fin packet is a raw ASCII UDP payload ("OK:...") whose
            # first two bytes decode as a bogus opcode — match BEFORE dispatch
            if FIN_STRING in data:
                log.info("FIN: %r from %s — blank download done, flash complete",
                         data[:60], addr[0])
                result["fin"] = True
                result["fin_time"] = time.time()
                exit_code = 0
                break

            op = struct.unpack("!H", data[:2])[0] if len(data) >= 2 else 0

            if op == OP_RRQ:
                mode, opts = parse_opts(data[2:])
                name = data[2:].split(b"\x00")[0].decode(errors="replace")
                log.info("RRQ from %s: name=%r mode=%s opts=%s (aliased to pinned image)",
                         addr[0], name, mode, opts)
                result["rrqs"].append({"t": time.time(), "client": addr[0], "name": name})
                if args.dry_run:
                    continue
                blksize = clamp_blksize(opts.get("blksize"))
                try:
                    interval = max(1, min(int(opts.get("timeout", 5)), 30))
                except ValueError:
                    interval = 5
                xfer = Transfer(addr, image, blksize, interval)
                log.info("negotiated %s: blksize=%d timeout=%ds (client asked blksize=%s)",
                         addr[0], blksize, interval, opts.get("blksize", "default"))
                if opts:
                    opt_items = []
                    if "blksize" in opts:
                        opt_items += [b"blksize", str(blksize).encode()]
                    if "timeout" in opts:
                        opt_items += [b"timeout", str(interval).encode()]
                    sock.sendto(struct.pack("!H", OP_OACK) + b"\x00".join(opt_items) + b"\x00", addr)
                pkt = xfer.start()
                if pkt:
                    sock.sendto(pkt, addr)
                continue

            if op == OP_ACK and xfer is not None and addr[0] == xfer.addr[0]:
                acked_block = struct.unpack("!H", data[2:4])[0]
                was_complete = xfer.completed
                pkt, lost = xfer.on_ack(acked_block)
                if pkt is not None:
                    sock.sendto(pkt, addr)
                    if lost:
                        xfer.resends += 1
                        last_activity = time.time()
                elif xfer.completed and not was_complete:
                    log.info("transfer complete: %d bytes, last block %d to %s",
                             xfer.bytes_sent, xfer.block, addr[0])
                    result["transferred"] = xfer.bytes_sent
                    result["completed"] = time.time()
                continue

            if op == OP_ERROR:
                log.error("client error from %s: %r", addr[0], data)
                continue

            if op == 0 and data:
            # non-TFTP payload — the fin packet arrives as raw ASCII on :69
                if FIN_STRING in data:
                    log.info("FIN: %r from %s — blank download done, flash complete", data, addr[0])
                    result["fin"] = True
                    result["fin_time"] = time.time()
                    exit_code = 0
                    break
                log.info("non-TFTP payload from %s: %r", addr[0], data[:80])
                result.setdefault("other_udp", []).append(
                    {"t": time.time(), "client": addr[0], "data": data[:80].hex()})
                continue
    except KeyboardInterrupt:
        log.warning("interrupted (SIGTERM/Ctrl-C) — writing run record with partial state")

    if args.log_dir:
        with open(os.path.join(args.log_dir, "run.json"), "w") as f:
            json.dump(result, f, indent=1)
        log.info("run record: %s", os.path.join(args.log_dir, "run.json"))
    if not result.get("fin") and result.get("transferred"):
        log.warning("no fin packet, but full transfer happened — verify on the device "
                    "(boot may lag the write by ~15s)")
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
