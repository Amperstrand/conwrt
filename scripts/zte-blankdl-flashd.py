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

Usage:
    python3 zte-blankdl-flashd.py --image root_uImage --sha256:<hex> [--dry-run]
    python3 zte-blankdl-flashd.py --image root_uImage --expect-sha256 <hex> \\
        --log-dir runs/mf286d-001

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
MAX_BLOCK = 65535
DEFAULT_BLKSIZE = 512
MAX_BLKSIZE = 1468  # largest the stock client asks for
RETRIES = 8
RX_TIMEOUT = 10.0


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


class Transfer:
    def __init__(self, addr, image, blksize, interval):
        self.addr = addr
        self.image = image
        self.blksize = blksize
        self.interval = interval
        self.block = 0
        self.acked = -1
        self.deadline = time.time() + 900.0  # 38MB @ ~4MB/s worst case
        self.bytes_sent = 0

    def next_data(self):
        off = self.block * self.blksize
        if off >= len(self.image):
            return None  # final block already sent; waiting for last ACK
        chunk = self.image[off:off + self.blksize]
        self.block += 1
        self.bytes_sent += len(chunk)
        return struct.pack("!HH", OP_DATA, self.block) + chunk


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
    sock.bind((args.bind, args.port))
    log.info("listening on %s:%d%s", args.bind, args.port, " (dry-run)" if args.dry_run else "")

    xfer = None
    result = {"image": path, "sha256": sha, "bytes": len(image), "fin": False,
              "rrqs": [], "started": time.time()}
    deadline = time.time() + args.timeout
    exit_code = 2

    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            if xfer and time.time() > xfer.deadline:
                log.error("transfer stalled past hard deadline")
                break
            continue

        op = struct.unpack("!H", data[:2])[0] if len(data) >= 2 else 0

        if op == OP_RRQ:
            mode, opts = parse_opts(data[2:])
            name = data[2:].split(b"\x00")[0].decode(errors="replace")
            log.info("RRQ from %s: name=%r mode=%s opts=%s (aliased to pinned image)",
                     addr[0], name, mode, opts)
            result["rrqs"].append({"t": time.time(), "client": addr[0], "name": name})
            if args.dry_run:
                continue
            blksize = min(int(opts.get("blksize", DEFAULT_BLKSIZE)), MAX_BLOCK) or DEFAULT_BLKSIZE
            interval = min(int(opts.get("timeout", 5)), 30) or 5
            xfer = Transfer(addr, image, blksize, interval)
            if opts:
                opt_items = []
                if "blksize" in opts:
                    opt_items += [b"blksize", str(blksize).encode()]
                if "timeout" in opts:
                    opt_items += [b"timeout", str(interval).encode()]
                sock.sendto(struct.pack("!H", OP_OACK) + b"\x00".join(opt_items) + b"\x00", addr)
            pkt = xfer.next_data()
            if pkt:
                sock.sendto(pkt, addr)
            continue

        if op == OP_ACK and xfer is not None and addr[0] == xfer.addr[0]:
            acked_block = struct.unpack("!H", data[2:4])[0]
            xfer.acked = acked_block
            pkt = xfer.next_data()
            if pkt is None:
                if acked_block == xfer.block:
                    log.info("transfer complete: %d bytes in %d blocks to %s",
                             xfer.bytes_sent, xfer.block, addr[0])
                    result["transferred"] = xfer.bytes_sent
                    result["completed"] = time.time()
                continue
            sent = False
            for _ in range(RETRIES):
                sock.sendto(pkt, addr)
                sent = True
                time.sleep(0.01)
                break
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
