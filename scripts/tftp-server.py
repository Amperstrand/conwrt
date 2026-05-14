#!/usr/bin/env python3
"""Minimal read-only TFTP server (RFC 1350) for router flashing.

Serves files from a directory over UDP.  Only supports RRQ (read) in octet
mode — exactly what U-Boot's ``tftpboot`` command needs.

Usage::

    python3 tftp-server.py /path/to/firmware/dir
"""
import logging
import os
import socket
import struct
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [tftp] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("tftp")

# TFTP opcodes
OP_RRQ = 1
OP_DATA = 3
OP_ACK = 4
OP_ERROR = 5

BLOCK_SIZE = 512
MAX_PACKET = 516  # 4 header + 512 data
RETRIES = 5
TIMEOUT = 5.0


def _send_error(addr, sock, code, msg):
    sock.sendto(struct.pack("!HH", OP_ERROR, code) + msg.encode() + b"\x00", addr)


def _handle_rrq(data, addr, server_sock, serve_dir):
    # Parse: \0filename\0mode\0
    parts = data.split(b"\x00")
    if len(parts) < 3:
        _send_error(addr, server_sock, 0, "Malformed request")
        return
    filename = parts[0].decode(errors="replace")
    mode = parts[1].decode(errors="replace").lower()

    if mode != "octet":
        _send_error(addr, server_sock, 0, f"Unsupported mode: {mode}")
        return

    if ".." in filename or filename.startswith("/"):
        _send_error(addr, server_sock, 2, "Access violation")
        return

    filepath = os.path.join(serve_dir, filename)
    if not os.path.isfile(filepath):
        _send_error(addr, server_sock, 1, "File not found")
        return

    log.info(f"RRQ {filename} -> {addr[0]}:{addr[1]}")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as xfer_sock:
        xfer_sock.settimeout(TIMEOUT)
        block = 1
        try:
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(BLOCK_SIZE)
                    if not chunk and block > 1:
                        break
                    if not chunk:
                        chunk = b""
                    pkt = struct.pack("!HH", OP_DATA, block) + chunk

                    for _ in range(RETRIES):
                        xfer_sock.sendto(pkt, addr)
                        try:
                            ack, _ = xfer_sock.recvfrom(MAX_PACKET)
                            op, ack_block = struct.unpack("!HH", ack[:4])
                            if op == OP_ACK and ack_block == block:
                                break
                        except socket.timeout:
                            continue
                    else:
                        log.warning(f"Timeout sending block {block} to {addr}")
                        return

                    block = (block + 1) & 0xFFFF or 1
                    if len(chunk) < BLOCK_SIZE:
                        break
            log.info(f"Sent {filename} ({block - 1 or 65535} blocks)")
        except OSError as e:
            _send_error(addr, server_sock, 0, str(e))


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <directory>", file=sys.stderr)
        sys.exit(1)

    serve_dir = os.path.abspath(sys.argv[1])
    if not os.path.isdir(serve_dir):
        print(f"Error: {serve_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 69))
    log.info(f"Serving {serve_dir} on UDP port 69")

    try:
        while True:
            data, addr = sock.recvfrom(MAX_PACKET)
            op = struct.unpack("!H", data[:2])[0]
            if op == OP_RRQ:
                _handle_rrq(data[2:], addr, sock, serve_dir)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == "__main__":
    main()
