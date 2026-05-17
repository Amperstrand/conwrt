#!/usr/bin/env python3
"""Minimal read-only TFTP server (RFC 1350) for router flashing.

Usage::

    python3 tftp-server.py <directory>
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

OP_RRQ = 1
OP_DATA = 3
OP_ACK = 4
OP_ERROR = 5

BLOCK_SIZE = 512
MAX_PACKET = 516
RETRIES = 5
TIMEOUT = 5.0


def _send_error(sock, addr, code, msg):
    sock.sendto(struct.pack("!HH", OP_ERROR, code) + msg.encode() + b"\x00", addr)


def _handle_rrq(data, addr, server_sock, serve_dir):
    parts = data.split(b"\x00")
    if len(parts) < 3:
        return _send_error(server_sock, addr, 0, "Malformed request")
    filename = parts[0].decode(errors="replace")
    mode = parts[1].decode(errors="replace").lower()

    if mode != "octet":
        return _send_error(server_sock, addr, 0, f"Unsupported mode: {mode}")
    if ".." in filename or filename.startswith("/"):
        return _send_error(server_sock, addr, 2, "Access violation")

    filepath = os.path.join(serve_dir, filename)
    if not os.path.isfile(filepath):
        return _send_error(server_sock, addr, 1, "File not found")

    log.info(f"RRQ {filename} -> {addr[0]}:{addr[1]}")

    # Dedicated transfer socket — avoids shared-socket recvfrom race
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as xfer:
        xfer.settimeout(TIMEOUT)
        block = 1
        try:
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(BLOCK_SIZE)

                    pkt = struct.pack("!HH", OP_DATA, block) + (chunk or b"")

                    for attempt in range(RETRIES):
                        xfer.sendto(pkt, addr)
                        try:
                            ack, _ = xfer.recvfrom(MAX_PACKET)
                            if struct.unpack("!HH", ack[:4]) == (OP_ACK, block):
                                break
                        except socket.timeout:
                            if attempt == RETRIES - 1:
                                log.warning(f"Timeout block {block} -> {addr}")
                                return
                            continue

                    if len(chunk) < BLOCK_SIZE:
                        break
                    block = (block % 65535) + 1

            log.info(f"Sent {filename} ({block} block(s))")
        except OSError as exc:
            _send_error(xfer, addr, 0, str(exc))


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <directory>", file=sys.stderr)
        sys.exit(1)

    serve_dir = os.path.abspath(sys.argv[1])
    if not os.path.isdir(serve_dir):
        print(f"Error: {serve_dir} is not a directory", file=sys.stderr)
        sys.exit(1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", 69))
    except PermissionError:
        print("Error: Port 69 requires root. Run with sudo or on OpenWrt (root).", file=sys.stderr)
        sys.exit(1)
    log.info(f"Serving {serve_dir} on UDP port 69")

    try:
        while True:
            data, addr = sock.recvfrom(MAX_PACKET)
            if struct.unpack("!H", data[:2])[0] == OP_RRQ:
                _handle_rrq(data[2:], addr, sock, serve_dir)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == "__main__":
    main()
