#!/usr/bin/env python3
"""macOS-compatible zycast multicast sender.

Sends ZyXEL multicast flash packets on macOS using IP_MULTICAST_IF
(which works cross-platform) instead of Linux-specific ioctls.
"""
import socket
import struct
import sys
import time
import threading

_MAGIC = 0x7A797800  # "zyx\0" big-endian
_HEADER_FMT = "!IHIIIHBB2sB5s"
_HEADER_SIZE = struct.calcsize(_HEADER_FMT)  # 30
_CHUNK_SIZE = 1024
_PKT_DELAY = 0.02  # 20ms inter-packet delay (matching -t 20)

_TYPE_RAS = 0x04  # BIT(2) — kernel partition

def send(image_path, interface_ip, group="225.0.0.0", port=5631):
    with open(image_path, "rb") as f:
        image_data = f.read()

    file_len = len(image_data)
    print(f"zycast: {image_path} ({file_len} bytes)")
    print(f"  iface IP: {interface_ip}")
    print(f"  multicast: {group}:{port}")
    print(f"  type: ras (0x{_TYPE_RAS:02x})")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                    socket.inet_aton(interface_ip))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)

    loop = 0
    try:
        while True:
            offset = 0
            packet_id = 0
            while offset < file_len:
                chunk = image_data[offset:offset + _CHUNK_SIZE]
                chunk_len = len(chunk)
                total = sum(chunk)
                checksum = ((total >> 16) + total) & 0xFFFF

                header = struct.pack(
                    _HEADER_FMT,
                    _MAGIC,
                    checksum,
                    packet_id,
                    chunk_len,
                    file_len,
                    0,            # unused
                    _TYPE_RAS,    # type
                    _TYPE_RAS,    # images bitmap
                    b'FF',        # country code
                    0x01,         # flags
                    b'\x00' * 5,  # reserved
                )

                sock.sendto(header + chunk, (group, port))
                offset += chunk_len
                packet_id += 1
                time.sleep(_PKT_DELAY)

            loop += 1
            print(f"  loop {loop} complete ({packet_id} chunks), repeating...")
            time.sleep(0.1)
    except KeyboardInterrupt:
        print(f"\nzycast: stopped after {loop} loop(s)")
    finally:
        sock.close()


if __name__ == "__main__":
    image = sys.argv[1] if len(sys.argv) > 1 else \
        "images/openwrt-25.12.4-ramips-mt7621-zyxel_nr7101-initramfs-recovery.bin"
    iface_ip = sys.argv[2] if len(sys.argv) > 2 else "192.168.2.10"
    send(image, iface_ip)
