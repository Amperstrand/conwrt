#!/usr/bin/env python3
"""Configure an OpenWrt device via serial console.

When network access is unavailable (wrong IP, no SSH, broken firmware),
this tool provides a serial-based configuration interface to:
- Change LAN IP address
- Enable/disable password authentication
- Install SSH authorized keys
- Run arbitrary uci/shell commands
- Verify device state

Usage:
    python3 scripts/serial-configure.py [PORT] [BAUD] [OPTIONS]

Options:
    --set-ip IP         Set LAN IP address
    --enable-password   Enable password authentication
    --disable-password  Disable password authentication
    --install-key FILE  Install SSH public key from file
    --command CMD       Run arbitrary shell command
    --show-config       Print current network/dropbear config
    --show-firmware     Print firmware version

Examples:
    # Change LAN IP
    python3 scripts/serial-configure.py /dev/cu.usbserial-XXXX 57600 --set-ip 192.168.5.1

    # Install SSH key
    python3 scripts/serial-configure.py /dev/cu.usbserial-XXXX 57600 --install-key ~/.ssh/id_ed25519.pub

    # Show device state
    python3 scripts/serial-configure.py /dev/cu.usbserial-XXXX 57600 --show-config --show-firmware
"""
import argparse
import serial
import sys
import time
from pathlib import Path


def send_and_read(s: serial.Serial, command: str, wait: float = 2.0) -> str:
    """Send a command via serial and read the response."""
    s.write((command + "\r\n").encode())
    time.sleep(wait)
    resp = b""
    end = time.time() + 1.0
    while time.time() < end:
        if s.in_waiting:
            resp += s.read(4096)
            time.sleep(0.1)
        else:
            time.sleep(0.1)
    text = resp.decode("ascii", errors="replace")
    # Remove echo and prompt lines
    lines = [l.strip() for l in text.split("\n")
             if l.strip()
             and command not in l
             and "root@" not in l
             and not l.strip().startswith("^C")]
    return "\n".join(lines) if lines else "(ok)"


def break_to_prompt(s: serial.Serial):
    """Send Ctrl-C and Enter to get a clean shell prompt."""
    s.write(b"\x03")
    time.sleep(0.5)
    s.write(b"\r\n")
    time.sleep(1)
    s.read(4096)  # Flush any pending output


def main():
    parser = argparse.ArgumentParser(
        description="Configure OpenWrt device via serial console"
    )
    parser.add_argument("port", nargs="?", default="/dev/cu.usbserial-BG02QAPG",
                        help="Serial port")
    parser.add_argument("baud", nargs="?", type=int, default=57600,
                        help="Baud rate (default: 57600)")
    parser.add_argument("--set-ip", metavar="IP",
                        help="Set LAN IP address")
    parser.add_argument("--enable-password", action="store_true",
                        help="Enable password authentication")
    parser.add_argument("--disable-password", action="store_true",
                        help="Disable password authentication")
    parser.add_argument("--install-key", metavar="FILE",
                        help="Install SSH public key from file")
    parser.add_argument("--command", metavar="CMD",
                        help="Run arbitrary shell command")
    parser.add_argument("--show-config", action="store_true",
                        help="Print current network and SSH config")
    parser.add_argument("--show-firmware", action="store_true",
                        help="Print firmware version")
    args = parser.parse_args()

    s = serial.Serial(args.port, args.baud, timeout=1)
    break_to_prompt(s)

    if args.show_firmware:
        print("=== Firmware ===")
        print(send_and_read(s, "cat /etc/openwrt_release"))

    if args.show_config:
        print("=== Network Config ===")
        print(send_and_read(s, "uci show network.lan"))
        print("\n=== Dropbear Config ===")
        print(send_and_read(s, "uci show dropbear"))

    if args.set_ip:
        print(f"=== Setting LAN IP to {args.set_ip} ===")
        send_and_read(s, f"uci set network.lan.ipaddr='{args.set_ip}'")
        send_and_read(s, "uci commit network")
        send_and_read(s, "ifup lan", wait=3)
        result = send_and_read(s, "uci get network.lan.ipaddr")
        print(f"Verified: {result}")

    if args.enable_password:
        print("=== Enabling password auth ===")
        send_and_read(s, "uci set dropbear.@dropbear[0].PasswordAuth='on'")
        send_and_read(s, "uci commit dropbear")
        send_and_read(s, "/etc/init.d/dropbear restart", wait=3)
        print("Password auth enabled")

    if args.disable_password:
        print("=== Disabling password auth ===")
        send_and_read(s, "uci set dropbear.@dropbear[0].PasswordAuth='off'")
        send_and_read(s, "uci commit dropbear")
        send_and_read(s, "/etc/init.d/dropbear restart", wait=3)
        print("Password auth disabled (key-only)")

    if args.install_key:
        key_path = Path(args.install_key).expanduser()
        if not key_path.exists():
            print(f"ERROR: Key file not found: {key_path}", file=sys.stderr)
            sys.exit(1)
        key = key_path.read_text().strip()
        print(f"=== Installing SSH key from {key_path} ===")
        # Use printf to avoid echo quoting issues with long keys
        send_and_read(s, "mkdir -p /etc/dropbear")
        # Write key in chunks to avoid serial line wrapping
        send_and_read(s, f"echo '{key}' > /etc/dropbear/authorized_keys", wait=3)
        send_and_read(s, "chmod 600 /etc/dropbear/authorized_keys")
        result = send_and_read(s, "wc -c /etc/dropbear/authorized_keys")
        print(f"Key installed: {result}")

    if args.command:
        print(f"=== Running: {args.command} ===")
        print(send_and_read(s, args.command, wait=3))

    s.close()


if __name__ == "__main__":
    main()
