#!/usr/bin/env python3
"""Wake-on-LAN webhook server for MAAS power management.

Runs on the MAAS controller (or any machine on the bench network).
Receives HTTP requests from MAAS's webhook power driver and translates
them into WoL magic packets or ping checks.

Endpoints:
    POST /power/on?mac=<MAC>    → send WoL magic packet
    POST /power/off?mac=<MAC>    → no-op (WoL can't power off)
    GET  /power/query?mac=<MAC>&ip=<IP> → ping check, return status

MAAS webhook driver config:
    power_type = webhook
    power_on_uri = http://<this-server>:8081/power/on?mac=<MAC>
    power_off_uri = http://<this-server>:8081/power/off?mac=<MAC>
    power_query_uri = http://<this-server>:8081/power/query?mac=<MAC>&ip=<IP>
    power_on_regex = status.*:.*running
    power_off_regex = status.*:.*stopped

Usage:
    maas_wol_webhook.py [--port 8081] [--interface eth0]
"""

from __future__ import annotations

import argparse
import asyncio
import struct
import subprocess
import sys
from http.server import ThreadingHTTPServer as HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


def send_wol(mac: str, interface: str = "") -> bool:
    """Send a Wake-on-LAN magic packet to the given MAC address."""
    try:
        # Clean the MAC address
        mac_clean = mac.replace(":", "").replace("-", "").lower()
        if len(mac_clean) != 12:
            return False

        # Build magic packet: 6×0xFF + 16×MAC
        mac_bytes = bytes.fromhex(mac_clean)
        magic = b"\xff" * 6 + mac_bytes * 16

        # Send as UDP broadcast on port 9 (WoL standard)
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if interface:
            try:
                sock.setsockopt(socket.SOL_SOCKET, 25, interface.encode())  # SO_BINDTODEVICE
            except (OSError, AttributeError):
                pass  # Not all platforms support SO_BINDTODEVICE
        sock.sendto(magic, ("255.255.255.255", 9))
        sock.sendto(magic, ("255.255.255.255", 7))  # Alternate port
        sock.close()
        return True
    except Exception as e:
        print(f"WoL send error: {e}", file=sys.stderr)
        return False


def ping_host(ip: str) -> bool:
    """Check if a host is reachable via ping."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", ip],
            capture_output=True, timeout=5
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


class WoLHandler(BaseHTTPRequestHandler):
    server_version = "MaasWoL/1.0"

    def _send_json(self, data: dict, code: int = 200):
        import json
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        mac = params.get("mac", [""])[0]

        if not mac:
            self._send_json({"error": "missing mac parameter"}, 400)
            return

        if parsed.path == "/power/on":
            interface = self.server.wol_interface
            success = send_wol(mac, interface)
            if success:
                self._send_json({"status": "running", "mac": mac, "action": "wol_sent"})
            else:
                self._send_json({"error": "wol_send_failed", "mac": mac}, 500)

        elif parsed.path == "/power/off":
            # WoL cannot power off — return success but note the limitation
            self._send_json({"status": "stopped", "mac": mac, "action": "noop"})

        else:
            self._send_json({"error": "not found"}, 404)

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        mac = params.get("mac", [""])[0]
        ip = params.get("ip", [""])[0]

        if parsed.path == "/power/query":
            if not ip:
                self._send_json({"error": "missing ip parameter"}, 400)
                return
            alive = ping_host(ip)
            status = "running" if alive else "stopped"
            self._send_json({"status": status, "mac": mac, "ip": ip})

        elif parsed.path == "/health":
            self._send_json({"status": "ok"})

        else:
            self._send_json({"error": "not found"}, 404)

    def log_message(self, format, *args):
        """Log to stderr."""
        import datetime
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        try:
            msg = format % args if args else format
        except (TypeError, ValueError):
            msg = str(args) if args else format
        print(f"[{ts}] {self.address_string()} {msg}")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--port", type=int, default=8081,
                   help="HTTP port to listen on (default: 8081)")
    p.add_argument("--interface", default="",
                   help="Network interface to send WoL packets from (default: all)")
    args = p.parse_args()

    server = HTTPServer(("0.0.0.0", args.port), WoLHandler)
    server.wol_interface = args.interface
    print(f"MAAS WoL webhook server listening on :{args.port}")
    if args.interface:
        print(f"Sending WoL packets from interface: {args.interface}")
    print(f"Endpoints: POST /power/on?mac=<MAC>, POST /power/off?mac=<MAC>, GET /power/query?mac=<MAC>&ip=<IP>")
    server.serve_forever()


if __name__ == "__main__":
    main()
