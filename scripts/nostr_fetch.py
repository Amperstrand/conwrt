"""Minimal nostr relay client for querying NIP-94 release events.

Connects to WebSocket relays using only the Python standard library (socket + ssl).
Queries for kind 1063 (NIP-94 file metadata) events and returns structured release
information for firmware packages.

This module is self-contained — no external dependencies, no conwrt imports.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import socket
import ssl
import struct
import time
from urllib.parse import urlparse

log = logging.getLogger(__name__)

# -- Default constants ----------------------------------------------------------

# From TollGate's config_manager/config_manager_config.go defaults
DEFAULT_RELAYS = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://nostr.mom",
]

# From TollGate's config_manager/config_manager_identities.go trusted_maintainer_1
TRUSTED_PUBKEY = "5075e61f0b048148b60105c1dd72bbeae1957336ae5824087e52efa374f8416a"

# NIP-94 file metadata event kind
NIP94_KIND = 1063


# -- NIP-94 event parsing -------------------------------------------------------

def parse_nip94_event(event: dict) -> dict:
    """Extract structured release fields from a NIP-94 (kind 1063) event.

    Returns a flat dict with event metadata and tag-derived fields:
    event_id, pubkey, created_at, url, x (sha256), version, architecture,
    filename, release_channel, package_name, compression.
    """
    result: dict = {
        "event_id": event["id"],
        "pubkey": event["pubkey"],
        "created_at": event["created_at"],
    }
    for tag in event.get("tags", []):
        if len(tag) >= 2:
            result[tag[0]] = tag[1]
    return result


# -- WebSocket client (stdlib only) ---------------------------------------------

class NostrRelayClient:
    """Minimal WebSocket client for nostr relay communication.

    Uses raw socket + ssl for WSS connections. Implements enough of RFC 6455
    for text frame exchange with nostr relays.
    """

    def __init__(self) -> None:
        self._sock: socket.socket | None = None

    def connect(self, relay_url: str, timeout: float = 10.0) -> None:
        """Connect to a nostr relay via WebSocket over TLS.

        Performs the HTTP Upgrade handshake required by RFC 6455.
        """
        parsed = urlparse(relay_url)
        host = parsed.hostname or ""
        port = parsed.port or 443
        path = parsed.path or "/"

        ctx = ssl.create_default_context()
        raw = socket.create_connection((host, port), timeout=timeout)
        self._sock = ctx.wrap_socket(raw, server_hostname=host)

        key = base64.b64encode(os.urandom(16)).decode()
        headers = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        self._sock.sendall(headers.encode())

        # Read HTTP 101 response
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed during WebSocket handshake")
            response += chunk

        status_line = response.split(b"\r\n")[0].decode()
        if "101" not in status_line:
            raise ConnectionError(f"WebSocket upgrade failed: {status_line}")

    def send(self, message: list) -> None:
        """JSON-encode *message* and send as a masked text WebSocket frame."""
        self._send_frame(0x01, json.dumps(message).encode())

    def recv(self) -> list | None:
        """Receive one WebSocket frame, JSON-decode, return parsed list.

        Returns ``None`` on close frame.
        """
        data = self._recv_exact(2)
        opcode = data[0] & 0x0F

        if opcode == 0x08:  # close
            return None

        if opcode == 0x09:  # ping → pong
            self._send_frame(0x0A, b"")
            return self.recv()

        length = data[1] & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._recv_exact(8))[0]

        payload = self._recv_exact(length)
        return json.loads(payload)

    def close(self) -> None:
        """Send a masked close frame and close the socket."""
        if self._sock:
            try:
                self._send_frame(0x88, b"")
            except OSError:
                pass
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    # -- Private helpers ---------------------------------------------------------

    def _recv_exact(self, n: int) -> bytes:
        """Read exactly *n* bytes, handling partial reads."""
        assert self._sock is not None
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Connection closed")
            buf += chunk
        return buf

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        """Encode and send a masked WebSocket client frame."""
        assert self._sock is not None
        mask = os.urandom(4)
        header = bytearray()
        header.append(0x80 | opcode)  # FIN + opcode, mask bit set

        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))

        header.extend(mask)

        masked = bytearray(len(payload))
        for i in range(len(payload)):
            masked[i] = payload[i] ^ mask[i & 3]

        self._sock.sendall(bytes(header) + bytes(masked))


# -- High-level query -----------------------------------------------------------

def query_releases(
    relay_urls: list[str],
    trusted_pubkey: str,
    package_name: str,
    architecture: str,
    release_channel: str = "stable",
    timeout: float = 15.0,
) -> list[dict]:
    """Query nostr relays for NIP-94 release events matching the given filters.

    Connects to each relay, sends a REQ subscription for kind 1063 events,
    collects results until EOSE or timeout, and returns deduplicated releases
    sorted by ``created_at`` descending (newest first).

    Relay failures are logged and skipped — the function never raises for
    individual relay errors.
    """
    seen_ids: set[str] = set()
    releases: list[dict] = []

    for url in relay_urls:
        client = NostrRelayClient()
        try:
            client.connect(url, timeout=min(timeout, 10.0))

            sub_id = f"conwrt-{os.urandom(4).hex()}"
            client.send([
                "REQ", sub_id,
                {
                    "kinds": [NIP94_KIND],
                    "authors": [trusted_pubkey],
                    "#architecture": [architecture],
                    "#release_channel": [release_channel],
                    "#package_name": [package_name],
                },
            ])

            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if client._sock:
                    client._sock.settimeout(remaining)

                msg = client.recv()
                if msg is None:
                    break

                if not isinstance(msg, list) or len(msg) < 2:
                    continue

                if msg[0] == "EOSE":
                    break

                if msg[0] == "EVENT" and len(msg) >= 3:
                    event = msg[2]
                    if not isinstance(event, dict):
                        continue
                    if event.get("pubkey") != trusted_pubkey:
                        continue
                    eid = event.get("id", "")
                    if eid in seen_ids:
                        continue
                    seen_ids.add(eid)
                    releases.append(parse_nip94_event(event))

            client.send(["CLOSE", sub_id])

        except (
            ConnectionError,
            socket.timeout,
            ssl.SSLError,
            json.JSONDecodeError,
            OSError,
        ) as exc:
            log.debug("Relay %s failed: %s", url, exc)
        finally:
            client.close()

    releases.sort(key=lambda r: r.get("created_at", 0), reverse=True)
    return releases
