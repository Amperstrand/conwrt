"""Unit tests for nostr_fetch.py — NIP-94 relay client."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from nostr_fetch import (
    NIP94_KIND,
    TRUSTED_PUBKEY,
    NostrRelayClient,
    parse_nip94_event,
    query_releases,
)

SAMPLE_EVENT = {
    "id": "evt_001",
    "pubkey": TRUSTED_PUBKEY,
    "created_at": 1700000000,
    "kind": NIP94_KIND,
    "tags": [
        ["url", "https://blossom.example.com/tollgate-wrt_v0.4.0.ipk"],
        ["x", "deadbeef" * 8],
        ["version", "v0.4.0"],
        ["architecture", "aarch64_cortex-a53"],
        ["release_channel", "stable"],
        ["package_name", "tollgate-wrt"],
        ["compression", "none"],
        ["filename", "tollgate-wrt_v0.4.0.ipk"],
    ],
    "content": "",
    "sig": "sig_placeholder",
}

OTHER_PUBKEY = "0" * 64


# ---------------------------------------------------------------------------
# parse_nip94_event
# ---------------------------------------------------------------------------


class TestParseNip94Event:
    def test_extracts_all_fields(self):
        result = parse_nip94_event(SAMPLE_EVENT)
        assert result["event_id"] == "evt_001"
        assert result["pubkey"] == TRUSTED_PUBKEY
        assert result["created_at"] == 1700000000
        assert result["url"] == "https://blossom.example.com/tollgate-wrt_v0.4.0.ipk"
        assert result["x"] == "deadbeef" * 8
        assert result["version"] == "v0.4.0"
        assert result["architecture"] == "aarch64_cortex-a53"
        assert result["release_channel"] == "stable"
        assert result["package_name"] == "tollgate-wrt"
        assert result["compression"] == "none"
        assert result["filename"] == "tollgate-wrt_v0.4.0.ipk"


# ---------------------------------------------------------------------------
# NostrRelayClient._send_frame
# ---------------------------------------------------------------------------


class TestNostrRelayClientSendFrame:
    @patch("nostr_fetch.os.urandom")
    def test_send_frame(self, mock_urandom):
        mask = b"\xaa\xbb\xcc\xdd"
        mock_urandom.return_value = mask

        client = NostrRelayClient()
        client._sock = MagicMock()
        client._send_frame(0x01, b"hello")

        sent = client._sock.sendall.call_args[0][0]
        # FIN + opcode 0x01 = 0x81
        assert sent[0] == 0x81
        # MASK bit | length 5 = 0x85
        assert sent[1] == 0x85
        # 4-byte mask key
        assert sent[2:6] == mask
        # Masked payload: each byte XOR'd with mask[i & 3]
        expected = bytes(b ^ mask[i & 3] for i, b in enumerate(b"hello"))
        assert sent[6:] == expected


# ---------------------------------------------------------------------------
# NostrRelayClient.recv — text frame
# ---------------------------------------------------------------------------


class TestNostrRelayClientRecv:
    def test_recv_text_frame(self):
        client = NostrRelayClient()
        client._sock = MagicMock()

        payload = json.dumps(["EVENT", "sub1", {"id": "abc"}]).encode()
        header = bytes([0x81, len(payload)])  # FIN+text, unmasked server frame
        client._sock.recv.side_effect = [header, payload]

        result = client.recv()
        assert result == ["EVENT", "sub1", {"id": "abc"}]


# ---------------------------------------------------------------------------
# NostrRelayClient.recv — ping → pong
# ---------------------------------------------------------------------------


class TestNostrRelayClientRecvPing:
    def test_ping_triggers_pong(self):
        client = NostrRelayClient()
        client._sock = MagicMock()

        # Frame 1: ping (opcode 0x09), length 0
        ping_header = bytes([0x89, 0x00])
        # Frame 2: text (opcode 0x01) with JSON payload
        next_payload = json.dumps(["OK", "sub1", True]).encode()
        next_header = bytes([0x81, len(next_payload)])

        client._sock.recv.side_effect = [ping_header, next_header, next_payload]

        with patch.object(client, "_send_frame") as mock_send:
            result = client.recv()
            mock_send.assert_called_once_with(0x0A, b"")

        assert result == ["OK", "sub1", True]


# ---------------------------------------------------------------------------
# NostrRelayClient.recv — close frame
# ---------------------------------------------------------------------------


class TestNostrRelayClientRecvClose:
    def test_close_returns_none(self):
        client = NostrRelayClient()
        client._sock = MagicMock()

        close_header = bytes([0x88, 0x00])  # FIN + close opcode, length 0
        client._sock.recv.side_effect = [close_header]

        assert client.recv() is None


# ---------------------------------------------------------------------------
# query_releases
# ---------------------------------------------------------------------------


class TestQueryReleases:
    @patch("nostr_fetch.NostrRelayClient")
    def test_query_releases(self, MockClient):
        mock_client = MockClient.return_value
        mock_client._sock = MagicMock()
        mock_client.recv.side_effect = [
            ["EVENT", "sub1", SAMPLE_EVENT],
            ["EOSE", "sub1"],
        ]

        result = query_releases(
            relay_urls=["wss://relay.example.com"],
            trusted_pubkey=TRUSTED_PUBKEY,
            package_name="tollgate-wrt",
            architecture="aarch64_cortex-a53",
        )

        assert len(result) == 1
        assert result[0]["event_id"] == "evt_001"
        assert result[0]["version"] == "v0.4.0"

    @patch("nostr_fetch.NostrRelayClient")
    def test_query_releases_dedup(self, MockClient):
        mock_client = MockClient.return_value
        mock_client._sock = MagicMock()
        # Two relays return the same event (same id)
        mock_client.recv.side_effect = [
            ["EVENT", "s1", SAMPLE_EVENT],
            ["EOSE", "s1"],
            ["EVENT", "s2", SAMPLE_EVENT],
            ["EOSE", "s2"],
        ]

        result = query_releases(
            relay_urls=["wss://relay1.example.com", "wss://relay2.example.com"],
            trusted_pubkey=TRUSTED_PUBKEY,
            package_name="tollgate-wrt",
            architecture="aarch64_cortex-a53",
        )

        assert len(result) == 1  # deduplicated

    @patch("nostr_fetch.NostrRelayClient")
    def test_query_releases_failure_skipped(self, MockClient):
        # First client: connect raises → relay skipped
        bad = MagicMock()
        bad.connect.side_effect = ConnectionError("refused")
        bad._sock = None
        # Second client: returns events normally
        good = MagicMock()
        good._sock = MagicMock()
        good.recv.side_effect = [
            ["EVENT", "s1", SAMPLE_EVENT],
            ["EOSE", "s1"],
        ]
        MockClient.side_effect = [bad, good]

        result = query_releases(
            relay_urls=["wss://bad.relay", "wss://good.relay"],
            trusted_pubkey=TRUSTED_PUBKEY,
            package_name="tollgate-wrt",
            architecture="aarch64_cortex-a53",
        )

        assert len(result) == 1
        assert result[0]["event_id"] == "evt_001"

    @patch("nostr_fetch.NostrRelayClient")
    def test_query_releases_pubkey_filter(self, MockClient):
        other_event = {**SAMPLE_EVENT, "pubkey": OTHER_PUBKEY, "id": "evt_other"}
        mock_client = MockClient.return_value
        mock_client._sock = MagicMock()
        mock_client.recv.side_effect = [
            ["EVENT", "sub1", other_event],
            ["EOSE", "sub1"],
        ]

        result = query_releases(
            relay_urls=["wss://relay.example.com"],
            trusted_pubkey=TRUSTED_PUBKEY,
            package_name="tollgate-wrt",
            architecture="aarch64_cortex-a53",
        )

        assert result == []
