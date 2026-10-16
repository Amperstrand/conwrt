"""Live VPN provider API contract tests — read-only, network-hitting.

These validate the APIs conwrt's provider scripts depend on, from the host,
with no router involved. Two tiers:

* **Public contract tests** (no credentials): assert the JSON shape of the
  public endpoints every generated first-boot script parses — when a provider
  renames a field, these fail instead of a silently broken tunnel on a
  flashed router.
* **Credential-gated tests** (skip unless the matching env var is set):
  exercise the read-only authenticated endpoints. Key-ROTATING endpoints
  (surfshark wireguard/new, ivpn key POST, mullvad wg-peers POST) are
  deliberately NOT exercised — they would invalidate existing keys.

Run: ``make test-live`` (or ``pytest tests/live -m live -v``).

Secrets come from the environment ONLY (never config.toml, never committed):

===========================  ==================================================
Env variable                 Unlocks
===========================  ==================================================
CONWRT_LIVE_NORDVPN_TOKEN    NordVPN /v1/users/services/credentials (read-only)
CONWRT_LIVE_PIA_USER         PIA token generation (with CONWRT_LIVE_PIA_PASS)
CONWRT_LIVE_PIA_PASS         (username is the p-number, not the email)
CONWRT_LIVE_MULLVAD_TOKEN    Mullvad GET /www/accounts/me (read-only)
===========================  ==================================================
"""
from __future__ import annotations

import base64
import os
import urllib.request

import pytest

pytestmark = pytest.mark.live

_TIMEOUT = 20


def _get_json(url: str, headers: dict[str, str] | None = None):
    req = urllib.request.Request(url, headers={"User-Agent": "conwrt-live-tests/1.0", **(headers or {})})
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        import json
        return json.loads(resp.read().decode())


def _post_json(url: str, data: bytes, headers: dict[str, str] | None = None):
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"User-Agent": "conwrt-live-tests/1.0", **(headers or {})},
    )
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        import json
        return json.loads(resp.read().decode())


# ---------------------------------------------------------------------------
# NordVPN — public endpoints consumed host-side by _resolve_endpoint()
# ---------------------------------------------------------------------------


class TestNordvpnPublicApi:
    def test_countries_list_contract(self):
        countries = _get_json("https://api.nordvpn.com/v1/servers/countries")
        assert isinstance(countries, list) and countries
        sample = countries[0]
        for field in ("id", "code", "name"):
            assert sample.get(field), f"country entry missing {field}"
        assert any(c["code"].lower() == "de" for c in countries)

    def test_recommendations_contract_includes_wg_public_key(self):
        servers = _get_json(
            "https://api.nordvpn.com/v1/servers/recommendations?limit=1"
            "&filters%5Bservers_technologies%5D%5Bidentifier%5D=wireguard_udp"
        )
        assert isinstance(servers, list) and servers
        server = servers[0]
        assert server.get("hostname") and server.get("station")
        keys = [
            meta.get("value")
            for tech in server.get("technologies", [])
            if tech.get("identifier") == "wireguard_udp"
            for meta in tech.get("metadata", [])
            if meta.get("name") == "public_key"
        ]
        assert keys and keys[0], "wireguard_udp server without public_key metadata"

    def test_hostname_filter_currently_ignored(self):
        """Canary: /v1/servers ignores hostname filters too (verified
        2026-10-14 — 100 arbitrary geo-local servers regardless of the pin).
        The hostname-pin path verifies client-side, so pins fail loudly today;
        if this canary flips, hostname pins work again."""
        servers = _get_json(
            "https://api.nordvpn.com/v1/servers?filters%5Bhostname%5D=de1507"
        )
        assert isinstance(servers, list)
        assert not any(s.get("hostname") == "de1507.nordvpn.com" for s in servers), \
            "hostname filter appears to WORK now — the pin-verification error path can be relaxed"

    def test_stations_ip_filter_currently_ignored(self):
        """Canary: /v1/servers ignores stations[ip] and returns an arbitrary
        100-server page. _resolve_endpoint relies on this being true (it
        refuses IP pins and client-side selects hostnames) — if NordVPN ever
        re-enables the filter, revisit the IP-pin refusal."""
        stations = _get_json(
            "https://api.nordvpn.com/v1/servers?filters%5Bstations%5D%5Bip%5D=203.0.113.1"
        )
        assert isinstance(stations, list)
        assert not any(s.get("station") == "203.0.113.1" for s in stations), \
            "stations[ip] filter appears to WORK now — the IP-pin refusal can be lifted"


# ---------------------------------------------------------------------------
# Mullvad — public relay list parsed on-device by vpn-mullvad
# ---------------------------------------------------------------------------


class TestMullvadPublicApi:
    def test_wireguard_relays_contract(self):
        relays = _get_json("https://api.mullvad.net/www/relays/wireguard/")
        assert isinstance(relays, list) and relays
        for relay in relays[:5]:
            for field in ("country_code", "ipv4_addr_in", "pubkey", "hostname"):
                assert relay.get(field), f"relay {relay.get('hostname')} missing {field}"

    def test_country_code_filter_finds_se(self):
        relays = _get_json("https://api.mullvad.net/www/relays/wireguard/")
        assert any(r.get("country_code") == "se" for r in relays)


# ---------------------------------------------------------------------------
# IVPN — public server list parsed on-device by vpn-ivpn
# ---------------------------------------------------------------------------


class TestIvpnPublicApi:
    def test_servers_contract(self):
        data = _get_json("https://api.ivpn.net/v4/servers.json")
        wg_gateways = data.get("wireguard", [])
        assert wg_gateways, "no wireguard gateways in servers.json"
        wg_hosts = [h for g in wg_gateways[:10] for h in g.get("hosts", []) if h.get("public_key")]
        assert wg_hosts, "no WireGuard-capable hosts in the first gateways"
        host = wg_hosts[0]
        assert host.get("host"), "wg host missing host IP"


# ---------------------------------------------------------------------------
# Surfshark — public cluster list parsed on-device by vpn-surfshark
# ---------------------------------------------------------------------------


class TestSurfsharkPublicApi:
    def test_servers_contract(self):
        clusters = _get_json("https://api.surfshark.com/v4/server/clusters/generic?countryCode=")
        assert isinstance(clusters, list) and clusters
        for cluster in clusters[:5]:
            for field in ("country", "countryCode", "connectionName", "pubKey"):
                assert cluster.get(field), f"cluster {cluster.get('connectionName')} missing {field}"


# ---------------------------------------------------------------------------
# Credential-gated, read-only authenticated endpoints
# ---------------------------------------------------------------------------


class TestNordvpnCredentials:
    TOKEN = os.environ.get("CONWRT_LIVE_NORDVPN_TOKEN", "")

    @pytest.mark.skipif(not TOKEN, reason="CONWRT_LIVE_NORDVPN_TOKEN not set")
    def test_service_credentials_include_nordlynx_key(self):
        basic = base64.b64encode(f"token:{self.TOKEN}".encode()).decode()
        creds = _get_json(
            "https://api.nordvpn.com/v1/users/services/credentials",
            headers={"Authorization": f"Basic {basic}"},
        )
        assert isinstance(creds, dict)
        assert creds.get("nordlynx_private_key"), "token valid but no nordlynx key returned"


class TestPiaToken:
    USER = os.environ.get("CONWRT_LIVE_PIA_USER", "")
    PASSWORD = os.environ.get("CONWRT_LIVE_PIA_PASS", "")

    @pytest.mark.skipif(not (USER and PASSWORD), reason="CONWRT_LIVE_PIA_USER/_PASS not set")
    def test_token_generation_returns_usable_token(self):
        from urllib.parse import urlencode
        payload = urlencode({"username": self.USER, "password": self.PASSWORD}).encode()
        data = _post_json(
            "https://www.privateinternetaccess.com/api/v2/token",
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert isinstance(data, dict)
        assert data.get("token"), "PIA credentials rejected (or 2FA-enabled account)"


class TestMullvadAccount:
    TOKEN = os.environ.get("CONWRT_LIVE_MULLVAD_TOKEN", "")

    @pytest.mark.skipif(not TOKEN, reason="CONWRT_LIVE_MULLVAD_TOKEN not set")
    def test_account_info_read_only(self):
        account = _get_json(
            "https://api.mullvad.net/www/accounts/me/",
            headers={"Authorization": f"Token {self.TOKEN}"},
        )
        assert isinstance(account, dict)
        assert "expiry" in account or "account_id" in account
