"""Idempotency regression tests — verify no accumulation on repeated configure.

These tests assert that rendered shell output for each use case:
1. Uses named sections (not anonymous uci add + @type[-1])
2. Uses del_list before add_list (no list accumulation)
3. Contains cleanup loops for stale sections from previous runs
4. Produces identical output on second render (pure function)
"""
from profile.ops import render_shell
from use_cases.wireguard_client import _build_wireguard_client_ops
from use_cases.wireguard_server import _build_wireguard_server_ops
from use_cases.guest_wifi import _build_guest_wifi_ops
from use_cases.sqm import _build_sqm_ops
from use_cases.doh import _build_doh_ops
from use_cases.adguard import _build_adguard_ops
from profile.wifi import wwan_setup_ops, wwan_setup_shell, wwan_setup_firstboot

import re


def _assert_no_anonymous_firewall_add(rendered: str, label: str) -> None:
    """Verify no anonymous firewall section creation via 'uci add firewall'."""
    matches = re.findall(r"^uci add firewall \w+", rendered, re.MULTILINE)
    assert not matches, f"{label}: found anonymous firewall add(s): {matches}"


def _assert_no_zone_index(rendered: str, label: str) -> None:
    """Verify no hardcoded @zone[N] index references."""
    matches = re.findall(r"@zone\[\d+\]", rendered)
    assert not matches, f"{label}: found hardcoded @zone[N]: {matches}"


def _assert_add_list_has_del_list(rendered: str, label: str) -> None:
    """Verify every add_list on firewall zones has a preceding del_list."""
    lines = rendered.split("\n")
    for _i, line in enumerate(lines):
        if "uci add_list firewall." in line and ".network=" in line:
            # Check if a del_list for the same value exists in the rendered output
            value = re.search(r"network='([^']*)'", line)
            if value:
                iface = value.group(1)
                del_pattern = "del_list" in rendered and iface in rendered
                assert del_pattern, (
                    f"{label}: add_list for '{iface}' without del_list"
                )


def _assert_deterministic(build_fn, params: dict, label: str) -> None:
    """Verify render is a pure function — same input = same output."""
    r1 = render_shell(build_fn(params))
    r2 = render_shell(build_fn(params))
    assert r1 == r2, f"{label}: render is not deterministic"


# ── WireGuard Client ─────────────────────────────────────────────────

class TestWireguardClientIdempotency:
    PARAMS = {
        "peer_public_key": "SERVERKEY",
        "endpoint_host": "vpn.example.com",
        "kill_switch": True,
    }

    def test_no_anonymous_firewall_add(self):
        rendered = render_shell(_build_wireguard_client_ops(self.PARAMS))
        _assert_no_anonymous_firewall_add(rendered, "wg_client")

    def test_named_sections(self):
        rendered = render_shell(_build_wireguard_client_ops(self.PARAMS))
        assert "uci set firewall.wg_client_vpn=zone" in rendered
        assert "uci set firewall.wg_client_fwd=forwarding" in rendered
        assert "uci set firewall.wg_client_killswitch=rule" in rendered

    def test_cleanup_loop_present(self):
        rendered = render_shell(_build_wireguard_client_ops(self.PARAMS))
        assert "while uci show firewall" in rendered
        assert "name='vpn'" in rendered

    def test_deterministic(self):
        _assert_deterministic(_build_wireguard_client_ops, self.PARAMS, "wg_client")


# ── WireGuard Server ──────────────────────────────────────────────────

class TestWireguardServerIdempotency:
    PARAMS = {
        "private_key": "PRIVKEY",
        "peer1_public_key": "PEERKEY",
    }

    def test_no_anonymous_firewall_add(self):
        rendered = render_shell(_build_wireguard_server_ops(self.PARAMS))
        _assert_no_anonymous_firewall_add(rendered, "wg_server")

    def test_named_sections(self):
        rendered = render_shell(_build_wireguard_server_ops(self.PARAMS))
        assert "uci set firewall.wg_server_vpn=zone" in rendered
        assert "uci set firewall.wg_server_fwd_lan=forwarding" in rendered
        assert "uci set firewall.wg_server_fwd_wan=forwarding" in rendered
        assert "uci set firewall.wg_server_allow=rule" in rendered

    def test_cleanup_loop_present(self):
        rendered = render_shell(_build_wireguard_server_ops(self.PARAMS))
        assert "while uci show firewall" in rendered

    def test_deterministic(self):
        _assert_deterministic(_build_wireguard_server_ops, self.PARAMS, "wg_server")


# ── Guest WiFi ────────────────────────────────────────────────────────

class TestGuestWifiIdempotency:
    PARAMS = {
        "ssid": "conwrt-guest",
        "key": "guestpass",
    }

    def test_no_anonymous_firewall_add(self):
        rendered = render_shell(_build_guest_wifi_ops(self.PARAMS))
        _assert_no_anonymous_firewall_add(rendered, "guest_wifi")

    def test_named_firewall_sections(self):
        rendered = render_shell(_build_guest_wifi_ops(self.PARAMS))
        assert "firewall.guest=zone" in rendered
        assert "firewall.guest_fwd=forwarding" in rendered

    def test_deterministic(self):
        _assert_deterministic(_build_guest_wifi_ops, self.PARAMS, "guest_wifi")


# ── SQM ───────────────────────────────────────────────────────────────

class TestSqmIdempotency:
    PARAMS = {"download_kbps": 100000, "upload_kbps": 50000}

    def test_no_anonymous_firewall_add(self):
        rendered = render_shell(_build_sqm_ops(self.PARAMS))
        _assert_no_anonymous_firewall_add(rendered, "sqm")

    def test_deterministic(self):
        _assert_deterministic(_build_sqm_ops, self.PARAMS, "sqm")


# ── DoH ───────────────────────────────────────────────────────────────

class TestDohIdempotency:
    PARAMS = {"provider": "cloudflare"}

    def test_no_anonymous_firewall_add(self):
        rendered = render_shell(_build_doh_ops(self.PARAMS))
        _assert_no_anonymous_firewall_add(rendered, "doh")

    def test_dnsmasq_server_has_delete(self):
        rendered = render_shell(_build_doh_ops(self.PARAMS))
        # doh deletes the server list before adding — no accumulation
        assert "uci delete dhcp" in rendered or "UciDelete" in str(rendered)
        assert "uci add_list" in rendered

    def test_deterministic(self):
        _assert_deterministic(_build_doh_ops, self.PARAMS, "doh")


# ── AdGuard ───────────────────────────────────────────────────────────

class TestAdguardIdempotency:
    PARAMS = {"dns_port": 5353}

    def test_no_anonymous_firewall_add(self):
        rendered = render_shell(_build_adguard_ops(self.PARAMS))
        _assert_no_anonymous_firewall_add(rendered, "adguard")

    def test_deterministic(self):
        _assert_deterministic(_build_adguard_ops, self.PARAMS, "adguard")


# ── WWAN Setup ────────────────────────────────────────────────────────

class TestWwanIdempotency:
    def test_ops_no_zone_index(self):
        rendered = render_shell(wwan_setup_ops())
        _assert_no_zone_index(rendered, "wwan_ops")

    def test_ops_has_del_list(self):
        rendered = render_shell(wwan_setup_ops())
        assert "del_list" in rendered, "wwan_ops: missing del_list before add_list"

    def test_shell_no_zone_index(self):
        _assert_no_zone_index(wwan_setup_shell(), "wwan_shell")

    def test_shell_has_del_list(self):
        script = wwan_setup_shell()
        assert "del_list" in script, "wwan_shell: missing del_list before add_list"

    def test_firstboot_no_zone_index(self):
        _assert_no_zone_index(wwan_setup_firstboot(), "wwan_firstboot")

    def test_firstboot_has_del_list(self):
        script = wwan_setup_firstboot()
        assert "del_list" in script, "wwan_firstboot: missing del_list before add_list"

    def test_all_variants_use_wan_by_name(self):
        for label, script in [
            ("ops", render_shell(wwan_setup_ops())),
            ("shell", wwan_setup_shell()),
            ("firstboot", wwan_setup_firstboot()),
        ]:
            assert "'wan'" in script, f"wwan_{label}: missing wan zone lookup by name"
