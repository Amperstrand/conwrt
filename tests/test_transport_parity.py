"""Transport parity tests: verify render_shell and render_ubus produce
equivalent UCI mutations for each use case.

Shell-only ops (section type declarations, ShellCommand fallbacks,
comments, blank lines) are excluded from comparison — only typed UCI
ops that both transports can handle are compared.
"""
import re
from profile.ops import render_shell, render_ubus


def _extract_uci_from_shell(script: str) -> list[tuple]:
    tuples: list[tuple] = []
    for line in script.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"uci set ([\w-]+)\.([^.]+)\.(\S+?)='([^']*)'", line)
        if m:
            tuples.append(("set", m.group(1), m.group(2), m.group(3), m.group(4)))
            continue
        m = re.match(r"uci add_list ([\w-]+)\.([^.]+)\.(\S+?)='([^']*)'", line)
        if m:
            tuples.append(("add-list", m.group(1), m.group(2), m.group(3), m.group(4)))
            continue
        m = re.match(r"uci commit ([\w-]+)", line)
        if m:
            tuples.append(("commit", m.group(1)))
            continue
        m = re.match(r"uci delete ([\w-]+)\.([^.]+?)(?:\.(\S+))?$", line)
        if m:
            tuples.append(("delete", m.group(1), m.group(2), m.group(3) or ""))
            continue
    return tuples


def _extract_uci_from_ubus(calls: list) -> list[tuple]:
    tuples: list[tuple] = []
    for call in calls:
        if call.method == "set" and call.object_name == "uci":
            p = call.params
            for k, v in p.get("values", {}).items():
                if isinstance(v, list):
                    for item in v:
                        tuples.append(("add-list", p["config"], p["section"], k, str(item)))
                else:
                    tuples.append(("set", p["config"], p["section"], k, str(v)))
        elif call.method == "commit" and call.object_name == "uci":
            tuples.append(("commit", call.params["config"]))
        elif call.method == "delete" and call.object_name == "uci":
            p = call.params
            tuples.append(("delete", p["config"], p["section"], p.get("option", "")))
        elif call.method == "add" and call.object_name == "uci":
            p = call.params
            config = p["config"]
            section_type = p["type"]
            for k, v in p.get("values", {}).items():
                if isinstance(v, list):
                    for item in v:
                        tuples.append(("add-list", config, f"@{section_type}[-1]", k, str(item)))
                else:
                    tuples.append(("set", config, f"@{section_type}[-1]", k, str(v)))
    return tuples


def _assert_parity(ops_fn, params: dict) -> None:
    ops = ops_fn(params)
    shell_uci = _extract_uci_from_shell(render_shell(ops))
    ubus_uci = _extract_uci_from_ubus(render_ubus(ops))
    assert shell_uci == ubus_uci, (
        f"\n--- shell UCI ({len(shell_uci)}) ---\n"
        + "\n".join(str(t) for t in shell_uci)
        + f"\n--- ubus UCI ({len(ubus_uci)}) ---\n"
        + "\n".join(str(t) for t in ubus_uci)
    )


class TestParitySqm:
    def test_default(self):
        from use_cases.sqm import _build_sqm_ops
        _assert_parity(_build_sqm_ops, {"download_kbps": 100, "upload_kbps": 50})

    def test_custom_interface(self):
        from use_cases.sqm import _build_sqm_ops
        _assert_parity(_build_sqm_ops, {"download_kbps": 100, "upload_kbps": 50, "interface": "eth1"})


class TestParitySshHardening:
    def test_default(self):
        from use_cases.ssh_hardening import _build_ssh_hardening_ops
        _assert_parity(_build_ssh_hardening_ops, {})

    def test_custom_port(self):
        from use_cases.ssh_hardening import _build_ssh_hardening_ops
        _assert_parity(_build_ssh_hardening_ops, {"port": 2222, "idle_timeout": 600})


class TestParityTravelmate:
    def test_default(self):
        from use_cases.travelmate import _build_travelmate_ops
        _assert_parity(_build_travelmate_ops, {})

    def test_custom_radio(self):
        from use_cases.travelmate import _build_travelmate_ops
        _assert_parity(_build_travelmate_ops, {"radio": "radio1", "timeout": 120})


class TestParityAdguard:
    def test_default(self):
        from use_cases.adguard import _build_adguard_ops
        _assert_parity(_build_adguard_ops, {})

    def test_custom_ports(self):
        from use_cases.adguard import _build_adguard_ops
        _assert_parity(_build_adguard_ops, {"dns_port": 53, "web_port": 8080})


class TestParityMwan3:
    def test_default(self):
        from use_cases.mwan3 import _build_mwan3_ops
        _assert_parity(_build_mwan3_ops, {})


class TestParityOpenclash:
    def test_default(self):
        from use_cases.openclash import _build_openclash_ops
        _assert_parity(_build_openclash_ops, {})


class TestParityWireguardClient:
    def test_default(self):
        from use_cases.wireguard_client import _build_wireguard_client_ops
        _assert_parity(_build_wireguard_client_ops, {
            "peer_public_key": "KEY", "endpoint_host": "vpn.example.com",
        })

    def test_kill_switch_off(self):
        from use_cases.wireguard_client import _build_wireguard_client_ops
        _assert_parity(_build_wireguard_client_ops, {
            "peer_public_key": "KEY", "endpoint_host": "vpn.example.com",
            "kill_switch": False,
        })


class TestParityWireguardServer:
    def test_default(self):
        from use_cases.wireguard_server import _build_wireguard_server_ops
        _assert_parity(_build_wireguard_server_ops, {"private_key": "testkey"})

    def test_with_peer(self):
        from use_cases.wireguard_server import _build_wireguard_server_ops
        _assert_parity(_build_wireguard_server_ops, {
            "private_key": "testkey",
            "peer1_public_key": "peerkey",
            "peer1_allowed_ips": "10.1.99.2/32",
        })


class TestParityGuestWifi:
    def test_default(self):
        from use_cases.guest_wifi import _build_guest_wifi_ops
        _assert_parity(_build_guest_wifi_ops, {})

    def test_secured(self):
        from use_cases.guest_wifi import _build_guest_wifi_ops
        _assert_parity(_build_guest_wifi_ops, {
            "ssid": "MyGuest", "key": "guestpass", "encryption": "psk2",
        })

    def test_open(self):
        from use_cases.guest_wifi import _build_guest_wifi_ops
        _assert_parity(_build_guest_wifi_ops, {
            "ssid": "FreeWiFi", "encryption": "none", "isolation": False,
        })


class TestParityDoh:
    def test_default(self):
        from use_cases.doh import _build_doh_ops
        _assert_parity(_build_doh_ops, {})

    def test_google(self):
        from use_cases.doh import _build_doh_ops
        _assert_parity(_build_doh_ops, {"provider": "google"})

    def test_custom_port(self):
        from use_cases.doh import _build_doh_ops
        _assert_parity(_build_doh_ops, {"listen_port": 5353})


class TestParityMesh11sd:
    def test_default(self):
        from use_cases.mesh11sd import _build_mesh11sd_ops
        _assert_parity(_build_mesh11sd_ops, {"mesh_id": "test-mesh"})

    def test_with_ap(self):
        from use_cases.mesh11sd import _build_mesh11sd_ops
        _assert_parity(_build_mesh11sd_ops, {
            "mesh_id": "test-mesh", "ssid": "MeshNet", "key": "secret",
        })


class TestParityFipsRfcomm:
    def test_default(self):
        from use_cases.fips_bluetooth_rfcomm import _build_fips_rfcomm_ops
        _assert_parity(_build_fips_rfcomm_ops, {})

    def test_server(self):
        from use_cases.fips_bluetooth_rfcomm import _build_fips_rfcomm_ops
        _assert_parity(_build_fips_rfcomm_ops, {"role": "server", "channel": 5})

    def test_with_peers(self):
        from use_cases.fips_bluetooth_rfcomm import _build_fips_rfcomm_ops
        _assert_parity(_build_fips_rfcomm_ops, {
            "role": "client",
            "peers": [{"npub": "npub1test", "bt_mac": "AA:BB:CC:DD:EE:FF"}],
        })


class TestParityTollgate:
    def test_default(self):
        from use_cases.tollgate import _build_tollgate_ops
        _assert_parity(_build_tollgate_ops, {})

    def test_with_payment(self):
        from use_cases.tollgate import _build_tollgate_ops
        _assert_parity(_build_tollgate_ops, {
            "mint_url": "https://mint.example.com",
            "lightning_address": "pay@node.com",
            "price_per_minute": 5,
        })

    def test_mint_only(self):
        from use_cases.tollgate import _build_tollgate_ops
        _assert_parity(_build_tollgate_ops, {
            "mint_url": "https://mint.example.com",
        })


# Shell-only use cases (no parity test):
# - auto-sqm: heredoc-written script contains UCI-like lines (sqm.$INTERFACE=queue)
#   that would contaminate the shell extractor; filesystem ops have no typed equivalent
# - usb-tether: runtime USB device discovery via /sys/class/net walk; uci commands
#   use shell variables ($USB_DEV, $zone) not known at op-generation time
# These intentionally rely on shell constructs that cannot map to ubus RPC.
