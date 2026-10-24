"""Shared building blocks for VPN provider use cases.

All provider modules import these helpers to avoid duplicating the
firewall, DNS, verification, and keypair-generation logic.

Shell fragments (*_sh) are raw strings for embedding in provider scripts.
Op builders (build_*_ops) return structured Op lists for the ops pipeline.
"""
from __future__ import annotations

from profile.ops import (
    BlankLine,
    Comment,
    Op,
    ServiceAction,
    ShellCommand,
    UciAddList,
    UciCommit,
    UciSet,
)
from profile.uci_helpers import uci_cleanup_sections


# -- Shell fragment generators (embedded in provider scripts) ------------------

JSON_HELPER_SH = """# JSON parsing: try jq, install via apk (OpenWrt >=25.x) or opkg (<=24.x)
if ! command -v jq >/dev/null 2>&1; then
    apk add jq >/dev/null 2>&1 || { opkg update >/dev/null 2>&1 && opkg install jq >/dev/null 2>&1; }
fi
json_get() {
    # $1 = key name; reads JSON from stdin; returns first string value
    if command -v jq >/dev/null 2>&1; then
        jq -r ".$1 // empty"
    else
        tr -d '\\n' | sed "s/.*\\"$1\\"[[:space:]]*:[[:space:]]*//" | sed 's/[,"].*//' | tr -d '"'
    fi
}
"""


def keypair_sh(
    priv_path: str = "/tmp/vpn_private.key",
    pub_path: str = "/tmp/vpn_public.key",
) -> str:
    """Generate WireGuard keypair on the device."""
    return (
        f"# Generate WireGuard keypair\n"
        f"wg genkey > {priv_path}\n"
        f"wg pubkey < {priv_path} > {pub_path}\n"
        f"chmod 600 {priv_path}\n"
    )


def wg_cleanup_sh(iface: str = "wg0") -> str:
    """Remove old WireGuard interface and all peer sections."""
    return (
        f"# Clean up old WireGuard interface + peers\n"
        f"uci -q delete network.{iface}\n"
        f"while uci -q get network.@wireguard_{iface}[0] >/dev/null 2>&1; do\n"
        f"    uci delete network.@wireguard_{iface}[0]\n"
        f"done\n"
    )


def transport_sh(body: str, script_path: str = "/tmp/vpn_setup.sh") -> str:
    """Transport a multiline provider script intact through the SSH executor.

    ``scripts/profile/apply.py::_run_step_script`` joins control-flow scripts
    line-by-line with `` && ``, which turns multiline ``if``/``while`` blocks
    and function definitions into ash syntax errors (``then && apk ...``) —
    breaking SSH configuration mode for every WireGuard provider. Wrapping the
    body in a single-quoted heredoc routes the step through the executor's
    stdin transport instead (``set -e`` + newline-preserved payload), and the
    body then runs verbatim via ``sh``. The quoted delimiter keeps shell
    variables literal at write time so they expand when the inner script runs.
    """
    return (
        f"cat > {script_path} << 'VPN_SETUP_EOF'\n"
        f"{body.strip()}\n"
        f"VPN_SETUP_EOF\n"
        f"sh {script_path}"
    )


def wg0_uci_sh(
    priv_key: str,
    address: str,
    peer_key: str,
    endpoint_host: str,
    endpoint_port: str,
    mtu: str = "1280",
    keepalive: str = "25",
    listen_port: bool = True,
    allowed_ips: str = "0.0.0.0/0",
) -> str:
    """The shared WireGuard interface + peer uci stanza.

    Arguments are shell fragments as they appear in the generated script
    (variable references like '"$WG_PRIV"' or single-quoted literals like
    "'10.5.0.2/32'") so each provider keeps its own variable names while
    the stanza itself is defined once.
    """
    listen = "uci set network.wg0.listen_port='51820'\n" if listen_port else ""
    # allowed_ips comes from a parsed provider config file (trust boundary):
    # it lands inside a single-quoted uci value in generated shell, so only
    # CIDR-list characters may pass — a quote or metachar would break out.
    import re as _re

    if not _re.fullmatch(r"[0-9A-Fa-f:. ,/]+", allowed_ips.strip()):
        raise ValueError(
            f"allowed_ips must be a CIDR list, got {allowed_ips!r} (#468)"
        )
    allowed_ips = allowed_ips.strip()
    return (
        f"uci set network.wg0=interface\n"
        f"uci set network.wg0.proto='wireguard'\n"
        f"uci set network.wg0.private_key={priv_key}\n"
        f"{listen}"
        f"uci add_list network.wg0.addresses={address}\n"
        f"uci set network.wg0.mtu='{mtu}'\n"
        f"uci set network.wg0.auto='1'\n"
        f"\n"
        f"uci add network wireguard_wg0\n"
        f"uci set network.@wireguard_wg0[0].public_key={peer_key}\n"
        f"uci set network.@wireguard_wg0[0].endpoint_host={endpoint_host}\n"
        f"uci set network.@wireguard_wg0[0].endpoint_port={endpoint_port}\n"
        f"uci add_list network.@wireguard_wg0[0].allowed_ips='{allowed_ips}'\n"
        f"uci set network.@wireguard_wg0[0].route_allowed_ips='1'\n"
        f"uci set network.@wireguard_wg0[0].persistent_keepalive='{keepalive}'\n"
    )


def static_route_sh(
    server_var: str,
    gateway: str,
    upstream_iface: str = "wwan",
    route_name: str = "vpn_server_route",
) -> str:
    """Add static route to VPN server via upstream gateway.

    CRITICAL: Without this, route_allowed_ips=1 creates a default route
    through wg0, but wg0 can't reach the VPN server because the only route
    to it goes through wg0 itself — a circular deadlock.
    """
    return (
        f"# Static route: prevent circular routing through VPN tunnel\n"
        f"uci -q delete network.{route_name}\n"
        f"uci set network.{route_name}=route\n"
        f"uci set network.{route_name}.interface='{upstream_iface}'\n"
        f"uci set network.{route_name}.target=\"${{{server_var}}}\"\n"
        f"uci set network.{route_name}.netmask='255.255.255.255'\n"
        f"uci set network.{route_name}.gateway='{gateway}'\n"
    )


# -- Op list builders (shared across all providers) -----------------------------

def build_firewall_ops(
    iface: str = "wg0",
    kill_switch: bool = True,
    allow_management: bool = True,
) -> list[Op]:
    """Firewall zone, LAN→VPN forwarding, and optional kill switch.

    Uses named sections (vpn_zone, vpn_fwd, vpn_killswitch) with stale-section
    cleanup for idempotent reconfiguration.

    ``allow_management`` opens SSH/LuCI ports from the VPN zone to the router
    itself (input chain, evaluated before the zone reject policy). The zone
    policy stays REJECT: without the rule, the router is unreachable through
    the tunnel; with it, remote management works over the VPN exit — which
    also means the router's SSH is reachable from the VPN exit IP, protected
    only by key-only auth.
    """
    ops: list[Op] = [
        BlankLine(),
        Comment(text="--- VPN firewall zone + forwarding ---"),
        uci_cleanup_sections("firewall", "name='vpn'"),
        uci_cleanup_sections("firewall", "dest='vpn'"),
        uci_cleanup_sections("firewall", "name='KillSwitch-Reject-NonVPN'"),
        uci_cleanup_sections("firewall", "name='Allow-VPN-Management'"),
        ShellCommand(command="uci set firewall.vpn_zone=zone"),
        UciSet(config="firewall", section="vpn_zone", values={
            "name": "vpn",
            "input": "REJECT",
            "output": "ACCEPT",
            "forward": "REJECT",
            "masq": "1",
            "mtu_fix": "1",
            "network": iface,
        }),
        ShellCommand(command="uci set firewall.vpn_fwd=forwarding"),
        UciSet(config="firewall", section="vpn_fwd", values={
            "src": "lan",
            "dest": "vpn",
        }),
    ]
    if allow_management:
        ops.extend([
            BlankLine(),
            Comment(text="--- Management (SSH/LuCI) from the VPN zone ---"),
            ShellCommand(command="uci set firewall.vpn_mgmt=rule"),
            UciSet(config="firewall", section="vpn_mgmt", values={
                "name": "Allow-VPN-Management",
                "src": "vpn",
                "proto": "tcp",
                "dest_port": "22 80 443",
                "target": "ACCEPT",
            }),
        ])
    if kill_switch:
        ops.extend([
            BlankLine(),
            ShellCommand(command="uci set firewall.vpn_killswitch=rule"),
            UciSet(config="firewall", section="vpn_killswitch", values={
                "name": "KillSwitch-Reject-NonVPN",
                "src": "lan",
                "dest": "wan",
                "proto": "all",
                "target": "REJECT",
            }),
        ])
    return ops


def build_dns_ops(dns_servers: list[str]) -> list[Op]:
    """Configure dnsmasq to use provider DNS through the tunnel."""
    if not dns_servers:
        return []
    ops: list[Op] = [
        BlankLine(),
        Comment(text="--- VPN DNS through tunnel ---"),
    ]
    for dns in dns_servers:
        ops.append(ShellCommand(
            command=f"uci del_list dhcp.@dnsmasq[0].server='{dns}' 2>/dev/null; true",
        ))
        ops.append(UciAddList(
            config="dhcp", section="@dnsmasq[0]", option="server", value=dns,
        ))
    ops.append(ShellCommand(command="uci set dhcp.@dnsmasq[0].noresolv='1'"))
    return ops


def build_verify_ops(iface: str = "wg0", kill_switch: bool = True,
                     kind: str = "wireguard") -> list[Op]:
    """Commit, restart network, verify tunnel. Auto-remove kill switch on failure.

    kind="wireguard": success = `wg show` handshake within 30s.
    kind="openvpn": success = tun iface up with an address (traffic check is
    left to the caller — OpenVPN has no equivalent single probe).
    """
    ops: list[Op] = [
        UciCommit(config="network"),
        UciCommit(config="firewall"),
        UciCommit(config="dhcp"),
        ServiceAction(name="network", action="restart"),
        ServiceAction(name="dnsmasq", action="restart"),
    ]
    if not kill_switch:
        return ops
    if kind == "openvpn":
        ops.append(ShellCommand(
            command=(
                "i=0; while [ $i -lt 45 ]; do"
                f" if ip -4 addr show dev {iface} 2>/dev/null | grep -q inet; then"
                " echo 'VPN: tun interface verified'; exit 0;"
                " fi; sleep 1; i=$((i+1));"
                " done;"
                " echo 'VPN: tun interface failed — removing kill switch to restore WAN';"
                " uci delete firewall.vpn_killswitch;"
                " uci commit firewall;"
                " fw4 restart"
            ),
        ))
        return ops
    ops.append(ShellCommand(
        command=(
            "i=0; while [ $i -lt 30 ]; do"
            f" if wg show {iface} 2>/dev/null | grep -q 'latest handshake'; then"
            " echo 'VPN: tunnel verified'; exit 0;"
            " fi; sleep 1; i=$((i+1));"
            " done;"
            " echo 'VPN: tunnel failed — removing kill switch to restore WAN';"
            " uci delete firewall.vpn_killswitch;"
            " uci commit firewall;"
            " fw4 restart"
        ),
    ))
    return ops
