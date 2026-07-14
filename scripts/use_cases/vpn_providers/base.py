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

JSON_HELPER_SH = """# JSON parsing: try jq, define fallback for BusyBox ash
if ! command -v jq >/dev/null 2>&1; then
    opkg update >/dev/null 2>&1 && opkg install jq >/dev/null 2>&1
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
        f"uci set network.{route_name}.target='${{{server_var}}}'\n"
        f"uci set network.{route_name}.netmask='255.255.255.255'\n"
        f"uci set network.{route_name}.gateway='{gateway}'\n"
    )


# -- Op list builders (shared across all providers) -----------------------------

def build_firewall_ops(iface: str = "wg0", kill_switch: bool = True) -> list[Op]:
    """Firewall zone, LAN→VPN forwarding, and optional kill switch.

    Uses named sections (vpn_zone, vpn_fwd, vpn_killswitch) with stale-section
    cleanup for idempotent reconfiguration.
    """
    ops: list[Op] = [
        BlankLine(),
        Comment(text="--- VPN firewall zone + forwarding ---"),
        uci_cleanup_sections("firewall", "name='vpn'"),
        uci_cleanup_sections("firewall", "dest='vpn'"),
        uci_cleanup_sections("firewall", "name='KillSwitch-Reject-NonVPN'"),
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


def build_verify_ops(iface: str = "wg0", kill_switch: bool = True) -> list[Op]:
    """Commit, restart network, verify handshake. Auto-remove kill switch on failure."""
    ops: list[Op] = [
        UciCommit(config="network"),
        UciCommit(config="firewall"),
        ServiceAction(name="network", action="restart"),
    ]
    if kill_switch:
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
