"""mptcp-bonding — MultiPath TCP connection aggregation via BondingShouldBeFree.

MPTCP (RFC 8684) allows a single TCP connection to use multiple network paths
simultaneously, enabling true bandwidth aggregation (not just failover like mwan3).

Standard OpenWrt kernels disable MPTCP (CONFIG_MPTCP=n). This use case requires
a custom OpenWrt image built with CONFIG_MPTCP=y, available via:

  1. BondingShouldBeFree firmware selector:
     https://firmware.bondingshouldbefree.org
  2. BSBF's OpenWrt fork: github.com/bondingshouldbefree/openwrt
  3. OpenMPTCProuter: openmptcprouter.com (legacy, uses shadowsocks)

Architecture:
  Router (MPTCP-enabled OpenWrt)
    ├── WAN1 (e.g. fiber) ──┐
    ├── WAN2 (e.g. 4G/5G) ──┤── MPTCP subflows ──→ VPS (deaggregator) → Internet
    └── WAN3 (e.g. Starlink)─┘

  The VPS receives MPTCP subflows from all WANs, reassembles them into a single
  stream, and NATs to the real internet. This gives you the combined bandwidth
  of all WAN links for every TCP connection.

  BondingShouldBeFree (BSBF) uses:
    - MPTCP kernel (upstream Linux with CONFIG_MPTCP=y)
    - UDP encapsulation tunnel (udp-encap-tun) for TCP-over-UDP
    - UUID-based client identification
    - Per-client bandwidth limiting on the server

Server setup (on VPS):
  curl -fsSL srv.bondingshouldbefree.org | sudo sh
  sudo bsbf-add-client 50  # 50 Mbps limit; returns port + UUID

Client setup (on MPTCP-enabled OpenWrt):
  apk add curl && curl -fsSL owrt.bondingshouldbefree.org | sh -s -- \\
    --server-ipv4 <VPS_IP> --server-port <PORT> --uuid <UUID>

Key differences from mwan3:
  - mwan3: failover/load-balancing (per-connection routing, NOT aggregation)
  - MPTCP bonding: true aggregation (single connection uses ALL WANs)
  - mwan3 works on stock OpenWrt (iptables-nft compat)
  - MPTCP bonding requires custom kernel (CONFIG_MPTCP=y)

References:
  - BSBF: https://github.com/bondingshouldbefree
  - BSBF docs: https://github.com/bondingshouldbefree/.github/blob/test/profile/documentation.md
  - OpenMPTCProuter: http://www.openmptcprouter.com/
  - MPTCP on OpenWrt wiki: https://openwrt.org/docs/guide-user/network/mptcp
  - RFC 8684: https://www.rfc-editor.org/rfc/rfc8684
"""
from __future__ import annotations

from typing import Any

from profile.ops import BlankLine, Comment, Op, ServiceAction, ShellCommand, UciCommit, UciSet, render_shell

from . import ParamDef, UseCase, register


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    server_ipv4 = str(params.get("server_ipv4", ""))
    server_port = str(params.get("server_port", ""))
    uuid = str(params.get("uuid", ""))
    bandwidth_limit = int(params.get("bandwidth_limit", 0))

    if not server_ipv4:
        raise ValueError("server_ipv4 is required (VPS IP running BSBF server)")
    if not server_port:
        raise ValueError("server_port is required (from 'bsbf-add-client' on VPS)")
    if not uuid:
        raise ValueError("uuid is required (from 'bsbf-add-client' on VPS)")

    return {
        "server_ipv4": server_ipv4,
        "server_port": server_port,
        "uuid": uuid,
        "bandwidth_limit": bandwidth_limit,
    }


def _build_mptcp_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    server_ip = r["server_ipv4"]
    server_port = r["server_port"]
    uuid = r["uuid"]

    ops: list[Op] = []

    ops.append(Comment(text="--- mptcp-bonding (BondingShouldBeFree) ---"))

    ops.append(Comment(text=f"Server: {server_ip}:{server_port}, UUID: {uuid[:8]}..."))

    ops.append(ShellCommand(
        command=f"apk add curl 2>/dev/null || opkg update && opkg install curl 2>/dev/null || true"
    ))

    ops.append(BlankLine())

    ops.append(ShellCommand(
        command=(
            f'curl -fsSL owrt.bondingshouldbefree.org | sh -s -- '
            f'--server-ipv4 {server_ip} '
            f'--server-port {server_port} '
            f'--uuid {uuid}'
        )
    ))

    ops.append(BlankLine())

    ops.append(ShellCommand(command="echo 'BSBF bonding client installed. Verify with: bsbf-bonding --status'"))

    ops.append(ShellCommand(
        command='echo "To uninstall: bsbf-bonding --uninstall"'
    ))

    ops.append(BlankLine())

    ops.append(Comment(text="NOTE: This use case requires an MPTCP-enabled OpenWrt kernel."))
    ops.append(Comment(text="Build custom firmware at: https://firmware.bondingshouldbefree.org"))
    ops.append(Comment(text="Or flash BSBF's OpenWrt fork from github.com/bondingshouldbefree/openwrt"))

    return ops


register(UseCase(
    name="mptcp-bonding",
    description="MultiPath TCP connection bonding via BondingShouldBeFree (requires custom MPTCP kernel)",
    packages=[
        # No standard packages — BSBF installs its own binaries
        # The kernel must be built with CONFIG_MPTCP=y (not stock OpenWrt)
    ],
    params={
        "server_ipv4": ParamDef(type=str, default="",
                                description="VPS IP running BSBF server (from 'curl srv.bondingshouldbefree.org | sudo sh')"),
        "server_port": ParamDef(type=str, default="",
                               description="Server port (from 'sudo bsbf-add-client' output on VPS)"),
        "uuid": ParamDef(type=str, default="",
                        description="Client UUID (from 'sudo bsbf-add-client' output on VPS)"),
        "bandwidth_limit": ParamDef(type=int, default=0,
                                   description="Bandwidth limit in Mbps (0 = unlimited, set on server side)"),
    },
    test_status="untested",
    tested_notes="Requires custom MPTCP-enabled OpenWrt image (CONFIG_MPTCP=y). "
                 "BSBF (May 2026) is the recommended solution. "
                 "Server (VPS) and client (router) components available. "
                 "Cannot be tested on stock OpenWrt QEMU (no CONFIG_MPTCP). "
                 "Firmware selector: https://firmware.bondingshouldbefree.org",
    build_configure=lambda p: render_shell(_build_mptcp_ops(p)),
    build_configure_ops=_build_mptcp_ops,
))
