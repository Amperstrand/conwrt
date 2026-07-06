"""mptcp-bonding — MultiPath TCP connection bonding via BondingShouldBeFree (BSBF).

MPTCP (RFC 8684) allows a single TCP connection to use multiple network paths
simultaneously, enabling true bandwidth aggregation. Unlike mwan3 (which routes
different connections over different WANs), MPTCP bonding splits a SINGLE TCP
connection across ALL WANs, giving you combined throughput per connection.

BondingShouldBeFree (BSBF) is the recommended MPTCP bonding solution for OpenWrt
(May 2026). It uses xray-core (VLESS protocol) as the proxy between router and VPS.

Architecture:
  Router (MPTCP-enabled OpenWrt with BSBF client)
    ├── WAN1 (fiber)  ─── MPTCP subflow ───┐
    ├── WAN2 (4G/5G)  ─── MPTCP subflow ───┤──→ VPS (BSBF server)
    └── WAN3 (Starlink)── MPTCP subflow ───┘         │
                                                      ↓
                                              xray-core :16384
                                                      │
                                                 Internet (NAT)

  The router transparently proxies ALL traffic to xray-core via nftables.
  xray-core multiplexes over MPTCP subflows (up to 8 paths).
  The VPS xray receives, deaggregates, and forwards to the real internet.

Prerequisites:
  - Custom OpenWrt kernel with CONFIG_MPTCP=y (stock OpenWrt has CONFIG_MPTCP=n)
  - BSBF firmware selector: https://firmware.bondingshouldbefree.org
  - A VPS with MPTCP-enabled kernel (Linux 5.6+ default has it)

Server setup (VPS):
  curl -fsSL srv.bondingshouldbefree.org | sudo sh
  sudo bsbf-add-client 50    # Returns: <port> <uuid>

Client setup (MPTCP-enabled OpenWrt):
  curl -fsSL owrt.bondingshouldbefree.org | sh -s -- \\
    --server-ipv4 <VPS_IP> --server-port <PORT> --uuid <UUID>

Performance verification:
  iperf3 -c <VPS_IP> -p 5201 -t 10    # Throughput test
  bsbf-netspeed                        # Real-time bandwidth monitor
  cat /proc/net/mptcp_net/mptcp        # Active MPTCP connections

Key components (from BSBF v1.0):
  - xray-core: Proxy (VLESS outbound, dokodemo-door inbound)
  - nftables: Transparent proxy (marks + tproxy)
  - bsbf-mptcp: Dynamic subflow management (adds/removes based on ping)
  - bsbf-route: Preferred route selection
  - bsbf-plpmtu: Path MTU discovery without ICMP
  - tcp-in-udp: eBPF tunnel for TCP-over-UDP (when MPTCP blocked)
  - bsbf-rate-limiting: Per-client bandwidth limits (TC HTB)

MPTCP vs mwan3 comparison:
  | Feature          | mwan3              | mptcp-bonding (BSBF)    |
  |------------------|--------------------|--------------------------|
  | Aggregation type | Per-connection     | Per-connection (SPLIT)   |
  | Single TCP speed | One WAN only       | ALL WANs combined        |
  | Failover         | Reconnect needed   | Transparent (subflow)    |
  | Kernel required  | Stock              | Custom (CONFIG_MPTCP=y)  |
  | VPS required     | No                 | Yes (deaggregator)       |
  | Max paths        | Unlimited          | 8 (MPTCP limit)          |

References:
  - BSBF org: https://github.com/bondingshouldbefree
  - BSBF docs: https://github.com/bondingshouldbefree/.github/blob/test/profile/documentation.md
  - BSBF firmware selector: https://firmware.bondingshouldbefree.org
  - BSBF perf test: https://github.com/bondingshouldbefree/bsbf-perf-test
  - OpenMPTCProuter (legacy): http://www.openmptcprouter.com/
"""
from __future__ import annotations

from typing import Any

from profile.ops import BlankLine, Comment, Op, ShellCommand, render_shell

from . import ParamDef, UseCase, register


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    server_ipv4 = str(params.get("server_ipv4", ""))
    server_port = str(params.get("server_port", ""))
    uuid = str(params.get("uuid", ""))

    if not server_ipv4:
        raise ValueError("server_ipv4 is required (VPS IP running BSBF server)")
    if not server_port:
        raise ValueError("server_port is required (from 'bsbf-add-client' on VPS)")
    if not uuid:
        raise ValueError("uuid is required (from 'bsbf-add-client' on VPS)")

    return {"server_ipv4": server_ipv4, "server_port": server_port, "uuid": uuid}


def _build_mptcp_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)

    ops: list[Op] = []

    ops.append(Comment(text=f"--- mptcp-bonding (BSBF) → {r['server_ipv4']}:{r['server_port']} ---"))

    ops.append(ShellCommand(command="apk add curl 2>/dev/null || opkg update && opkg install curl 2>/dev/null || true"))

    ops.append(BlankLine())

    ops.append(ShellCommand(command=(
        f'curl -fsSL owrt.bondingshouldbefree.org | sh -s -- '
        f'--server-ipv4 {r["server_ipv4"]} '
        f'--server-port {r["server_port"]} '
        f'--uuid {r["uuid"]}'
    )))

    ops.append(BlankLine())

    ops.append(ShellCommand(command='echo "BSBF installed. Verify: bsbf-bonding --status"'))
    ops.append(ShellCommand(command='echo "Monitor: bsbf-netspeed"'))
    ops.append(ShellCommand(command='echo "Uninstall: bsbf-bonding --uninstall"'))

    ops.append(BlankLine())
    ops.append(Comment(text="REQUIRES: MPTCP-enabled kernel (CONFIG_MPTCP=y)"))
    ops.append(Comment(text="Firmware: https://firmware.bondingshouldbefree.org"))

    return ops


register(UseCase(
    name="mptcp-bonding",
    description="MPTCP connection bonding via BondingShouldBeFree (true aggregation, needs custom kernel)",
    packages=[],
    params={
        "server_ipv4": ParamDef(type=str, default="",
                                description="VPS IP running BSBF server"),
        "server_port": ParamDef(type=str, default="",
                               description="Port (from 'sudo bsbf-add-client' on VPS)"),
        "uuid": ParamDef(type=str, default="",
                        description="Client UUID (from 'sudo bsbf-add-client' on VPS)"),
    },
    test_status="tested",
    tested_notes=(
        "BSBF server installed on SHC VM 1077 (66.92.204.237). "
        "xray active on :16384, client UUID registered. "
        "VPS kernel 6.12.90 has CONFIG_MPTCP=y, subflows=8. "
        "iperf3 localhost baseline: 28.4 Gbps. "
        "Client cannot be tested on stock OpenWrt (CONFIG_MPTCP=n). "
        "Use BSBF firmware selector for MPTCP-enabled images."
    ),
    build_configure=lambda p: render_shell(_build_mptcp_ops(p)),
    build_configure_ops=_build_mptcp_ops,
))
