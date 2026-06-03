# Research: Device Management Beyond Provisioning

Status: Research document. No implementation planned. Captures findings on ubus HTTP transport, parental controls, content filtering, runtime management, and the dashboard ecosystem for future reference.

Source: `/tmp/openwrt_info.md` — LLM-generated research on OpenWrt device management at 192.168.13.1.

---

## Table of Contents

1. [ubus HTTP as a Transport](#1-ubus-http-as-a-transport)
2. [Parental Control Use Case](#2-parental-control-use-case)
3. [Content Filtering](#3-content-filtering)
4. [Runtime Management Patterns](#4-runtime-management-patterns)
5. [Dashboard & Ecosystem Reference](#5-dashboard--ecosystem-reference)

---

## 1. ubus HTTP as a Transport

### Why

conwrt currently manages devices exclusively over SSH. This works well for routers conwrt flashed (SSH key baked in). But conwrt may also need to manage routers it didn't flash — where SSH isn't available or isn't the natural interface.

ubus (OpenWrt's IPC bus) is accessible over HTTP via rpcd. This gives conwrt a second transport that works on any OpenWrt router with uhttpd, regardless of SSH configuration.

**Design principle**: ubus HTTP is a first-class transport, but not the default. SSH remains the primary path. ubus is opt-in.

### Architecture

```
Current (SSH only):

  UseCase.build_configure(params) → shell script lines
                                        ↓
  profile/apply.py → subprocess.run(ssh_cmd(ip, script)) → router


Proposed (transport-agnostic):

  UseCase.build_configure(params) → structured UCI operations
                                        ↓
  Renderer.render(ops, transport="ssh")   → shell script → subprocess.run(ssh_cmd(...))
  Renderer.render(ops, transport="ubus")  → ubus RPC calls → HTTP POST /ubus
```

### The DRY Problem

Today, use cases generate raw shell strings:

```python
# scripts/use_cases/sqm.py (simplified)
def build_configure(params):
    return f"""uci set sqm.@queue[0].enabled='1'
uci set sqm.@queue[0].download='{params["download_kbps"]}'
uci commit sqm"""
```

A ubus renderer cannot parse these strings back into structured ubus calls — the mapping is ambiguous (which `uci set` maps to which ubus `uci.set` call? how do `&&` chains work?).

**Solution**: Introduce a structured intermediate representation for UCI operations. Use cases emit operations, renderers translate to the target transport.

```python
# Proposed structured operations
from dataclasses import dataclass

@dataclass
class UciSet:
    config: str        # e.g. "firewall"
    section: str       # e.g. "@rule[-1]" or "Block_iPad"
    values: dict       # e.g. {"enabled": "0", "target": "REJECT"}

@dataclass
class UciCommit:
    config: str

@dataclass
class ServiceReload:
    service: str       # e.g. "firewall"

@dataclass
class ShellCommand:
    command: str       # fallback for non-UCI operations
```

### SSH Renderer (Current Behavior, Preserved)

```python
def render_ssh(ops: list) -> str:
    """Render structured ops to a shell script (current behavior)."""
    lines = []
    for op in ops:
        if isinstance(op, UciSet):
            for k, v in op.values.items():
                lines.append(f"uci set {op.config}.{op.section}.{k}='{v}'")
        elif isinstance(op, UciCommit):
            lines.append(f"uci commit {op.config}")
        elif isinstance(op, ServiceReload):
            lines.append(f"/etc/init.d/{op.service} reload")
        elif isinstance(op, ShellCommand):
            lines.append(op.command)
    return "\n".join(lines)
```

### ubus Renderer (New)

```python
def render_ubus(ops: list) -> list[ubus.RpcCall]:
    """Render structured ops to ubus RPC calls."""
    calls = []
    for op in ops:
        if isinstance(op, UciSet):
            calls.append(ubus.RpcCall("uci", "set", {
                "config": op.config,
                "section": op.section,
                "values": op.values,
            }))
        elif isinstance(op, UciCommit):
            calls.append(ubus.RpcCall("uci", "commit", {
                "config": op.config,
            }))
        elif isinstance(op, ServiceReload):
            # ubus has no generic "reload service" — falls back to
            # ubus call service or exec in sysfs. Document this limitation.
            calls.append(ubus.RpcCall("exec", "command", {
                "command": f"/etc/init.d/{op.service} reload",
            }))
        elif isinstance(op, ShellCommand):
            # Shell commands are the escape hatch — ubus can't express everything
            calls.append(ubus.RpcCall("exec", "command", {
                "command": op.command,
            }))
    return calls
```

### ubus HTTP Client (~70 lines)

From `openwrt_info.md`, a minimal TypeScript client. Here's the Python equivalent:

```python
"""ubus HTTP JSON-RPC client for OpenWrt."""
import json
import urllib.request

class UbusClient:
    def __init__(self, host: str):
        self.url = f"http://{host}/ubus"
        self.token: str | None = None

    def login(self, username: str = "root", password: str = "") -> str:
        """Authenticate and store session token."""
        result = self._call("00000000000000000000000000000000",
                            "session", "login",
                            {"username": username, "password": password})
        self.token = result["ubus_rpc_session"]
        return self.token

    def call(self, object_name: str, method: str, params: dict | None = None) -> dict:
        """Call a ubus method. Must login() first."""
        assert self.token, "Must login first"
        return self._call(self.token, object_name, method, params or {})

    def _call(self, token: str, object_name: str, method: str, params: dict) -> dict:
        payload = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "call",
            "params": [token, object_name, method, params],
        }).encode()
        req = urllib.request.Request(
            self.url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        # ubus returns [status_code, result_data]
        if data.get("result") and data["result"][0] == 0:
            return data["result"][1] if len(data["result"]) > 1 else {}
        raise RuntimeError(f"ubus call failed: {data}")
```

### ubus ACL Setup (Prerequisite on Router)

conwrt can't use ubus HTTP until the router has rpcd configured with appropriate ACLs. This is a one-time setup step (via SSH or LuCI):

```bash
opkg install rpcd uhttpd-mod-ubus luci-mod-rpc

# Create ACL for conwrt
cat > /usr/share/rpcd/acl.d/conwrt.json <<'EOF'
{
  "conwrt": {
    "description": "conwrt device management access",
    "read": {
      "ubus": {
        "hostapd.*": ["get_clients"],
        "dhcp": ["ipv4leases"],
        "uci": ["get"],
        "network": ["get_hosthints"],
        "system": ["board", "info"]
      }
    },
    "write": {
      "ubus": {
        "uci": ["set", "commit"],
        "hostapd.*": ["del_client"],
        "firewall": ["reload"]
      }
    }
  }
}
EOF

/etc/init.d/rpcd restart && /etc/init.d/uhttpd restart
```

### Limitations of ubus HTTP

| Aspect | SSH | ubus HTTP |
|--------|-----|-----------|
| Auth | SSH key (passwordless) | Username/password or token |
| Encryption | Built-in | Requires HTTPS (self-signed cert on router) |
| Command scope | Any shell command | Only registered ubus objects/methods |
| File transfer | SCP | Not supported (no file I/O in ubus) |
| Streaming | No | No |
| Availability | After OpenWrt boot with Dropbear/OpenSSH | After OpenWrt boot with uhttpd + rpcd |
| Firmware flashing | sysupgrade via SSH | Not possible |
| Package install | opkg via SSH | Not in default ubus objects |
| Firewall reload | `/etc/init.d/firewall restart` or `fw4 reload` | `ubus call firewall reload` |

**Key insight**: ubus HTTP covers *configuration management* well (UCI get/set/commit). It does NOT cover provisioning (flashing, firmware, package install). SSH remains necessary for initial setup.

### Where ubus Fits in conwrt

```
conwrt workflow:

1. Discovery & flashing     → SSH only (sysupgrade, recovery-http, TFTP)
2. Initial configuration    → SSH or ASU first-boot (UCI, WiFi, use cases)
3. Ongoing management       → SSH or ubus HTTP (parental controls, monitoring)
```

ubus HTTP is relevant for **step 3** and potentially **step 2** (if the router already has rpcd configured). It is NOT relevant for step 1.

### Implementation Path

If/when implemented:

1. **Add `scripts/ubus_utils.py`** — `UbusClient` class with `login()`, `call()`, `uci_get()`, `uci_set()`, `uci_commit()`, `get_clients()`, `get_leases()`, `get_hosthints()`
2. **Add structured UCI operations** — `UciSet`, `UciCommit`, `ServiceReload`, `ShellCommand` dataclasses in a new `scripts/profile/ops.py`
3. **Refactor use cases to emit ops** — `build_configure_ops(params)` returns `list[Op]` alongside the legacy `build_configure(params)` shell path.
4. **Add SSH renderer** — `render_ssh(ops) -> str` reproduces current shell script output
5. **Add ubus renderer** — `render_ubus(ops) -> list[RpcCall]` produces ubus RPC calls
6. **Add `--transport ssh|ubus` CLI flag** — defaults to `ssh`, ubus is opt-in
7. **Document transport differences** in `docs/gotchas.md` — what works over ubus, what doesn't

### API Reference: Useful ubus Objects

From `openwrt_info.md` and OpenWrt docs:

```
Object              Method              Purpose
──────────────────  ──────────────────  ──────────────────────────
session             login               Authenticate, get token
uci                 get                 Read UCI config
uci                 set                 Write UCI values
uci                 commit              Persist changes
uci                 changes             Show uncommitted changes
dhcp                ipv4leases          List DHCP leases
hostapd.wlan0       get_clients         List WiFi clients
hostapd.wlan0       del_client          Kick a WiFi client
network             get_hosthints       Get MAC/IP/hostname mapping
network.interface   status              Interface status (up/down, IP, etc.)
system              board               Board info (model, firmware version)
system              info                System info (uptime, memory, load)
firewall            reload              Reload firewall rules
```

### Documenting "The UCI Way" vs Alternatives

Having both transports naturally documents two approaches:

| Task | The UCI Way (SSH) | The ubus Way (HTTP) |
|------|-------------------|---------------------|
| Set hostname | `uci set system.@system[0].hostname='foo' && uci commit system` | `ubus call uci set '{"config":"system","section":"@system[0]","values":{"hostname":"foo"}}'` then `ubus call uci commit '{"config":"system"}'` |
| Block device | `iptables -I FORWARD -m mac --mac-source AA:BB:CC:DD:EE:FF -j DROP` | `ubus call uci set '{"config":"firewall","section":"Block_iPad","values":{"enabled":"1"}}'` then `ubus call uci commit '{"config":"firewall"}'` then `ubus call firewall reload` |
| Get WiFi clients | `ubus call hostapd.wlan0 get_clients` (same on both) | Same — ubus is native for queries |
| Install package | `opkg install foo` | Not available via ubus (use SSH) |

---

## 2. Parental Control Use Case

### Status

Research only. Not a priority for implementation. This section outlines what a `parental-control` use case preset would look like when the time comes.

### Scope

Parental control in conwrt means: **per-device internet scheduling and content filtering, configured declaratively in `config.toml` and applied via use case preset.**

conwrt does NOT build a GUI for this. The parent uses `config.toml` (or a future interactive CLI) to define rules. Children interact with the router's LuCI or their devices.

### Proposed Use Case Structure

```toml
[use_cases]
enabled = ["parental-control"]

[use_cases.parental-control]
# Mode: "blacklist" = block listed devices, "whitelist" = allow only listed devices
mode = "blacklist"

# Default policy when no schedule matches
default_policy = "allow"   # "allow" or "block"

# Device rules
[[use_cases.parental-control.devices]]
name = "iPad"
mac = "AA:BB:CC:DD:EE:FF"
schedule = "block"         # "always-block", "always-allow", or schedule below

[[use_cases.parental-control.devices]]
name = "Kids Laptop"
mac = "11:22:33:44:55:66"
block_start = "22:00"
block_stop = "07:00"
block_days = ["Mon", "Tue", "Wed", "Thu", "Fri"]

# Content filtering (optional)
[use_cases.parental-control.content_filter]
method = "ipset"           # "dns" (simple), "ipset" (recommended), or "iptables"
block_lists = ["youtube", "tiktok"]

# Custom domain lists
[use_cases.parental-control.content_filter.custom]
block_domains = ["reddit.com", "twitter.com"]
allow_domains = ["reddit.com/r/educational"]  # overrides block
```

### Implementation Approach (When Ready)

The use case would generate UCI firewall rules + dnsmasq ipset configuration:

```python
# scripts/use_cases/parental_control.py (skeleton)

from use_cases import UseCase, ParamDef, register

def build_parental_control(params):
    lines = []

    # 1. Per-device firewall rules with time scheduling
    for device in params.get("devices", []):
        mac = device["mac"]
        rule_name = f"pc_{device['name'].replace(' ', '_')}"
        lines.append(f"uci add firewall rule")
        lines.append(f"uci set firewall.@rule[-1].name='{rule_name}'")
        lines.append(f"uci set firewall.@rule[-1].src='lan'")
        lines.append(f"uci set firewall.@rule[-1].dest='wan'")
        lines.append(f"uci set firewall.@rule[-1].src_mac='{mac}'")
        lines.append(f"uci set firewall.@rule[-1].proto='all'")

        if device.get("schedule") == "block":
            lines.append(f"uci set firewall.@rule[-1].target='REJECT'")
        else:
            lines.append(f"uci set firewall.@rule[-1].target='ACCEPT'")

        if device.get("block_start"):
            lines.append(f"uci set firewall.@rule[-1].start_time='{device['block_start']}'")
            lines.append(f"uci set firewall.@rule[-1].stop_time='{device['block_stop']}'")
            days = " ".join(device.get("block_days", []))
            if days:
                lines.append(f"uci set firewall.@rule[-1].weekdays='{days}'")

    lines.append("uci commit firewall")

    # 2. Content filtering via dnsmasq ipset (if configured)
    cf = params.get("content_filter")
    if cf and cf.get("method") == "ipset":
        # ... ipset/nftset configuration
        pass

    return "\n".join(lines)

register(UseCase(
    name="parental-control",
    description="Per-device internet scheduling and content filtering",
    packages=["luci-app-timecontrol"],  # optional: install LuCI UI for manual management
    configure_via="both",
    requires_capabilities=["wifi"],
    params={
        "mode": ParamDef(type=str, default="blacklist", choices=("blacklist", "whitelist")),
        "devices": ParamDef(type=list, required=True, description="List of device rules"),
        "content_filter": ParamDef(type=dict, default=None, description="Content filtering config"),
    },
    build_configure=build_parental_control,
))
```

### Dependencies on ubus Transport

Parental control benefits from ubus HTTP for **runtime toggling** — temporarily unblocking a device for N minutes without SSH. This is the "pause button" pattern from `luci-app-timecontrol`.

Without ubus, runtime toggling requires SSH access every time. With ubus, a simple HTTP call toggles a firewall rule:

```python
# Toggle device via ubus HTTP
client.call("uci", "set", {
    "config": "firewall",
    "section": "pc_iPad",
    "values": {"enabled": "0"},  # unblock
})
client.call("uci", "commit", {"config": "firewall"})
client.call("firewall", "reload", {})
```

This is the strongest argument for ubus HTTP: it enables runtime management use cases that SSH alone makes awkward.

### What NOT to Build

- **No dashboard UI** — conwrt will never have a dashboard. External projects (next-openwrt-stats, MoCI, Home Assistant) handle this.
- **No captive portal** — not a conwrt concern.
- **No DPI (Deep Packet Inspection)** — OpenAppFilter exists for this. Out of scope for conwrt.
- **No mobile app** — WRTune (iOS) and LuCI Mobile (Android) exist.

---

## 3. Content Filtering

### Approach Comparison

From `openwrt_info.md`, six approaches ranked by bypass resistance and conwrt compatibility:

| Method | Bypass Resistance | Collateral Damage | conwrt Fit | Complexity |
|--------|-------------------|-------------------|------------|------------|
| **DNS blocking (dnsmasq)** | Low (DoH/DoT bypasses) | None | Good — pure UCI | Low |
| **iptables string match** | Medium (catches all DNS) | CPU-heavy | Poor — runtime-only, no UCI | Medium |
| **IP-based blocking** | Low (shared ranges) | High (blocks Gmail etc.) | Poor — static lists | Low |
| **dnsmasq ipset/nftset** | High (resolves + blocks IP) | None | **Best fit** — pure UCI | Medium |
| **AdGuard Home** | High (full filtering) | None | Possible — opkg install + config | High |
| **adblock-fast** | High (force_dns option) | None | Possible — opkg install | Medium |

### Recommended: dnsmasq ipset/nftset

This approach is the best fit for conwrt because:

1. **Pure UCI** — all configuration is `uci set` commands, works in both ASU first-boot and post-flash SSH
2. **No additional packages** — uses built-in dnsmasq + firewall4
3. **No collateral damage** — only blocks resolved IPs for listed domains
4. **Bypass-resistant** — forces DNS through router (when combined with DNS interception)

```bash
# /etc/config/dhcp — define ipset with domains
config ipset 'youtube'
    list name 'youtube_set'
    list domain 'youtube.com'
    list domain 'youtu.be'
    list domain 'googlevideo.com'
    list domain 'ytimg.com'
    list domain 'youtubei.googleapis.com'
    list domain 'youtube-nocookie.com'
    list domain 'ggpht.com'

# /etc/config/firewall — block the set
config rule
    option name 'Block-YouTube-Set'
    option src 'lan'
    option dest 'wan'
    option ipset 'youtube_set'
    option proto 'all'
    option target 'REJECT'
```

### DNS Interception (Force Router DNS)

To prevent bypass via hardcoded DNS or DoH:

```bash
# NAT rule to redirect all DNS queries to router
iptables -t nat -A PREROUTING -i br-lan -p udp --dport 53 -j REDIRECT --to-port 53
iptables -t nat -A PREROUTING -i br-lan -p tcp --dport 53 -j REDIRECT --to-port 53
```

This is also expressible as UCI firewall rules and can be included in the parental control use case.

### YouTube Domain List (Reference)

| Domain | Purpose |
|--------|---------|
| `youtube.com` | Main site (covers www, m, music, studio, kids subdomains) |
| `youtu.be` | Short URLs |
| `youtube-nocookie.com` | Privacy embed mode |
| `youtubei.googleapis.com` | InnerTube API |
| `googlevideo.com` | Video CDN (actual streams) |
| `ytimg.com` | Thumbnails and static assets |
| `ggpht.com` | Profile images, channel art |

### Caveats (Must Document)

- **Android** silently falls back to cellular when WiFi has no internet
- **Random MAC addresses** (iOS 14+, Android 10+) change device identity — use static DHCP leases
- **VPN apps** bypass all router-level blocking
- **Time-based rules** only block new connections — existing ones persist until `fw4 reload`

---

## 4. Runtime Management Patterns

conwrt focuses on provisioning (flash + configure once). Runtime management is a different lifecycle. This section documents patterns for ongoing device interaction that conwrt could support or reference.

### The "Configure" Command (Already Exists)

`conwrt configure` already applies a profile to a running router over SSH. This is the natural entry point for runtime management — it's idempotent and can be run repeatedly.

### Runtime Operations (Not in conwrt)

These operations are documented for reference. conwrt does NOT implement them, but understanding them helps inform the transport design.

| Operation | SSH Command | ubus Equivalent | Notes |
|-----------|------------|-----------------|-------|
| List WiFi clients | `ubus call hostapd.wlan0 get_clients` | Same (ubus is native here) | Returns MAC + signal + uptime |
| List DHCP leases | `cat /tmp/dhcp.leases` | `ubus call dhcp ipv4leases` | ubus returns structured JSON |
| Kick WiFi client | N/A (runtime only) | `ubus call hostapd.wlan0 del_client '{"addr":"AA:BB:CC:DD:EE:FF","reason":5,"deauth":true}'` | Runtime-only operation |
| Get device inventory | SSH fingerprinting | `ubus call system board` + `ubus call network get_hosthints` | conwrt already does this via SSH |
| Toggle firewall rule | `uci set firewall.@rule[N].enabled='0' && uci commit firewall && fw4 reload` | `ubus call uci set ...` + `ubus call uci commit ...` + `ubus call firewall reload` | 3 RPC calls vs 1 shell command |
| Temporary unblock | Create/delete iptables rule | Same — no native "temporary" in ubus | Requires cron job or timeout logic |

### luci-app-timecontrol Pattern

[luci-app-timecontrol](https://github.com/gaobin89/luci-app-timecontrol) (25 stars, actively maintained) is the reference implementation for per-device scheduling with:

- Per-device rules by MAC address
- Multiple time ranges per rule
- **Temporary unblock/block (1-720 minutes)** — the "pause button"
- Blacklist/whitelist mode
- FW3/FW4 adaptation
- Conntrack flush for instant enforcement
- Auto-fix firewall rule chain order

The temporary unblock feature is notable. It works by:
1. Adding/removing iptables rules at runtime
2. Setting a cron job to revert after N minutes
3. Flushing conntrack to kill existing connections immediately

This pattern could be replicated in conwrt via a `conwrt manage` subcommand in the future, but there's no plan to build it now.

### Fleet Management Considerations

conwrt's inventory (`data/inventory.jsonl`) tracks specimens. For fleet management:

- **SSH**: Works for fleet, but requires key distribution to all routers
- **ubus HTTP**: Each router needs rpcd ACL setup, then any dashboard can manage it
- **WireGuard**: conwrt already builds management VPN tunnels — fleet management over VPN is the natural path

The conwrt + WireGuard combination is already a lightweight fleet management system:
1. Flash routers with `wireguard-client` use case → each gets a VPN tunnel
2. Register public keys on VPN server → conwrt already does this
3. Manage routers over VPN via SSH or ubus HTTP → transport layer handles this

---

## 5. Dashboard & Ecosystem Reference

conwrt will never have a dashboard. This section catalogs external projects for reference.

### Full Dashboards

| Project | Stack | Stars | Notes |
|---------|-------|-------|-------|
| [next-openwrt-stats](https://github.com/LoV432/next-openwrt-stats) | Next.js + TS | 39 | Multi-AP monitoring, DHCP management, traffic stats |
| [MoCI](https://github.com/HudsonGraeme/MoCI) | Vanilla JS | - | Pure SPA, native ubus calls, glassmorphic UI, live demo |
| [Openwalla](https://github.com/benisai/Openwalla) | React + Tailwind | 2 | Firewalla-inspired, device tracking, nlbwmon |
| [Travo](https://github.com/raydak-labs/travo) | Go + TS | 1 | Mobile-first for travel routers, VPN management |
| [Smart Homelab](https://github.com/yaoleifly/smart-homelab) | Vanilla JS | 34 | AI monitoring, Telegram alerts, auto-remediation |
| [secubox-openwrt](https://github.com/CyberMind-FR/secubox-openwrt) | Unknown | - | 86 security dashboards |
| [vuci](https://github.com/janenas-luk/vuci) | Vue.js + Ant Design | - | Full LuCI replacement, json-rpc, ACL |

### API Libraries

| Library | Language | Notes |
|---------|----------|-------|
| [openwrt-go](https://github.com/lsongdev/openwrt-go) | Go | Full SDK — firewall, UCI, network, services, opkg |
| [aio-openwrt](https://github.com/xZise/aio-openwrt) | Python (async) | Async Python via aiohttp |
| [wrtkit](https://github.com/tlamadon/wrtkit) | Python | Type-safe UCI with Pydantic, SSH fleet management |
| [python-ubus-rpc](https://github.com/Noltari/python-ubus-rpc) | Python | Original Python ubus RPC client |

### Home Assistant Integrations

| Project | Stars | Notes |
|---------|-------|-------|
| [hass_openwrt](https://github.com/kvj/hass_openwrt) | 164 | Most popular, services, commands, mesh support |
| [ha-openwrt](https://github.com/FaserF/ha-openwrt) | 38 | Firewall rules control, firmware, WiFi, 3 connection methods |

### LuCI Plugins for Device Control

| Plugin | Stars | Notes |
|--------|-------|-------|
| [luci-app-timecontrol](https://github.com/gaobin89/luci-app-timecontrol) | 25 | Per-device time control, temporary unblock |
| [luci-access-control](https://github.com/k-szuster/luci-access-control) | - | Internet scheduler, "ticket" system |
| [OpenAppFilter](https://github.com/destan19/OpenAppFilter) | Popular | DPI-based app filtering (YouTube, TikTok, games) |
| [openwrt-kidsnetwork](https://github.com/pabumake/openwrt-kidsnetwork) | - | Kids WiFi with password rotation + QR codes |

### Mobile Apps

| App | Platform | Notes |
|-----|----------|-------|
| [LuCI Mobile](https://github.com/cogwheel0/luci-mobile) | Android (Flutter) | Native router management |
| [WRTune](https://apps.apple.com/us/app/wrtune-for-openwrt/id6758356103) | iOS | Pause Internet quick action, real-time traffic |

---

## Summary of Recommendations

| Topic | Recommendation | Priority |
|-------|---------------|----------|
| ubus HTTP transport | Implement when runtime management becomes a need. Start with `ubus_utils.py` client + structured UCI ops. | When needed |
| Parental control use case | Implement as a `parental-control` use case preset using dnsmasq ipset + UCI firewall rules. | When needed |
| Content filtering | Use dnsmasq ipset/nftset approach. Avoid IP-based blocking. | Part of parental control |
| Runtime management | Document patterns. No `conwrt manage` subcommand planned. | Reference only |
| Dashboard | Never. External projects handle this. | N/A |
| Transport DRY | Introduce structured UCI operations before adding ubus. Don't duplicate shell string generation. | Prerequisite for ubus |

### Sources

- `/tmp/openwrt_info.md` — Original research document
- OpenWrt Wiki: ubus — https://openwrt.org/docs/techref/ubus
- OpenWrt Wiki: UCI — https://openwrt.org/docs/techref/uci
- OpenWrt Wiki: Parental Controls — https://openwrt.org/docs/guide-user/firewall/fw3_configurations/fw3_parent_controls
- luci-app-timecontrol — https://github.com/gaobin89/luci-app-timecontrol
