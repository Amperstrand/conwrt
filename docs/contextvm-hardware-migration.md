# Physical Hardware Testing via Context-VM

## Problem

All conwrt testing today runs against QEMU x86_64 VMs. This can't test:
- WiFi (no WiFi hardware on QEMU x86)
- USB tethering (no USB on QEMU x86)
- Flash methods (sysupgrade, recovery-http, zycast, serial)
- Hardware-specific features (PoE, switch chips, DSA ports)
- Real bufferbloat (QEMU networking has no real bandwidth constraint)

Physical routers (NR7101, GS1900-8HP, COVR-X1860) are on the local network.
Tests need to run from somewhere that can reach them.

## Architecture: Context-VM as Remote Test Runner

```
┌─────────────────────────────────────────────────────────┐
│                    Context-VM (SHC)                      │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌───────────────────────┐  │
│  │ pytest   │  │ playwright│  │ result_publisher      │  │
│  │ (API)    │  │ (LuCI UI) │  │ → Nostr/Blossom       │  │
│  └────┬─────┘  └─────┬────┘  └───────────────────────┘  │
│       │              │                                    │
│       └──────┬───────┘                                    │
│              │ SSH/HTTP                                   │
│  ┌───────────┴────────────────────────┐                   │
│  │ WireGuard VPN (wg0)                │                   │
│  │ 10.0.0.x/24                        │                   │
│  └───────────┬────────────────────────┘                   │
└──────────────┼──────────────────────────────────────────┘
               │ VPN tunnel ( WireGuard UDP 51820 )
               │
    ┌──────────┴──────────┐
    │ WireGuard Server    │
    │ (VPS or home router)│
    │ 10.0.0.1            │
    └──────────┬──────────┘
               │ LAN
    ┌──────────┴──────────────────────────────┐
    │                                          │
    ▼                  ▼                       ▼
┌────────┐    ┌────────────┐          ┌────────────┐
│ NR7101 │    │ GS1900-8HP │          │ COVR-X1860 │
│10.0.0.2│    │ 10.0.0.3   │          │ 10.0.0.4   │
│(OpenWrt│    │ (OpenWrt)  │          │ (OpenWrt)  │
│ flashed)│    │            │          │            │
└────────┘    └────────────┘          └────────────┘
```

## How It Works

### 1. Router Onboarding (one-time, per device)

Flash each router with conwrt + WireGuard client use case:

```toml
[use_cases]
enabled = ["wireguard-client"]

[use_cases.wireguard-client]
peer_public_key = "<SERVER_PUBKEY>"
endpoint_host = "vpn.example.com"
endpoint_port = 51820
address = "10.0.0.X/32"   # unique per router
allowed_ips = "10.0.0.0/24"

[wireguard]
registration_server = "wg-server"  # SSH alias for the WG server
wg_interface = "wg0"
```

After flashing, each router:
- Auto-generates its own WireGuard keypair on first boot
- Connects to the WG server
- Registers its public key
- Becomes reachable at 10.0.0.X from the VPN

### 2. Context-VM Setup (per test run)

The cloud-lab framework orders an SHC VM and bootstraps it:

```bash
scripts/cloud-lab.py submit-conwrt \
    --hardware \
    --vpn-endpoint vpn.example.com:51820 \
    --vpn-peer-key "<SERVER_PUBKEY>" \
    --vpn-address 10.0.0.100/32 \
    --routers 10.0.0.2,10.0.0.3,10.0.0.4 \
    --publish
```

The bootstrap script:
1. Installs WireGuard on the context-VM
2. Connects to the VPN (gets 10.0.0.100)
3. Discovers routers via SSH sweep of 10.0.0.0/24
4. Runs test suites against each router
5. Publishes results to Nostr/Blossom
6. Self-deletes

### 3. Test Suites per Device

Each router gets device-appropriate tests:

| Router | Model | Tests |
|--------|-------|-------|
| NR7101 | Outdoor CPE | WiFi STA/AP, SQM, flash verify, 5G modem (if present) |
| GS1900-8HP | PoE Switch | Port status, PoE power, VLAN config, switch chip |
| COVR-X1860 | Mesh AP | WiFi mesh, guest-wifi, recovery-http flash |

Test results tagged with device model + serial for per-device tracking.

### 4. Result Publishing

Each test run publishes:
- Per-device results (passed/failed per test)
- Device inventory (model, firmware, serial, MAC)
- Artifacts (uci show, tc qdisc, iperf3 JSON, screenshots)
- All to Nostr kind 30078 with `project_tag=conwrt-hardware`

Dashboard shows hardware runs alongside QEMU runs, filtered by device.

## Migration Path

### Phase 1: VPN Infrastructure (1-2 days)
- Set up WireGuard server (VPS or home router)
- Flash one router (GS1900-8HP — already running OpenWrt) with WG client
- Verify VPN connectivity from a remote machine

### Phase 2: Hardware Test Suite (2-3 days)
- Write `conwrt/hardware/` test modules:
  - `test_switch.py` — port status, PoE, VLANs (GS1900-8HP)
  - `test_wifi.py` — radio detection, STA/AP, signal (COVR-X1860)
  - `test_flash_lifecycle.py` — sysupgrade roundtrip
- Each test takes router IP + SSH key as fixture

### Phase 3: Context-VM Integration (1-2 days)
- Add `--hardware` flag to conwrt SHC bootstrap
- Bootstrap installs WireGuard, connects to VPN, runs hardware tests
- Results publish with `project_tag=conwrt-hardware`

### Phase 4: Dashboard (1 day)
- Add `conwrt-hardware` to dashboard PROJECT_TAG_MAP
- Show device model + serial in run detail panel
- Group runs by device

## Key Design Decisions

1. **WireGuard over Tailscale/ZeroTier**: WG is already a conwrt use case,
   routers already support it, no extra dependencies. Tailscale would add
   a proprietary coordination server.

2. **SHC over self-hosted runner**: SHC gives us KVM (for QEMU fallback tests),
   ephemeral VMs (no persistent state), and the existing cloud-lab framework.
   A self-hosted runner at home would need to be always-on.

3. **Per-run VPN connection**: The context-VM connects fresh each run. No
   persistent VPN state. Routers stay connected to the WG server permanently.

4. **No direct internet from routers**: Tests run FROM the context-VM TO the
   routers. Routers don't need internet — the context-VM orchestrates everything.

5. **Device registry**: Each router is identified by its WG IP + MAC address.
   The inventory is tracked in `data/inventory.jsonl` (specimen-level, local
   to the conwrt repo). The WG IP mapping is the "phone book" for reaching
   devices remotely.
