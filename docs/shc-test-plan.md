# conwrt SHC Test Plan — Extensive Use Case Validation

## Current Test Coverage

### Tested (dry-run + QEMU runtime on SHC)
- **SQM** — dry-run (16 tests), runtime (tc qdisc CAKE verified)
- **DoH** — dry-run + runtime (resolver config verified)
- **SSH hardening** — dry-run + runtime (password disabled verified)
- **WireGuard client** — dry-run + runtime (wg0 config verified)
- **WireGuard server** — dry-run + runtime (auto-keygen verified)
- **VPN node** — dry-run + runtime (nak listing script verified)
- **nodns** — dry-run + runtime (dnsmasq zone verified)

### NOT tested (dry-run only or untested)
- **mwan3** — dry-run only, never run on a real OpenWrt instance
- **AdGuard** — dry-run only
- **guest_wifi** — dry-run only
- **travelmate** — dry-run only
- **openclash** — dry-run only
- **auto_sqm** — dry-run only
- **ssl** — dry-run only
- **tollgate** — dry-run only
- **mesh11sd** — dry-run only
- **usb_tether** — requires physical USB
- **fips_bluetooth_rfcomm** — requires physical Bluetooth

## Plan: Showcase Tests on SHC

### Test 1: Multi-WAN Bonding with Simulated Link Failure (FLAGSHIP)

**Architecture** (single SHC VM with KVM):
```
┌─────────────────────────────────────────────────────┐
│              SHC VM (2C/8GB/16GB)                     │
│                                                       │
│  ┌──────────┐         ┌──────────────────────────┐   │
│  │ ISP1 NS  │ ←─────→ │  OpenWrt QEMU VM         │   │
│  │ 10.0.1.1 │  eth1   │  mwan3 failover/balanced │   │
│  │ (httpd)  │         │                          │   │
│  └──────────┘         │  eth0: LAN 192.168.1.1   │   │
│                       │  eth1: WAN → ISP1        │   │
│  ┌──────────┐         │  eth2: WAN → ISP2        │   │
│  │ ISP2 NS  │ ←─────→ │                          │   │
│  │ 10.0.2.1 │  eth2   │  Client (192.168.1.100)  │   │
│  │ (httpd)  │         │  runs in same VM         │   │
│  └──────────┘         └──────────────────────────┘   │
│                                                       │
│  Test client: curl through OpenWrt, verify:           │
│    1. Traffic goes via ISP1 (primary)                 │
│    2. Kill ISP1 → traffic fails over to ISP2          │
│    3. Restore ISP1 → traffic returns to primary       │
│    4. Balanced mode → traffic distributed             │
└─────────────────────────────────────────────────────┘
```

**Steps**:
1. Install QEMU on SHC VM
2. Download OpenWrt x86 image (with mwan3 pre-installed)
3. Create 3 Linux network namespaces (ISP1, ISP2, client)
4. Connect namespaces to QEMU via TAP devices
5. Configure mwan3 on OpenWrt via conwrt
6. Test failover: simulate ISP1 down (iptables DROP in namespace)
7. Test recovery: remove DROP, verify return to primary
8. Test balanced: verify load distribution via mwan3 status
9. Document with evidence (ping traces, mwan3 status, throughput)

**Evidence produced**:
- `mwan3 status` output showing active interfaces
- Ping traces showing failover timing
- `ip route` showing route changes
- Traffic logs showing load distribution in balanced mode
- Screenshots/video of the test

### Test 2: SQM Bufferbloat Reduction (Quantified)

**Architecture**: OpenWrt QEMU VM + tc netem for latency injection

**Steps**:
1. Boot OpenWrt VM
2. Add 100ms latency via tc netem on the WAN interface
3. Measure latency WITHOUT SQM (flood ping while downloading)
4. Configure SQM via conwrt (`sqm` use case)
5. Measure latency WITH SQM (same flood + download)
6. Compare: show CAKE reduces max latency by N×

**Evidence**: before/after latency graphs, `tc qdisc` output

### Test 3: WireGuard Site-to-Site Tunnel

**Architecture**: Two OpenWrt QEMU VMs connected via WG tunnel

**Steps**:
1. Boot OpenWrt VM A (server, 10.0.0.1)
2. Boot OpenWrt VM B (client, 10.0.0.2)
3. Configure WG server on A via conwrt (`wireguard-server`)
4. Configure WG client on B via conwrt (`wireguard-client`)
5. Verify tunnel: ping 10.66.42.1 from B
6. Verify routing: traffic from B routes through A

**Evidence**: `wg show` handshake, ping across tunnel, `ip route` on both

### Test 4: AdGuard DNS Ad Blocking

**Architecture**: OpenWrt QEMU VM + AdGuard Home

**Steps**:
1. Boot OpenWrt VM
2. Install + configure AdGuard via conwrt (`adguard` use case)
3. Query a known ad domain (e.g., doubleclick.net)
4. Verify it's blocked (NXDOMAIN or 0.0.0.0)
5. Query a legitimate domain (e.g., example.com)
6. Verify it resolves correctly

**Evidence**: dig output showing blocked vs allowed domains

### Test 5: DoH Encrypted DNS Verification

**Architecture**: OpenWrt QEMU VM + tcpdump

**Steps**:
1. Boot OpenWrt VM WITHOUT DoH
2. tcpdump on WAN interface → DNS queries visible in plaintext (port 53)
3. Configure DoH via conwrt (`doh` use case)
4. tcpdump on WAN interface → DNS queries now over HTTPS (port 443)
5. Verify DNS still resolves correctly

**Evidence**: tcpdump before/after showing port 53 → 443 shift

### Test 6: SSH Hardening Verification

**Architecture**: OpenWrt QEMU VM

**Steps**:
1. Boot OpenWrt VM with password auth enabled
2. Verify password SSH works (baseline)
3. Apply `ssh-hardening` via conwrt
4. Verify password auth refused
5. Verify key auth still works

**Evidence**: SSH attempts before/after

## Implementation Priority

| Test | Impact | Effort | Priority |
|---|---|---|---|
| Multi-WAN bonding | HIGH — flagship showcase | Medium (QEMU + namespaces) | P0 |
| SQM bufferbloat | HIGH — quantifiable benefit | Low (single VM) | P1 |
| WireGuard site-to-site | MEDIUM — already partially tested | Medium (two VMs) | P2 |
| AdGuard DNS | MEDIUM — visual, easy to understand | Low | P3 |
| DoH verification | LOW — already tested | Low | P4 |
| SSH hardening | LOW — already tested | Low | P5 |

## Cost Estimate

- VM 1143 (2C/8GB/16GB): $1.06/day
- Tests run for ~4 hours: ~$0.18
- Credit available: $95.42
- No additional VMs needed for most tests (single VM with namespaces)

## Success Criteria

Each test must produce:
1. conwrt command that configures the use case
2. Verification command that proves it works
3. Evidence artifact (log output, screenshot, measurement)
4. Documentation showing the full workflow

All evidence published to tests.tollgate.me via Nostr/Blossom.
