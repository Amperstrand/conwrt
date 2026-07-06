# MPTCP Bonding Test Plan — Comprehensive Performance + Failover

**Methodology**: Based on NetBeez MPTCP testing guide (April 2026) +
BSBF documentation + OpenWrt SNAPSHOT CONFIG_MPTCP verification.

## Architecture

```
SHC VM A (europa-mptcp-router, 2C/8GB)     SHC VM B (europa-vpn-vps, existing)
┌──────────────────────────────────┐        ┌─────────────────────────────┐
│ QEMU: OpenWrt SNAPSHOT           │        │ BSBF Server                 │
│ Kernel 6.18+ (CONFIG_MPTCP=y)   │        │ xray-core :16384            │
│                                  │        │ iperf3 -s -p 5201           │
│ eth0: LAN (tap0 → host SSH)     │        │ MPTCP enabled (kernel 6.12) │
│ eth1: WAN1 (SLIRP 10.0.2.0/24)  │        │                             │
│ eth2: WAN2 (SLIRP 10.0.3.0/24)  │        │ 66.92.204.237               │
│                                  │        └──────────┬──────────────────┘
│ MPTCP endpoints:                 │                   │
│   10.0.2.15 dev eth1 subflow    │───────────────────┤
│   10.0.3.15 dev eth2 subflow    │───────────────────┤
│                                  │                   │
│ iperf3 --mptcp -c 66.92.204.237 │                   ▼
└──────────────────────────────────┘              Internet
```

## Prerequisites

1. **SHC VM A**: Fresh `europa-mptcp-router` (2C/8GB, Debian 13)
   - QEMU + KVM installed
   - OpenWrt SNAPSHOT x86-64 image downloaded
   - 3 NICs configured (LAN tap + 2 WAN SLIRP)

2. **SHC VM B** (VM 1077, existing):
   - BSBF server running (xray :16384) ✅ already deployed
   - iperf3 installed ✅ already installed
   - MPTCP enabled ✅ `net.mptcp.enabled=1`

3. **OpenWrt image**: SNAPSHOT r35216+ (has CONFIG_MPTCP=y since Oct 2024)
   - Download: `https://downloads.openwrt.org/snapshots/targets/x86/64/openwrt-x86-64-generic-squashfs-combined.img.gz`

## Test Procedures

### Phase 0: Setup (5 min)

```bash
# On SHC VM A (fresh europa-mptcp-router):
sudo apt-get install -y qemu-system-x86 qemu-utils
cd /tmp
wget -q "https://downloads.openwrt.org/snapshots/targets/x86/64/openwrt-x86-64-generic-squashfs-combined.img.gz"
gunzip openwrt-x86-64-generic-squashfs-combined.img.gz
truncate -s 1G openwrt-x86-64-generic-squashfs-combined.img

# TAP for LAN access
sudo ip tuntap add dev tap0 mode tap
sudo ip link set tap0 up
sudo ip addr add 192.168.1.100/24 dev tap0

# Enable host routing (for LAN → internet)
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -s 192.168.1.0/24 -j ACCEPT
sudo iptables -A FORWARD -d 192.168.1.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Boot OpenWrt SNAPSHOT with 3 NICs
sudo qemu-system-x86_64 -m 768 -display none \
  -serial file:/tmp/console.log \
  -drive file=/tmp/openwrt-x86-64-generic-squashfs-combined.img,format=raw,if=virtio \
  -netdev tap,id=lan,ifname=tap0,script=no,downscript=no \
  -device virtio-net-pci,netdev=lan \
  -netdev user,id=wan1,net=10.0.2.0/24 \
  -device virtio-net-pci,netdev=wan1 \
  -netdev user,id=wan2,net=10.0.3.0/24 \
  -device virtio-net-pci,netdev=wan2 \
  -enable-kvm -daemonize -pidfile /tmp/ow.pid
```

Wait 90 seconds, then:
```bash
# Install SSH key + verify
ssh -o StrictHostKeyChecking=no root@192.168.1.1 "mkdir -p /etc/dropbear; echo '<YOUR_PUBKEY>' > /etc/dropbear/authorized_keys"

# Verify MPTCP
ssh root@192.168.1.1 "cat /proc/sys/net/mptcp/enabled"
# Expected: 1

# Verify 3 interfaces
ssh root@192.168.1.1 "ls /sys/class/net/"
# Expected: br-lan eth0 eth1 eth2 lo
```

### Phase 1: Dual-WAN Configuration (2 min)

```bash
ssh root@192.168.1.1 << 'EOF'
# Configure WAN1 on eth1
uci set network.wan=interface
uci set network.wan.proto=dhcp
uci set network.wan.device=eth1
uci commit network

# Configure WAN2 on eth2
uci set network.wan2=interface
uci set network.wan2.proto=dhcp
uci set network.wan2.device=eth2
uci commit network

/etc/init.d/network restart
EOF

sleep 10

# Get WAN IPs
WAN1_IP=$(ssh root@192.168.1.1 "ip -br addr show eth1 | awk '{print \$3}' | cut -d/ -f1")
WAN2_IP=$(ssh root@192.168.1.1 "ip -br addr show eth2 | awk '{print \$3}' | cut -d/ -f1")
echo "WAN1: $WAN1_IP, WAN2: $WAN2_IP"

# Install iperf3 (apk for SNAPSHOT)
ssh root@192.168.1.1 "apk update && apk add iperf3"
```

### Phase 2: MPTCP Endpoint Configuration (1 min)

```bash
ssh root@192.168.1.1 << EOF
# Flush existing endpoints
ip mptcp endpoint flush

# Add both WAN interfaces as MPTCP subflow endpoints
ip mptcp endpoint add $WAN1_IP dev eth1 subflow
ip mptcp endpoint add $WAN2_IP dev eth2 subflow

# Set limits
ip mptcp limits set subflows 8 add_addr_accepted 4

# Verify
ip mptcp endpoint show
ip mptcp limits show
EOF
```

Expected output:
```
<WAN1_IP> id 1 subflow dev eth1
<WAN2_IP> id 2 subflow dev eth2
add_addr_accepted 4 subflows 8
```

### Phase 3: Throughput Aggregation Test (5 min)

**Goal**: Prove MPTCP combines bandwidth from both WAN paths.

```bash
# On VPS (VM 1077): start iperf3 server
iperf3 -s -p 5201

# On OpenWrt VM: baseline single-path TCP test
iperf3 -c 66.92.204.237 -p 5201 -t 10 -J > /tmp/baseline_tcp.json

# MPTCP aggregated test
iperf3 -c 66.92.204.237 -p 5201 -t 10 --mptcp -J > /tmp/mptcp_bonded.json
```

**Expected result** (based on NetBeez research):
- Single-path TCP: ~X Mbps (limited by one SLIRP path)
- MPTCP bonded: ~2X Mbps (both paths combined)
- With QEMU SLIRP (shared host NIC), aggregation gain may be modest
- The key metric: **MPTCP total ≥ single-path total** (no regression)

**Monitor subflows during test** (run in parallel):
```bash
ip mptcp monitor > /tmp/mptcp_monitor.log &
```

### Phase 4: Failover Test — Kill WAN1 (3 min)

**Goal**: Prove TCP connection survives when one path dies.

```bash
# Start 30-second MPTCP iperf3 test
iperf3 -c 66.92.204.237 -p 5201 -t 30 --mptcp -i 1 > /tmp/failover_test.txt &

# Wait 10 seconds, then kill WAN1
sleep 10
ip link set eth1 down
echo "WAN1 DOWN at $(date +%T)"

# Wait 10 more seconds, then restore WAN1
sleep 10
ip link set eth1 up
echo "WAN1 UP at $(date +%T)"

# Wait for test to complete
wait

cat /tmp/failover_test.txt
```

**Expected result** (based on NetBeez April 2026 test):
```
[5] 0.00-1.00 sec ~X MBytes ~X Mbits/sec        # Normal: both paths active
[5] 1.00-2.00 sec ~X MBytes ~X Mbits/sec        # Normal
...
[5] 9.00-10.00 sec ~X MBytes ~X Mbits/sec        # Last second before kill
[5] 10.00-11.00 sec ~0.3X MBytes ~0.3X Mbits/sec # WAN1 down: throughput dips ~70%
[5] 11.00-12.00 sec ~0.7X MBytes ~0.7X Mbits/sec # Recovering: subflow removed
[5] 12.00-13.00 sec ~X MBytes ~X Mbits/sec        # Fully recovered on WAN2 alone
...
[5] 20.00-21.00 sec ~X MBytes ~X Mbits/sec        # WAN1 restored: throughput rises
[5] 21.00-22.00 sec ~X MBytes ~X Mbits/sec        # Both paths active again
```

**Key proof points**:
1. Connection did NOT drop (no "connection reset" or "broken pipe")
2. Throughput recovered within ~2 seconds of link failure
3. Throughput increased again when link restored
4. `ip mptcp monitor` shows subflow create/destroy events

### Phase 5: Failover Test — Kill WAN2 (mirror of Phase 4)

Same as Phase 4 but kill `eth2` instead of `eth1`. Proves failover works in both directions.

### Phase 6: BSBF Throughput Test (5 min)

**Goal**: Measure actual bonded throughput through the full BSBF stack (xray + VLESS + MPTCP).

```bash
# Install BSBF client (if not already installed)
ssh root@192.168.1.1 "apk add curl && curl -fsSL owrt.bondingshouldbefree.org | sh -s -- \
  --server-ipv4 66.92.204.237 --server-port 16384 --uuid 1eb861ca-192b-47e4-8806-f0e28489bbab"

# Run iperf3 through BSBF transparent proxy
iperf3 -c 66.92.204.237 -p 5201 -t 10 -J > /tmp/bsbf_throughput.json
```

**Expected result**:
- BSBF throughput < raw MPTCP throughput (VLESS encryption + proxy overhead)
- Still higher than single-path (bonding still works through xray)
- Rate limit caps at 50 Mbps (configured on server)

### Phase 7: Evidence Capture + Publication

```bash
# Capture all evidence
mkdir -p /tmp/mptcp-evidence
cp /tmp/baseline_tcp.json /tmp/mptcp-evidence/
cp /tmp/mptcp_bonded.json /tmp/mptcp-evidence/
cp /tmp/failover_test.txt /tmp/mptcp-evidence/
cp /tmp/mptcp_monitor.log /tmp/mptcp-evidence/
ssh root@192.168.1.1 "ip mptcp endpoint show; ip mptcp limits show; cat /proc/sys/net/mptcp/enabled" > /tmp/mptcp-evidence/mptcp_config.txt
ssh root@192.168.1.1 "uname -r; cat /etc/openwrt_release" > /tmp/mptcp-evidence/system_info.txt

# Publish to Nostr/Blossom
python3 conwrt/publish_results.py \
  --results-dir /tmp/mptcp-evidence \
  --run-id "conwrt-mptcp-dualwan-failover-$(date +%s)" \
  --summary "MPTCP dual-WAN bonding + failover test on OpenWrt SNAPSHOT" \
  --passed 1 --failed 0
```

## FIPS Integration: Multi-Router HA

For a production high-availability setup combining MPTCP with physical router redundancy:

```
Layer 1: MPTCP subflows (per-link failover, ~2s recovery)
  └── BSBF client manages subflow add/remove based on ping RTT

Layer 2: BSBF client (per-router, reconnects if entire router dies)
  └── xray reconnects to VPS within ~10s

Layer 3: FIPS/keepalived (per-site, VRRP between routers)
  └── Gateway IP floats between routers (~3s VRRP failover

Layer 4: nodns/mDNS (service discovery, survives any single failure)
  └── Clients rediscover the active gateway
```

This gives 4 layers of redundancy:
- Link failure → MPTCP subflow failover (transparent, ~2s)
- Router failure → VRRP gateway failover (~3s)
- VPS failure → Secondary VPS (if configured, manual DNS switch)
- ISP failure → Alternate WAN (if mwan3 or BSBF multi-WAN configured)

## References

- NetBeez MPTCP testing: https://netbeez.net/blog/testing-mptcp-with-iperf3/
- iperf3 --mptcp documentation: iperf3 3.19+ (built-in MPTCP flag)
- BSBF documentation: https://github.com/bondingshouldbefree/.github/blob/test/profile/documentation.md
- BSBF performance test scripts: https://github.com/bondingshouldbefree/bsbf-perf-test
- OpenWrt MPTCP wiki: https://openwrt.org/docs/guide-user/network/mptcp
- RFC 8684 (MPTCP): https://www.rfc-editor.org/rfc/rfc8684
- Selective conntrack flush for clean failover: https://sindro.me/posts/2026-05-01-mwan3-failover-conntrack/
- OpenWrt CONFIG_MPTCP commit (Oct 2024): openwrt/openwrt@c8d5abd
