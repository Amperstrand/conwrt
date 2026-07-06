# conwrt + vps-on-demand: Combined SHC Deployment

## Architecture

```
europa.westernbtc.com (SHC Dev VPS, 2C/8GB, $0.46/day)
│
├── Debian 13 (host)
│   ├── WireGuard (kernel module, host-level for management)
│   ├── Firecracker daemon (ContextVM MCP, port 8080)
│   │   ├── microVM: API service (256MB)
│   │   ├── microVM: Background worker (256MB)
│   │   └── microVM: Database (256MB)
│   └── QEMU (KVM)
│       └── OpenWrt VM (512MB)
│           ├── WireGuard server (UDP 51820 → public IP)
│           ├── SQM (traffic shaping for VPN clients)
│           ├── Firewall (zone isolation)
│           └── DNS/DHCP for VPN subnet
│
├── UDP 51820 → OpenWrt (VPN endpoint)
├── TCP 24000-24999 → Firecracker VMs (SSH)
└── TCP 8080 → Firecracker daemon (management API)
```

## Why This Works on $0.46/day

- WireGuard is kernel-space: near-zero CPU/RAM overhead
- Firecracker microVMs boot in ~125ms, use only what they need
- OpenWrt in QEMU with KVM: near-native speed, 512MB is plenty
- 8GB RAM easily fits host + OpenWrt + 5+ microVMs
- 16GB disk: 3GB used, 13GB free for VM images + overlays

## Deployment

### One-time setup (conwrt + vps-on-demand)

```bash
# 1. Order persistent SHC VM
scripts/cloud-lab.py submit-conwrt-vpn --branch master --keep-vm

# 2. Set up DNS: europa.westernbtc.com → <SHC public IP>
# 3. Configure WireGuard clients to connect to europa.westernbtc.com:51820
```

### What the bootstrap does

1. Installs WireGuard + Firecracker + QEMU + nak
2. Downloads and boots OpenWrt VM (KVM, UDP 51820 forwarded)
3. Configures OpenWrt via conwrt:
   - WireGuard server (auto-generated keypair)
   - SQM for traffic shaping
   - Firewall zones (VPN → LAN → WAN)
4. Starts Firecracker daemon (ContextVM MCP listener on Nostr kind 25910)
5. Tests: VPN handshake, ping through tunnel, Firecracker VM boot
6. Publishes results to Nostr/Blossom

### VPN client config

Clients (routers, context-VMs, laptops) connect to europa.westernbtc.com:51820.
The server's public key is published at `/etc/wireguard/server_public_key` on the OpenWrt VM.

For conwrt-managed routers:
```toml
[use_cases]
enabled = ["wireguard-client"]

[use_cases.wireguard-client]
peer_public_key = "<europa server pubkey>"
endpoint_host = "europa.westernbtc.com"
endpoint_port = 51820
address = "10.0.0.X/32"
allowed_ips = "10.0.0.0/24"
```

### Firecracker microVM access through VPN

VPN clients (10.0.0.x) can reach Firecracker VMs (172.16.x.y) through
the OpenWrt VM's routing. OpenWrt's firewall allows VPN→WAN forwarding,
and the Debian host routes between the OpenWrt VM and Firecracker VMs.

## Testing

```bash
# Full lifecycle test on SHC (auto-cleanup):
scripts/cloud-lab.py submit-conwrt-vpn --branch master

# Test verifies:
# 1. OpenWrt boots with WireGuard server configured by conwrt
# 2. Host WireGuard client handshakes with OpenWrt server
# 3. Ping through tunnel (10.0.0.2 → 10.0.0.1)
# 4. Key rotation (new client keypair, re-handshake)
# 5. Results published to tests.tollgate.me
```

## Production vs Test

| Aspect | Test | Production |
|--------|------|------------|
| VM lifetime | Ephemeral (auto-cancel) | Persistent |
| DNS | IP only | europa.westernbtc.com |
| Purpose | Verify config works | Serve VPN clients |
| Firecracker | Optional | Running daemon |
| Cost | ~$0.01 (10 min) | $0.46/day |
