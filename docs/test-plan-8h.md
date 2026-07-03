# 8-Hour Depth-First Test Plan

## Inventory: What's Built vs What's Tested

### Components and Test Status

| # | Component | Repo | Unit Tests | E2E on SHC | Gaps |
|---|-----------|------|-----------|------------|------|
| 1 | wg-jwt-peer (VPN endpoint) | vps-on-demand | 8 pass | Cashu→JWT→WG→ping PASS | No persistence, no restart recovery |
| 2 | tollgate-auth JWT signing | tollgate-ssh | 9 pass | Cashu→JWT PASS | Caddy redirects /v1/wg to GH Pages |
| 3 | lnforward drop-off | lnforward | 35 pass | Route deployed, token submit untested with real Cashu | Never tested rotate mode |
| 4 | conwrt dry-run use cases | conwrt | 16 pass | N/A (no infra needed) | All pass |
| 5 | conwrt SQM on QEMU | conwrt | 5 pass (earlier) | PASS on SHC KVM | Pre-bake packages untested |
| 6 | conwrt wireguard-server | conwrt | 3 pass (dry-run) | Server-only tested on Debian | Never on OpenWrt |
| 7 | conwrt wireguard-client | conwrt | 3 pass (dry-run) | Never tested against real server | The critical untested role |
| 8 | conwrt vpn-node (listing) | conwrt | 1 pass (dry-run) | nak listing published manually | First-boot script never tested |
| 9 | conwrt DoH | conwrt | 2 pass (dry-run) | Never on real OpenWrt | Runtime behavior unverified |
| 10 | conwrt ssh-hardening | conwrt | 1 pass (dry-run) | Never on real OpenWrt | Dropbear config unverified |
| 11 | Europa node daemon | vps-on-demand | N/A | Deployed once, VM expired | Not persistent |
| 12 | deploy-vpn.py | vps-on-demand | N/A | Used manually | Never run as one-shot |

### Unknown Unknowns (surfaced)

1. **JWT exp vs session_timeout mismatch**: JWT exp is +100s (from Cashu token). WG peer auto-removes at exp. But what if client needs more time? Must re-pay.
2. **IP allocation race**: wgManager.nextIP increments without atomicity. Two simultaneous payments could get same IP.
3. **wg-jwt-peer restart**: Peers are in-memory only. Restart = all peers lost. Need persistence.
4. **Caddy config on nodns.shop**: `/v1/wg/connect` redirects to GitHub Pages. Public HTTPS broken.
5. **Cashu token format**: testnut.cashu.exchange returns V4 tokens (cashuB...). tollgate-auth's replay guard might not handle V4.
6. **Multiple sequential payments**: Does nextIP reset? Does it monotonically increase across restarts?
7. **DNS through tunnel**: JWT includes `"dns": "1.1.1.1"` but nobody configures the client's DNS.
8. **Tunnel MTU**: Default 1420. Large packets might fragment.
9. **Concurrent wg-jwt-peer instances**: If daemon restarts, old timer-based removals fire on dead process.
10. **testnut.cashu.exchange reliability**: FakeWallet sometimes delays quote resolution.

## Depth-First Execution Order

### Wave 1: Fix Critical Bugs (30 min)
- [ ] Fix Caddy config on nodns.shop for /v1/wg/connect
- [ ] Add peer persistence to wg-jwt-peer (SQLite)
- [ ] Fix IP allocation race (mutex already exists, verify)

### Wave 2: Test All conwrt Use Cases on OpenWrt QEMU (2 hours)
- [ ] Boot OpenWrt VM on SHC with KVM
- [ ] Test SQM (configure + tc qdisc verify)
- [ ] Test DoH (configure + https-dns-proxy verify)
- [ ] Test ssh-hardening (configure + dropbear verify)
- [ ] Test wireguard-server (configure + wg show verify)
- [ ] Test wireguard-client (configure + handshake verify)
- [ ] Test nodns (configure + dnsmasq verify)
- [ ] Test combined: SQM + DoH + ssh-hardening
- [ ] Publish results to tests.tollgate.me

### Wave 3: Test VPN Payment Roles (1.5 hours)
- [ ] Test lnforward drop-off with real testnut token (backup mode)
- [ ] Test lnforward drop-off with real testnut token (rotate mode)
- [ ] Test full payment→JWT→tunnel→expiry flow
- [ ] Test reconnection after expiry (re-pay)
- [ ] Test concurrent payments (race condition)
- [ ] Publish results to tests.tollgate.me

### Wave 4: Test Europa Node + Listing (1 hour)
- [ ] Deploy europa-node daemon on persistent SHC
- [ ] Verify listing appears on europa.westernbtc.com
- [ ] Verify /purchase endpoint accepts Cashu
- [ ] Verify peer lifecycle (add + expire)
- [ ] Publish results to tests.tollgate.me

### Wave 5: Test VPN Node conwrt Use Case (1 hour)
- [ ] Boot OpenWrt VM
- [ ] Apply vpn-node + wireguard-server use cases
- [ ] Verify nak publishes kind 30402 listing
- [ ] Verify listing visible on europa.westernbtc.com
- [ ] Publish results

### Wave 6: Bufferbloat + Network Quality (1 hour)
- [ ] Boot OpenWrt VM with SQM
- [ ] Run iperf3 baseline (no SQM)
- [ ] Configure SQM via conwrt
- [ ] Run iperf3 with SQM
- [ ] Compare latency under load
- [ ] Publish comparison results

### Wave 7: Documentation + Issues (30 min)
- [ ] Update vpn-payment-architecture.md with test results
- [ ] File issues for bugs found
- [ ] Create handover document
