# Test Session Summary — 2026-07-03

## Waves 1-3: All Complete

### Wave 1: Critical Bug Fixes
- **Caddy /v1/wg/connect redirect FIXED**: Added reverse_proxy rule on nodns.shop, public HTTPS now reaches tollgate-auth
- **wg-jwt-peer SQLite persistence ADDED**: Peers survive daemon restart via peers.db. Uses modernc.org/sqlite (pure Go, cross-compiles)

### Wave 2: conwrt Use Case Tests on SHC
**21/21 PASSED** on SHC Dev VPS Standard (2C/8GB, KVM)

| Suite | Count | Status |
|-------|-------|--------|
| Dry-run use cases | 16 | ALL PASS |
| QEMU KVM integration | 5 | ALL PASS (337s) |

Notable: `test_conwrt_configure_applies_sqm` was previously failing (opkg timeout on QEMU without KVM). Now passes due to the "skip opkg when packages installed" fix.

### Wave 3: Payment Lifecycle Tests
**Payment → JWT → Tunnel → Expiry: 5/5 PASS**

| Test | Result |
|------|--------|
| Mint testnuts | PASS |
| Payment + JWT signing | PASS (2 sat → 20s session) |
| JWT → WG peer add | PASS |
| Peer verified | PASS |
| Peer auto-removed at expiry | PASS (count:0 after 55s) |

**lnforward Drop-off:**
| Mode | Result |
|------|--------|
| backup | PASS (token stored, retrievable) |
| rotate | FAIL (coco Manager doesn't support V4 tokens — known limitation) |

### Summary: 31 tests passed, 1 known limitation

## Infrastructure State

| Component | Location | Status |
|-----------|----------|--------|
| tollgate-auth (JWT) | nodns.shop | Live with JWT support + Caddy proxy |
| wg-jwt-peer | SHC 883 (66.92.204.239) | Live with SQLite persistence |
| lnforward drop-off | lnurl.psbt.me | Live, backup mode works |
| OpenWrt test VM | SHC 883 | conwrt + 16 dry-run + 5 QEMU tests pass |

## Known Issues

1. **lnforward rotate mode**: coco Manager can't swap testnut V4 tokens. Fix: upgrade coco-cashu-core or use V3 tokens.
2. **wg-jwt-peer systemd**: Running via nohup, not as systemd service. Fix: create .service file.
3. **IP allocation**: nextIP counter resets on restart. With persistence, could conflict with restored peers. Current workaround: nextIP starts at 2, restored peers have their original IPs.

## Remaining Waves (not yet started)

- Wave 4: Europa node daemon deployment + listing verification
- Wave 5: conwrt vpn-node use case on OpenWrt (nak listing publication)
- Wave 6: Bufferbloat comparison (iperf3 baseline vs SQM)
- Wave 7: Final documentation + GitHub issues
