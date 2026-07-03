# Final Test Session Report — 2026-07-03

## Summary: 31/32 tests passed across 5 repos on production infrastructure

All tests run on SHC Dev VPS (2C/8GB, KVM) and nodns.shop production server.

## Test Results by Wave

### Wave 1: Critical Bug Fixes
- Caddy `/v1/wg/connect` redirect FIXED on nodns.shop (added reverse_proxy to :8091)
- wg-jwt-peer SQLite persistence ADDED (modernc.org/sqlite, pure Go)

### Wave 2: conwrt Use Case Tests — 21/21 PASS

| Suite | Count | Duration | Evidence |
|-------|-------|----------|----------|
| Dry-run use cases | 16 | 2.1s | Python 3.13 on SHC, all PASS |
| QEMU KVM integration | 5 | 337s | OpenWrt 24.10.2, KVM-accelerated |

Previously failing `test_conwrt_configure_applies_sqm` now PASSES due to
opkg skip-when-installed fix + pre-baked packages.

### Wave 3: Payment Lifecycle — 5/5 PASS + lnforward 1/2

| Test | Result | Evidence |
|------|--------|----------|
| Mint testnuts | PASS | 10 sat, 7 proofs from testnut.cashu.exchange |
| Payment + JWT | PASS | tollgate-auth on nodns.shop signed Ed25519 JWT |
| JWT → WG peer | PASS | wg-jwt-peer at 66.92.204.239 accepted |
| Peer verified | PASS | count:1 in /peers API |
| Peer auto-expired | PASS | count:0 after 20s + cleanup timer |
| lnforward backup | PASS | Token stored with UUID receipt |
| lnforward rotate | FAIL | coco Manager V4 token incompatibility (issue #10) |

### Wave 4-6: Previously Proven (from earlier in session)

| Test | Result | Evidence |
|------|--------|----------|
| Europa node listing | PASS | Appeared on europa.westernbtc.com/operators |
| Bufferbloat (ping) | PASS | CAKE reduces max latency 2.6x (0.126→0.047ms) |
| VPN tunnel ping | PASS | 3/3 received, 0.041ms avg through WireGuard |
| JWT interoperability | PASS | Go-signed JWT verified by wg-jwt-peer on SHC |

### Unit Tests

| Component | Tests | Result |
|-----------|-------|--------|
| wg-jwt-peer (Go) | 8 | ALL PASS |
| tollgate-auth JWT (Go) | 9 | ALL PASS |
| lnforward security (TS) | 35 | ALL PASS |
| conwrt dry-run (Python) | 16 | ALL PASS |

## GitHub Issues Filed

1. [Amperstrand/vps-on-demand#7](https://github.com/Amperstrand/vps-on-demand/issues/7) — wg-jwt-peer systemd service file
2. [Amperstrand/lnforward#10](https://github.com/Amperstrand/lnforward/issues/10) — rotate mode V4 token failure

## Infrastructure Deployed

| Component | Location | Status |
|-----------|----------|--------|
| tollgate-auth (JWT) | nodns.shop | Live, Caddy proxies /v1/wg/connect |
| wg-jwt-peer + WG | SHC 883 (66.92.204.239) | Live, SQLite persistence |
| lnforward drop-off | lnurl.psbt.me | Live, backup mode working |
| conwrt tests | SHC 883 | 21/21 pass with KVM |

## Known Limitations

1. **lnforward rotate mode**: coco Manager can't parse Cashu V4 tokens. Backup mode works.
2. **wg-jwt-peer**: No systemd service — runs via nohup, doesn't survive VM reboot.
3. **conwrt publish_results.py**: Missing nostr_publish module on Mac. Workaround: use nak directly.
4. **OpenWrt QEMU VM**: SSH sometimes unreachable after test teardown. Needs VM reboot.

## What's Ready for Production

- Cashu payment → JWT → WireGuard peer → tunnel → expiry lifecycle: FULLY PROVEN
- conwrt use case UCI generation for 8+ use cases: FULLY PROVEN (dry-run)
- SQM on OpenWrt via conwrt configure: FULLY PROVEN (QEMU KVM)
- WireGuard server/client compatibility: FULLY PROVEN (dry-run + tunnel test)
- Cashu backup to lnforward: FULLY PROVEN (backup mode)
