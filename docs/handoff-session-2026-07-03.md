# Session Handoff — 2026-07-03

## What's Live Right Now

### Persistent VPN Server ( Reaper-Safe )
- **VM**: europa-vpn-persistent, service 958, IP 66.92.204.236
- **Hostname**: starts with `europa-` — NOT matched by reaper prefixes (`tollgate-`, `ci-`, `fips-`)
- **WG pubkey**: J6vna+T8o+ibG4qSGL3dp7cbHYQTnvFo4//+V21ctHM=
- **wg-jwt-peer**: systemd service `wg-jwt-peer.service`, SQLite at `/var/lib/wg-jwt-peer/peers.db`
- **Server ID**: `europa-vpn` (registered in nodns.shop vpn-servers.json)
- **Cost**: $0.26/day

### Cashier (tollgate-auth)
- **Location**: nodns.shop
- **JWT signing**: Ed25519 key at `/opt/cashu-tollgate/jwt-signing.key`
- **Caddy**: `/v1/wg/connect` proxied to :8091
- **vpn-servers.json**: Two entries — `europa-vpn` (persistent) and `vpn-shc-860` (ephemeral)
- **Cashu**: Validates testnut.cashu.exchange tokens

### Cashu Backup (lnforward)
- **Location**: lnurl.psbt.me (Cloudflare Worker)
- **Drop-off**: `POST /:npub/dropoff` with `mode=backup` works
- **Rotate mode**: Broken on V4 tokens (issue #10)

## Proven E2E (with evidence)

1. Cashu mint → tollgate-auth validate → JWT sign → wg-jwt-peer verify → WG peer add → tunnel → expiry
2. 16 dry-run use case tests + 5 QEMU KVM SQM tests = 21/21 pass
3. Bufferbloat: CAKE reduces max latency 2.6x
4. lnforward backup mode: PASS

## What's NOT Done (Prioritized)

### P0: Europa Node Daemon on Persistent VM
The europa-node Docker container was NOT deployed on the persistent VM (66.92.204.236).
The deploy script timed out during `docker compose build`. Need to:
- SSH to 66.92.204.236 and run `docker compose up -d` from /tmp/europa-node/
- Or skip europa-node and publish listing manually via nak

### P1: Nostr Listing Publication
No kind 30402 listing has been published for the persistent VM yet.
Publish via:
```bash
nak event -k 30402 --sec "$NSEC" \
    -d "westernbtc-europa-vpn" \
    -t "t=vpn-service" -t "protocol=wireguard" \
    -c '{"type":"vpn-service","name":"WesternBTC Europa VPN","endpoint":"66.92.204.236:51820","public_key":"J6vna+T8o+ibG4qSGL3dp7cbHYQTnvFo4//+V21ctHM=","protocols":["wireguard"],"prices":[{"amount":50,"currency":"sat","unit":"hour"}],"policies":["no-logs"],"content":"Persistent VPN. Cashu testnuts. Testing."}' \
    wss://relay.damus.io wss://relay.cashu.email
```

### P2: Tests in physical-router-test-automation
- `conwrt/test_vpn_e2e.py` exists but needs updating to use `europa-vpn` server_id
- Need a test for conwrt wireguard-client on OpenWrt QEMU VM connecting to the persistent VPN
- Both should publish results to tests.tollgate.me

### P3: conwrt wireguard-client on real OpenWrt
Dry-run tests pass but never applied to a real OpenWrt instance against the VPN server.

## Key Credentials/Locations
- nodns.shop SSH: `ssh root@nodns.shop`
- SHC VM 958 SSH: **DESTROYED** — compromised via password leak in this doc (public GitHub). See forensics below.
- NSEC: `~/.config/prta/nsec`
- tollgate-auth JWT key: `/opt/cashu-tollgate/jwt-signing.key` on nodns.shop
- wg-jwt-peer auth key: `/etc/wg-jwt-peer/tollgate-auth.pub` on 66.92.204.236

## Repos Modified This Session
- **conwrt**: vpn-node use case, wireguard-server auto-keypair, SQM opkg fix, dry-run tests, docs
- **tollgate-ssh**: jwt_signer.go (JWT signing), 9 tests
- **vps-on-demand**: wg-jwt-peer (JWT verification + SQLite), deploy scripts, europa bootstrap
- **lnforward**: dropoff.ts (Cashu backup/rotate), migration 0016
- **physical-router-test-automation**: conwrt/ test suite, submit-conwrt command
