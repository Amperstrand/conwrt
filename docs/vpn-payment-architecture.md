# VPN Payment Architecture — Verified and Documented

## What We Built

A complete payment-gated VPN system where a centralized cashier
(tollgate-auth) collects Cashu payments and issues JWTs that
authorize WireGuard access on remote VPN servers. The VPN servers
hold no money and need no wallet.

## Components

| Component | Repo | Role | Status |
|-----------|------|------|--------|
| tollgate-auth | tollgate-ssh | Cashier: validates Cashu, signs JWT | Code complete, 9 tests, pushed |
| wg-jwt-peer | vps-on-demand | VPN endpoint: verifies JWT, adds WG peer | Code complete, 8 tests, e2e passed |
| lnforward | lnforward | Backup: stores Cashu tokens per npub | Deployed to Cloudflare, live |
| conwrt vpn-node | conwrt | Use case: publishes Nostr listing | 16 dry-run tests, pushed |
| conwrt wireguard-server | conwrt | Use case: WireGuard server config | Auto-keypair, pushed |

## How It Works

```
1. DISCOVERY (public Nostr)
   VPN server publishes kind 30402 listing
   Includes: protocol, region, price, payment endpoint, server_id
   Does NOT include: IP, WG pubkey, subnet, session data

2. PAYMENT (private HTTPS)
   Client pays Cashu at tollgate-auth (nodns.shop)
   tollgate-auth validates + consumes token (swap at mint)
   tollgate-auth signs JWT with Ed25519

3. AUTHORIZATION (JWT, carried by client)
   Client receives: {endpoint, server_pubkey, jwt}
   Client POSTs jwt to VPN server's wg-jwt-peer
   wg-jwt-peer verifies signature (offline), checks exp + server_id
   wg-jwt-peer runs: wg set wg0 peer <pubkey> allowed-ips <ip>/32
   Sets timer: removes peer at exp

4. CONNECTION (WireGuard)
   Client configures WireGuard with returned endpoint + pubkey
   Tunnel established

5. REVENUE (periodic sweep)
   tollgate-auth accumulates Cashu
   Sweeps to lnforward /:operator-npub/dropoff (backup mode)
   Operator withdraws via Lightning
```

## Privacy Properties

- Nostr listing: no IP, no pubkey, no session data
- Payment: private HTTPS between client and tollgate-auth
- Session metadata: inside JWT, never on Nostr
- WireGuard: encrypted by design

## JWT Format

```json
Header: {"alg": "EdDSA", "typ": "JWT"}
Claims: {
  "iss": "tollgate-auth",
  "sub": "wg_peer",
  "pubkey": "<client WG public key>",
  "allowed_ip": "10.66.42.42",
  "server_id": "europa-ks",
  "exp": 1783011494,
  "iat": 1783010894
}
Signature: Ed25519 over base64url(header) + "." + base64url(claims)
```

Verified compatible between tollgate-auth (Go signer) and
wg-jwt-peer (Go verifier). Integration test passed on SHC VM.

## Test Results

### Unit Tests
- tollgate-auth jwt_signer_test.go: 9/9 passed
  - Sign + verify, invalid key, missing key, registry load,
    missing registry, unknown server, sign session, request
    unmarshal, response serialization
- wg-jwt-peer jwt_test.go: 8/8 passed
  - Valid JWT, expired, wrong server, bad signature, garbage
    input, split, peer expiry, multiple peers

### Integration Test (SHC VM 854)
1. Go tool signs JWT with Ed25519 (same code as tollgate-auth)
2. POST /peer to wg-jwt-peer on port 8082
3. wg-jwt-peer verifies signature offline (no network calls)
4. Checks server_id matches + exp not expired
5. wg set wg0 peer added successfully
6. Health: {"active_peers":1, "ok":true}
7. Two peers visible in wg show with correct allowed-ips

### Earlier E2E Test (SHC VM)
- WireGuard tunnel: handshake + ping verified (0.046ms)
- Europa listing: published to Nostr, visible on europa.westernbtc.com
- Cashu testnuts: accepted as payment method
- Bufferbloat: CAKE reduces max latency 2.6x

## Deployment Status

| What | Where | Running |
|------|-------|---------|
| lnforward drop-off | lnurl.psbt.me (Cloudflare) | Live |
| Europa node | europa.westernbtc.com listing | Was live (VM expired) |
| tollgate-auth | nodns.shop | Running old code (no JWT yet) |
| wg-jwt-peer | SHC VM 854 | Running (test instance) |

## To Deploy Production

1. Build tollgate-auth with JWT changes for the nodns.shop host
2. Generate Ed25519 keypair: `openssl genpkey -algorithm ED25519`
3. Create vpn-servers.json with the VPN server registry
4. Restart tollgate-auth with TOLLGATE_JWT_KEY + TOLLGATE_VPN_SERVERS env vars
5. Deploy wg-jwt-peer to the VPN server with the matching public key
6. VPN server publishes Nostr listing with payment_endpoint pointing to nodns.shop

## Environment Variables

### tollgate-auth
```
TOLLGATE_JWT_KEY=/path/to/ed25519-private.pem
TOLLGATE_VPN_SERVERS=/path/to/vpn-servers.json
```

### wg-jwt-peer
```
--auth-key=/path/to/ed25519-public.pem
--server-id=europa-ks
--wg-interface=wg0
--listen=:8082
```

### vpn-servers.json
```json
{
  "europa-ks": {
    "endpoint": "66.92.204.236:51820",
    "pubkey": "<WG server public key>",
    "subnet": "10.66.42.0/24",
    "listen_port": 51820
  }
}
```
