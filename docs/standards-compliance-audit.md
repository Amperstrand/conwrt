# Standards Compliance Audit — Cashu VPN + VPS Service

**Date**: 2026-07-04
**Audience**: Operators and developers
**Status**: Living document — update as compliance improves

---

## Executive Summary

Our service implements Cashu-paywalled VPN and Firecracker VPS access with
three interfaces: HTTP API (NUT-24), Nostr listing (NIP-99), and ContextVM
MCP-over-Nostr (kind 25910). The core payment flow works end-to-end, but
several standards compliance gaps prevent full interoperability with the
broader Cashu, Nostr, and Europa ecosystems.

**Compliance scorecard**: 7/15 checks pass, 5 partial, 3 fail.

---

## 1. Cashu NUTs Compliance

### NUT-04: Mint Tokens
**Status**: ✅ Compliant (via faucet)

The faucet API (`GET /api/mint?amount=N`) uses Nutshell CLI which calls
`POST /v1/mint/quote/bolt11` and `POST /v1/mint/bolt11` internally. The
testnut FakeWallet auto-pays quotes, so no Lightning is needed.

### NUT-07: Check State
**Status**: ❌ Not explicitly implemented

We do not call `POST /v1/checkstate` to verify proofs before accepting them.
The `cdk-cli receive` command performs a NUT-03 swap which implicitly checks
state (spent proofs fail the swap), but we don't verify independently.

**Fix needed**: Call `/v1/checkstate` before accepting tokens, or switch to
Nutshell Python which handles this during `wallet.receive()`.

### NUT-10/11: Spending Conditions / P2PK
**Status**: ❌ Not implemented

We accept any valid Cashu token. We do not require P2PK-locked tokens, which
means:
- Tokens could be front-run (stolen in transit)
- No multi-sig or escrow support
- Europa protocol expects a `p2pk` field in Cashu payment tags

**Fix needed**: Generate a P2PK pubkey per transaction, require tokens locked
to it. This prevents front-running and enables offline verification.

### NUT-18: Payment Requests
**Status**: ⚠️ Partially compliant

We generate `creqA`-encoded payment requests in the NUT-24 `X-Cashu` header.
However:
- The encoding uses CBOR + base64url, which matches the spec
- We do NOT include NUT-10 locking conditions in the request
- We do NOT support the `t` (transport) field — clients must use the header

**What's missing**: NUT-10 locking, transport field (POST callback, Nostr).

### NUT-24: HTTP 402 Payment Required
**Status**: ⚠️ Partially compliant

**VPS endpoint** (`POST /v1/vms/create`): ✅ Implemented
- Returns `402 + X-Cashu: creqA...` when no payment
- Accepts `X-Cashu: cashuB...` header for payment
- Also accepts token-in-body for backward compatibility

**VPN endpoint** (`POST /v1/wg/connect`): ❌ NOT implemented
- Still uses token-in-body (`{"token": "cashuB..."}`)
- Does NOT return 402 + X-Cashu
- Inconsistent with VPS endpoint

**Fix needed**: Add NUT-24 to `/v1/wg/connect` on nodns.shop.

### NUT-26: Alternative Encoding
**Status**: ❌ Not implemented

We only produce `creqA` (NUT-18), not `creqb` (NUT-26). NUT-26 is 30-60%
smaller. Not critical but reduces header size.

---

## 2. Nostr NIPs Compliance

### NIP-01: Basic Protocol
**Status**: ✅ Compliant

All events are properly signed with secp256k1/Schnorr. Event IDs are
correct SHA-256 hashes of the canonical serialization.

### NIP-19: bech32 Entities
**Status**: ✅ Compliant

Provider npubs are correctly encoded. Our provider:
- hex: `ebed800d267153c35999947962ac38ecf560b09a8245a382df5572840fba6f6c`
- npub: `npub1a0kcqrfxw9fuxkvej3uk9tpcan6kpvy6sfz68qkl24eggra6dakqy75ct7`

### NIP-40: Expiration Timestamp
**Status**: ❌ Not used

ContextVM kind 25910 events are ephemeral but do not carry `["expiration", ...]`
tags. Relays may store them indefinitely. Should add expiration to reduce
relay storage burden.

### NIP-44: Encrypted Messages (v2)
**Status**: ❌ NOT implemented on ContextVM

**This is a significant gap.** Our ContextVM messages (kind 25910) are sent
in PLAINTEXT. The ContextVM spec (CEP-4) requires NIP-44 v2 encryption via
gift wrap (kind 1059 or 21059).

Currently, anyone monitoring the relay can read:
- The MCP method being called (e.g., `create_vps`)
- The Cashu token in the arguments
- The SSH key being installed
- The VM connection details in the response

**Fix needed**: Wrap kind 25910 messages in kind 21059 (ephemeral gift wrap)
with NIP-44 v2 encryption.

### NIP-59: Gift Wrap
**Status**: ❌ Not used

Same issue as NIP-44. ContextVM spec requires gift wrapping.

### NIP-90: Data Vending Machines
**Status**: N/A (deprecated)

Per ADR-007 in hackathon-tooling, NIP-90 DVM is deprecated for our use case.
ContextVM (kind 25910) is the replacement. The Firecracker daemon's DVM
mode (`--dvm` flag) exists but is not enabled.

### NIP-99: Classified Listings
**Status**: ❌ Non-compliant with Europa protocol

Our kind 30402 listing has several issues:

| Field | Europa Spec | Our Listing | Fix |
|-------|-------------|-------------|-----|
| Protocol tag | `["t", "europa-protocol"]` | `["t", "vpn-service"]` | Change to `europa-protocol` |
| VPN protocol | `["t", "wireguard"]` | `["protocol", "wireguard"]` | Change tag name to `t` |
| Title | `["title", "..."]` tag | In content JSON only | Add as tag |
| Payment (Cashu) | `["payment", "cashu", "mint_url", "p2pk", "endpoint"]` | In content JSON only | Add as tag |
| Prices | `["price", "amount", "unit"]` tags | In content JSON only | Add as tags |
| Status | `["status", "active"]` | Missing | Add |
| Location | `["location", "..."]` or `["g", "geohash"]` | Missing | Add |
| Geohash ladder | `["g", "d"]`, `["g", "dh"]`, ... | Missing | Add |

**Impact**: Our listing is invisible on europa.westernbtc.com because it
doesn't match the Europa protocol filter (`#t: vpn-marketplace` or
`#t: europa-protocol`).

---

## 3. ContextVM Compliance

### Kind 25910: MCP Messages
**Status**: ✅ Working (tested E2E)

The server correctly:
- Listens for kind 25910 on 3 relays
- Parses MCP JSON-RPC requests
- Dispatches to 6 tools (create_vps, connect_vpn, list_vms, destroy_vm, faucet, health)
- Returns responses as kind 25910

### Kind 11316: Server Announcement
**Status**: ✅ Published

### Kind 11317: Tools List
**Status**: ✅ Published with correct tool definitions

### CEP-4: Encryption
**Status**: ❌ Not implemented

All ContextVM messages are plaintext. See NIP-44 section above.

### CEP-8: Payment
**Status**: ⚠️ Non-standard

We embed Cashu tokens directly in MCP tool arguments (`cashu_token` parameter).
CEP-8 defines a `direct_payment` tag for standardized payment attachment.
Our approach works but is not interoperable with CEP-8-compliant clients.

### CEP-17: Relay List Metadata (kind 10002)
**Status**: ❌ Not published

We don't publish kind 10002 with our relay list. ContextVM clients use
this to discover which relays to connect to for our server.

### CEP-19: Ephemeral Gift Wrap (kind 21059)
**Status**: ❌ Not used

Should use kind 21059 for ephemeral encrypted MCP messages.

---

## 4. Security Audit

### Credential Exposure
| Credential | Where Exposed | Risk |
|-----------|---------------|------|
| Cashu token | Plaintext in ContextVM args | HIGH — token stealable |
| SSH key | Plaintext in ContextVM args | MEDIUM — key visible |
| VM SSH port | Plaintext in ContextVM response | LOW — already public via DNAT |
| WireGuard pubkey | Plaintext in ContextVM args | LOW — pubkeys are not secret |

### Token Front-Running
Any Cashu token sent over plaintext ContextVM can be intercepted and
redeemed by a third party before our server processes it. NUT-10 P2PK
locking would prevent this.

### Rate Limiting
- VPS proxy: No rate limiting on `/v1/vms/create`
- Faucet: No rate limiting on `/api/mint` (could be abused)
- ContextVM: No rate limiting on kind 25910 requests

---

## 5. Priority Fixes

### P0: Fix Europa listing (immediate visibility)
1. Change `["t", "vpn-service"]` → `["t", "europa-protocol"]`
2. Change `["protocol", "wireguard"]` → `["t", "wireguard"]`
3. Add `["title", "WesternBTC TestVPN+VPS"]`
4. Add `["status", "active"]`
5. Add `["payment", "cashu", "https://testnut.cashu.exchange", "", "https://nodns.shop/v1/wg/connect"]`
6. Add `["price", "1", "sat"]` (or similar format)
7. Add `["location", "US"]` and geohash tags

### P1: Fix ContextVM encryption
1. Implement NIP-44 v2 encryption for kind 25910 messages
2. Use kind 21059 (ephemeral gift wrap) wrapper
3. Encrypt both requests and responses

### P2: Add NUT-24 to VPN endpoint
1. Update tollgate-auth `/v1/wg/connect` to return 402 + X-Cashu
2. Accept X-Cashu header for payment

### P3: Fix daemon source code
1. Fix the `/run/sshd` tmpfs ordering bug in git repo
2. Commit and push the fix

### P4: Add P2PK locking
1. Generate ephemeral keypair per transaction
2. Include pubkey in NUT-18 payment request
3. Require tokens locked to our pubkey

### P5: Publish kind 10002 relay list
1. Publish our relay list for ContextVM discovery
2. Include relay.cashu.email, nos.lol, offchain.pub

---

## 6. Current Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    nodns.shop (payment)                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │ faucet-api   │  │ tollgate-auth│  │ vps-proxy (NUT24)│  │
│  │ :8095        │  │ :8091        │  │ :8094            │  │
│  │ GET /api/mint│  │ /v1/wg/*     │  │ /v1/vms/*        │  │
│  │ → cashuB...  │  │ (token-body) │  │ (X-Cashu header) │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│                        Caddy routes all                     │
└───────────────────────────┬─────────────────────────────────┘
                             │
┌────────────────────────────┴────────────────────────────────┐
│              VM 1077 — europa-vpn-vps (66.92.204.237)        │
│  ┌──────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐ │
│  │ WireGuard│  │wg-jwt-peer│  │firecracker│  │ContextVM  │ │
│  │ :51820   │  │ :8080     │  │-daemon    │  │MCP server │ │
│  │          │  │           │  │ :8081     │  │ kind 25910│ │
│  └──────────┘  └───────────┘  └───────────┘  └───────────┘ │
│  fail2ban | SSH key-only | /dev/kvm | NAT (172.16.1.0/24)   │
└─────────────────────────────────────────────────────────────┘

Standards compliance:
  ✅ NUT-04 (mint via faucet)
  ✅ NUT-18 (creqA in 402 response)
  ⚠️ NUT-24 (VPS only, not VPN)
  ❌ NUT-07 (no explicit checkstate)
  ❌ NUT-10/11 (no P2PK locking)
  ✅ NIP-01 (event signing)
  ✅ NIP-19 (bech32)
  ❌ NIP-44 (no ContextVM encryption)
  ❌ NIP-99 (Europa format non-compliant)
  ✅ ContextVM kind 25910 (tested)
  ✅ ContextVM kind 11317 (tools list)
  ❌ ContextVM CEP-4 (no encryption)
  ❌ ContextVM CEP-17 (no relay list)
```

---

## 7. What Works Today (verified E2E)

| Flow | Payment | Interface | Status |
|------|---------|-----------|--------|
| Buy VPS | NUT-24 X-Cashu header | HTTP POST | ✅ Tested |
| Buy VPS | Token-in-body | HTTP POST | ✅ Tested |
| Buy VPN | Token-in-body | HTTP POST | ✅ Tested |
| List tools | None | ContextVM kind 25910 | ✅ Tested |
| Health check | None | ContextVM kind 25910 | ✅ Tested |
| Faucet | None | HTTP GET | ✅ Tested |
| Outbound internet | — | NAT + MASQUERADE | ✅ Verified |
| Per-VM SSH keys | — | Daemon injects key | ✅ Verified |
| Europa listing | — | NIP-99 kind 30402 | ❌ Wrong format |
