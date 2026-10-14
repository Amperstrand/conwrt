# VPN provider support & test status

How each VPN provider in `scripts/use_cases/vpn_providers/` is configured,
what has been verified, and what still needs a test. Last full audit:
**2026-10-14** (live API contracts re-verified from this repo, see
`tests/live/test_vpn_live_apis.py`).

## Test tiers

| Tier | Command | Needs | What it proves |
|------|---------|-------|----------------|
| Hermetic | `make test` | nothing (CI runs it) | Op rendering: every uci block, quoting, kill switch, routes |
| Live API contract | `make test-live` | internet | The provider APIs still return the JSON shape our generated first-boot scripts parse |
| Live API, credentials | `make test-live` + env secrets | provider account | Read-only authenticated endpoints (token exchange, account info) |
| Bench | `make bench-vpn` | physical router + `CONWRT_BENCH_TOKEN` | Real tunnel establishment, exit verification, iperf3 throughput per technology |
| Hardware validation | manual (recorded in `test_status`/`tested_notes`) | a router + account | The full use case works on a real device |

Credential-gated tests **skip silently** when their env var is unset. Secrets
come from the environment only — never `config.toml` under test, never
committed:

| Env variable | Unlocks | Destructive? |
|---|---|---|
| `CONWRT_LIVE_NORDVPN_TOKEN` | NordVPN service-credentials fetch (`nordlynx_private_key`) | no (read-only) |
| `CONWRT_LIVE_PIA_USER` + `CONWRT_LIVE_PIA_PASS` | PIA token generation | no (additive) |
| `CONWRT_LIVE_MULLVAD_TOKEN` | Mullvad account info | no (read-only) |
| `CONWRT_BENCH_TOKEN` | Full bench scenarios on a router | yes (configures the router) |

Key-**rotating** endpoints are deliberately never exercised by tests:
Surfshark `wireguard/new`, IVPN `account/wireguard/key`, Mullvad
`wg-peers` POST — calling them invalidates existing keys. Their request
shape is covered hermetically only.

## Provider matrix

| Provider | Technologies | Config surface | Hermetic | Live contract | Bench | Hardware |
|---|---|---|---|---|---|---|
| `vpn-nordvpn` | NordLynx (WireGuard) | `access_token` or `config_file`; **country** selection (`server` param) | `TestNordvpnOps`, `TestNordvpnPinnedServerKey` | countries / recommendations / filter canaries | `nordlynx` scenario | ✅ tested 2026-10-08 (COVR-X1860 A1, 25.12.5) |
| `vpn-nordvpn-openvpn` | OpenVPN udp/tcp (CBC/GCM) | `access_token`; country selection | `TestNordvpnOps` | same endpoints as above | `openvpn-udp-cbc/-gcm`, `openvpn-tcp` | ✅ tested (DE exit, service creds) |
| `vpn-nordvpn-ikev2` | IKEv2/IPsec | `access_token`; needs strongswan baked into the image | (rendering) | — | `ikev2-*` (needs `CONWRT_BENCH_IPSEC=1`) | ❌ untested (degrades gracefully without token) |
| `vpn-pia` | WireGuard | `username`/`password` (device fetches token + registers key) | `TestPiaOps` | token exchange (gated) | — | ✅ tested on hardware |
| `vpn-pia-openvpn` | OpenVPN (static recipe) | `username`/`password`, validated US pool + RSA-4096 CA | `TestPiaOpenvpnOps` | — (static recipe, no API dependency) | — | ⚠️ recipe validated manually on GL-MT3000 (recipes/glinet/mt3000/notes.md); provider op-path not yet exercised |
| `vpn-mullvad` | WireGuard | `account_token`; optional country | `TestMullvadOps` | relays list (✅ fixed 2026-10-14) | — | ❌ untested |
| `vpn-ivpn` | WireGuard | `account_id` + secret | `TestIvpnOps` | servers.json (✅ fixed 2026-10-14) | — | ❌ untested |
| `vpn-surfshark` | WireGuard | `username`/`password`; optional country | `TestSurfsharkOps` | v4 clusters (✅ fixed 2026-10-14) | — | ❌ untested |
| `vpn-openvpn` | any (bring-your-own `.ovpn`) | `ovpn_config`, `username`/`password` | `TestOpenvpnOps` | — (no provider API) | — | ❌ untested |

Related non-provider VPN use cases: `wireguard-client` (tested on hardware),
`vpn-node`, `cashu_vpn_client` — see `python3 scripts/conwrt.py list-use-cases`.

## API drift log

Provider APIs break silently — the generated scripts curl them at first boot
on a router where debugging is painful. The live contract tests exist to
catch drift on the host. Found and fixed so far:

- **2026-10-14 — NordVPN**: `/v1/servers` now **ignores all filters**
  (`hostname`, `stations[ip]`, …) and returns an arbitrary ~100-server page.
  Consequences: hostname/IP pins are unverifiable and now **refuse loudly**
  (country selection is the supported pin); the pin resolution
  (`_select_server`) verifies client-side. Two canaries in
  `tests/live/test_vpn_live_apis.py` flip if NordVPN restores filtering.
- **2026-10-14 — Mullvad**: relay list moved from
  `/public/relays/wireguard/` (now an infinite-301 trap) to
  `/www/relays/wireguard/`, and the field `public_key` was renamed
  `pubkey` — the old script would have configured an **empty WireGuard peer
  key**. Fixed in `vpn-mullvad`.
- **2026-10-14 — IVPN**: server list moved to `/v4/servers.json` (the
  extensionless path 404s) and reshaped to `{"wireguard": [{hosts:
  [...]}]}` (no more `wg_port`; 51820 fallback stands). Fixed in `vpn-ivpn`.
- **2026-10-14 — Surfshark**: `/v3/servers` is gone; replaced by
  `/v4/server/clusters/generic` (public, no auth), which is **hostname-only**
  (`connectionName` + `pubKey`, no IP field). `vpn-surfshark` now uses the
  hostname as `endpoint_host` and resolves the static-route IP on-device,
  skipping the route when DNS fails.

## What still needs a test

1. **Mullvad / IVPN / Surfshark hardware runs** — the API contracts are now
   verified live, but no tunnel has been brought up on a real router. Next
   bench session: flash a router with each provider and record
   `test_status="tested"` + notes. (Mullvad/IVPN/Surfshark accounts needed.)
2. **NordVPN IKEv2 on hardware** — requires an image with strongswan baked
   (`CONWRT_BENCH_IPSEC=1` bench scenarios exist for it).
3. **PIA-OpenVPN provider op-path on hardware** — the recipe is validated;
   running it through `conwrt configure` on a router is the missing step.
4. **VM tier for VPN use cases** — the QEMU session VM exercises the ops
   pipeline but a real tunnel needs a real upstream + credentials; not
   attempted. Feasible: flash-VM + user-net NAT + a provider token would
   validate key exchange end-to-end without bench hardware.

## Adding a provider

1. Implement `scripts/use_cases/vpn_providers/<name>.py` using the shared
   builders in `base.py` (`build_firewall_ops`, `build_dns_ops`,
   `build_verify_ops`, `static_route_sh`, `wg_cleanup_sh`).
2. Register with `test_status="untested"` — never claim `tested` without a
   hardware run.
3. Add hermetic ops tests (`tests/test_vpn_provider_ops.py`).
4. Add live contract tests for every endpoint the generated script curls
   (`tests/live/test_vpn_live_apis.py`) — public endpoints ungated,
   credential endpoints skipif-gated, rotating endpoints never.
5. Update this matrix.
