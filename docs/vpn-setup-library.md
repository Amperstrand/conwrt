# VPN Setup Library — Design Proposal

Status: **proposal + first contribution** (PIA OpenVPN, validated on hardware).

## Motivation

conwrt already has `scripts/use_cases/wireguard_client.py` and `scripts/wg-setup.py`,
but commercial VPN providers differ in *how a user authenticates* and *how servers
are discovered*. Today each provider would need bespoke glue. This proposes a small,
provider-agnostic library so a new provider is mostly data + a config template.

## Provider model

Every provider is described by two things:

### 1. `CredentialSpec` / login method

How the user's account maps onto the provider's protocol:

| Login method        | Example provider        | What the user supplies            | What OpenWrt stores                        |
|---------------------|-------------------------|-----------------------------------|--------------------------------------------|
| `username_password` | Private Internet Access | p-number + password               | `auth-user-pass` file (mode 600)           |
| `token`             | PIA (WireGuard/API)     | short-lived API token             | credentials file / `wg` config             |
| `api_key`           | Mullvad, IVPN           | account number / key              | derived WireGuard keypair + account id     |
| `keypair`           | self-hosted WireGuard   | server pubkey (client generates)  | `private_key` + `peer_public_key`          |
| `oauth_device`      | future providers        | device-code flow                  | token file                                 |

PIA's OpenVPN path is `username_password` — no token exchange. (PIA's token API is
still useful to *validate credentials* before pushing config; see `pia-health`.)

### 2. `ProviderSpec`

- `id` (e.g. `pia`)
- `protocol` (`openvpn` | `wireguard`)
- `packages` (`openvpn-openssl`, `kmod-tun`, …)
- `server_discovery`: an endpoint that returns current endpoints
  (PIA: `https://serverlist.piaservers.net/vpninfo/servers/v6`), or a static pool.
- `config_template`: protocol-specific settings (cipher/auth/`pull-filter`, …)
- `dns`: in-tunnel resolvers (PIA: `10.0.0.241/242/243`)
- `resilience`: health probe + fail-open/fail-closed policy

## Mapping to conwrt

- Each provider becomes a **use-case preset** (`scripts/use_cases/<protocol>_<provider>.py`)
  built from the typed `profile.ops` DSL and registered via `register(UseCase(...))`.
- **Shell artifacts** (credentials, `.ovpn`, on-device watchdog scripts) use the new
  `WriteFile` op — safe heredocs without ad-hoc quoting.
- An optional **Ansible role** (`ansible/roles/<provider>_<protocol>/`) wraps the same
  steps for operators who manage routers with Ansible.

## Resilience model (shared)

All VPN use cases should share one posture:

1. **Functional health probe** — not log-scraping. Prove the data plane through a
   tunnel-only destination:
   - route via the tunnel interface (`ip route get 1.1.1.1` → `dev <tun>`), **and**
   - a packet through it (ping the tunnel peer gateway) **or** a DNS query to an
     in-tunnel resolver.
2. **Restart → rotate** — restart the daemon, then drop a repeatedly failing endpoint
   from the pool (OpenVPN `remote-random`, WireGuard endpoint switch).
3. **Phased posture**
   - `validation`: fail **open** after a timeout (restore WAN + normal DNS) so a router
     is never stranded; re-enforce once healthy.
   - `enforced`: fail **closed** (strict kill switch); never fall back to the ISP.
   - Auto-advance `validation → enforced` after N seconds of cumulative healthy operation.
4. **Reversibility** — always back up the configs and provide a one-shot rollback.

This mirrors the existing WireGuard use case's "verify, else remove the kill switch"
behaviour and generalises it.

## Provider matrix (roadmap)

| Provider | Protocol  | Login method        | Status                |
|----------|-----------|---------------------|-----------------------|
| PIA      | OpenVPN   | username_password   | **first contribution**|
| PIA      | WireGuard | token               | planned               |
| WireGuard| WireGuard | keypair             | exists (`wireguard-client`) |
| Mullvad  | WireGuard | api_key             | planned               |
| IVPN     | OpenVPN   | username_password   | planned               |

## First contribution: PIA OpenVPN

`scripts/use_cases/openvpn_pia.py` implements the above for PIA:

- password auth file + RSA-4096 CA (`pia-foss/manual-connections`)
- 10-endpoint US pool with `remote-random`
- `pull-filter ignore "route-ipv6"` / `"ifconfig-ipv6"` (PIA pushes IPv6 onto a v4 tun)
- `data-ciphers` (the singular `cipher` is ignored by OpenVPN 2.7)
- **no `persist-tun`** (dead tunnels must drop routes, not blackhole)
- IPv6 disabled (kernel + LAN)
- DNS lock to `10.0.0.241/242/243`
- functional `pia-health` + `pia-watchdog` (restart → rotate → fail open → enforce)

## Safety notes

- Never write a kill switch that can strand the device: keep a known-good backup and a
  watchdog that restores WAN fallback during validation.
- On UBIFS overlay devices `uci commit` is permanent — verify with `uci get` before commit.
- Prefer tunnel-only probe targets so health cannot be satisfied through the ISP.
