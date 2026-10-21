# Selling Bench VM Access for Ecash — Adaptation Study and Recommendation

**Issue:** #193 (research) · **Spike:** #194 (`MaasBackend`, Amperstrand/Paygress PR #1) · **Rust crates:** #169 (PRs #200/#201)
**Date:** 2026-10-15 · **Status:** recommendation ready; fork path underway

## Executive summary

The bench can provision a customer VM with one command, give it VPN-only
egress, and optionally expose it through a Nostr-keyed mesh. What is missing
is the payment + lease layer. We studied **paygress** (Nostr-controlled
ecash compute marketplace, Rust) at source level, inventoried our own
TollGate/SHC prior art, and spiked the integration: a **fork of paygress
with a MAAS-backed compute backend** (deploy-without-commissioning,
mock-proven end to end).

**Recommendation: proceed on the fork path (Option C).** It reuses
paygress's hardest-won code — prepaid per-second leases, mint whitelisting,
expiry sweeps, warm standby, MCP-native consumers — while keeping MAAS as
the source of truth for machines, which is the operator requirement that
killed the run-upstream idea (Option A). The thin-own-service fallback
(Option B) stays armed behind #194's kill criteria.

Three gates before any non-self tenant:

1. Live-region validation of the no-commission spawn path (#194 remainder).
2. Customer VLAN isolation (#168) — L3 separation AND a default-deny
   filter: routed VLAN membership alone does not stop a tenant reaching
   MAAS, the BMCs, management, or other tenants. The milestones plan
   (maas-compute-milestones.md, tenant-isolation pre-req) requires
   default-deny nftables + unreachability tests, with ONE selective
   allow: the MAAS metadata service.
3. The economic floor from §5 — idle warm-pool capacity is the only real
   marginal cost; the rate must clear it or the pilot is charity.

## 1. The platform we are selling from

| Component | State | Source |
|---|---|---|
| MAAS region | Running on the lab region host (single-board, self-flashed, USB SSD) | `recipes/raspberry-pi/maas-portable-lab.md` |
| VM host candidate | One 8-core/16 GB host enlisted (VT-x unverified until M2) | `docs/maas-compute-milestones.md` M2 |
| Boot images | **0/15 complete — M1 blocker** (MAAS 3.6.6 temporal deadlocks) | milestones M1 |
| Network | Bench router segment; DHCP for the bench subnet is MAAS-owned | recipe |
| VPN egress | WireGuard bench→VPS exit verified (~30 ms, public IP = VPS) | milestones §VPN |

(Live hostnames, hardware serials, and enlistment state live in the
operator's private inventory project — conwrt stays species-level,
AGENTS.md lab-registry rule.)
| Provisioning | compose→commission→deploy ~8 min one-command | #193 context |
| Rust MAAS fluency | `conwrt-maas` crates (types/provider/CLI) + paygress `MaasBackend` | #169, #194 |

The M1 image-sync blocker gates everything downstream (commissioning needs
images). It is a lab-side fix (manual image placement or 3.7.x trial), not
a design risk — but it is the critical path item today.

## 2. Prior art

### 2.1 paygress (external, source-studied, research-only)

Marketplace for renting compute with Cashu ecash, **Nostr as the control
plane — no central server**. Consumer discovers providers via kind 38383
offers + 38384 heartbeats, sends a NIP-17 encrypted spawn request with a
Cashu token; provider redeems (NUT-03 swap) → `lease = value_msats ÷
rate_msats_per_sec` → provisions → returns SSH access via encrypted DM. A
30 s sweep destroys workloads at expiry; top-ups extend. Backends: LXD,
Proxmox, Docker, KVM. ~7 k LOC core, `cdk` 0.17 wallet (SQLite) +
`nostr-sdk` 0.43.

Mechanisms worth adopting regardless of build-vs-reuse (from #193, refined
by reading the fork):

1. **All pre-payment guards run BEFORE the token is redeemed** — mint
   whitelist (also the SSRF guard: a token pointing at an attacker mint
   never triggers an outbound call), disk-headroom, template-support,
   warm-standby checks. A failed request costs the consumer nothing. This
   ordering is the single most important pattern in the codebase
   (`src/provider/handlers/spawn.rs`; the disk-headroom refusal history is
   in their #87).
2. **Per-second prepaid leases from a single token redeem** — no accounts,
   no metering; the expiry sweep is the only reclamation path (deliberately
   unconditional `delete --force` so a failed stop cannot leak a workload).
   Our `MaasBackend::delete_container` is idempotent for the same reason.
3. **NIP-33 addressable offers + bucketed heartbeats** — provider presence
   as queryable history. Reusable for advertising bench capacity.
4. **State mirrored to disk on every change** — provider restarts don't
   strand paid-for workloads.
5. **Consumer-optional SSH password, alphanumeric-only** —
   injection-proof by charset, not escaping. Carries into our cloud-init
   `user_data` unchanged.
6. **Warm-standby failover** (kinds 38385/38386) — overkill now, but the
   standby economics (§5.3) inform our warm pool.
7. **MCP server as first-class consumer** — AI agents can discover/spawn/
   pay. Our felixfelix-bot is exactly this customer shape.
8. **Honest isolation tiers** — below attested tiers "the operator can
   read your workload's memory and disk". Copy the candor.

### 2.2 SHC / shc-toolkit (ours, private v2.4.x)

Full reseller client for Sovereign Hybrid Compute: 20-package catalog,
per-CPU coefficients + NVMe disk rates, **Nostr-event HTTP auth**
(`Authorization: Nostr <event>`), btcpay invoices, affiliate payouts,
gcloud-compute-compatible CLI, Playwright noVNC console automation,
GitHub-runner + MCP clients — proven in the tollgate cloud lab.

Directly reusable for the fork path: **the pricing/catalog modeling**
(tier definitions as data), the Nostr-auth pattern if we add an HTTP
surface, and the gcloud-compat CLI idea for CI-shaped customers.

### 2.3 TollGate (ours, OpenWrt + gonuts Cashu)

Ecash paywall proven end-to-end in reseller mode. Lessons that price in:
funded wallets in RAM die on reboot (proofs swap on spend) — paygress's
SQLite wallet is the fix we inherit; renewal flows need explicit UX;
bridges skip wired detectors — monitor the money path, not just the
control plane.

### 2.4 What the #194 spike added

`MaasBackend` (Amperstrand/Paygress PR #1) implements paygress's 7-method
`ComputeBackend` trait over the MAAS region API, including the
**deploy-without-commissioning** sequence (compose → mark-broken →
fresh-MAC interface attach → mark-fixed → deploy), which is what keeps a
spawn inside their 300 s backend-call budget — a fresh commissioning run
(~8 min) would blow it. Eight wiremock tests pin the wire contract. The
spike converted Option C from a slide into a code path; what remains
unproven is live-region latency and API stability (§7).

## 3. Adaptation architecture options

### Option A — run paygress-cli provider unmodified (upstream)

`provider setup --backend kvm` on the compute host, our own wg tunnel
instead of vpn.cashu.icu.

**Rejected.** Reasons, in order of weight:

- The operator requirement is **MAAS as source of truth** for machines;
  their provider shells out to `lxc`/`qemu` and would shadow MAAS's view.
- Upstream-interaction etiquette: our fleet norms keep us from leaning on
  external maintainers; running their release train means tracking it.
- Their KVM backend (one qemu per spawn) matches isolation but not our
  region-managed lifecycle (power, commissioning states, VLAN placement).
- Still our problems anyway: VLAN isolation, fips mesh access, mint setup.

### Option B — thin own service (inspiration-only)

`cdk-rust` + `nostr-sdk` + our provisioning: offer/heartbeat events,
NIP-17 spawn handler, redeem → duration → provision → DM credentials.
~the paygress feature set minus their failure-mode hardening.

**Cost:** we re-earn the hard 20% — sweep edge cases, token-redeem
ordering, standby, restart durability, consumer-client quirks — that
paygress already paid for in production iterations. **Keep as the
fallback** (triggered by #194 kill criteria, §7); the shared crates
(#169) mean the MAAS half of B is already written either way.

### Option C — Amperstrand fork with MaasBackend (recommended, underway)

Fork lives at Amperstrand/Paygress (zero upstream interaction; we own the
delta, no sync obligation). Shape:

```
 consumer (CLI / MCP agent / felixfelix-bot)
      │  Nostr: offers 38383, heartbeats 38384, NIP-17 spawn + Cashu token
      ▼
 paygress provider (fork)
      │  pre-payment guards → redeem (NUT-03, whitelist = our mint)
      │  lease = value_msats ÷ rate_msat_per_sec
      ▼
 MaasBackend ── region API 2.0 ──► MAAS region host
      │                               │ compose / deploy / power / delete
      │                               ▼
      │                        VM host (KVM)
      ▼
 customer VM ── bench VLAN ──► bench wg gateway ──► VPS exit ──► internet
 access: SSH creds via NIP-17 DM; surface options in §6
```

Done so far: the backend, the no-commission spawn path (mock-proven),
credential handling (env-only, OAuth1 PLAINTEXT → HMAC at live validation),
capacity reporting with deliberately-unmeasured disk (their headroom gate
must not trust pooled storage numbers), setup/CLI wiring.

Remaining on C: live-region validation, warm pool v0, real self-consumer
spawn (testnet mint), expiry-sweep debris watch (known MAAS/LXD
non-atomic-delete class), access surface, VLAN isolation.

**Dividend:** the fork's MAAS client is hand-rolled for independence while
conwrt's #169 crates ride unmerged branches; once #200/#201 merge, a later
refactor can share one MAAS client crate between conwrt and paygress —
one wire contract, two consumers, tested from both sides.

## 4. Where each paygress mechanism lands on MAAS

| paygress concept | MAAS mapping | Notes |
|---|---|---|
| container id / name | `paygress-<id>` hostname → system_id | names are the durable handle; system ids opaque |
| create (spawn) | compose → no-commission cycle → deploy | 300 s budget: deploy is the only long step |
| start/stop | `power_on` / `power_off` ops | |
| delete (sweep) | DELETE machine; 404-tolerant | unconditional force, same doctrine |
| node status | vm-host read (cpu/memory) | disk reported unmeasured, by design |
| container IP | machine `ip_addresses[]` | answers None until DHCP — matches their boot-window model |
| image / template | deploy `user_data` (cloud-init) + MAAS image | template catalogue is a later mapping; M1 unblocks images first |
| password/key | cloud-init `chpasswd`/`ssh_authorized_keys` | charset rule carries unchanged |
| warm standby | pre-Ready machines pool | §5.3; MAAS Ready state is the natural standby |

## 5. Economic / ops model

### 5.1 Cost floor (the bench as it stands)

| Item | Monthly | Notes |
|---|---|---|
| VPS exit | ~€5 | fixed IP, WireGuard, public NAT |
| Power (desktop, idle+warm pool) | ~€10–15 | 40–80 W continuous at EU rates |
| Region-host + bench-router power | ~€2 | negligible |
| Hardware | sunk | region host, bench router, desktop, USB SSD |
| Bandwidth | €0 marginal | WiFi uplink is the ceiling, not billed |

Marginal cost per running VM ≈ power delta only (~10–20 W). **The real
capacity numbers:** 8 cores / 16 GB host → ~5–6 concurrent 2c/2G VMs with
headroom; uplink shared. This is a hobby-scale supply, which fits the
intended customers (self, felixfelix-bot, CI-shaped jobs), not a business.

### 5.2 Rate setting

paygress solves metering with `rate_msat_per_sec`; adopt it wholesale.
Breakeven arithmetic for the operator:

```
monthly_floor ≈ VPS + power ≈ 20 €
             ≈ (at 100_000 sats/€) 2.0M sats = 2.0 B msat   # 1 sat = 1000 msat
supply ≈ 5 VMs × 720 h ≈ 3600 VM-hours/month (if always sold)
breakeven ≈ 2.0 B msat ÷ 3600 h ≈ 556_000 msat/VM-hour ≈ 155 msat/s at 2c/2G
```

(An earlier draft read "2.0M msat" and "~1 msat/s clears the floor" — a
1000× sats↔msat slip: at ~1 msat/s per VM and 10% utilization the pilot
recovers ≈ €0.013/month against the €20 floor, i.e. charity, not
breakeven.) Even at **full** utilization the per-VM rate must be ≳155
msat/s — quote rates in **sats/s**, not msat/s, at this scale; SHC's
per-CPU-coefficient catalog is the right shape for tiered rates
(1c/1G, 2c/2G, 4c/4G). Actual market rate is an operator decision at
pilot time — the number to publish is the **rate in the offer event**,
and paygress already carries it.

### 5.3 Warm-pool economics

A Ready MAAS machine costs idle desktop watts and one compose's disk. With
1–2 warm machines, spawn ≈ deploy time (~2–4.5 min target). paygress's
standby lesson ("standbys earn for reserved capacity") suggests later
selling *reserved* warm capacity at a premium; v0 needs only: pool size 1–2,
`create_container` claims from pool, background replenish after claim.

### 5.4 Money path ops

- **Our own mints** on the exit VPS: whitelist points at testnet for the
  pilot, mainnet mint for real sales; provider wallet is paygress's SQLite
  (`cdk`) — survives restarts, unlike TollGate's RAM wallets.
- **Sweep:** earnings accumulate in the provider wallet; plan the
  ecash→Lightning sweep (their ngx_l402 path automates it on HTTP; on
  Nostr it's an operator cron we write once).
- **Custody honesty:** provider wallet = hot wallet; tenant secrets never
  touch disk (their volume-encryption keys are memory-only — kept).

## 6. Access surface (who can reach the VM they paid for)

1. **Bench-IP self-consumer** (first test): SSH from the bench network —
   zero new surface.
2. **VPS DNAT port range** (paygress's `ssh_port_start/end`): customer
   gets `vps-ip:port` → wg → customer VM. Moderate exposure; scope per
   lease lifetime.
3. **fips npub in the DM** (our Nostr-keyed mesh): access keyed to the
   payer's identity, no public ports. Differentiator; evaluate after 1–2.

Order: 1 → 2 → 3, each gated on the previous being boring.

## 7. Risks (and the standing kill criteria)

| Risk | Severity | Mitigation / trigger |
|---|---|---|
| **MAAS API instability** — interface-registration bug class, temporal deadlocks | high | #194 kill criterion: if the backend turns flaky on live validation → fall back to Option B for anonymous surface, keep MAAS for operator-mediated |
| **Deploy latency > 300 s** even with no-commission + pool | high | #194 kill criterion; in-fork we may also patch the constant — it is our fork |
| **M1 boot images** (0/15) | blocker, lab-side | manual placement / 3.7.x trial (milestones M1) — critical path today |
| **Tenant isolation pre-req** (#168) | high for non-self | L3 VLAN separation + default-deny nftables (MAAS metadata selectively reachable, everything else unreachable — tested); no anonymous tenant before it |
| **Fork maintenance** | medium | we own the delta; no upstream sync obligation; pin the fork commit in ops docs |
| **Ecash custody / regulatory** | medium | hot-wallet sizing caps, own mints first, testnet pilot; honest ToS language for what dedicated-host does and does not guarantee |
| **Nostr surface abuse** | medium | inherited guards: mint whitelist (=SSRF guard), disk gate, spawn deadline, their hardening history |
| **Sweep debris** (non-atomic deletes) | low-medium | idempotent delete (shipped); monitor region for orphans |
| **Uplink contention** | low | rate/offer states the shared-uplink reality; cap per-VM bandwidth later if needed |

## 8. Recommendation and phased plan

**Proceed with Option C.** Option A is rejected (MAAS bypass + etiquette);
Option B remains the documented fallback behind the kill criteria — and is
partially pre-paid by the #169 crates.

- **P0 — unblock + validate (owner-gated, lab-side):** fix M1 images; live
  proof of no-commission spawn latency + field re-pin; warm pool v0;
  self-consumer spawn with testnet mint (their CLI, second identity) —
  the #194 checklist.
- **P1 — pilot:** felixfelix-bot as first MCP consumer on bench-IP access;
  sweep-to-Lightning cron; state-durability restart drill.
- **P2 — external:** VLAN isolation (#168), VPS DNAT surface, mainnet
  rates from §5.2, offer/heartbeat advertising.
- **P3 — optional:** fips npub access, standby/reserved capacity tiers,
  shared MAAS client refactor with conwrt (#169 merge first).

## References

- #193 (this study's issue) · #194 (spike + checklist) · #168 (VLAN) ·
  #169 / PRs #200 / #201 (conwrt-maas Rust crates)
- Amperstrand/Paygress PR #1 (`MaasBackend`), fork of DhananjayPurohit/paygress
  at c833890 — source-studied, research-only upstream, zero interaction
- `docs/maas-compute-milestones.md` (M1–M8) ·
  `recipes/raspberry-pi/maas-portable-lab.md` (platform facts)
- shc-toolkit (private) `compute.py` / catalog model · TollGate reseller
  session notes (gonuts wallet)
