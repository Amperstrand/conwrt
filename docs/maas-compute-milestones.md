# MAAS Compute Implementation — Milestone Breakdown

**Source:** amperstrand_maas_compute_implementation_plan.md
**Date:** 2026-10-14
**Goal:** Secure VPS accessible to others through VPN
**Hardware:** Pi 4B (MAAS controller) + x1860 (network) + enlisted desktop (VM host candidate)

## Milestone Map

```
M1: Fix boot images ─→ M2: Commission VM host ─→ M3: Deploy first VM
                                                    │
M4: VPN isolation ──────────────────────────────────┤
                                                    │
M5: shc-toolkit provider ─→ M6: Lease controller ──┤
                                                    │
M7: Internal agent pilot ─→ M8: Cashu API ────────→ MVP
```

## M1: Fix boot image sync (BLOCKER)

**Why:** Without boot images, commissioning and deployment don't work. Everything else is blocked.

**What's broken:** MAAS 3.6.6's temporal workflow engine doesn't complete image downloads on the Pi's resource-constrained environment. The catalog registers (15 resources) but files stay incomplete.

**Approach options (in order of preference):**
1. Manually download and place images (bypass workflow)
2. Use MAAS CLI to force sync completion
3. Try MAAS 3.7.x (may have workflow fixes)
4. Pre-seed images on the USB disk during self-flash

**Estimated effort:** 0.5–1 day
**Exit criterion:** At least 1 ubuntu/noble amd64 image shows "complete" in MAAS

## M2: Commission the VM host

**Why:** Need a KVM-capable machine to host virtual machines.

**Hardware:** `awake-iguana.maas` (already enlisted, 8 cores, 16GB RAM, amd64)

**Steps:**
1. Fix boot images (M1)
2. Commission awake-iguana via MAAS portal/API
3. Verify VT-x support from commissioning output
4. Deploy Ubuntu Server LTS to it
5. Verify SSH access from MAAS

**Estimated effort:** 0.5 day (after M1)
**Exit criterion:** Machine status = "Deployed" with Ubuntu + SSH working

## M3: Register as LXD VM host + compose first VM

**Why:** MAAS needs a VM host to create virtual machines.

**Steps:**
1. SSH to awake-iguana, install LXD
2. Register as MAAS VM host (`maas admin vm-hosts create ...`)
3. Compose a test VM: 2 vCPU, 2GB RAM, 20GB disk
4. Deploy Ubuntu to the VM
5. Verify SSH to the VM

**Estimated effort:** 1 day
**Exit criterion:** MAAS can compose/deploy/delete a VM (10 clean runs)

## M4: VPN isolation and WireGuard exit

**Why:** Customers/agents need isolated network access. Traffic must exit through VPN, not the home internet.

**Architecture:**
```
Guest VM → customer VLAN → WireGuard gateway (Linux) → exit VPS → internet
```

**Steps:**
1. Set up WireGuard exit VPS (rented, fixed IP)
2. Configure WireGuard gateway on the VM host (or dedicated)
3. Create customer VLAN/subnet (separate from management)
4. nftables rules: deny by default, allow only through VPN
5. Test from inside a guest VM:
   - Public IP = exit VPS (not home IP)
   - Cannot reach MAAS/BMC/other tenants
   - VPN down = all traffic stops

**Estimated effort:** 2–4 days
**Exit criterion:** All security tests from the plan pass from inside a guest VM

## M5: shc-toolkit MaasProvider

**Why:** Programmatic VM lifecycle management for agents and API.

**Steps:**
1. Extract compute interface from shc-toolkit
2. Implement MaasProvider (compose/deploy/delete via MAAS API)
3. Typed state machine matching MAAS lifecycle
4. Unit tests with mocked MAAS API
5. Integration tests against real MAAS

**Estimated effort:** 3–5 days
**Exit criterion:** `shc-compute create/list/describe/destroy` works against MAAS

## M6: Lease controller

**Why:** Durable, crash-safe authority for VM lifecycle + payments.

**Steps:**
1. SQLite WAL lease database
2. State machine: REQUESTED→RESERVED→PAID→COMPOSING→...→DESTROYED
3. Capacity reservation, expiry, janitor cleanup
4. Reconciliation between MAAS and ledger

**Estimated effort:** 3–5 days
**Exit criterion:** Crash/restart tests pass, no duplicate sales or leaked VMs

## M7: Internal Hermes/Herdr pilot

**Why:** Prove agents can use the compute platform before opening externally.

**Steps:**
1. Hermes manager with boards for each project
2. Worker lane that calls lease controller
3. Issue → worktree → MAAS VM provisioned → tests run → PR → VM destroyed

**Estimated effort:** 2–4 days
**Exit criterion:** One automated PR from issue to merge, VM cleaned up

## M8: Cashu API (external access)

**Why:** Felix and other operators can pay for compute.

**Steps:**
1. Fix vps_proxy.py security issues (mint validation, idempotency, units)
2. Implement /v1/compute/quote and /v1/compute/leases endpoints
3. NUT-24 Cashu payment flow
4. Quota, rate limiting, spending caps

**Estimated effort:** 4–7 days
**Exit criterion:** Felix can buy one VM with a test wallet, resources reconcile

## Critical Path to "Secure VPS with VPN"

The minimum path to give someone secure access to a VM through VPN:

```
M1 (fix images) → M2 (commission host) → M3 (compose VM) → M4 (VPN)
```

**Estimated minimum time:** 4–7 days of focused work.

## Current State (2026-10-14)

| Item | Status |
|------|--------|
| MAAS running | ✅ Pi 4B, self-flashed |
| Network infrastructure | ✅ x1860, bench subnet, DHCP |
| Machine enlisted | ✅ awake-iguana (8 cores, 16GB) |
| Boot images | ❌ 0/15 complete (M1 blocker) |
| VM host registered | ❌ Not yet |
| VPN | ❌ Not started |
| Provider API | ❌ Not started |

## Immediate Next Actions

1. **Fix boot image sync** (M1) — try manual image placement or workflow bypass
2. **Commission awake-iguana** (M2) — verify VT-x, deploy Ubuntu
3. **Install LXD + register as VM host** (M3) — compose first test VM
4. **Set up WireGuard exit VPS** (M4) — can be done in parallel with M1-M3

## DHCP Snippets Deprecation Note

MAAS DHCP snippets (MD6 deprecation) don't affect our setup — we configure DHCP via the subnet/VLAN API, not snippets. No action needed, but noted for future MAAS upgrades.

## VPN Exit Node Configuration (2026-10-14)

### Architecture
```
  Customer VM → customer VLAN → x1860 gateway → WireGuard wg0 → VPS exit → internet
       │                          │                                    │
  10.50.0.x                 10.50.0.1                            46.224.104.12
  (bench subnet)         (WiFi uplink mgmt)                    (inr2.cashu.exchange)
                                                              (public NAT exit)
```

### WireGuard Setup (verified working)

**VPS (inr2.cashu.exchange / 46.224.104.12):**
```
[Interface]
Address = 10.99.0.1/24
ListenPort = 51820
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; iptables -A FORWARD -i wg0 -j ACCEPT

[Peer]  # x1860 bench gateway
PublicKey = XR7oMeguu6+ChSrhnQyfxkVyQAUBh3erw19UrmmkMgE=
AllowedIPs = 10.99.0.2/32, 10.50.0.0/24
```

**x1860 (OpenWrt UCI):**
```
network.wg0 = wireguard interface, private key, 10.99.0.2/24
peer = VPS public key, endpoint 46.224.104.12:51820
allowed_ips = 0.0.0.0/0 (all internet through VPN)
firewall: wg0 in wan zone (lan→wan forwarding allowed)
```

### Verified Performance
- WireGuard latency: ~30ms (bench → VPS)
- All bench devices automatically exit through VPN (no per-device config)
- Public IP confirmed: 46.224.104.12 (not home IP)
