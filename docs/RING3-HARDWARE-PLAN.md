# Ring-3 hardware day — plan for the x1860's return

Status: PLANNED (device away). Execute when the COVR-X1860 A1 (x1860-1)
is back on the bench. Everything below is scoped to ONE device session
with the standard envelope; nothing here requires new tooling.

## Goal

Convert the §4 ring-2 evidence (QEMU VM, `qemu_apply.rs` + the
`test_rust_apply_ports4_vm.py` runner) into **hardware-proven** rows
(parity-matrix evidence, travelmate precedent), and exercise the
paths a VM structurally cannot: real package installation, real
certs, real radios. Secondary: prototype the openclash feed
acquisition that the #486 review deferred to M7.

## Non-negotiable envelope (FACTS + AGENTS.md)

- Device lock `/tmp/conwrt-x1860/mutate.lock` (flock) for EVERY
  config-changing step; restore `/tmp/conwrt-x1860/baseline-uci.txt`
  before finishing.
- Flash budget: **max 2 sysupgrade cycles** this session; never
  `sysupgrade -F`; adoption script immediately post-flash (post-flash
  default is a rogue-DHCP-armed blank-password root at 192.168.1.1).
- Host uplink is wlp4s0 — never touched; use enp5s0 aliases
  (fake-WAN: 10.102.89.0/24 if the device needs internet).
- Two verified doors before any destructive step; deadman switch
  before any commit+reload (network-gear discipline).

## Phase 1 — non-flash apply validation (no sysupgrade spent)

Device is on 25.12.6 vanilla; `conwrt apply --execute` over SSH
against the live system. For each profile: apply, read back, verify,
ROLLBACK to baseline. Order cheapest-first:

1. **ssl** (the full post-flash story, not just flash-time):
   - cert-less negative on hardware (apply fails the named
     `certs deployed` verification — ring-2 result holds on real
     uhttpd);
   - run 1.x `deploy_ssl_post_flash` (lancert provider) for the
     device's real LAN IP → certs land at `/etc/tollgate/ssl/`;
   - re-apply → fully verified; **browse https://<lan-ip> from the
     host and confirm the browser-trusted chain** (that is the
     user-visible outcome the whole preset exists for);
   - qip provider variant once (wildcard);
   - rollback (uci delete cert/key/listen_https restore, rm certs).
2. **pbr**: the download-first dnsmasq→dnsmasq-full swap on REAL opkg
   (feed reachable via fake-WAN): prove the swap completes, dnsmasq
   survives, service enables; then reverse (remove pbr, reinstall
   dnsmasq, restore config from baseline).
3. **ssl TLS-backend guard**: device has libustream present → guard
   skips install (preserve). Optionally: remove libustream on the
   fake-WAN, apply, watch wolfssl install via the guarded line.
4. **openclash** (config surface, package from GitHub release IPK as
   a MANUAL pre-step — not the M7 acquisition phase): stub-free real
   `/etc/init.d/openclash enable`, dashboard reachable on :9090,
   import a throwaway subscription, confirm a proxied client probe —
   then record honestly which parts were manual (the boundary the
   #486 docs promise).
5. **nodns** (if the bench has the bot endpoint reachable): full plan
   on hardware, poll service running, `addn-hosts` resolving.

Each item = one parity-matrix evidence line upgrade + a dated note in
the model JSON's `tested_hardware` where applicable.

## Phase 2 — one flash cycle (optional, only if Phase 1 is green)

- ASU build via the FIXED profile path (#506) with the §4 profiles
  baked (openclash+ssl+sqm defaults) — proves the bake pipeline with
  canonical naming end-to-end on real hardware.
- Post-flash adoption → confirm first-boot defaults ran → re-run the
  Phase-1 ssl cert deploy (post-flash boundary timing on a virgin
  overlay).
- Second flash cycle stays in reserve for rollback.

## Phase 3 — the M7 openclash acquisition spike (time permitting)

On-hardware prototype of the deferred feed/IPK acquisition:
- pin the vernesong release URL + sha256 in the MODEL registry
  (species-level fact), 
- plan op shape: `EnsurePackageFromUrl` (download → sha-verify → opkg
  install /tmp), 
- validate manually via SSH FIRST (AGENTS.md test-before-automate),
  then propose the PlanOp with a hardware-proven note.

## Explicitly NOT this session

- tether/USB paths: x1860 has NO USB (FACTS) — needs a different
  specimen; keep hardware-gated.
- vpn-nordvpn ring-3: needs WAN + token; separate bench session.
- Anything touching dhcp.*/network.lan/dropbear.* outside the
  adoption script.

## Exit criteria

All Phase-1 profiles hardware-proven and rolled back to baseline;
evidence committed (parity-matrix + model JSON notes + this file's
status flip); flash budget unspent or one cycle with reserve intact;
#506-path ASU build proven on-device if Phase 2 ran.
