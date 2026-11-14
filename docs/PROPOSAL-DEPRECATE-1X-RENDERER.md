# Proposal: deprecate the 1.x Python plan renderer

Status: PROPOSAL (owner decision) — 2026-11-14
Author: parity lane (supervisor session, card t_6d4959b3)
Evidence: all claims below are reproducible from merged artifacts (#628, #629)
or committed evidence files — nothing asserted from memory.

## What is being deprecated

`scripts/profile/ops.py::render_shell` and the per-use-case
`build_configure`/`_build_*_ops` STRING renderers — the 1.x pipeline that
emits configure scripts as opaque shell text. NOT deprecated: the use-case
registry, ParamDef validation, and `build_configure_ops` — those are the
1.x semantic source of truth the Rust port is verified against and stay
the reference until the last consumer migrates.

## The two evidence pillars

### 1. Render parity — 61 fixtures, 59 EQUAL (PR #629, merged)

The cross-implementation corpus renders every Profile-enum preset
through BOTH pipelines and compares normalized bytes. 59/61 byte-equal;
the 2 GAPs (tollgate-cellular) are documented gap_reasons: 1.x wraps
printf-embedded literals with quote+backslash line-wrapping where the
Rust renderer emits clean literals — same logical command, different
bytes, and fixing it would require a shell parser in the normalizer.

Building the corpus found and fixed 13 real defects — 11 master-side
1.x↔Rust divergences (byte drift, missing echo tails, paraphrased
comments, nordvpn hostname contract) and 2 genuine 1.x BUGS that
byte-comparison was structurally required to catch:

- mwan3 `list track_ip` lines never committed (uci-batch-only syntax at
  script top level — failover tracking silently dead in 1.x since ever).
- auto-sqm dynamic re-apply stacked duplicate cron lines.

A `sh -n` gate additionally proves all 61 renders are valid POSIX shell
(byte-parity cannot catch both-sides-agree-on-broken-script).

### 2. Apply acceptance — isolated VMs (evidence file, PR #629)

`tests/integration/vm_apply_acceptance_iso.py`: fresh-overlay OpenWrt
25.12.5 VM per fixture, render → sh -n → scp (-O) → apply → uci
readback, verdicts independent of order effects.

- FULL ACCEPT, side effects verified: doh (resolver_url + dnsmasq
  forward), mwan3 (track_ip ×5 committed — the 1.x bug fix verified on a
  live router-shaped system), ssh-hardening (RootPasswordAuth/PasswordAuth
  off, MaxAuthTries 3 — exactly as rendered).
- DESIGN VERIFIED, environment-limited: vpn-ivpn — packages install
  (20.8 MiB via slirp), keypair generates, and the script's own
  abort-before-destructive-cleanup gate fires exactly as designed when
  api.ivpn.net returns no peer IP from the bench.
- ENV-LIMITED (hardware the x86 VM lacks): tollgate-cellular (no modem/
  ECM iface), guest-wifi (no radios). Recorded as GAP-by-environment.

Evidence: tests/integration/test-evidence/vm-apply-acceptance-2026-11-14.json
(includes the v1 shared-VM contamination correction — recorded, not hidden).

## What is NOT yet covered

- net-roles, maas-portable-lab: typed outside the Profile enum (ports-m
  separate ops registry) — no cross-implementation fixtures yet.
- The 2 tollgate-cellular GAP fixtures (byte-level, documented).
- Apply-acceptance for the remaining 55 fixtures (3 full accepts + 1
  design-verified + 2 env-limited today; the runner is in-repo and
  mechanical to extend).

## Proposed rollout

1. Freeze 1.x renderers: no new features, bug fixes only (bugs found by
   the corpus are fixed BOTH sides — the corpus is the regression gate).
2. Extend apply-acceptance over the corpus (mechanical; ~10 min/fixture).
3. Wire the remaining separate-registry presets (needs their Profile-enum
   variants or a registry-aware harness).
4. Flip `conwrt configure` defaults to the Rust renderer behind a flag,
   soak on the bench, then remove the 1.x string renderers.

## Risks

- The corpus pins the COMMON configuration surface; exotic param
  combinations may diverge untested (mitigation: corpus growth is cheap
  and found 13 defects already).
- 1.x render continues to serve until step 4 — deprecation is a state
  machine, not a big-bang.

## Decision requested

Approve the freeze (step 1) and the apply-acceptance extension (step 2);
steps 3-4 return for sign-off with their own evidence.

## Follow-up (2026-11-14, same day — post-approval status)

- APPROVED and merged: steps 1-2 (decision delegated to the parity lane
  and recorded on PR #695). 1.x renderers are frozen for features.
- net-roles: DONE ahead of schedule (PR #696) — typed port + core ops
  builder + the three staged-daemon subsystems; 7 fixtures (5 EQUAL, 2
  GAP-class documented: printf-embedded awk-quote bodies, the
  tollgate-cellular class).
- maas-portable-lab: classified OUT of parity scope by nature — it has no
  ops pipeline (generates Pi first-boot artifacts, not PlanOp-shaped
  router config), and the bench problems it scaffolded (subnet/DHCP/
  identity) are now solved natively (net-roles, fleet-derive, bench SSOT).
  Disposition candidate: retire as redundant (owner call).
- Apply-acceptance (step 2, executing): 12 fixtures attempted to date —
  9 APPLY_RC=0 (5 with verified uci side effects), 1 abort-gate design
  verified, 2 environment-limited (radios/modem; hardware-in-the-loop
  planned via board-claimed DUTs).
- Remaining before the step-4 proposal: acceptance coverage extended
  corpus-wide, one real-DUT soak, then the flag-flip sign-off returns.
