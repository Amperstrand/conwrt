# ADR 0013: Trust-on-first-boot (TOFB) — link-local enrollment with LED attestation

Status: proposed (design accepted for scaffolding; on-device behavior gated)
Milestone: M6 feed (#228)
Reversible: yes — TOFB ships as an opt-in image feature; images without it
behave exactly as today.

## Context

Freshly flashed units must establish their first trusted management key
without a physical console (#228). The x1860 species is case-sealed (no
serial), has a single 3-color status indicator (red/orange/white,
`models/dlink-covr-x1860-a1.json` hardware), one recessed reset button, two
ethernet ports, and WiFi. Two prior failure classes motivate TOFB:

- **Stale baked keys** (issue #228, `bench_observations.recovery_flash_matrix_2026_10_14`):
  a unit flashed with an image whose baked key belongs to a decommissioned
  host boots healthy but is unreachable — and there is no second door.
- **First-boot application failures** (#229, root-caused in PR #235): the
  uci-defaults script that installs baked keys is fragile in exactly the
  environment where it is the only chance.

Baked keys remain the primary path for operator-built images. TOFB is the
*no-trust-preinstalled* path: any image (including stale or vanilla ones)
can be adopted by the operator who is physically at the bench.

The issue's own option survey (#228 body) recommends Option B (IPv6
link-local HTTP bootstrap) over WiFi TOFU, and Option D (uci-defaults fix)
regardless — D is done (PR #235). This ADR adopts B's channel and adds an
out-of-band attestation code so the operator authenticates the device, not
just the link.

## Decision

TOFB = **first-boot device keypair + link-local enrollment endpoint + LED
attestation code + reset-button consent**, using only platform primitives.

### 1. Device identity (first boot)

When the TOFB marker (`/etc/conwrt/tofb.done`) is absent, an init-time
script:

1. **Entropy gate**: read 1 byte from `/dev/random` and discard. On the
   kernels this repo targets (4.19+; x1860 runs 6.6 on 24.10.x), a blocking
   read returns only once the kernel CRNG is seeded — before that,
   `/dev/urandom` output is weak. MT7621 has no TRNG and a fresh flash has
   no saved seed, so CRNG init relies on boot-time jitter; the gate makes
   the wait explicit instead of silent weakness. *Honest limits*: seeding
   latency on these boxes is unmeasured — NEEDS-BENCH; if it exceeds a few
   minutes, add a second source (e.g. network receive timing stirred in
   before keygen) rather than proceeding unseeded.
2. **Key generation**: `dropbearkey -t ed25519` (already on every OpenWrt
   image; no new packages, no hand-rolled crypto — repo policy). The TOFB
   key doubles as the dropbear host key until enrollment completes.
3. **Attestation derivation**: `code = digits10(SHA-256(public key blob))`
   — 6 decimal digits, zero-padded, from the first 8 bytes of the digest
   interpreted big-endian, mod 10^6. SHA-256 via BusyBox `sha256sum`
   (universally available per AGENTS.md tool rules).

### 2. Attestation display (out-of-band channel)

The single 3-color indicator encodes the code as six groups; group *i*
uses color `i mod 3` (R, O, W, R, O, W) so positions are self-locating,
and the digit is the blink count (0 = one long blink, 1–9 = N short
blinks), with inter-group pauses. Display loops until enrollment or
timeout, and can be re-triggered with a ~5 s reset-button hold (button
reachable by pin; consent gesture doubles as "show me the code").

Six decimal digits give a 1-in-a-million false-match per comparison — the
same human-verification budget as Bluetooth SSP numeric comparison.

### 3. Enrollment channel

BusyBox `httpd` bound to the **LAN-port IPv6 link-local address** only
(framework precedent: the dark-device discipline's zone-scoped fe80
transport, AGENTS.md Dark-Device rule 6; physical-link locality is the
perimeter). The endpoint accepts exactly one POST: the operator's public
key plus the 6-digit code. It:

- rejects requests whose code does not match the derived value (rate-limited
  by design: one comparison per request, endpoint dies after 3 failures);
- on match: appends the key to `/etc/dropbear/authorized_keys`, `chmod 600`,
  **verifies the write** (`grep -qF` of the key — the #229/#235 lesson:
  harden and mark done only after a provable write), then arms the standard
  key-only config, writes the TOFB marker, and tears the endpoint down.

Operator side: `scripts/tofb.py` scans/keys the device over link-local
(`ssh-keyscan` or the enrollment GET), computes the same 6-digit code from
the presented host key, the operator compares against the LED, and only
then enrolls.

### MITM-resistance argument

An active attacker on the bench segment can substitute keys in transit,
but cannot make the victim device's LED display the code derived from the
attacker's key. The operator compares two independent derivations of the
same code (device-optical vs client-computed), so a MITM must guess the
code (≤10^-6 per attempt, one attempt per pairing since three wrong codes
kill the endpoint) AND defeat the link-local scope (be on the same L2, on
the same physical port segment). Residual risk — physically observing and
decoding the LED sequence in real time — equals the Bluetooth-pairing
class and is bounded by bench physical access. What this design does NOT
claim: identity of the *species* (any unit of the model accepts pairing —
specimen-level verification stays the operator's inventory duty, AGENTS.md
MAC/serial gate).

### Failure and rollback modes

- **Code mismatch / abandoned pairing**: endpoint times out (default 15
  min) and shuts down; unit continues as a normal (keyless) OpenWrt box;
  power cycle restarts TOFB with the same key (marker absent, key
  persists — the code is stable for the life of the host key).
- **Wrong key enrolled**: physical reset-button hold at boot wipes
  `authorized_keys` + marker → TOFB re-runs (deliberate un-adoption).
- **Endpoint compromise window**: bounded to the TOFB phase (marker
  absent) and the link-local scope; the code is the only secret and it is
  single-purpose, short-lived, and human-rate-limited.
- **Script fragility**: every state mutation in the device script follows
  the #235 discipline — verify-then-commit, exit non-zero on failed
  verification so init retries rather than half-applies.

### What is explicitly NOT in v1

WiFi TOFU (issue Option A) — kept as fallback if link-local proves
impractical on a bench; mDNS discovery (Option C); any form of device-side
password. TOFB ships **opt-in** (a profile flag that includes the device
script in the ASU build); default images are unchanged.

## Consequences

- Stale-key lockouts stop being terminal: any image + physical operator ⇒
  adoption path.
- The bench workflow gains a uniform first-contact procedure for dark units
  of any species with a link-local stack and ≥1 controllable LED.
- Host-side pieces (`scripts/tofb.py`) are fully testable now; every
  on-device behavior (LED timing, httpd applet availability, entropy
  latency, button timing) is NEEDS-BENCH and marked so.
- Follow-up windows: profile-builder integration flag, image build with the
  script, bench validation, then default-on debate.

## Prior art in-org

- #228 option survey (this ADR implements B + attestation).
- PR #235 / #229: the verify-then-commit discipline the device script
  inherits; `scripts/profile/builder.py` `_ssh_key_firstboot` (the
  hardened-key pattern TOFB reuses at enrollment time).
- AGENTS.md Dark-Device discipline (zone-scoped v6 transport as the
  house-standard first-contact channel).
- `docs/DARK-DEVICE-PLAYBOOK.md` (the discovery ladder TOFB terminates in).

## Follow-up note: the opt-in shipping vehicle (2026-10-17)

The flag from "What is explicitly NOT in v1" landed as `[network] tofb =
true` in config.toml or `firmware-manager.py request --tofb`, mirroring
the `wan_ssh` precedent end to end (config attr + CLI flag OR-ed in
`cmd_request`, passed as the `tofb` build_plan kwarg —
`scripts/firmware-manager.py`, `scripts/profile/builder.py`). Default
builds are unchanged: flag off → no step → identical ASU `defaults`
payload, build request, and cache key.

**Vehicle: a uci-defaults fragment that installs + enables a procd init
service carrying the loop.** TOFB is marker-gated and must run at EVERY
boot until enrolled, so a one-shot uci-defaults shape cannot carry it;
ASU `files` shipping was rejected because our ASU client transports
`defaults` only (no file channel). The fragment base64-embeds the exact
bytes of `scripts/tofb-device.sh` at build time, writes it to
`/etc/conwrt/tofb-device.sh`, gates it on a baked SHA-256 (BusyBox
`sha256sum` — the baked digest equals host `sha256sum
scripts/tofb-device.sh`, so the shipped value is debuggable from the
checkout) plus `sh -n`, installs `/etc/init.d/tofb` (procd, `START=95`)
the same way, and only then enables it — every step `|| exit 1`.

**Failed installs retain, never half-apply.** Nothing is enabled until
everything verifies, and the TOFB step is appended LAST in the plan
because uci_apply_defaults deletes the defaults file based on the LAST
command's exit status — a failing TOFB subshell therefore retains the
whole file for next-boot retry (earlier steps are idempotent re-runs).

**No respawn** on the procd instance: the endpoint-death semantics
(3 wrong codes → down until power cycle) outrank transient-restart
comfort; an early-boot transient death means one power cycle restarts
TOFB, which the bench operator is positioned to do.

NEEDS-BENCH (on-device, gated before any default-on debate): `START=95`
vs link-local address/dropbearkey availability, rc.common `enabled`
semantics across variants, LED paths and httpd CGI wiring (inherited
from the device script), and whether a bounded procd respawn
(threshold/timeout/retry) can coexist with the 3-failure endpoint
budget.
