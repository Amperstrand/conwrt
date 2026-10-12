# ADR 0007: TollGate integration — orchestrate the backend, reimplement the UX patterns, copy no code

Status: accepted
Milestone: M7 (profile), continuous (license watch)

## Context

Research findings (2026-10-12, source-verified at
`tollgate-installer@1a30f43`, `tollgate-module-basic-go@a211725`):

- **tollgate-installer has NO LICENSE FILE.** README's last line says "MIT",
  but no LICENSE/COPYING/NOTICE exists and GitHub reports `license: null`.
  Absent license text, default copyright (all rights reserved) applies:
  **we may not copy, modify, or redistribute its code** until upstream adds
  a license (or grants one). Behavioral patterns/contracts are not
  copyrightable — reimplementing them is fine.
- TollGate business logic lives in `tollgate-module-basic-go` (GPL-3.0),
  shipped as `tollgate-wrt` ipk/apk from `FreedomTechFeed/packages` (GPL-2.0).
  Deploying/installing those artifacts does not infect conwrt (aggregation);
  *linking or copying* their code would.
- The installer's own architecture is "thin UI wrapper; all business logic
  lives in the router-side backend" — exposed as a small, stable ubus/rpcd
  contract (`rpcd/tollgate`: config_schema/get/set/save, wallet_*, status,
  health, upstream_*, clients) plus HTTP :2121.
- `tollgate-rs` (MIT, active) exists as a Rust TollGate implementation —
  future component reuse under a clean license.
- OpenTollGate org is operationally linked to Amperstrand (org `.github`
  migrated from Amperstrand/.github), but license boundaries remain per-repo.

## Decision

1. **Integration shape = profile + external backend** (option (c) from the
   research), packaged **out-of-tree** (`conwrt-profile-tollgate` or a
   clearly-separated profile in-tree once the module interface stabilizes):
   conwrt orchestrates lifecycle (flash OpenWrt, install feed-pinned
   `tollgate-wrt`, write UCI via the rpcd contract, health-probe :2121);
   TollGate keeps payments/identity/valve logic entirely in its backend.
2. **Reimplement the installer's generalizable mechanics in Rust** (patterns,
   not code): host-key trust ladder; one-shot credential reveal +
   persist-before-apply; discovery candidate taxonomy with demotion and
   structured diagnostics; job/step/log model with watchdog and panic
   containment; staging caches (memory + URL-hash-keyed disk, image-only);
   package digest verification hierarchy (independent anchor or "not
   verified", fail-closed option); refuse-downgrade + pinned-tag-exists CI
   test.
3. **License gates**: (a) no installer code until a LICENSE file lands
   upstream — tracked as an open item; (b) GPL-3.0/-2.0 artifacts may be
   *installed* but never vendored/linked; (c) watch `tollgate-rs` (MIT) for
   sanctioned reuse.
4. **Do not disrupt the existing TollGate installer** — 1.x's `tollgate.py`
   use case and the upstream wizard continue to work independently; the
   conwrt profile is additive.

## Consequences

- TollGate release churn (weekly pre-tags, stale-pin downgrade hazard) is
  contained in the profile module + its pin-exists test, not the engine.
- conwrt's wizard gets TollGate as "one more target", which is the product
  goal.
- Until upstream licensing is fixed, conwrt-2.0's TollGate support is a
  reimplementation of mechanics we already legally own in 1.x (conwrt already
  flashes TollGate images today).

## Alternatives considered

- **Wrap tollgate-installer binary under conwrt**: rejected — license-blocked
  for redistribution, Go/Rust double stack, hardcoded TollGate pipeline.
- **First-party port of installer internals**: rejected — same license block
  plus language mismatch.

## Open questions

- Will upstream add a LICENSE file? (Check before M7; not a blocker given
  decision 1.)
- Feed pin automation: mirror feed release metadata so the profile's pin
  bump is a tested PR, not a manual chase.
