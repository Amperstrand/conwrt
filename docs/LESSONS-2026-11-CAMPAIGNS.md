# Campaign retrospective — the 2026-11 unattended windows

The 2026-11-20 → 11-25 engagement: ~52 merged PRs across four
overnight campaigns run by two agents in parallel, issues 120 → 84,
branches 57 → clean, zero collision damage. This document records
what the machinery got right, where it bent, and what the next
campaign should assume. The hard rules extracted from it live in
AGENTS.md ("Campaign Lessons"); this is the narrative + the numbers.

## What was actually run

| campaign | charter | outcome |
|---|---|---|
| 1 (2026-11-20/23) | "test, improve, merge, fix, clean up" | ~21 PRs; branch hygiene; the audits began |
| 2 (2026-11-23) | audit + compare/contrast | 3 PRs + comparative digest 1 (ASU/Gluon/probe-rs/OpenWISP) + 4 issues |
| 3 (2026-11-24/25) | #794 coverage lanes | 3 PRs (dlink-recovery, auto_detect, firmware-manager) |
| 4 (2026-11-25) | #794 tier 2 | already done by sibling; bonus ssl lane found a real bug (#809) |

## The numbers that matter

- Test-to-source ratio crossed 1:1 (57.6k test lines vs 56.8k source
  in scripts/) and held through every lane.
- The actionable coverage band (modules 20-70% covered) went
  49 → 29 modules; every module named in the #794 map is now
  ≥62% (hnap 86, cmd_backup 95, esim 86, firmware-manager 79,
  overnight 77, chromium_upload 76, auto_detect 62).
- The parity corpus held byte-equality across all ~46 use cases
  through every change — the four-surface rule (both goldens + both
  characterizations move together) never produced a silent drift.
- `cargo audit`: 4 findings → 1 tracked with an applicability
  verdict (rsa/rc pinned by russh; we verify, never RSA-sign).

## The loop that worked: find → pin → file → fix → flip

The qip key-split bug (#809) is the cleanest specimen: a TESTS-ONLY
lane on "uncovered" code surfaced a live on-device bug (server.key
written beginning with a certificate block). The lane pinned the
buggy behavior as a characterization with a loud comment, filed the
issue with the reproduction, and moved on. The fix lane (one regex
class) flipped the pin to the clean assertion and added the
regression that keeps the fix honest. Total cost: ~20 minutes across
two lanes. This loop is now the default for coverage work —
characterization pins are first-class deliverables, not test debt.

## Non-findings (recorded so nobody re-plows them)

- Injection gates: every use-case f-string interpolation passes a
  token/charset gate (the #448 class is closed registry-wide).
- No tracked secrets; credential modules are env-driven with
  gitignored recovery records.
- Test hygiene: sleeps mocked, no unseeded random, loopback-only
  networking in unit tests.
- Deps healthy: minimal python pins, fresh lock, normal dupe profile.
- `.target-rustvm` untrack held (the one scare was a stale checkout).
- Unsafe inventory: 2 blocks, host-side FFI-adjacent.

## Where the machinery bent (and what to do differently)

- **Clock authority.** Host and supervisor clocks disagreed twice,
  and one full lane was chartered against work a sibling had already
  merged. Assume every briefing may be stale: re-verify the specific
  state (issues, PR list, coverage) inside the worktree before the
  first edit.
- **Piped-output phantoms.** Multiple "failed" readings that
  evaporated under file-captured runs. The fast tier is only
  trustworthy when its output goes to a file you then read.
- **The trimmed-PATH trap.** `PATH=/usr/local/bin:/usr/bin:/bin`
  prefixes hid `/root/.cargo/bin` (cargo 1.75) and `/root/.local/bin`
  (ruff) all session, producing the same false errors repeatedly.
  Full ambient PATH for anything that shells out to the toolchain.
- **Iteration-limit cutoffs eat the last unit.** After a context
  cutoff, a blind re-apply duplicated an inserted test (E0428) and
  mangled a union-merge. Grep for the change before re-applying it.

## Standing recommendations (owner decisions, ranked)

1. One claimed bench window burns the entire #769 validation batch
   (7 presets + listen/discover/adopt live legs). Highest value per
   hour of anything on the board.
2. #663 v2-ontology decision (probe-rs variant precedent posted) —
   unblocks the schema-parity cluster (#338/#339).
3. Workflow-scope clicks: #702 (cargo-deny lane), #764 (CI
   concurrency groups) — both fully prepared, both need the token
   scope only the owner has.

## Maintenance cadence

- Monthly: `cargo audit` re-run (watch #774's russh/rc line).
- Quarterly: re-run the audit campaign phase ladder
  (repo-audit-campaign skill) — the non-findings above are the
  "don't re-plow" list for it.
