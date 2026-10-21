# Conwrt 2.0 — Status & Handoff (2026-10-21, night)

Successor-session snapshot (the 2026-10-12→21 orchestrator session died at
21:11 mid-turn at token starvation after ~1847 messages; this session
recovered the lane from the repo and completed the in-flight wave).
Companions: [architecture](../architecture/conwrt-2.0-overview.md) ·
[ADRs](../adr/) · [parity matrix](roadmap/parity-matrix.md) ·
prior handoff [2026-10-12](handoff-conwrt2-2026-10-12.md).

## Where things stand

M1/M2 shipped; execution is now parity-matrix-driven waves (M9 policy: a
Python twin retires only when its Rust twin's parity tests are green and the
removal PR cites its row). Tonight's wave, end state:

| PR | Content | State |
|---|---|---|
| #412 | `conwrt-serial` crate: serial_transport.py port (linter, collector FSM, break recovery, tcp bridge) | **merged** (Wave 1A) |
| #418 | serial boot-capture + base64 flash driver on conwrt-serial (§5 siblings) | **merged** (serialcap worker, 23:2x) |
| #411 | Rust/Python plan-renderer parity harness + wireguard preset migration (§4) | owner-directed merge at 20:55, pending this session's CI round: original rust run was a real FAILURE (no_std gate: `vec!` out of scope in `wireguard.rs`) — fixed (`use alloc::vec;`), all gates replicated green locally, pushed; merge when CI lands |
| #417 | detection & recovery patterns for dark devices + gs1900 wedge-class model | **merged** (rebuilt this session) |
| #416 | typed-ops ports: tether + wireguard-client (+guest-wifi) (§4) | green, owned by live `ucport2` worker |
| #419 | `conwrt image` CLI — ASU request-with-packages parity slice (§3) | open (this session; recovered from uncommitted 2026-10-16 hub debris) |

## What this (successor) session did

1. **Recovered state**: hung session `ses_ed057d30…` tail + ledger + worktrees
   + PR inventory. Two live workers (`ucport2` w15, `serialcap` w16) were
   mid-flight and were left to finish (serialcap merged #418 itself).
2. **#411**: the 2h "in_progress" rust run completed as FAILURE — not a
   wedge. Merged origin/master into the PR branch (clean), re-verified the
   std surface locally (`cargo test --workspace` green; parity suite 14/14
   after adding the worktree-local `.cargo/config.toml` — the global
   target-dir pin silently breaks the test's binary lookup,
   `dev-session.sh start` prevents it), then replicated CI's no_std gate
   and found the real failure: `vec!` without `use alloc::vec;` in
   `wireguard.rs` (the head commit fixed `ToString` but missed the macro).
   One-line fix pushed; fmt/clippy/workspace/no_std/embassy cross-checks
   all green locally. Codex review never ran (usage limits) — same
   honest-disposition precedent as #412, recorded on-PR by the prior
   session.
3. **#417**: old branch was 380 commits behind carrying pre-landing
   executor/maas/trust-store work (already in master via #200/#201/#293+).
   Rebuilt from master: net-new docs + gs1900 model JSON only (3-way merge,
   master's newer schema fields kept). 92/92 model tests green. Force-push
   also cured the CI event-routing wedge. **Merged.**
4. **#419**: the 2026-10-16 `conwrt image` CLI slice sat UNCOMMITTED in the
   hub tree (root cause of the "hub is not read-only" drift). Rehomed into
   the `imgcli` worktree lane, verified (e2e vs mock ASU 2/2, fmt, clippy
   -D warnings, workspace green), PR'd. **Hub tree now pristine (0 dirty).**
5. Hub `master` remains a read-only ref (behind origin; that is fine — it is
   not a working branch).

## Known loose ends (ordered)

1. **#416 merge** — checks green; the `ucport2` worker was still iterating at
   handoff time. If the worker is gone, verify review disposition and merge.
2. **#419 CI** — was in flight at handoff; merge when green (owner is this
   lane; no review debt — Codex limits may block bot review, use the #412
   disposition precedent).
3. **`flash_b64.rs` flake** — `trigger_sysupgrade_writes_line_without_waiting`
   (from #418) failed once under full-workspace parallel load, 5/5 green
   isolated. Timing-sensitive; worth a look in the serialcap lane.
4. **Stale worktrees/ledger**: `tg-e2e-upload` + `esp32` lanes merged&gone
   (retire via `scripts/dev-session.sh stop`); `lockoutdoc` holds an
   UNCOMMITTED postmortem doc (2026-10-16 x1860 recovery lockout) — rehome
   like #419 or drop deliberately; `arpprobe-onereq` holds WIP (model JSON +
   flash dispatcher edits, Oct 17) — decide lane fate. `serialrust` ledger
   entry is stale (worktree already removed).
5. **Parity next steps** (matrix retirement queue): `conwrt fingerprint`
   operator-default docs swap (item 2); `firmware-manager.py` image/cache
   retirement once #419 + vanilla image sourcing land (item 3); §4 use-case
   ports continue per-plugin behind #411's harness; §5 siblings remaining:
   serial-console/serial-configure/serial-backup onto `conwrt-serial`.

## Bench facts that still hold

From the 2026-10-12 handoff: mips cross-build gap (#109), agent protocol
postcard-rpc decision (#107, ADR-0004 kill-criteria), classifier
management-interface refinement, model schema tightening (#118). The
handoff-2026-10-12 "open gaps" list remains the reference for M3+ planning.

## Session hygiene

This session's worktrees: `conwrt-par411` (#411 update+verify),
`conwrt-drp` (#417 rebuild + this handoff), `conwrt-imgcli` (#419). Retire
with `scripts/dev-session.sh stop <name>` once their PRs merge (`par411`,
`drp` are safe to stop immediately after #411 merges; `imgcli` after #419).
