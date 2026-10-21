# Conwrt 2.0 — Status & Handoff (2026-10-21, night — FINAL)

Successor-session snapshot (the 2026-10-12→21 orchestrator session died at
21:11 mid-turn at token starvation after ~1847 messages; this session
recovered the lane from the repo and completed the in-flight wave — every
PR of the wave is now merged). Companions:
[architecture](../architecture/conwrt-2.0-overview.md) ·
[ADRs](../adr/) · [parity matrix](roadmap/parity-matrix.md) ·
prior handoff [2026-10-12](handoff-conwrt2-2026-10-12.md).

## Where things stand

M1/M2 shipped; execution is parity-matrix-driven waves (M9 policy: a
Python twin retires only when its Rust twin's parity tests are green and
the removal PR cites its row). Tonight's wave — final state:

| PR | Content | State |
|---|---|---|
| #412 | `conwrt-serial` crate: serial_transport.py port | **merged** (Wave 1A) |
| #418 | serial boot-capture + base64 flash driver on conwrt-serial (§5) | **merged** (serialcap worker) |
| #411 | Rust/Python plan-renderer parity harness (§4) | **merged 22:38Z** — after 3 real CI failures fixed (no_std `vec!` macro; `cargo run` ambiguity → `default-run`; duplicate wireguard module vs #416 slimmed to harness-only) + one stale-merge-ref rerun trap |
| #417 | detection & recovery patterns for dark devices + gs1900 wedge-class model | **merged** (rebuilt from master; force-push also cured the CI event-routing wedge) |
| #416 | typed-ops ports: tether + wireguard-client/server + guest-wifi (§4) | **merged** (ucport2 worker; orchestrator-verified) |
| #419 | `conwrt image` CLI — ASU request-with-packages parity slice (§3) | **merged** (recovered from uncommitted 2026-10-16 hub debris; hub tree now pristine) |
| #424 | **red-master repair**: #421 merged 23:47Z with failing rust check (6/9 golden tests red on pristine master); filter extended to #421's apk-aware `EnsurePackage` two-line blocks | **merged 00:17Z** (this session) |
| #423 | ssh-hardening typed-ops port + same comparator fix | **open** (ucport2 worker, green; coordination note posted: rebase after #424 — comparator hunk drops empty; justify the wireguard-client golden removal) |

## What this (successor) session did

1. **Recovered state**: hung session `ses_ed057d30…` tail + ledger + worktrees
   + PR inventory. Two live workers (`ucport2` w15, `serialcap` w16) were
   mid-flight and were left to finish (serialcap merged #418 itself; ucport2
   later took #416 to merge and opened #423).
2. **#411 through four CI rounds**: (a) the 2h "zombie" rust run was a real
   FAILURE — no_std gate, `vec!` without `use alloc::vec;`; (b) round 2
   failed on `make parity-check` — `cargo run` ambiguous once the PR's
   second binary exists → `default-run = "conwrt"`; (c) round 3 failed on
   the `flash_b64` pty flake (see loose ends); (d) after #416+#421 landed,
   the branch's wireguard module/types/planners were strict duplicates of
   #416's shipped implementation — slimmed the PR to its unique value: the
   cross-language parity harness now drives **master's** planner/renderer,
   with the 2.x-only `EnsurePackage` apk/opkg preamble excluded from
   byte-parity on both sides (same documented exclusion as
   `use_case_goldens.rs`). All gates replicated locally (fmt, clippy
   -D warnings, workspace tests, no_std, parity-check, python parity 14/14).
   CI lesson: `gh run rerun` reuses the ORIGINAL merge ref — after merging a
   master fix, push a merge commit instead of rerunning.
3. **Red-master repair (#424)**: #421 (the #322 superset squash) merged with
   a failing rust check — its apk-aware package render broke 6/9 golden
   tests on pristine master. One-file filter fix; 62/62 workspace suites
   green post-fix. Sequenced #424 → #423 (worker acknowledged via note).
4. **#417 rebuilt** from master (old branch 380 commits behind carrying
   pre-landed executor/maas/trust-store work); gs1900 model JSON 3-way
   merged (master's newer schema fields kept); 92/92 model tests.
5. **#419 rehomed** the uncommitted 2026-10-16 hub `conwrt image` slice
   into a worktree lane; hub tree returned to pristine (0 dirty).
6. **Hygiene**: ledger pruned to reality (2 protected dirty lanes remain);
   merged/dead lanes retired (`imgcli`, `par411`, `drp`, `masterfix`,
   `esp32`, `tg-e2e-upload`, `ucport`, `serialcap` worktrees); Codex-review
   outages dispositioned on-PR per the #412 precedent (connector usage
   limits — no findings produced, human/session verification stands in).

## Known loose ends (ordered)

1. **#423 merge** — green, worker-owned; after its rebase, confirm the
   comparator hunk resolved to #424's version and the ssh-hardening port
   passes with the master filter.
2. **`flash_b64.rs` pty flake** (#418's test) — failed once in CI and once
   locally under full-workspace parallel load (`/dev/pts` contention),
   8/8 green isolated. Timing-sensitive; worth a stabilization pass in the
   serial lane.
3. **Stale worktrees/ledger**: `lockoutdoc` holds an UNCOMMITTED postmortem
   doc (2026-10-16 x1860 recovery lockout) — rehome like #419 or drop
   deliberately; `arpprobe-onereq` holds WIP (model JSON + flash dispatcher
   edits, Oct 17) — decide lane fate.
4. **Parity next steps** (matrix retirement queue): `conwrt fingerprint`
   operator-default docs swap (item 2); `firmware-manager.py` image/cache
   retirement once #419 + vanilla image sourcing land (item 3); §4
   use-case ports continue per-plugin behind #411's harness (sqm GAP
   documented in `tests/fixtures/parity/manifest.json` — shrink-only); §5
   siblings remaining: serial-console/serial-configure/serial-backup onto
   `conwrt-serial`.

## Bench facts that still hold

From the 2026-10-12 handoff: mips cross-build gap (#109), agent protocol
postcard-rpc decision (#107, ADR-0004 kill-criteria), classifier
management-interface refinement, model schema tightening (#118). The
handoff-2026-10-12 "open gaps" list remains the reference for M3+ planning.

## Session hygiene

This session created and retired: `conwrt-par411`, `conwrt-drp`,
`conwrt-imgcli`, `conwrt-masterfix`, `conwrt-handoff2` (this file's lane).
Live at handoff: `conwrt-ucport` (ucport2 worker, #423), `conwrt-lockoutdoc`
+ `conwrt-arpprobe-onereq` (protected, uncommitted work — see loose ends).
