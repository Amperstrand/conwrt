# Discover as a Strategy — encoding the dark-device ladder as data (#777)

> Design triage (2026-11-25 unattended lane). v2-shape adjacent (#100
> family), deliberately NOT a rewrite: everything below is additive
> plumbing around the implemented ladder. Landed with this doc:
> `scripts/discover_states.json` (the machine), `conwrt/strategy_states.py`
> (loader/validator/auditor), `bench_discover --json` `state_view` block,
> `tests/test_strategy_states.py` (lockstep + audit pins).

## The correspondence

labgrid's Strategy — a named state machine walking a board
off → bootloader → shell with per-transition verification — is the
architecture our dark-device playbook already is informally
(`docs/DARK-DEVICE-PLAYBOOK.md`, generalized in #759/#760). The mapping:

| labgrid concept | conwrt today | encoded as |
|---|---|---|
| State | "what we know about the device" (dark, v6-alive, banner-up…) | `states[]` |
| Transition + driver call | a ladder rung (probe command + verdict semantics) | `transitions[]` |
| per-transition verification | the rung's positive/negative meaning | `on_positive` / `on_negative` edges |
| Strategy composition | listen verdict → discover start | `entry_hints` |

## Modeling decisions (the ones that matter)

1. **States are knowledge states, not device states.** A probe does not
   move the device; it moves our certainty. Hence:
   - `on_positive` → the state the evidence ESTABLISHES;
   - `on_negative` → a SELF-EDGE (a negative adds no knowledge; the run
     falls through to the next rung). The single exception is the
     layer-0 control gate, whose negative is the terminal
     `methodology-unverified` abort (AGENTS rule 11 made structural).
2. **The control gate is a gate, not a move.** Positive keeps the run at
   `dark`; its value is that every subsequent negative is trustworthy.
   This is why "continuing after control-failed" is now a machine
   ILLEGALITY, not a code-review argument.
3. **Same-layer rung families** (three `1-v6` rungs, two `3-service`
   rungs) disambiguate by from-state during audit; the artifact pins
   them layer-for-layer and count-for-count against
   `bench_discover.build_ladder()` — JSON/artifact drift fails CI.
4. **Credentials stay a terminal with a human gate.** The
   credential-ladder transition ends at `shell-candidate`; both edges
   point there because execution is deliberately manual
   (print-only ladder, unchanged).

## The audit property (why this is worth the data file)

`audit_run()` walks a recorded run's (layer, status) sequence and
verifies every hop is an edge the machine allows:

- legal walk → `legal: true` + a rendered path
  (`dark -[v4-sweep:positive]-> v4-candidate`) directly citable in
  bench evidence;
- forbidden sequences — continuing past a failed control gate, a rung
  taken from a state the machine doesn't allow — are named problems,
  not surprises.

`bench_discover --json` now attaches this as `state_view` (fail-open:
an audit error is reported in the payload, never blocks a bench run).

## listen ⇄ discover composition

`conwrt listen` verdicts (`bootlisten.next_action`: no-frames, v6door,
alias-probe, dhcp-adopt, vendor-fallback, capture-longer) are
first-class state references via `entry_hints`: a listen run SEEDS
discover's starting state instead of re-probing from `dark`. The
first-step seed jump is the one tolerated path-illegality (documented,
first step only). Lockstep is pinned: every `next_action` the
classifier can emit must have a hint.

## What this deliberately does NOT do (yet)

- No probe behavior changes; prose output unchanged.
- `conwrt listen` output shape unchanged (its verdict ids are already
  the state vocabulary — composition is data + helper, no payload break).
- No Rust-side Strategy enum (v2 question; the JSON schema
  `conwrt-discover-strategy/1` is the contract a Rust port would
  consume).
- The v6 rungs' three probes share `on_positive: v6-alive`; if v2 wants
  graduated strength (link-local answer > NDP cache > all-nodes), split
  the state — schema allows it without a migration.

## Follow-ups this triage suggests

1. `conwrt discover --json` upstream consumers: report writers can cite
   `state_view.path` verbatim (adopt the field in bench evidence
   templates).
2. `conwrt listen --json` could emit `state:` alongside `next_action`
   (additive; resolver already exists here).
3. v2 (#100/#777 family): the same encoding for flash/recovery flows —
   the AP3915i CFG recipe and the zycast write-window are state machines
   with the same shape and stronger legality requirements.
