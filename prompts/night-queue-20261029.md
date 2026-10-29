# Night Queue 2026-10-29 — 16h unattended, software-only, Amperstrand-only

Session prompt for a long unattended run. Everything here is repo-side:
ZERO device/bench operations (no ssh to switches/DUTs/ERX, no PoE, no
serial — reads included). No posts/interactions outside Amperstrand
repos (AGENTS owner rule). Every "fixed" claim ships with a test in its
PR. Park-and-document on ambiguous review gates instead of forcing.

## Setup (once)

    cd ~/src && scripts/dev-session.sh start night-queue-1029
    # base: clean origin/master; one worktree, one lane, PRs as the trail

Progress convention: open a PR per item (squash-merge on green CI when
the change matches its issue's acceptance criteria; otherwise leave open
with a status comment), and post evidence to the driving issue. Do not
batch unrelated items into one PR.

## Phase 1 — tonight's fresh threads (~2h)

1. **conwrt #583 — exclusive-VM CI for the lifecycle test.** The spec is
   in the 2026-10-28 comment on the issue: local re-runs flap into
   sibling-QEMU contention (40 VM-start errors observed); the fix is a
   scheduled or otherwise exclusive CI slot (a concurrency-grouped
   workflow or a lock) so `test_sysupgrade_keep_config_lifecycle` gets a
   clean host. Accept: workflow PR + green dry run on the PR itself.
2. **Bundle-freshness failure (new, file a new issue first, then fix):**
   `tests/integration/test_wizard_recipes.py::TestBundleFreshness::test_committed_bundle_matches_code`
   FAILED on a clean origin/master worktree (evidence:
   /tmp/i583-prep.log on small, run 2026-10-28T23:24). Root-cause the
   committed-bundle vs code drift, fix forward (regenerate the bundle)
   or fix the test if the check is wrong. Accept: test green + the new
   issue carries the explanation.

## Phase 2 — review-debt grind (~2h)

Each item: check whether the finding still holds at HEAD (they may be
fixed already), then fix + PR + tick the issue, or comment
"verified fixed at HEAD <sha>".

- **#477** dlink-runbook: specimen gate only post-flash; no labgrid
  acquire/release in the runbook steps; static-IP step lacks UCI-verify
  discipline (source: PR #233 review).
- **#465** upstream-drafts: mlkem stanza doesn't disable edge defaults;
  Dropbear spike attributed to upstream but is OpenWrt-side (source:
  PR #223 review). These are DRAFT CORRECTIONS for a future upstream
  engagement — fix the drafts in-repo, do NOT post upstream.
- **#458** build-agent-apk: partial-cache wedge, unpinned apk-tools,
  non-unique revision in the build-agent image flow (source: PR #176).
- **#478** agents marker-scan rule drops P3 findings from the review
  sweep (source: PR #90).

## Phase 3 — the real feature (~3h)

**conwrt #555 — executor(apply) deadman/recovery window** (the Codex
#524 P1 lift-out). Plans that restart networking can wedge the executor
with no path back; the deadman window bounds the no-feedback period and
defines the recovery entry. Read the lift-out notes on #555 first — the
design constraints (what counts as progress, who arms the window, what
recovery may do) are in the thread. Accept: implementation + unit tests
+ integration test where the VM harness permits, PR referencing the
lift-out. This is the night's highest-value ticket — do not rush it to
fit Phase 4; push Phase 4 back instead.

## Phase 4 — lab registry software (~2h) — conwrt-bench repo

1. **Dossier corrections from the 2026-10-28 seat-truth sweep** (evidence
   on conwrt-bench #68 comment 6482171958): bay2 occupant = **ea7f**
   (dc:b8:08:6c:ea:7f, .12.113) not a6e4; lan7 = **47a2**
   (b4:2d:56:25:47:a2) alive — seed's "empty bay" wrong; lan6 = unknown
   device a8:63:7d:8f:61:a1; **a6e4 never left stock-p8** (powered off
   there — the recorded moves never executed). Update
   registry/devices/*.yaml accordingly, re-render docs/port-map.md per
   docs/inventory-management.md (a dossier change without re-render is a
   bug).
2. **benynet arms**: extend tools/benynet.py (merged MVP handles
   bench-owrt) with check-mode arms for the stock switch (zyxel-stock
   web API, READ-ONLY — cmd=773 truth, 775 lies) and er6p (uci reads
   over ssh :13.4). NO ERX arm tonight (production uplink, owner may
   touch only). Accept: `benynet.py check` runs all arms clean against
   the dossiers.

## Phase 5 — continuation lanes (~4h)

- **#522 typed-ops continuation**: 25/34 presets landed via #582;
   continue the same pattern for the remaining presets (see the issue's
   preset list + §4 conventions). One PR per coherent batch.
- **#67 (conwrt-bench) svi_preflight round 2**: nested-prefix rejection
   + prefixes generated from seed.yaml (spec on the issue).
- **#508 privacy sweep**: same-class unit identifiers remaining in
   tracked docs (the #290 scrub's sweep list is on the issue).

## Phase 6 — flex (~2h, stop early rather than rush)

- **#575 NR7101 validation trap**: non-cellular uplinks outrank wwan0 by
   route metric + dead rx_bytes -> false "profile has data". Pure
   software fix in the validation logic.
- **#571 silentlink**: AT-parsing robustness + audio-feedback polish.

## Stop conditions

- Ambiguous review gate -> park with a status comment, next item.
- A change needs device evidence to be honest -> park, next item.
- Everything lands early -> stop. Do not invent scope.

## Morning handoff

One comment on conwrt #583's successor issue or a fresh
`docs/sessions/2026-10-29-night-queue.md` in conwrt-bench: what landed
(PR list), what parked and why, what the first human decision should be.
