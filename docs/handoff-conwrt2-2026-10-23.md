# Conwrt 2.0 — Status & Handoff (2026-10-22/23, night — on-device campaign)

Checkpoint after the on-device validation campaign (the follow-up to
[handoff 2026-10-21](handoff-conwrt2-2026-10-21.md)). The lane's mode
shifted from design-recovery to **hardware-validated Rust migration with
live Python retirement**. Companions:
[parity matrix](roadmap/parity-matrix.md) · [roadmap](roadmap/roadmap.md).

## The test device made it all possible

`x1860-1` (COVR-X1860 A1, MAC `a8:63:7d:xx:xx:xx` — redacted #508, verbatim preserved in the private lab project) at `192.168.105.UNIT`
— adopted 2026-10-22 via two Rust-path flashes (vanilla 25.12.6, then
the ASU-baked loop, PR #437): key door, rogue-DHCP disarmed, seat IP
with explicit netmask. Facts/baseline/lock protocol live in
`/tmp/conwrt-x1860/` (FACTS.md, baseline-uci.txt, mutate.lock). No
serial door; recovery = physical U-Boot. Registry: `data/lab.yaml`
state `active`; inventory records appended for both flashes.

## What landed (2026-10-22 → 23:03, ~20 PRs)

**On-device proofs (worker lanes, x1860 hardware):**
- #444 — package-bearing profiles on real apk-era hardware:
  wireguard-client + guest-wifi apply→verify→revert ring-3 lifecycles,
  fake-WAN recipe (host MASQUERADE, rules torn down), `kmod-wireguard`
  runtime-apply hardware finding, 1.x `opkg_install_script` apk-aware
  fix (a11bfd6 semantics), preexisting-config refusal gate.
- #446 — all 9 typed profiles in apply/plan + #427(a)
  uci-revert-before-mutate in the executor.
- #430/#433/#435 — travelmate port + host-seeding + ring-3 e2e.
- #428/#429 — sqm byte-parity; wireguard apply proven in the QEMU oracle.
- #449 — §5 serial console family COMPLETE on the Rust side:
  configure + backup + console-monitor core (serialcfg lane).

**My lanes (orchestrator-executed):**
- #437 — netmask guard (the /32 postmortem as a hard gate), real-ASU
  request-with-packages proof, `adopt-fresh-openwrt.sh` (idempotent,
  no-op verified), model release → 25.12.6, full flash loop proven.
- #439 — profile/apply.py SSH-transport deprecation marker (salvage).
- #441 — classifier refinement: `conwrt diagnose --key` composes the
  unauthenticated verdict with a key-authenticated board read —
  headless OpenWrt resolves `ssh-only`→`openwrt` (live-proven); the
  2026-10-12 handoff's last open classifier gap, closed.
- #443 — #422 closed at the root (openpty slave held through the
  reopen, both harnesses) + the day's CI-runner rustup failure fixed
  (toolchain+components provisioned in the Python job; parity-build
  stderr surfaced — that capture identified the root cause in one read).
- #445 — `conwrt source-image` at 1.x parity (live cache-hit on the
  1.x-downloaded file — one cache, both tools).
- #450 — **retirement queue #3 fully executed**: 1.x
  `conwrt.py image`/`cache` REMOVED; `conwrt cache list/clean` added
  (plan/confirm split); the multi-hyphen `--model-id` matching bug
  fixed Rust-side (separator-normalized; the 1.x twin retired with the
  bug documented, per the migration directive).

**Others:** #440/#442/#448 (§4 typed-ops ports: adguard, mesh11sd,
rescue-watchdog, ssh-hardening, mwan3 — 15/34 use cases now typed);
#453 (#406 trust flake: kernel-enforced flock); #436/#452-adjacent
(F746 seat-env enabler); #423 (ssh-hardening golden parity).

## Retirement scoreboard (M9)

| Queue item | State |
|---|---|
| #1 validate_models → parity fixture | done long ago |
| #2 router-fingerprint.py | docs swap done (#434); CLI retained for stock-vendor scope by design |
| #3 firmware-manager image/cache | **EXECUTED end-to-end** (#437/#445/#450) |
| #4 profile/apply.py SSH transport | proven + deprecated (#438/#439); removal gated on remaining flows (ubus transport, unported profiles) |

§4 progress: 15/34 use cases typed; each new port lands with 1.x golden
parity (and this cycle fixed two 1.x defects found by the ports —
mwan3's pair in #448, opkg/apk semantics in #444).

## Open at handoff

- **#447** (zycast Rust mipsel port) — CI green; owner deliberately
  holding for on-device smoke (multicast hits every listener — AGENTS
  specimen rules make this an owner-present operation).
- **#451** (nodns + auto-sqm §4 ports) — green CI; Codex findings
  awaiting disposition (connector hit usage limits mid-review).
- Workers: wanapk active post-#444; several idle panes reusable
  (ring3read/apply3 w15-w17, wanapk w1A).

## Known environment constraints

- **Disk ENOSPC twice tonight** (three+ concurrent build lanes on
  389G). My lanes' targets are reaped on retirement; the recurring
  pressure is the fleet's build fan-out — the sweep tool exists, run it
  before spawning new lanes.
- **GitHub runner flakes** (rustup component conflicts; orphaned
  in_progress check-runs): diagnosed + fixed for the systematic case
  (#443); the zombie-job class still needs a manual cancel/rerun.
- Codex review connector: usage-limit outages interrupt review cycles;
  disposition per the pre-merge gate still applies — findings from
  earlier heads must be re-located and closed.

## Next lanes (ordered)

1. Merge #447/#451 when their cycles conclude (owner-gated / findings).
2. §4 continuation: 19 use cases remain (next by usage: travelmate
   follow-ups landed; doh/sqm GAP in the parity manifest is
   shrink-only — check `tests/fixtures/parity/manifest.json`).
3. §7 per-command retirement: `conwrt models`/`list` byte parity landed
   (#442-era); `conwrt probe`/`discover-v6` follow the same pattern.
4. M3 agent protocol (#107, ADR-0004 kill-criteria) — the largest
   unstarted design item; postcard-rpc 0.12 prototype branch exists.
5. mipsel on-router execution (#109) — toolchain-pin lane produced the
   seat-env enabler (#436); the SDK cross-build lane continues.

## Session hygiene

My lanes all retired via dev-session (worktrees gone, ledger minimal).
Device left in adopted baseline; fresh baseline-uci.txt recorded
post-#437-flash. Hub checkout intentionally stale — work from
origin/master worktrees.
