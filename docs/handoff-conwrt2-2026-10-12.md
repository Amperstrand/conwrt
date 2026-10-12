# Conwrt 2.0 — Status & Handoff (2026-10-12)

Session-state snapshot for whoever picks this up next (human or agent).
Unit-level identifiers live in the local inventory cache
(`data/inventory.jsonl`, gitignored) and the operator's private registry —
this document uses placeholders per AGENTS.md.

Companions: [architecture](../architecture/conwrt-2.0-overview.md) ·
[ADRs](../adr/) · [roadmap](roadmap.md) · parent issue #100.

## Where things stand

Status policy (external review 2026-10-12): a milestone is **shipped** only
when its implementing PR merges to master. Issues close on merge, not on
branch completion — #104/#105/#106 are reopened until #122/#123 land.

| Milestone | State | Evidence |
|---|---|---|
| M0 design/research/ADRs/backlog | 📦 in draft PR #119 | ADRs 0000–0011; parent #100 + issues #101–#118 |
| M1 Rust foundation | 📦 in draft PR #119 | workspace, conwrt-types (24-model corpus parity), conwrt-core (traits/classifier/mock), CLI, CI + no_std gate |
| M2 native CLI + workflow parity | 📦 in draft PRs #122/#123 | local-std provider, `conwrt diagnose`, SSH provider (russh + scp-over-exec + trust ladder), XMODEM via the `xmodem` crate |
| M3+ (agent, OpenWrt agent, MCU, profiles, UI) | ⬜ not started | #107–#117 |

## Verified evidence, by test ring (ADR-0011)

- **Ring 1 (offline, every PR)**: 16 Rust test suites green (69+ tests incl.
  real-model corpus validation, provider-swap acceptance, in-process russh
  server fixture covering auth/exec/trust-ladder/scp).
- **Ring 2 (QEMU VM, `CONWRT_QEMU_VM=1`)**: OpenWrt **25.12.5** VM (retargeted
  from 24.10.2; apk-native suite, 62 passed/2 skipped incl. the real flash
  lifecycle); Rust ring-2 tests prove TOFU, exec/exit codes, and a
  byte-verified scp roundtrip against the VM's real Dropbear.
- **Ring 3 (real hardware, env-gated)**: `tests/bench_router.rs`
  (`CONWRT_BENCH_ROUTER/MAC/KEY/IFACE`) — run live against the physical bench
  x1860: specimen gate (live ARP MAC must equal the expected specimen,
  enforced in code), board identity confirmed, 3/3 in ~1s. First real-hardware
  validation of the Rust SSH stack and of `conwrt diagnose`.
- **On-OpenWrt execution** (M4 exit criterion, VM form): static-pie
  x86_64-musl `conwrt` (2.25 MB) deployed via the provider's own scp +
  trust ladder onto the 25.12.5 VM; on-device model validation,
  self-diagnosis, and router-as-agent diagnosis of another host.

## Bench environment facts (details in local inventory / private registry)

- The bench x1860 (`dlink,covr-x1860-a1`, unit `<unit MAC>`) was rediscovered
  on an unadvertised subnet (`<bench subnet>`) after passive ARP capture —
  it had never been off; its uplink gateway was dead.
- It runs **OpenWrt 24.10.7** (the inventory record claimed 25.12.5 — stale;
  live evidence wins). Read-only session; no flashing or config changes made.
- Host-side bench aliases on the wired interface are local-only state.
- The house ERX (25.12.4) is production — identity-read once, otherwise
  untouched, per AGENTS.md.

## Open technical gaps & findings

1. **mips cross-build** (#109): rustup ships no std for
   `mips-unknown-linux-musl` (x1860/ERX class = mt7621). OpenWrt SDK rust is
   the recommended release path; `-Z build-std` + the staged musl.cc toolchain
   for CI. Until then, on-router execution is x86_64-VM-only.
2. **Agent protocol undecided** (#107): postcard-rpc 0.12 prototype with
   named kill-criteria (ADR-0004) — the largest architectural unknown left.
3. **Classifier refinement**: on-device self-diagnosis showed that a Dropbear
   bound to a specific interface (loopback refused) yields HTTP-only evidence
   and a conservative `stock-vendor` classification. A management-interface
   scope signal would refine this.
4. **SerialIo + serial-flash driver**: `SerialIo` trait + serialport wiring +
   the XMODEM transfer glued into a host-side serial-flash flow (the #104
   deferred piece; #106's transfer is ready and fitness-tested).
5. **Model schema tightening** (#118): live evidence already added one OUI
   (`a8:63:7d`) missing from the x1860 model — the de-facto field set keeps
   drifting from `model.schema.json`.
6. **Stale inventory practice**: the specimen record disagreed with live
   state (firmware version). Ring-3 runs should refresh the local cache as a
   matter of course.

## Recommended next steps (dependency-ordered, opinionated)

1. **Bench x1860 sysupgrade to 25.12.5** — the highest-value real-hardware
   milestone: first *mutating* conwrt-2.0 operation (push image via scp
   provider, `sysupgrade -n` via exec, reboot wait, re-verify + inventory
   refresh), with the full identity/authorization gates. **Destructive —
   requires explicit operator authorization before execution.**
2. **#107 postcard-rpc spike** (timeboxed) — decide the agent wire layer
   against ADR-0004's kill-criteria; de-risks M3/M5/M6.
3. **#109 mips builds via OpenWrt SDK** — unlocks on-router execution on the
   physical x1860 (router-as-agent, M4 for real).
4. **#113 desired-state profile schema + planner skeleton** with the
   dry-run purity gate — the product heart; port 2–3 use-case presets.
5. Smaller: #118 schema increment, the classifier refinement above, and the
   SerialIo/serial-flash driver.
