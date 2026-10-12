# ADR 0001: Rust migration strategy — incremental strangler, parity-gated

Status: accepted (reversible only by evidence of blocked parity)
Milestone: M0–M9

## Context

conwrt 1.x is ~72k LOC of Python (engine in `scripts/conwrt/` + `scripts/flash/`,
34 use-case plugins, 135 test files) plus one zero-dependency Go binary
(`cmd/zycast`). It works: 14/15 use cases tested on real hardware, QEMU
integration suite green. The 2.0 requirements — OpenWrt and MCU execution,
single-binary distribution, `no_std` embedded agents, one SSH/protocol stack
instead of three duplicated Python transports — are not reachable in Python
on ESP32/STM32 class hardware.

A big-bang rewrite would discard validated behavior (the flash state machine
encodes years of hardware lessons: UART break recovery, sysupgrade exit-code
246, Z-Loader timing, overlay-verify) and freeze the working 1.x flow.

## Decision

1. **Strangler-fig migration.** Rust components grow beside Python; Python
   remains the production flash path until a Rust component demonstrates
   behavioral parity against it (QEMU suite + goldens), then the Python twin
   is retired in the same PR series that completes parity (M9 for the engine).
2. **Data before code.** `models/*.json` is the first shared asset — Rust
   parses and validates the identical files (M1 slice). Model JSON never
   forks; `make validate-models` and `cargo conwrt models validate` must both
   stay green on the same tree.
3. **Parity oracle.** The existing QEMU OpenWrt VM suite is the behavioral
   reference. Each Rust capability lands with tests whose expectations were
   produced by (or cross-checked against) the Python implementation.
4. **Go zycast is wrapped, not ported, until M-late.** It is 546 LOC,
   dependency-free, already cross-compiles for OpenWrt MIPS/ARM, and is
   hardware-proven (NR7101 via Go binary on a MIPS switch). A Rust
   `conwrt-protocols::zycast` port must pass a byte-level frame test against
   the Go implementation before the Go binary is retired.
5. **No placeholder crates.** A crate exists when it carries tested code.
6. **Keep Python adapters where the ecosystem requires them** (labgrid client
   usage, OpenWrt packaging glue) even after M9; the runtime core is what
   goes Rust-first.

## Consequences

- Two implementations coexist for a long window; issue tracking must mark
  which side of the seam each bug fix lands on (parity backlog).
- CI cost grows (Python matrix + Rust jobs + cross-target checks).
- Single-binary distribution (`conwrt-cli`) is available early for read-only
  operations — a safe, immediately useful subset.

## Alternatives considered

- **Big-bang rewrite**: rejected — discards validated hardware behavior,
  freezes production flows, no rollback path.
- **Python + embedded Python (MicroPython on ESP32)**: rejected — no STM32 F7
  story with embassy-class drivers, async story weak, distribution story
  (ipk of CPython) already painful today (`scripts/openwrt-requirements.txt`).
- **Keep Go for everything portable**: rejected — MCU no_std story and
  ecosystem (embedded-hal/embassy) is Rust-native; team already sustains a
  mixed tree, but the 2.0 capability-trait architecture is a Rust pattern.

## Open questions

- Exact seam order after M2 (SSH transport first vs discovery first) —
  decide from M2 findings.
