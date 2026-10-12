# ADR 0011: Test strategy and supported-platform matrix

Status: accepted
Milestone: M1 onward

## Context

1.x already has a strong testing culture: 3,151 test functions, a QEMU
OpenWrt integration suite with per-session qcow2 overlays, hardware tests
gated by env (`CONWRT_DEVICE_IP`), and a hard policy of no network-mutating
commands from tests. The 2.0 additions are portability (MCU targets) and the
remote-agent surface. The tollgate-installer research contributed proven
patterns: injectable probes everywhere, fixture sshd with dual host keys,
non-vacuous regression guards, scheduled cross-repo release smoke, and
hardware rings behind CI environments.

## Decision

1. **Three rings:**
   - **Ring 1 — offline (every PR):** unit tests; mock-provider workflow
     tests; pure state-machine tests; validation of all 24 real model JSONs;
     dry-run purity test (a full plan against mock providers performs zero
     mutating calls — enforced by a recording mock).
   - **Ring 2 — QEMU/fixture (KVM runners or local `make integration`):**
     parity oracles vs 1.x; real Dropbear SSH via russh; fixture sshd
     (dual-key) for host-key trust paths; flash lifecycle in the VM.
   - **Ring 3 — hardware-in-the-loop (authorized only):** labgrid places /
     bench bays / physical routers; destructive tests behind explicit
     environment gates; never in default CI.
2. **Architectural acceptance tests (Ring 1, mandatory):**
   - same workflow + model data against local-mock and remote-mock
     providers produce identical results;
   - same profile produces identical plans from CLI and web frontends;
   - Tier-A crates `cargo check --no-default-features` for
     `thumbv7em-none-eabihf` (and `riscv32imac` once the ESP32 crate lands).
3. **Platform matrix is CI-visible:** builds for x86_64-linux (std),
   aarch64/mips musl (OpenWrt, via SDK or cross targets), thumbv7em
   (STM32), riscv32imac (ESP32-S3) — check jobs with flash/RAM size
   reporting for MCU apps (`cargo size`) once they exist.
4. **No test may touch real hardware or mutate networks** — the 1.x rule
   carries over verbatim; mock/scripted providers are the only I/O in
   Ring 1–2 (QEMU VMs excluded — they are the sanctioned local exception).
5. **Non-vacuous guards:** regression tests for behavioral bugs assert the
   bug's presence pre-fix (port of 1.x lessons and the e2e-probe pattern).

## Consequences

- Confidence ladder is explicit: Ring 1 green ⇒ mergeable; Ring 2 gates
  releases; Ring 3 gates hardware claims.
- Documentation and issues may only claim hardware support with Ring 3
  evidence links (extends the `tested_hardware` ledger discipline).

## Alternatives considered

- **Hardware-in-the-loop as default CI**: rejected — safety and cost.
- **Only Ring 1 (pure mocks)**: rejected — the 1.x QEMU suite is exactly
  what makes parity migration credible; keeping it is cheap.
