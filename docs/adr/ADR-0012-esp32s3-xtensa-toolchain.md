# ADR 0012: ESP32-S3 (Xtensa) Rust toolchain strategy

Status: accepted
Milestone: M5 (#111)
Reversible: yes — reopen when upstream rustc ships Xtensa codegen and
esp-hal documents a non-fork build path for `xtensa-esp32s3-none-elf`.

## Context

#111 scaffolds the ESP32-S3 agent on esp-hal 1.x. Unlike the Cortex-M
STM32 target (#110, PR #179), which builds with the pinned upstream
stable toolchain (1.99.0), the S3 is Xtensa: upstream rustc has no
Xtensa codegen, so the target and toolchain must be chosen before any
code is written — CI feasibility gates the whole milestone slice.

Findings (verified 2026-10-15, this worktree):

- Upstream stable 1.99.0 ships no `xtensa-*` targets (`rustup target
  list`). The Rust-on-ESP book still requires a compiler fork for
  Xtensa devices; upstream LLVM has most of the base ISA but a
  rustc-release path does not exist yet.
- esp-hal's own CI/xtask builds Xtensa chips with the esp-rs fork
  (`cargo +esp ... -Zbuild-std=core,alloc`) — the supported recipe.
- espup (`esp-rs/espup`) installs the fork as rustup toolchain `esp`.
  The host already carries `esp` = rustc 1.98.1-nightly (1.98.1.0),
  with `rustfmt`, `clippy`, and `rust-src` components, and a bundled
  `xtensa-esp-elf` GCC 14.2 cross-linker inside the toolchain
  directory (no PATH setup needed to link).
- esp-hal 1.2.2 (crates.io) builds clean for `xtensa-esp32s3-none-elf`
  with `cargo +esp build --release`, `[unstable] build-std =
  ["core","alloc"]`, and `-C link-arg=-nostartfiles
  -C link-arg=-Wl,-Tlinkall.x` (53.7 s cold build of a minimal
  embassy firmware — esp-hal 1.2.2 + esp-rtos 0.4 + embassy-usb 0.6).
  USB OTG (embassy-usb via `embassy-usb-synopsys-otg`) is enabled by
  the stable `esp32s3` chip feature — no `unstable` feature needed for
  the CDC transport.
- `cargo +esp clippy` and `cargo +esp fmt` work on the app crate.
  `cargo size` does NOT: cargo-binutils needs an `llvm-tools`
  component the `esp` toolchain does not offer. The GCC
  `xtensa-esp32s3-elf-size` binary (bundled with the toolchain's GCC;
  also on PATH after sourcing espup's `export-esp.sh`) parses the ELF
  and is the size-gate tool.
- In CI, `esp-rs/xtensa-toolchain@v1.5` (espup under the hood) installs
  the pinned fork on ubuntu-latest, honoring `GITHUB_TOKEN` for the
  GitHub-API rate limit. The pin is the version input `1.98.1.0` —
  identical to the local install, so local and CI build the same code.

## Decision

1. Build the ESP32-S3 firmware with the **esp-rs fork via espup**
   (`cargo +esp`), pinned to fork version **1.98.1.0**, target
   `xtensa-esp32s3-none-elf`, `-Zbuild-std=core,alloc` via the app's
   `.cargo/config.toml` `[unstable]` table, GCC-linked with
   `-nostartfiles -Tlinkall.x`.
2. Do NOT touch the workspace toolchain pin: the fork lives beside the
   pinned upstream stable and is only invoked inside
   `apps/conwrt-esp32s3` (workspace-excluded, same pattern as
   `apps/conwrt-stm32`).
3. CI gate for the firmware = separate job in `rust.yml` using
   `esp-rs/xtensa-toolchain@v1.5` (buildtargets `esp32s3`, version
   `1.98.1.0`): `cargo +esp fmt -- --check`, `cargo +esp clippy --
   -D warnings`, `cargo +esp build --release`, and a flash/RAM budget
   gate from `xtensa-esp32s3-elf-size` on the release ELF.
4. Firmware dep pins: esp-hal `~1.2` (README guidance for unstable-API
   consumers), esp-rtos `0.4` (esp-hal 1.2.x's async runtime), embassy
   stack 0.6/0.10 as released. esp-radio stays OUT of this scaffold
   (issue tracks its beta risk separately).

## Consequences

- Firmware builds require the `esp` toolchain on the host; the
  scaffold documents `espup install --targets esp32s3` for operators.
- Fork updates are manual (pin bump = deliberate act, like the stable
  pin in `rust-toolchain.toml`).
- The size gate uses GCC size, not cargo-binutils; the numbers (text/
  data/bss) match the STM32 gate's semantics.
- Upstream stable users are unaffected: root workspace jobs never
  invoke the fork.

## Alternatives considered

- **Upstream stable + `rustup target add`**: impossible today — no
  Xtensa target ships with upstream rustc.
- **Upstream nightly + build-std**: nightly carries some Xtensa
  target-spec work, but esp-hal's supported/tested configuration is
  the fork; choosing nightly would trade a supported path for an
  unpinned one. Revisit when esp-hal documents it.
- **Skip CI firmware builds (host-side checks only)**: rejected — CI
  can run the fork (xtensa-toolchain action is the esp-rs-blessed
  install), so the honest gate is a real build + size budget.

## Open questions

- esp-rtos 0.4 is new (esp-hal 1.2.x moved the async runtime into it);
  if it churns, pin tighter or vendor the embassy init directly.
