# ADR 0002: `no_std`, `alloc`, and `std` boundaries

Status: accepted
Milestone: M1

## Context

Targets span x86_64 Linux (fat std + tokio), OpenWrt musl (constrained std),
ESP32-S3 / STM32F746 (no OS, embassy). If the core is allowed casual `std`
usage, MCU targets become retrofits — the single most common failure mode of
"portable" Rust frameworks. Conversely, demanding `no_std` everywhere (e.g. in
the CLI) buys nothing.

Serde works `no_std` with `alloc`; JSON *parsing* via `serde_json` requires
`std`, but our model corpus is JSON while our wire format is postcard — JSON
parsing is a host-side concern.

## Decision

1. **Three tiers:**
   - Tier A (`no_std` + `alloc`): `conwrt-types`, `conwrt-core`,
     `conwrt-protocols`, `conwrt-profiles`, `conwrt-agent-proto`. No `std`,
     no tokio, no file I/O. Async via `async fn` in trait (AFIT), executor-
     agnostic.
   - Tier B (`std`): providers (`local-std`, `openwrt`), apps (CLI, web),
     labgrid adapter.
   - Tier C (embassy/MCU HAL): `apps/conwrt-esp32`, `apps/conwrt-stm32`,
     MCU provider crates. Implements Tier-A traits with embassy drivers.
2. **CI gate:** Tier-A crates must `cargo check --no-default-features` for
   `thumbv7em-none-eabihf` (STM32F7 class) on every PR. Added in the M1 slice.
3. **Features:** `std`/`json` features are additive conveniences on Tier-A
   crates (e.g. `conwrt-types` gains a `json` feature for `serde_json`
   parsing; MCU builds omit it). Default features serve the desktop build;
   CI checks both.
4. **Allocation discipline:** Tier A may use `alloc` (String/Vec/Box) freely —
   all four MCU targets have heap capacity for this domain — but must not
   spawn threads, touch clocks, or open files; those are capabilities.
5. **Time is a capability.** No Tier-A code calls an instant clock directly;
   timeouts are passed in or read from a `Time` capability trait so replayable
   tests and MCU tick sources work identically.

## Consequences

- The compile-target gate catches accidental `std` leakage mechanically.
- `serde_json` usage stays behind features; the wire format (postcard) is the
  only format Tier A parses unconditionally.
- Slight ceremony for host conveniences (JSON, fs) — accepted.

## Alternatives considered

- **Fully `no_std` core without `alloc`**: rejected — model matching, plan
  rendering, and path handling without allocation would dominate the design;
  none of the target MCUs are that small.
- **`std`-only core + FFI to MCU shells**: rejected — defeats agent-on-MCU
  goals; `no_std` must be native, not a port layer.
