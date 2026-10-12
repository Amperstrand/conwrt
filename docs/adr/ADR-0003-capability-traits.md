# ADR 0003: Capability trait design

Status: accepted (trait set itself is expected to evolve until M3)
Milestone: M1 (first traits), M2–M3 (full set)

## Context

The same logical capability (serial, sockets, power) must be providable by
Linux, macOS, OpenWrt, an MCU peripheral, a remote conwrt agent, labgrid, or a
mock. The ecosystem already standardizes I/O shapes: `embedded-hal` 1.0
(bus GPIO/SPI/I2C), `embedded-io`/`embedded-io-async` 0.7 (byte streams),
`embedded-nal(-async)` 0.9 (sockets). Research findings (2026-10-12):

- `embedded-io-async` is executor-agnostic (AFIT) and bridges to tokio via
  `embedded-io-adapters::tokio_1::FromTokio` — one shared core can be driven
  by either runtime.
- There is **no standard trait for network-interface configuration** (IP/DHCP/
  up/down) — `embassy-net::Stack` and smoltcp `Interface` are concrete types.
- A monolithic `Platform` trait couples every workflow to every capability and
  makes partial providers (an STM32 with UART but no Wi-Fi) impossible to
  express.

## Decision

1. **Small composable traits**, one per capability family, in `conwrt-core`
   (later split to `conwrt-cap` if the set grows): `LinkProbe`, `SerialIo`,
   `SocketIo`, `InterfaceConfig`, `PowerControl`, `Gpio`, `BlockStorage`,
   `Time`, `SecretStore`. Workflows take generics bounded by exactly the
   traits they need (`fn diagnose<P: LinkProbe + Time>(...)`).
2. **Reuse ecosystem shapes where they exist**: byte-stream capabilities are
  expressed as `embedded_io_async::{Read, Write}` plus thin conwrt extension
  traits (open/close/flush semantics); GPIO/delay reuse `embedded_hal`
  signatures where MCU providers will implement them.
3. **Define our own `InterfaceConfig`** (set ip/dhcp/up/down, list links) —
  no standard exists; document that embassy-net/std implement it per platform.
4. **Provider granularity is per-capability**, not per-platform: a provider
  type implements one or more traits; apps compose. The remote-agent client
   implements traits by RPC; a mock implements them from a script.
5. **Error model**: each trait has an associated `Error` type with
   `From`-bounds into `conwrt_core::Error` so workflows compose errors without
   losing provider detail.
6. **Object safety is deferred**: M1–M2 use static dispatch (generics).
   When the remote provider needs dynamic dispatch (M3), introduce an
   `Arc<dyn>`-style erasure *in the provider layer only* — Tier-A traits stay
   AFIT/generic.

## Consequences

- Workflows compile only against what they use — partial devices (and tests)
  provide partial capability sets.
- Same-workflow/any-provider becomes mechanically verifiable (mock vs local
  vs remote in CI).
- Trait evolution until M3 is expected; the M1 slice deliberately ships the
  minimal set (`LinkProbe`, `Time`, mock) rather than the full family.

## Alternatives considered

- **Monolithic `Platform` trait**: rejected — partial providers impossible,
  mock fidelity terrible, agent capability advertisement becomes all-or-
  nothing.
- **Adopt `embedded-nal-async` wholesale for sockets**: partially adopted —
  our `SocketIo` mirrors its shape but adds provider-level error context;
  full adoption can be revisited when the local-std provider lands (M2).
