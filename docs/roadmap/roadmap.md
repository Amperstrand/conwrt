# Conwrt 2.0 Roadmap

Status: proposed (M0) · Parent tracking issue: see GitHub backlog
Depends on: [architecture overview](../architecture/conwrt-2.0-overview.md),
[ADRs](../adr/). Milestones are dependency-ordered; each names its exit
criterion. Adjust after every milestone retro.

```
M0 design ──► M1 foundation ──► M2 native CLI ──► M3 agent ──► M4 openwrt agent
                    │                                          └──────────► M5 mcu agents ──► M6 standalone mcu
                    └────────────────► M7 profiles + UI ◄────────────────────────────┘
                                              └► M8 labgrid/HIL ──► M9 legacy retirement
```

## M9 — Legacy Python retirement: parity matrix live

The component-by-component parity matrix (Python component × Rust
coverage × evidence link) is maintained at [parity-matrix.md](parity-matrix.md)
(issue #117). A Python twin retires ONLY when its Rust replacement's
parity tests are green and the removal PR cites its matrix row.
Sanctioned permanent Python (bench/labgrid/packaging glue) is listed
there too.

## M0 — Architecture and research 📦 (draft PR #119)

Audit of 1.x (engine map, model schema reality, safety mechanisms, test
inventory); library dossier (postcard/COBS, russh/sunset, embassy/esp-hal 1.x,
embassy-net/smoltcp, rustls/embedded-tls, xmodem/tftp gaps, OpenWrt SDK
cross-compilation); TollGate integration research (license blockage, rpcd
contract, pattern catalogue). ADRs 0000–0011. Backlog created.

**Exit:** documented design + actionable issues + first slice selected. ✔

## M1 — Portable Rust foundation 📦 (draft PR #119)

- Cargo workspace (`crates/`, `apps/`) beside Python; no 1.x disruption.
- `conwrt-types`: DeviceModel parsing + validation of the real `models/*.json`
  corpus (schema-parity with `schemas/model.schema.json`); MAC/OUI types.
- `conwrt-core`: capability traits (`LinkProbe`, `Time`), boot-state
  classifier (pure function + evidence struct), MAC→model identification,
  mock provider.
- `apps/conwrt-cli`: `models validate`, `identify --mac`, `probe --scenario`
  (read-only, mock transport).
- CI: fmt/clippy/test + `thumbv7em-none-eabihf` no_std gate + real-models
  validation test.

**Exit:** `cargo test` green incl. all 24 models validating; `make ci`
(Python) unaffected; CLI demonstrates a real read-only diagnostic workflow
against mock capabilities. Rust workflow runs in GitHub CI.

## M2 — Native CLI and workflow parity 📦 (draft PRs #122/#123; SerialIo + serial-flash driver and XMODEM receiver matrix #124 remain)

- `providers/conwrt-local-std`: tokio/serialport/std::net implementations of
  the M1 trait set (real ARP/ping/HTTP/SSH-banner probing, read-only).
- Port boot-state detection with golden tests cross-checked against
  `scripts/router-probe.py` behavior (QEMU ring for Dropbear reality).
- russh-based SSH provider + scp-over-exec (ADR-0005); host-key trust ladder.
- `conwrt diagnose --ip …` — first real hardware-safe read-only operation.
- XMODEM implementation in `conwrt-protocols` (fills the README-promised,
  never-implemented method) with loopback tests.

**Exit:** one real, useful, read-only conwrt operation works through Rust on
Linux against a live OpenWrt target (QEMU-verified, bench-verified when
authorized), with mock/local parity tests green.

## M3 — Remote conwrt agent

- `conwrt-agent-proto` v0: postcard+COBS, version handshake, capability
  advertisement, leases (ADR-0004); postcard-rpc prototype with named
  kill-criteria.
- `conwrt-agent` exporting serial + socket capabilities from Linux;
  controller-side remote provider consuming them.
- Disconnect semantics: `complete`-class operations survive controller loss.
- Stream transfer of a firmware-sized payload with resume.

**Exit:** the M2 diagnostic workflow runs unchanged (same binary code path)
against remote providers — the architectural acceptance test is green in CI.

## M4 — Router-to-router execution

- Cross-compile for OpenWrt targets (aarch64/mips musl; SDK-first builds —
  ADR-0011 matrix); package as ipk.
- OpenWrt host runs agent (and read-only controller workflows); reuse of
  common discovery/diagnosis.
- Constrained-memory validation (RAM/flash budget documented).

**Exit:** an OpenWrt device safely diagnoses another router using the shared
engine (QEMU-to-QEMU first, then authorized bench).

## M5 — Embedded agents

- STM32F7: embassy-stm32 + embassy-net; USB-CDC agent exposing UART + raw
  Ethernet (frame-level, ADR-0004 level 3).
- ESP32-S3: esp-hal 1.x + esp-radio (beta-status risk tracked); USB-CDC
  agent first, Wi-Fi later.
- Embedded feature profiles + `cargo size` gates in CI.

**Exit:** a laptop uses a microcontroller's UART/Ethernet through conwrt
(mock-first, then bench HIL with authorized devices).

## M6 — Standalone microcontroller execution

- Executor role on MCU: run a supported workflow locally (recovery flash
  from block storage / streamed image).
- Power-loss and link-loss behavior verified (agent lease `complete`
  semantics under interruption).

**Exit:** an MCU performs a supported router maintenance workflow without a
laptop (HIL evidence).

## M7 — Desired-state profiles and UI

- `conwrt-profiles`: schema v1, planner, typed ops IR (port of
  `profile/ops.py` semantics), dry-run purity gate, drift verification.
- Port 1.x use-case presets incrementally (test-status fields preserved).
- TollGate profile via rpcd contract (ADR-0007) + feed pin automation.
- `conwrt-web`: axum + rust-embed wizard over the same engine; WS progress;
  plan-preview parity acceptance test.

**Exit:** the same target configuration is deployable through both CLI and
graphical workflow with identical plans; at least five representative
profiles (stock-OpenWrt, TollGate, VPN gateway, travel router, guest AP).

## M8 — Labgrid and advanced automation

- Labgrid provider (consume places: console/power/network) + conwct as a
  labgrid tool (ADR-0010); QEMU VMs enrolled as places (#76).
- Richer diagnostics (pcap-driven boot-signature matching port), repeatable
  automated maintenance with explicit safety policies.

**Exit:** a scheduled lab job flashes + verifies a device end-to-end through
labgrid-managed resources using conwrt.

## M9 — Legacy deprecation

- Complete migration of supported behavior to Rust; parity matrix fully
  green per component; Python/shell runtime dependencies retired except
  sanctioned adapters (labgrid bridge, packaging glue).
- Distribution/packaging updated (static binaries + OpenWrt ipk + MCU
  images); compatibility shims versioned and documented.

**Exit:** supported conwrt flows no longer require Python; legacy code
removed with parity evidence linked in the removal PRs.

---

## Explicitly deferred / tracked separately

- Windows host support (revisit at M2+; std providers keep it cheap later).
- Transparent Ethernet tunneling (ADR-0004 level 4).
- Native desktop GUI.
- sunset-based SSH from MCUs (adopt when a milestone needs it).
