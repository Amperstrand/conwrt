# Conwrt 2.0 Architecture Overview

Status: proposed (M0) — implementation started on `feat/conwrt-2.0-rust-foundation`
Companion documents: [ADRs](../adr/) · [Roadmap](../roadmap/roadmap.md) · [Audit of the current codebase](../architecture-analysis.md)

## 1. Vision

Conwrt 2.0 is a portable Rust framework for taking a supported router from its
**current state** to a **verified desired state** — regardless of whether that
requires configuration only, package installation, a sysupgrade, or full
recovery from a bootloader or serial console:

```
Discover → Diagnose → Plan → Prepare → Apply → Verify → Report
```

The same engine and the same device-model data must run:

- as a native CLI/GUI on Linux and macOS (and later Windows),
- on OpenWrt itself (router-to-router operations),
- on microcontrollers (ESP32-S3, STM32F746/F469) as standalone executors or
  resource providers,
- and against labgrid-managed hardware in a test lab.

The engine never trades away the safety rules in `AGENTS.md`: identify the exact
hardware and specimen before destructive operations, never force an incompatible
image, treat multicast flashing as multi-device, keep diagnostics read-only by
default.

## 2. Layered architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Frontends (thin, no business logic)                                     │
│  conwrt-cli (clap)   conwrt-web (axum + rust-embed SPA + WS events)      │
└──────────────┬─────────────────────────────────────────────┬─────────────┘
               │ calls                                       │ HTTP/WS
┌──────────────▼─────────────────────────────────────────────▼─────────────┐
│  conwrt-core — the engine (no_std + alloc)                                │
│  · device-state interpretation & model identification                     │
│  · workflow planning & explicit state machines (port of flash ctx/dispatch)│
│  · desired-state reconciliation: plan / dry-run / apply / verify / drift  │
│  · safety policy: identity gates, destructive-op authorization, dry-run   │
│  · progress & structured events, failure taxonomy                         │
└──────────────┬────────────────────────────────────────────────────────────┘
               │ depends only on
┌──────────────▼────────────────┐  ┌────────────────────────────────────────┐
│  conwrt-cap — capability      │  │  conwrt-protocols (no_std-friendly)    │
│  traits: SerialIo, SocketIo,  │  │  tftp, xmodem, zycast framing, ubus    │
│  LinkProbe, PowerControl,     │  │  rpc, u-boot http, HNAP(legacy),       │
│  Gpio, Storage, Time, ...     │  │  image verification (sha256/ed25519)   │
│  (embedded-io-async shaped)   │  │  — all generic over I/O traits         │
└──────────────┬────────────────┘  └────────────────┬───────────────────────┘
               │ implemented by                       │
┌──────────────▼──────────────────────────────────────▼──────────────────────┐
│  Providers                                                                 │
│  · local-std   (Linux/macOS: tokio, serialport, std::net, russh)          │
│  · openwrt     (musl build of local-std subset)                           │
│  · remote      (conwrt-agent client: capabilities served by another box)  │
│  · esp32       (esp-hal 1.x + embassy, esp-radio, embassy-usb CDC)        │
│  · stm32       (embassy-stm32 + embassy-net/smoltcp, USB CDC)             │
│  · labgrid     (adapter mapping labgrid places → conwrt capabilities)     │
│  · mock        (scripted, for tests and dry-runs)                         │
└────────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│  conwrt-agent-proto — wire protocol between instances                    │
│  postcard-encoded, COBS-framed, versioned; over USB CDC, TCP, (SSH)      │
│  Roles: Controller · Executor · ResourceProvider (one box may be all)    │
└──────────────────────────────────────────────────────────────────────────┘

  Data (kept strictly separate):
  models/*.json   species-level device definitions (git, shared with 1.x)
  profiles/*.toml desired-state definitions (git)
  specimens       unit-level inventory (private, per AGENTS.md)
  runs/           execution evidence, append-only (local)
```

## 3. Key architectural rules

1. **The engine depends on capability traits, never on platforms.**
   `conwrt-core` compiles for `thumbv7em-none-eabihf` (CI-enforced). Anything
   needing `std` lives in providers or apps.

2. **One workflow, any provider.** The diagnostic/flashing workflow is written
   once against traits; local std, remote-agent, MCU, and mock providers are
   interchangeable. This is an automated acceptance test, not an aspiration
   (see testing strategy).

3. **Protocols are generic over I/O.** TFTP/XMODEM/zycast/ubus live in
   `conwrt-protocols`, parameterized by `embedded-io-async`-style traits — the
   same code serves a tokio UDP socket (laptop), an embassy-net socket (STM32),
   and a remote-agent socket proxy.

4. **Agent protocol carries capabilities, not policy.** The protocol exposes
   resources (serial, ethernet, storage, power) with leases and permissions;
   it knows nothing about flashing routers. Planning stays in the controller.

5. **Desired-state profiles are declarative and composable.** Today's use-case
   presets (`scripts/use_cases/`) evolve into profile modules with typed
   parameters, capability requirements, conflict detection, plan/dry-run/apply/
   verify/drift semantics. The core decides whether a target needs config-only,
   packages, sysupgrade, or full recovery — the profile does not.

6. **Frontends share one engine.** CLI, HTTP API, and web UI are thin shells
   over the same plan/apply calls; the same profile produces an identical plan
   from CLI and UI (acceptance-tested).

7. **Safety mechanisms are engine-level, not UX-level.** Identity gates
   (model↔board.json↔board_name↔MAC/specimen), destructive-op authorization,
   dry-run purity (no hardware writes), and multicast containment live in
   `conwrt-core` so every frontend and every provider inherits them.

## 4. Execution roles

| Role | Responsibility | Example |
|---|---|---|
| Controller | decides what to do: planning, safety policy, UI | laptop CLI |
| Executor | runs a conwrt workflow | ESP32 performing recovery unattended |
| Resource provider | lends hardware capabilities | STM32 exposing UART+ETH over USB |

One device can hold all three roles (standalone STM32 flashing a router).
Remote Ethernet is exposed at four explicit levels — TCP/UDP socket proxying,
delegated services (agent-local TFTP/HTTP), raw frame access (ARP/broadcast),
and optional tunneling — because "forward a TCP connection" ≠ "lend an
interface" (ADR-0004).

## 5. Crate map (target state)

| Crate | Stability boundary | Notes |
|---|---|---|
| `conwrt-types` | **exists (M1 slice)** | domain types: DeviceModel (parses today's `models/*.json`), MAC/OUI, capability enums |
| `conwrt-core` | **exists (M1 slice)** | capability traits, boot-state classifier, identification, mock provider |
| `conwrt-protocols` | **exists (M2 slice)** | tftp, **xmodem — via the maintained `xmodem` crate**, zycast, ubus, verification |
| `conwrt-profiles` | M7 | desired-state schema, planner, module registry |
| `conwrt-agent-proto` | M3 | wire format, framing, versioning |
| `conwrt-agent` | M3+ | provider-side implementation (export capabilities) |
| `providers/conwrt-local-std` | **exists (M2 slice)** | tokio/serialport/httparse/russh providers |
| `apps/conwrt-cli` | **exists (M1 slice)** | clap frontend |
| `apps/conwrt-web` | M7 | axum + embedded UI |
| `apps/conwrt-esp32`, `apps/conwrt-stm32` | M5/M6 | embassy apps |

Crates are created when they carry real code — no placeholder hierarchy
(ADR-0001). The Go zycast binary is wrapped/kept until a Rust port proves
parity (it is already zero-dependency and cross-compiles to OpenWrt targets).

## 6. Library selections (summary — full dossier in ADRs)

**Libraries-first policy**: maintained crates are adopted wherever they fit;
protocol or platform code is hand-rolled only when no crate covers the need,
and every such case is recorded with its justification in the owning
ADR/crate docs (e.g. subprocess `ping` for unprivileged ICMP; `/proc/net/arp`
parsing for the Linux neighbor table).

| Concern | std (desktop/OpenWrt) | no_std (MCU) |
|---|---|---|
| serialization | postcard 1.x (+postcard-schema) | same |
| framing | COBS (`cobs` crate) | same |
| SSH | russh 0.64 (+scp-over-exec) | sunset 0.6 (by the Dropbear author) |
| TLS | rustls | embedded-tls (embassy org) |
| HTTP | reqwest (rustls-tls) | reqwless |
| TCP/IP | std::net / tokio | embassy-net + smoltcp 0.14 |
| runtime | tokio | embassy-executor (esp-hal 1.x on S3) |
| hashing/signing | sha2, ed25519-dalek | same (verify-only) |
| UI | axum + rust-embed | picoserve (status page) |

Dropbear interop matrix (OpenWrt 24.10 = Dropbear 2024.86): negotiate
`curve25519-sha256` + `chacha20-poly1305@openssh.com`/`aes*-ctr` +
`ssh-ed25519`/`rsa-sha2-*`; never depend on ssh-rsa(SHA-1) (disabled in
Dropbear defaults). File transfer: scp-over-exec (Dropbear ships `/usr/bin/scp`,
no sftp-server); SFTP only where `openssh-sftp-server` is installed (ADR-0005).

## 7. What is reused, wrapped, or retired from 1.x

| 1.x component | Disposition |
|---|---|
| `models/*.json` + `schemas/` | **reuse as-is** (Rust parses them today); tighten schema incrementally (versioned) |
| use-case registry + typed ops pipeline (`profile/ops.py`) | **port the design** into `conwrt-profiles` (M7) |
| flash state machine (`flash/context.py`, `flash_dispatcher.py`) | **port** State/Event discipline into explicit Rust enums; drop the mutable god-object |
| discovery (OUI, ARP, LLDP, boot-state probes) | **port** into core + local-std provider (M2) |
| Go zycast (`cmd/zycast`) | **wrap now, port later** — zero-dep, already cross-compiles |
| serial tooling (base64 flash, boot capture, configure) | **port** onto SerialIo capability |
| QEMU integration suite | **keep** as parity oracle for Rust behaviors |
| dlink-hnap | **retire** (validation blocks OpenWrt images; documented non-functional) |
| `serial-xmodem` (README-promised, never implemented) | **implement fresh** in `conwrt-protocols` |
| 3 duplicated SSH transports (Python) | **collapse** into one russh-based provider |
| tollgate-installer UX patterns | **reimplement patterns** (trust ladder, one-shot credentials, job model) — no code (license, ADR-0007) |

## 8. Testing strategy (summary — ADR-0011)

Three rings: (1) offline units + mock-provider workflow tests (every PR);
(2) QEMU OpenWrt VM suite — reused from 1.x as the parity oracle (local/CI with
KVM); (3) hardware-in-the-loop behind explicit authorization (labgrid, bench
bays, private registry). Two architectural acceptance tests run in ring 1:

- the same workflow runs unchanged against local-mock and remote-mock providers;
- the same profile yields identical plans from CLI and web frontends.

## 9. Explicit non-goals

- A generic distributed-computing framework — the agent protocol exists only
  to serve conwrt's concrete capabilities.
- TollGate business logic in conwrt (payments/identity stay in the TollGate
  backend; conwrt orchestrates via its rpcd contract — ADR-0007).
- Bypassing compatibility/identity checks for "any state → any state": the
  engine's job is to prove a transition safe or refuse it.
