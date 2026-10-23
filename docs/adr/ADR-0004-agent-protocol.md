# ADR 0004: Conwrt agent protocol — postcard + COBS, leased resources

Status: accepted (spike verdict 2026-10-12; M3 production validation recorded 2026-10-23 — see both sections)
Milestone: M3 (prototype), M5 (MCU agents)

## Context

Any platform may expose capabilities to another conwrt instance (Controller /
Executor / ResourceProvider roles). The protocol must work over USB CDC
(byte stream, noisy), TCP (framed), and ideally ride an SSH channel; it must
be `no_std`-friendly and support large payloads (firmware ≈ 5–50 MB), streams,
cancellation, and link loss mid-operation (an upgrade must not be "failed"
merely because the controller disconnected).

Research findings (2026-10-12):
- **postcard 1.1** (MIT/Apache) is the de-facto compact serde format for
  embedded; `postcard-schema` provides wire-level schema fingerprints.
- **COBS framing** (`cobs` 0.5) self-synchronizes after garbage — exactly the
  post-reboot serial reality; overhead ≤ ~0.4%. Length-prefix framing never
  resynchronizes.
- **postcard-rpc 0.12** (James Munns) provides key-dispatch RPC with
  `WireTx/WireRx` traits and host clients for serial/USB — but ships **no TCP
  wire**, no built-in stream multiplexing, and is 0.x-churny.

## Decision

1. **Wire format: postcard.** Every message starts with a versioned header
   (`proto_version: u16`, `schema_fingerprint: u64` from postcard-schema).
   Mismatch ⇒ structured refusal, never interpretation.
2. **Framing: COBS** on byte-stream transports (USB CDC, serial, and TCP
   alike) — one codec everywhere, resynchronization after boot garbage.
3. **Start from postcard-rpc 0.12 prototype** (M3) for dispatch/host tooling;
   **kill-criteria**: if firmware streaming over TCP needs >300 LOC of
   wrapper for backpressure/resume, or version negotiation fights the
   framework, we fork to a custom ~1-week header/dispatch layer over the same
   postcard+COBS primitives (keeping the schema-fingerprint discipline).
4. **Session handshake**: version + role + capability advertisement +
   authentication (see §8) before any resource access.
5. **Resource leases**: exclusive or shared leases per resource (a UART, an
   Ethernet interface, a power channel) with explicit acquire/release,
   heartbeat-based expiry, and controller-disconnect policy declared per
   operation: `abort` (default for probes) vs `complete` (for flashing —
   the agent finishes a validated in-flight write and parks results for
   reconnection).
6. **Streams as first-class**: firmware push is a leased stream with
   chunk acks and resume tokens, not an RPC with a giant buffer.
7. **Remote Ethernet has four explicit levels** — providers declare which
   they implement:
   1. socket proxy (TCP/UDP open/read/write/close),
   2. delegated services (agent-local TFTP/HTTP servers driven by RPC),
   3. raw frame access (send/receive Ethernet frames incl. ARP/broadcast —
      needed for U-Boot recovery where the target has no IP stack),
   4. optional transparent interface tunneling (later; only if 1–3 prove
      insufficient).
   A controller must not assume level 1 implies level 3.
8. **Security (progressively)**: v0 over USB CDC = trust the physical link;
   network transports require pairing (first-use key exchange) + session
   encryption (rustls on std, embedded-tls on MCU) + per-lease permission
   scopes (read-only diagnostics default; destructive ops need an explicit
   grant). Secrets never transit in the clear; redaction applied in logs.
9. **Time-critical loops execute at the agent.** The controller sends intent
   ("TFTP-serve this verified image to 192.168.0.1, report milestones");
   the agent runs the millisecond-level protocol. This mirrors 1.x lessons
   (Z-Loader's ~7 s window) and keeps the protocol coarse-grained.

## Consequences

- One codec + one format everywhere; MCU agents parse the same messages the
  desktop does.
- postcard is not self-describing: additive-only evolution + catch-all enum
  arms + schema fingerprint gates are mandatory review points.
- The postcard-rpc-vs-custom decision is deliberately deferred behind the M3
  prototype with named kill-criteria. **Resolved 2026-10-12: ADOPTED** (see
  the spike verdict below).

## Spike verdict (2026-10-12) — postcard-rpc ADOPTED

The #107 prototype (branch `spike/conwrt-2.0-postcard-rpc`, commits
1886f10 + 7398909) answered every kill-criterion in the framework's favor:

| Criterion | Threshold | Measured |
|---|---|---|
| Custom wire wrapper LOC | < 300 | **232** (TCP + COBS, host + device sides) |
| Streaming/backpressure/resume LOC | ≤ 300 | **144** (a `/status` endpoint + idempotent contiguous-append chunks) |
| Behavior | must survive controller loss | 5 MiB push killed at 40%, reconnected, resumed from the device-reported offset, assembled sha256 verified |
| Cost | sanity | 46 µs/rtt echo; ~21 MiB/s lock-step push; 51.6 MiB/s effective on resume |

Decision: build `conwrt-agent-proto` (M3) on postcard-rpc 0.12 with a thin
shared COBS pump and two wires (TCP, USB-CDC). The device
one-connection-per-`run()` model maps directly onto the lease/reconnect
semantics of §5. Full API findings and measurements: issue #107.

## M3 production validation (2026-10-23)

The provisional clause is retired: `conwrt-agent-proto` has carried the
M3 design in production-shaped code since the spike, and the milestone's
exit criterion — *the M2 diagnostic workflow runs unchanged against
remote providers* — has standing test evidence.

What shipped on the adopted stack (postcard-rpc 0.12 + shared COBS pump):

- **Protocol v2 with real lease semantics**: `Granted` surfaces
  `lease_id` (#378); controller-loss policies (§5 `abort`/`complete`)
  live in `leases` with heartbeat expiry; CLI heartbeats + release-on-
  Ctrl-C on the controller side.
- **Resumable firmware-class streams** as designed (§6): windowed
  executor transfer separating offset from state (#226 slices), POST
  pump for executor pushes, transfer status that survives
  reconnection.
- **Safety posture of §8 v0**: loopback-only default listener, non-
  loopback requires explicit opt-in, capability details validated as
  the documented colon syntax (#335) — network pairing + session
  encryption remain future work (see Open questions).
- **The exit criterion, tested**: `tests/{e2e,integration,qemu_e2e,
  router_to_router,two_instance,hil_mock}.rs` — including QEMU VM
  round-trips, router-to-router runs, and the HIL lossy-resume replay
  under connection churn (#226 ring-2); plus the on-OpenWrt execution
  proof (static-pie deploy to a 25.12.5 VM, router-as-agent diagnosing
  another host — commit 28543b2).
- **Tier discipline holds** (ADR-0002): the crate builds `no_std` +
  `alloc` by default; MCU consumers (F746 slices) reuse
  `protocol`/`cobs`/`leases` verbatim.

## Open questions

- **§8 network security**: v0 trusts the physical link (USB CDC) or
  loopback only. Pairing + rustls/embedded-tls session encryption +
  per-lease permission scopes are designed but unbuilt — the trigger
  for building them is the first non-bench network deployment.
- **Remote Ethernet level 3** (raw frames for U-Boot-era targets): the
  four-level model (§7) stands; only levels 1–2 have implementations.
- **postcard-rpc 0.x churn**: additive-only message evolution +
  schema-fingerprint gates are the standing mitigation; the fork option
  (custom header/dispatch over the same postcard+COBS primitives)
  remains the named escape hatch if 0.x breaks us.
- **Protocol v2 → v3**: no concrete driver yet; the versioned-header
  mismatch ⇒ structured refusal rule (§1) is the gate that makes a
  future bump cheap.

## Alternatives considered

- **minicbor** (explicit field indexes, BlueOak license): strong runner-up;
  revisit only if postcard evolution turns painful.
- **JSON lines**: rejected — 3–6× larger, no `no_std` parse of note, framing
  ambiguity around embedded newlines in binary-adjacent data.
- **gRPC/prost**: rejected — codegen weight, poor `no_std` client story.
