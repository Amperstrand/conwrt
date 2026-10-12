# ADR 0004: Conwrt agent protocol — postcard + COBS, leased resources

Status: accepted (protocol details provisional until M3 prototype)
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

## Alternatives considered

- **minicbor** (explicit field indexes, BlueOak license): strong runner-up;
  revisit only if postcard evolution turns painful.
- **JSON lines**: rejected — 3–6× larger, no `no_std` parse of note, framing
  ambiguity around embedded newlines in binary-adjacent data.
- **gRPC/prost**: rejected — codegen weight, poor `no_std` client story.
