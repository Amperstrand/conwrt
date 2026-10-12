# ADR 0010: Labgrid integration boundary

Status: accepted
Milestone: M8

## Context

Labgrid manages serial ports, power switches, network interfaces, and places
(exclusive acquisition). conwrt must work in labgrid labs without duplicating
labgrid's resource management. Today the relationship is process-level only
(AGENTS.md: `labgrid-client -p <place> ssh|console|power`; coordinator at
`ai-legion:20408`; registry in the private conwrt-lab repo). Issue #76
(enroll QEMU VM as labgrid place) and #9 (switch-initiated flash with PoE)
are the live threads.

## Decision

1. **Both directions, explicitly scoped:**
   - *Conwrt consumes labgrid*: a `labgrid` provider crate implements conwrt
     capability traits (`SerialIo`, `PowerControl`, `LinkProbe`) by driving
     `labgrid-client` (or the labgrid Python API behind a thin subprocess/
     service adapter — Python adapter is explicitly sanctioned here, per
     ADR-0001 §6).
   - *Labgrid calls conwrt*: conwrt CLI is usable as a labgrid "tool" —
     read-only `conwrt diagnose --json` and gated mutating commands, with
     place acquisition/release left to labgrid's own machinery.
2. **Never duplicate**: no place database, no coordinator, no resource
   reservation logic in conwrt. The agent protocol's leases govern
   *conwrt-to-conwrt* resource lending only; when labgrid is present, it
   owns acquisition and conwrt leases nest inside a labgrid reservation.
3. **QEMU VMs enroll as labgrid places** (issue #76) so the parity suite
   can run under the same HIL tooling as physical bays.
4. **Hardware-in-the-loop gating**: destructive CI against labgrid places
   runs only in explicitly authorized environments (the tollgate backend's
   model: PR = QEMU ring only; physical ring behind required-reviewer
   GitHub environments).

## Consequences

- Lab users keep their toolchain; conwrt gains HIL resources cheaply.
- The Python adapter remains a permanent bridge (acceptable per ADR-0001).

## Alternatives considered

- **Reimplement a mini-labgrid in the agent protocol**: rejected —
  out-of-scope duplication, explicitly forbidden by the mission.
- **Labgrid-only testing (no direct hardware access)**: rejected — field
  use (laptop + router) is the primary product surface.
