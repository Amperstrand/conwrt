# ADR 0008: CLI, API, and UI layering — one engine, thin frontends

Status: accepted
Milestone: M2 (CLI read-only), M7 (web wizard)

## Context

The product needs a friendly graphical wizard (generalized tollgate-
installer UX) *and* a CLI *and* a programmatic surface. 1.x already
demonstrates the cost of frontend duplication risk (wizard-bundle.json is
generated from the same source as the CLI specifically to avoid drift).

## Decision

1. **One engine, three thin shells**: `conwrt-cli` (clap), `conwrt-web`
   (axum localhost server + rust-embed single-page UI + WebSocket events),
   and the library API itself (`conwrt-core` consumed as a crate). Frontends
   contain presentation only — zero workflow logic.
2. **Plan/apply/verify are the only mutating entry points**; every frontend
   calls the identical engine functions. Acceptance test: a profile produces
   a byte-identical plan via CLI and via web API (CI-enforced).
3. **Event stream is structured** (engine emits typed progress/failure
   events; CLI renders lines, web forwards over WS, agent forwards over the
   wire protocol — same serialization discipline as ADR-0004).
4. **Local web UI binds loopback by default** (CORS loopback-only, never
   wildcard — tollgate-installer's hardening pattern); remote UI is a
   deliberate flag with authentication.
5. **Single-binary distribution preserved**: `conwrt-web` embeds its assets
   (rust-embed); `conwrt-cli` remains one static binary per platform.
6. Native GUI/desktop wrappers are a later non-goal until the web UX proves
   insufficient.

## Alternatives considered

- **TUI-first only**: kept as a 1.x artifact (`conwrt_tui.py` stays until
  M9); the 2.0 surface is CLI + web.
- **Electron/Qt native app**: rejected — distribution weight, no added
  capability over localhost web.
