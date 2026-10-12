# Rust Migration Ledger (conwrt 2.0)

Single source of truth for Python → Rust migration status. A Python command
enters **soft deprecation** (pointer notice + configurable delay via
`CONWRT_RUST_MIGRATION_DELAY`, default 15 s) only when its Rust replacement
has reached feature parity for that capability. It moves to **retired**
(deleted) only after the Rust path is verified in real use.

| Python surface | Rust replacement | Parity | Stage |
|---|---|---|---|
| `conwrt list` (model listing) | `conwrt models` | ✅ validated on the same 24-model corpus (both validators green) | **soft-deprecated** (2026-10-12) |
| `router-probe.py` (boot-state probe) | `conwrt diagnose --ip <addr>` | ✅ same evidence model, stricter classification (`ssh-only` vs speculative `openwrt`) | **soft-deprecated** (2026-10-12) |
| `make validate-models` (CI) | `conwrt models` / `make rust-ci` | ✅ equivalent validation | not gated (CI infra, no user friction) |
| `router-fingerprint.py` | `conwrt fingerprint` | ✅ core parity (authenticated release/board/hostname; specimen & port inventory remain 1.x-only) | pending merge #130 |
| `conwrt.py flash` (sysupgrade) | sysupgrade example → CLI | ❌ Rust lifecycle proven (ring-2/ring-3) but not CLI-complete | — |
| `firmware-manager.py` (ASU) | `conwrt-image` | 🚧 library crate done w/ 56 mocked-HTTP tests (#132: request/poll/sha256-verified download, Python-parity cache layout, list/clean); CLI + model→target resolution pending | — |
| `conwrt.py configure` / use cases | planner + executor (`conwrt plan` / `conwrt apply`) | 🚧 sqm: plan + shell-render + SSH apply + verification done (#133); more profiles pending; unverified on hardware | — |
| serial-\* tools | XMODEM core done; driver pending | ❌ | — |

## Rules

1. Soft deprecation is added **only at parity**, per capability — never
   speculatively.
2. The notice always prints; only the delay is configurable
   (`CONWRT_RUST_MIGRATION_DELAY=<seconds>`, `0` disables the wait).
3. Tests and CI pin the delay to `0` (`tests/conftest.py`, workflow env).
4. Retirement (removal) requires production verification of the Rust path
   and an explicit decision — soft deprecation never auto-escalates.
