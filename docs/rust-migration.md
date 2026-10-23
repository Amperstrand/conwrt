# Rust Migration Ledger (conwrt 2.0)

Single source of truth for Python → Rust migration status. A Python command
enters **soft deprecation** (pointer notice + configurable delay via
`CONWRT_RUST_MIGRATION_DELAY`, default 15 s) only when its Rust replacement
has reached feature parity for that capability. It moves to **retired**
(deleted) only after the Rust path is verified in real use.

| Python surface | Rust replacement | Parity | Stage |
|---|---|---|---|
| `conwrt list` (model listing) | `conwrt models` | ✅ **byte parity** on the real 24-model corpus — one golden pins both sides (`tests/test_parity_rust_models.py`); Python output aligned to the Rust shape (sorted flash methods + `N model(s) valid` footer) | **deprecated** (2026-10-23, §7 item 1; removal rides the flash-engine retirement — `conwrt-openwrt-install.sh` calls it on-router) |
| `router-probe.py` (boot-state probe) | `conwrt diagnose --ip <addr>` | ✅ same evidence model, stricter classification (`ssh-only` vs speculative `openwrt`) | **soft-deprecated** (2026-10-12) |
| `make validate-models` (CI) | `conwrt models` / `make rust-ci` | ✅ equivalent validation | not gated (CI infra, no user friction) |
| `router-fingerprint.py` | `conwrt fingerprint` | ✅ core parity (authenticated release/board/hostname; specimen & port inventory remain 1.x-only) | **merged #130** (2026-10-13) |
| `conwrt.py flash` (sysupgrade) | sysupgrade example → CLI | ❌ Rust lifecycle proven (ring-2/ring-3) but not CLI-complete | — |
| `firmware-manager.py` (ASU) | `conwrt-image` | ✅ library parity: request/poll (202/queued+backoff)/sha256-verified download, byte-parity cache key (Python-oracle goldens), list/show/find/clean, Python-written-metadata interop goldens. 92 mocked-HTTP tests total | **merged #132/#135/#136** (2026-10-13); CLI + model→target resolution pending |
| `conwrt image` (vanilla sourcing) | `conwrt-image::downloads` | ✅ release/suffix precedence, sha256sums-index verify, flat `images/` cache; filename golden vs real `image_filename()` output | **merged #135** (2026-10-13); CLI pending |
| `firmware.py` image selection | `conwrt-image::select` | ✅ flash-method type preferences, fallback scan, initramfs companion (Python's dead `initramfs` preference documented as deviation) | **merged #136** (2026-10-13); caller of the flash flow pending |
| `conwrt.py configure` / use cases | planner + executor (`conwrt plan` / `conwrt apply`) | 🚧 sqm + doh profiles: plan → shell-render → SSH apply → verification loop, QEMU-verified | **merged #133→#137, #134** (2026-10-13); more profiles pending; unverified on hardware |
| serial-\* tools | XMODEM core done; driver pending | ❌ | — |
| agent protocol (2.0) | postcard-RPC spike | 🧪 TCP viability proven (46 µs/rtt) + firmware streaming w/ backpressure+resume verified | **merged #139** (spike evidence, `spikes/postcard-rpc/`); real crate is an ADR-0004 decision |

## Rules

1. Soft deprecation is added **only at parity**, per capability — never
   speculatively.
2. The notice always prints; only the delay is configurable
   (`CONWRT_RUST_MIGRATION_DELAY=<seconds>`, `0` disables the wait).
3. Tests and CI pin the delay to `0` (`tests/conftest.py`, workflow env).
4. Retirement (removal) requires production verification of the Rust path
   and an explicit decision — soft deprecation never auto-escalates.
