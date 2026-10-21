# M9 Parity Matrix — Python component × Rust coverage × evidence

**Issue:** #117 (parent #100) · **Policy:** ADR-0001 — a Python twin is
retired ONLY when its Rust replacement's parity tests are green against
the QEMU suite (the behavioral oracle); every removal PR cites its row
here. Sanctioned permanent Python is listed at the bottom.

Status legend: **none** (no Rust counterpart) · **partial** (Rust slice
exists, gap documented) · **parity-tested** (green evidence linked;
retirement candidate once the flow below is Python-free end-to-end) ·
**superseded** (Rust replaced it; Python removable now, removal PR
pending) · **permanent** (sanctioned).

Inventory date: 2026-10-16. Rust = `crates/` + `apps/`; Python engine =
`scripts/conwrt/` (8.2k LOC, 12 cmd modules) + `scripts/flash/` +
`scripts/profile/` + ~30 use-case plugins + tooling.

## 1. Model & schema layer

| Python component | LOC | Rust coverage | Evidence | Retirement |
|---|---|---|---|---|
| `scripts/model_loader.py` | ~200 | **parity-tested** — `conwrt-types` parses the same 24-model corpus, lossless via flatten-`extras` | `crates/conwrt-types/tests/real_corpus.rs` (validate + byte-faithful roundtrip); `make parity-check` in CI (#210) | Superseded for read paths once `conwrt-cli` consumers exist; retire with the CLI slice that reads models from Rust |
| `scripts/validate_models.py` | 56 | **parity-tested** — dual-typed sections enforced identically (baud range, warnings shape); drift = CI failure | `tests/test_model_schema_parity.py` + negatives in `tests/fixtures/schema-negative/`; Rust CI step `Model-schema parity` (#210) | Same — keep ONE validator authoritative (the schema); the other becomes a parity fixture |
| `scripts/inventory.py` | ~150 | none (specimen-level; local-only) | — | None — M-late; needs registry design (ADR-0009) |

## 2. Detection & identification

| Python component | LOC | Rust coverage | Evidence | Retirement |
|---|---|---|---|---|
| `scripts/router-probe.py` (boot-state detect) | ~300 | **parity-tested** — `conwrt-core` classifier (evidence-based, pure) + `conwrt-local-std::LinkProbe` | `crates/conwrt-core` state tests; CLI `conwrt diagnose` on real provider | Partial — pcap-side boot signatures still Python (`flash/serial_monitor.py` sibling logic); retire probe when pcap classifier lands in Rust |
| `scripts/router-fingerprint.py` | ~250 | **parity-tested** — `conwrt-local-std::ssh::fingerprint` (authenticated `/etc/openwrt_release` evidence, trust-gated) | `providers/conwrt-local-std/tests/fingerprint.rs` (ring 1, live russh fixture); CLI `conwrt fingerprint` | Superseded for OpenWrt targets; stock-vendor fingerprint paths remain Python |
| `scripts/conwrt/device_detect.py`, `device_profile.py`, `auto_detect.py` | ~800 | partial — MAC/OUI identification (`conwrt-core::identify`) + `conwrt probe`/`identify` CLI | `identify.rs` unit tests over real corpus | Partial — profile/registry heuristics (HNAP, OEM pages) not ported |
| `scripts/conwrt/hnap.py`, `oem_handlers.py` | ~700 | none | — | None — OEM-specific; port per-model on demand |

## 3. Flash engine (the safety-critical core)

| Python component | LOC | Rust coverage | Evidence | Retirement |
|---|---|---|---|---|
| `scripts/conwrt/context.py`, `detect.py`, `preflight.py`, `port_isolator.py` (event state machine) | ~2500 | partial — `conwrt-core` diagnose workflow (mock-proven); no pcap event loop in Rust | `crates/conwrt-core/tests/diagnose_workflow.rs` | None for the pcap-driven engine — M7/M8; the AGENTS-embedded hardware lessons (sysupgrade 246, UART break, Z-Loader timing) must carry over test-first |
| `scripts/conwrt/serial_monitor.py` | ~300 | partial — milestone parsing concepts in `conwrt-core`; live serial read loop remains Python | `tests/test_flash_serial_monitor.py` (29 tests, the #202 fix) | None — serial stack Rust port is M5+ (embedded-io) |
| `scripts/flash/` (upload, recovery flows) | ~1800 | none (XMODEM transport only, see §5) | — | None |
| `scripts/firmware-manager.py` (ASU) | ~900 | **partial → parity-tested** — `conwrt-image`: submit/poll/download/sha-verify/cache + **`conwrt image` CLI with `--packages`/`--defaults`** (model-resolved, cache short-circuit; #214-era slice) | `crates/conwrt-image` httpmock tests + `apps/conwrt-cli/tests/cli_image.rs` (binary e2e: submit→poll→download→verify→cache→short-circuit) | Partial — remaining gap is the config.toml use-case profile (plan→packages/defaults pipeline, M7); vanilla `image` sourcing stays Python until its own slice |
| `scripts/maas_flash.py`, `maas_wol_webhook.py`, MAAS tooling | ~900 | **parity-tested** — `conwrt-maas` (flash pipeline, provider, HTTP client) + CLI `conwrt maas` | #200/#201; wiremock/httpmock suites; `docs/maas-*` | Superseded for the flows `conwrt maas` covers (image status tool #205 is Python by design — evidence reading, keep until MAAS API settles) |

## 4. Configure / profiles / use cases

| Python component | LOC | Rust coverage | Evidence | Retirement |
|---|---|---|---|---|
| `scripts/profile/ops.py` + `apply.py` (typed ops pipeline) | ~900 | **partial — parity-tested for the apply path**: `conwrt-core::plan` (typed ops) + `conwrt-local-std::execute::apply_plan` over russh | `providers/conwrt-local-std/tests/qemu_apply.rs` (ring 2: real QEMU Dropbear VM, rendered script == Python-shaped uci) | Partial — 2 of 34 use cases typed (sqm, doh); each additional profile lands with its parity test |
| `scripts/profile/overlay.py`, `builder.py`, `wifi.py`, `uci_helpers.py` | ~1200 | partial — plan/render shell path only | `conwrt-core/src/plan.rs` | None — bake/overlay (ASU first-boot) pipeline is M7 |
| `scripts/use_cases/*` (30 plugins) | ~5000 | partial (sqm, doh only) | plan.rs unit tests mirror the 1.x validators | Per-plugin: port on demand with its parity test |
| `scripts/configure-stock-switch.py`, `cmd_lan_migrate.py` | ~400 | none | — | None — bench-adjacent one-offs |

## 5. Serial & protocols

| Python component | LOC | Rust coverage | Evidence | Retirement |
|---|---|---|---|---|
| XMODEM (none in Python — Python uses base64 serial) | — | **parity-tested** — `conwrt-protocols`: wire-exact frames + failure-mode pins + verified retry policy + `embedded-io-async` adaptation (SerialIo seam, chunked adapter, offloaded engine; host completion/cancellation/no-starvation proofs) | `crates/conwrt-protocols/tests/xmodem_fitness.rs` (14 tests, #212), `tests/serial_io_spike.rs` (4 tests, #124) | n/a — Rust-first capability; receiver matrix (`docs/xmodem-receiver-matrix.md`, #124) gates hardware use |
| `scripts/serial_transport.py`, `serial-console.py`, `serial-boot-capture.py`, `serial-flash.py` (base64), `serial-configure.py`, `serial-backup.py` | ~2200 | partial — `serial_transport.py` **parity-tested** in `conwrt-serial` (PR #412: script linter, RC-marker collector FSM, command-FIFO `run`/`send_script`, FT232R break-recovery driver over serialport-rs + `tcp://` bridge); `serial-boot-capture.py` **parity-tested** (`boot_capture`: two-phase break wait → `--recovery-wait` reopen → silence-terminated capture to `console.raw`/`console.log`, milestones via the SHARED `conwrt-probe-core` tracker — the ad-hoc `BOOT_MARKERS` table superseded, not forked; mid-capture break recovery is a documented delta); `serial-flash.py` (base64) **parity-tested** (`flash`: chunked `echo` staging + on-device decode + **on-device `sha256sum` verification — the #405 policy, receiver-side only, superseding the Python `--verify` size check**); async serial seam remains `conwrt-protocols::serial_io` (#124); still Python: `serial-console.py`, `serial-configure.py`, `serial-backup.py` | `crates/conwrt-serial` tests (38 unit + 11 mock + 8 pty + 5 tcp from PR #412; 6 `tests/boot_capture_pty.rs` + 5 `tests/flash_b64.rs` mock-BusyBox-shell pty suites for boot-capture/flash); Python oracles `tests/test_serial_transport.py` + `tests/test_serial_tcp.py` | `serial_transport.py`/`serial-boot-capture.py`/`serial-flash.py` superseded once a Rust consumer (CLI or flow) drives them; remaining siblings retire as they port onto `conwrt-serial::SerialConsole` |

## 6. SSH & trust

| Python component | LOC | Rust coverage | Evidence | Retirement |
|---|---|---|---|---|
| SSH transport in `conwrt.py`/`profile/apply.py` (paramiko/subprocess ssh) | ~600 | **parity-tested** — russh stack: host-key ladder + refusal taxonomy + persistent TOFU store + redacted creds (#207/#209) | `providers/conwrt-local-std/tests/ssh_fixture.rs` (12 tests incl. zero-auth-before-approval pins) + `qemu_dropbear.rs` (ring 2) | Superseded for the apply/fingerprint flows the Rust CLI covers; full retirement rides the CLI slice |

## 7. CLI surface

| Python component | LOC | Rust coverage | Evidence | Retirement |
|---|---|---|---|---|
| `scripts/conwrt.py` + `scripts/conwrt/cli.py` + 12 `cmd_*` | ~3000 | partial — `conwrt-cli`: models/identify/diagnose/probe/discover-v6/fingerprint/apply/plan/agent/maas | `apps/conwrt-cli/tests/cli_maas.rs`; ring-2 apply test | Per-command: retire a `cmd_*` when its Rust twin passes the same QEMU oracle; `make ci` shrinks accordingly |
| `scripts/conwrt_tui.py`, `conwrt-lite` | ~1500 | none | — | None — M7 UI |

## 8. Bench & lab tooling — sanctioned PERMANENT Python

Per #117: ecosystem-bound glue stays Python. `scripts/bench_*.py` (17
tools), `dut_recover.py`, `erx_dhcp_guard.py`, `lab_registry` consumers,
`conwrt_serial_bridge.py` (labgrid exporter), `er6p_redeploy.py`,
`gs1900-bench-arm.sh` — these speak labgrid/ubus/OpenWrt packaging and
are operator tooling, not product surface. Review annually, not per-M9.

## 9. Test tiers (the oracle — retires LAST)

| Tier | Role | Disposition |
|---|---|---|
| QEMU integration suite (`tests/integration/`) | Behavioral oracle for every parity claim | **Permanent through M9**; each Rust parity test that duplicates a suite case links it in its row above |
| Unit tier (Python, 4.6k) | Engine internals | Retires with its component |
| Venue/bench tiers | Hardware validation | Permanent (venues arc, #181-#192) |

## Retirement queue (order of attack)

1. **`validate_models.py` → parity fixture**: the schema stays
   authoritative; the Python runner becomes the parity harness itself
   (already is — `make parity-check`). No removal needed.
2. **`router-fingerprint.py`** — Rust twin ring-2 green; retire when
   `conwrt fingerprint` is the operator default (docs swap).
3. **`firmware-manager.py` download/verify/cache paths** — retire the
   `image`/`cache` Python commands when `conwrt image` reaches feature
   parity (request-with-packages is the remaining gap).
4. **`profile/apply.py` SSH path** — retire when `conwrt apply --execute`
   covers the ops set used by CI (sqm today).
5. Everything else: per-row gates above; nothing retires without a
   green Rust twin AND a removal PR citing this file's row.
