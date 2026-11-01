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
| `scripts/router-fingerprint.py` | ~250 | **parity-tested** — `conwrt-local-std::ssh::fingerprint` (authenticated `/etc/openwrt_release` evidence, trust-gated) | `providers/conwrt-local-std/tests/fingerprint.rs` (ring 1, live russh fixture); CLI `conwrt fingerprint`; ring-2 `qemu_dropbear.rs` | **Deprecated for OpenWrt targets (2026-10-22)**: docs swap done (README points at `conwrt fingerprint`), the script prints a deprecation notice on operator use; internal 1.x imports and stock-vendor paths remain until they port |
| `scripts/conwrt/device_detect.py`, `device_profile.py`, `auto_detect.py` | ~800 | partial — MAC/OUI identification (`conwrt-core::identify`) + `conwrt probe`/`identify` CLI | `identify.rs` unit tests over real corpus | Partial — profile/registry heuristics (HNAP, OEM pages) not ported. Classifier refinement LANDED (2026-10-22): `conwrt diagnose --key` composes the unauthenticated verdict with a key-authenticated board read — headless OpenWrt (no LuCI) now resolves `ssh-only` → `openwrt` (and vendor boxes → `stock-vendor`), live-proven on the x1860 |
| `scripts/conwrt/hnap.py`, `oem_handlers.py` | ~700 | none | — | None — OEM-specific; port per-model on demand |

## 3. Flash engine (the safety-critical core)

| Python component | LOC | Rust coverage | Evidence | Retirement |
|---|---|---|---|---|
| `scripts/flash/context.py`, `detect.py`, `preflight.py`, `port_isolator.py` (event state machine) | ~2500 | partial — `conwrt-core` diagnose workflow (mock-proven); no pcap event loop in Rust | `crates/conwrt-core/tests/diagnose_workflow.rs` | None for the pcap-driven engine — M7/M8; the AGENTS-embedded hardware lessons (sysupgrade 246, UART break, Z-Loader timing) must carry over test-first |
| `scripts/conwrt/flash_dispatcher.py` (live dispatch: `flash.{context,detect,preflight,port_isolator,device_profile,device_detect,upload}` + `conwrt/handlers_{uboot,oem,zycast,serial,edgeos}` + post-flash) | ~1500 | none — the live flash dispatcher is pure orchestration over the §3 engine modules; it ports with them (M7/M8) | — | None — tracks the engine rows above by construction (imports them directly); give it ring-1 tests when the engine port lands |
| `scripts/conwrt/serial_monitor.py` | ~300 | partial — milestone parsing concepts in `conwrt-core`; live serial read loop remains Python | `tests/test_flash_serial_monitor.py` (29 tests, the #202 fix) | None — serial stack Rust port is M5+ (embedded-io) |
| `scripts/flash/` (upload, recovery flows) | ~1800 | none (XMODEM transport only, see §5) | — | None |
| `scripts/firmware-manager.py` (ASU) | ~900 | **partial → parity-tested** — `conwrt-image`: submit/poll/download/sha-verify/cache + **`conwrt image` CLI with `--packages`/`--defaults`** (model-resolved, cache short-circuit; #214-era slice) | `crates/conwrt-image` httpmock tests + `apps/conwrt-cli/tests/cli_image.rs` (binary e2e: submit→poll→download→verify→cache→short-circuit) | Partial — `request`-with-packages is **real-ASU-proven** (2026-10-22: x1860 25.12.6 build w/ sqm + seat defaults, sha-verified, cache short-circuit, netmask guard `validate_defaults_script`); remaining gap is the config.toml use-case profile (plan→packages/defaults pipeline, M7); vanilla sourcing now Rust (⁠`conwrt source-image⁠`, live-parity-proven 2026-10-22: same URL, cache-hit on the 1.x-downloaded file, sha verified against the real index) — retirement queue #3 COMPLETE |
| `scripts/maas_flash.py`, `maas_wol_webhook.py`, MAAS tooling | ~900 | **parity-tested** — `conwrt-maas` (flash pipeline, provider, HTTP client) + CLI `conwrt maas` | #200/#201; wiremock/httpmock suites; `docs/maas-*` | Superseded for the flows `conwrt maas` covers (image status tool #205 is Python by design — evidence reading, keep until MAAS API settles) |

## 4. Configure / profiles / use cases

| Python component | LOC | Rust coverage | Evidence | Retirement |
|---|---|---|---|---|
| `scripts/profile/ops.py` + `apply.py` (typed ops pipeline) | ~900 | **partial — parity-tested for the apply path**: `conwrt-core::plan` (typed ops) + `conwrt-local-std::execute::apply_plan` over russh | `providers/conwrt-local-std/tests/qemu_apply.rs` (ring 2: real QEMU Dropbear VM, rendered script == Python-shaped uci) | Partial — 33 of 34 use cases typed (sqm, doh, tether ×4, wireguard-client, wireguard-server, guest-wifi, ssh-hardening, travelmate, adguard, mesh11sd, rescue-watchdog, mwan3, pbr, nodns, auto-sqm, openclash, ssl, vpn-pia-openvpn, vpn-pia, vpn-nordvpn, vpn-nordvpn-openvpn, mptcp-bonding, tollgate, tollgate-security, vpn-openvpn, vpn-surfshark, vpn-ivpn, vpn-mullvad, vpn-node, vpn-nordvpn-ikev2); each additional profile lands with its parity test |
| `scripts/profile/overlay.py`, `builder.py`, `wifi.py`, `uci_helpers.py` | ~1200 | partial — plan/render shell path only | `conwrt-core/src/plan.rs` | None — bake/overlay (ASU first-boot) pipeline is M7 |
| `scripts/use_cases/*` (30 plugins) | ~5000 | partial (sqm, doh, tether ×4, wireguard-client, wireguard-server, guest-wifi, ssh-hardening, travelmate, adguard, mesh11sd, rescue-watchdog, mwan3, pbr, nodns, auto-sqm, openclash, ssl, vpn-pia-openvpn, vpn-pia, vpn-nordvpn, vpn-nordvpn-openvpn, mptcp-bonding, tollgate, tollgate-security, vpn-openvpn, vpn-surfshark, vpn-ivpn, vpn-mullvad, vpn-node, vpn-nordvpn-ikev2) | plan.rs unit tests mirror the 1.x validators; `crates/conwrt-core/tests/use_case_goldens.rs` byte-compares rendered command lines against goldens generated from the actual 1.x builders (`tests/goldens/*.sh`, incl. wireguard-server + ssh-hardening + travelmate); ring-2 apply for wireguard-client (full plan, prebaked pkgs) + tether (shell surface; USB parts hardware-gated) + nodns (FULL plan — heredocs, dnsmasq addn-hosts, service enable) + openclash/pbr (config surface: strip+stub for non-prebaked pkgs) + ssl (cert-less negative fails verification by name; cert-present positive fully verifies) in `qemu_apply.rs` (#493/#500, VM-run via `tests/integration/test_rust_apply_ports4_vm.py`); travelmate additionally ring-3 **green end-to-end** (x1860-1 real hardware, clean-slate run: apply + uci verify + paired-`uplink` recognition + auto-join of a host-seeded network + `net ok` captive probe + verified teardown — `hw_travelmate.rs`, runnable unattended via env pins; preset still NOT deprecated: the ASU bake pipeline needs the Python plugin until M7) | Per-plugin: port on demand with its parity test |
| `scripts/configure-stock-switch.py`, `cmd_lan_migrate.py` | ~400 | none | — | None — bench-adjacent one-offs |

## 5. Serial & protocols

| Python component | LOC | Rust coverage | Evidence | Retirement |
|---|---|---|---|---|
| XMODEM (none in Python — Python uses base64 serial) | — | **parity-tested** — `conwrt-protocols`: wire-exact frames + failure-mode pins + verified retry policy + `embedded-io-async` adaptation (SerialIo seam, chunked adapter, offloaded engine; host completion/cancellation/no-starvation proofs) | `crates/conwrt-protocols/tests/xmodem_fitness.rs` (14 tests, #212), `tests/serial_io_spike.rs` (4 tests, #124) | n/a — Rust-first capability; receiver matrix (`docs/xmodem-receiver-matrix.md`, #124) gates hardware use |
| ZyXEL Multiboot zycast (1.x: Go `cmd/zycast` reference + `scripts/zycast.py` fallback) | — | **parity-tested** — Rust-first: `conwrt-protocols::zycast` no_std encoder (ADR-0002 core; M4/M5 reuse) + `conwrt-zycast` sender (SO_BINDTODEVICE) + the `conwrt zycast` CLI (specimen gate enforced); #447/#498 deconflicted 2026-10-24, #550 close-out | golden vectors vs the Go reference (`conwrt-zycast` tests, byte-equivalence across the relocated encoder); `scripts/zycast_netns_proof.sh --host` LIVE PASS (netns-isolated wire proof: framing, payload, ordering, bounded exit); mipsel lane: `scripts/zycast-mipsel-build.sh` | n/a — Rust-first; the Go binary stays the hardware-blessed sender until Rust gets its own hardware flash evidence; `docs/zycast.md` is the comparison record |
| `scripts/serial_transport.py`, `serial-console.py`, `serial-boot-capture.py`, `serial-flash.py` (base64), `serial-configure.py`, `serial-backup.py` | ~2200 | partial — `serial_transport.py` **parity-tested** in `conwrt-serial` (PR #412: script linter, RC-marker collector FSM, command-FIFO `run`/`send_script`, FT232R break-recovery driver over serialport-rs + `tcp://` bridge); `serial-boot-capture.py` **parity-tested** (`boot_capture`: two-phase break wait → `--recovery-wait` reopen → silence-terminated capture to `console.raw`/`console.log`, milestones via the SHARED `conwrt-probe-core` tracker — the ad-hoc `BOOT_MARKERS` table superseded, not forked; mid-capture break recovery is a documented delta); `serial-flash.py` (base64) **parity-tested** (`flash`: chunked `echo` staging + on-device decode + **on-device `sha256sum` verification — the #405 policy, receiver-side only, superseding the Python `--verify` size check**); async serial seam remains `conwrt-protocols::serial_io` (#124); still Python: `serial-console.py`, `serial-configure.py`, `serial-backup.py` | `crates/conwrt-serial` tests (38 unit + 11 mock + 8 pty + 5 tcp from PR #412; 6 `tests/boot_capture_pty.rs` + 5 `tests/flash_b64.rs` mock-BusyBox-shell pty suites for boot-capture/flash); Python oracles `tests/test_serial_transport.py` + `tests/test_serial_tcp.py` | `serial_transport.py`/`serial-boot-capture.py`/`serial-flash.py` superseded once a Rust consumer (CLI or flow) drives them; remaining siblings retire as they port onto `conwrt-serial::SerialConsole` |

## 6. SSH & trust

| Python component | LOC | Rust coverage | Evidence | Retirement |
|---|---|---|---|---|
| SSH transport in `conwrt.py`/`profile/apply.py` (subprocess ssh; the paramiko mention was stale) | ~600 | **parity-tested** — russh stack: host-key ladder + refusal taxonomy + persistent TOFU store + redacted creds (#207/#209) | `providers/conwrt-local-std/tests/ssh_fixture.rs` (12 tests incl. zero-auth-before-approval pins) + `qemu_dropbear.rs` (ring 2) | **Deprecated for sqm + ssh-hardening + adguard + rescue-watchdog + wireguard-client apply flows** (2026-10-22): `conwrt apply --execute` exposes all five (sqm oracle-proven; the rest carry per-row §4 evidence + ring-2); transport banner in `apply.py`. Full retirement rides the remaining profiles' Rust proofs + the ubus transport |

## 7. CLI surface

| Python component | LOC | Rust coverage | Evidence | Retirement |
|---|---|---|---|---|
| `scripts/conwrt.py` + `scripts/conwrt/cli.py` + 12 `cmd_*` | ~3000 | partial — `conwrt-cli`: models/identify/diagnose/probe/discover-v6/fingerprint/apply/plan/agent/maas | `apps/conwrt-cli/tests/cli_maas.rs`; ring-2 apply test; **§7 item 1 `list` → `conwrt models`: byte parity pinned both sides** — `tests/test_parity_rust_models.py` runs `conwrt.py list` AND `conwrt models` against one committed golden (`tests/fixtures/parity/models_list.txt`, Rust-generated); the two tables differed (flash-method order: JSON insertion vs BTreeMap sorted; Rust count footer) — per this matrix the RUST output is the go-forward shape and the Python twin was aligned to it (sorted methods, `N model(s) valid in models` footer) rather than faking equality | Per-command: retire a `cmd_*` when its Rust twin passes the same QEMU oracle; `make ci` shrinks accordingly. **`conwrt.py list` DEPRECATED 2026-10-23** (§7 item 1): docs swapped (README, getting-started, in-CLI pointers), soft-deprecation gate already in place; removal BLOCKED by the internal caller `scripts/conwrt-openwrt-install.sh` (on-router smoke check — no Rust binary on-router), rides the §3 flash-engine retirement (M7-M8). **§7 item 2 `probe`/`discover-v6` AUDITED 2026-10-23 — deprecation gate UNMET** (restraint, not action): (a) no Rust twin for the multi-target sweep (target collection from models + /24 interface-alias orchestration + multi-IP loop is Python-only and load-bearing for `cmd_watch`), (b) the single-target `conwrt diagnose` deliberately classifies stricter (`ssh-only` vs the Python sweep's speculative `openwrt` on any SSH responder — §2 divergence, not drift), (c) no QEMU-oracle case exists for probe. `discover-v6` is Rust-first with no Python CLI twin — nothing to retire. Evidence pinned instead: the deterministic Rust diagnostic surface (`apps/conwrt-cli/tests/cli_probe.rs`, all 6 scenarios) and the Python sweep's corpus target universe (`tests/test_probe_corpus.py` golden — all 24 models' default/recovery IPs currently collapse into the 4 fallback addresses). §7 per-command track pauses until a Rust sweep or the pcap classifier (M7-M8) lands |
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
   (already is — `make parity-check`). No removal needed. **DONE by
   design.**
2. **`router-fingerprint.py`** — Rust twin ring-2 green; retire when
   `conwrt fingerprint` is the operator default (docs swap).
   **DEPRECATED 2026-10-22** (#433 follow-up deprecation pass): docs
   swap landed (README), script prints a deprecation notice for
   operator use, matrix §2 row updated. Removal waits on the
   stock-vendor paths porting; internal 1.x imports
   (`fingerprint_router`/`save_fingerprint`) are untouched.
3. **`firmware-manager.py` download/verify/cache paths** — retire the
   `image`/`cache` Python commands when `conwrt image` reaches feature
   parity (request-with-packages is the remaining gap). **OPEN** —
   gate unmet.
4. **`profile/apply.py` SSH path** — retire when `conwrt apply
   --execute` covers the ops set used by CI (sqm today).
   **DEPRECATED 2026-10-22**: `tests/integration/test_rust_apply_sqm.py`
   proves the Rust apply path inside the QEMU oracle suite (fingerprint
   + board gate + full verification), and the run caught and fixed a
   real set -e render bug (`_sqm_dev=$(uci get ...)` without `|| true`
   aborts under the 2.x `set -e` preamble when `wan.device` is absent).
   Removal waits on the remaining profiles' Rust proofs + the ubus
   transport.
5. Everything else: per-row gates above; nothing retires without a
   green Rust twin AND a removal PR citing this file's row.
6. **§7 per-command CLI retirement** (started 2026-10-23): item 1
   `conwrt.py list` → `conwrt models` **DEPRECATED** — byte parity
   pinned both sides (`tests/test_parity_rust_models.py`), docs
   swapped, Python output aligned to the Rust table shape. Removal
   rides the flash-engine retirement (the on-router install script
   still calls it). Item 2 `probe`/`discover-v6` **AUDITED — gate
   UNMET** (2026-10-23): no Rust sweep twin, deliberate ssh-only
   divergence (§2), no probe oracle; `discover-v6` has no Python
   twin. Pinned instead: `apps/conwrt-cli/tests/cli_probe.rs` (all
   6 diagnostic scenarios) + `tests/test_probe_corpus.py` (sweep
   target universe). The track resumes when a Rust sweep or the
   pcap classifier (M7-M8) lands.

Deprecation audit (2026-10-22) — candidates considered and NOT
deprecated, with the blocking gate: `serial_transport.py` (parity-tested
but "superseded once a Rust consumer drives it" — none yet),
`model_loader.py` (retirement rides the 1.x CLI consumers reading
models from Rust — no consumer migrated), `validate_models.py`
(deliberate permanent fixture), the 11 ported use-case presets (the
ASU bake pipeline that embeds their output is 1.x-only until M7 — the
plugins are load-bearing, including travelmate's 2026-10-22 seeding
extension), `serial_console.py` family (port onto
`conwrt-serial::SerialConsole` not started), TUI (M7).
