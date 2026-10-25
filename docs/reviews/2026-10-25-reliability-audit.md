# conwrt PR #545 — Serial-Rescue Subsystem Reliability Audit

**Date:** 2026-10-25 · **Scope:** `crates/conwrt-serial` as merged in PR #545 (`src/watch.rs`, `tftp.rs`, `uboot.rs`, `detect.rs`, `io.rs`, `recovery.rs`, `flash.rs`, `console.rs`; `recipes/`; `docs/lessons/2026-10-24-gs1900-lockout.md`).
**Method:** full source read of all seven modules; live crate-ecosystem research (crates.io API + docs.rs, fetched 2026-10-25); test-harness prior-art study (labgrid, esptool, OpenOCD, expectrl — fetched from upstream repos/docs); reconciled against `prior-art-report.md` in this directory.

---

## (a) Adopt-vs-keep table for every hand-rolled piece

| # | Hand-rolled piece | Verdict | Candidate crate(s) | Why |
|---|---|---|---|---|
| 1 | SHA-256, `watch.rs:951-1028` (78 lines, FIPS 180-4 by hand) | **ADOPT `sha2`** | [`sha2` 0.11.1](https://crates.io/crates/sha2) (327M recent downloads; RustCrypto) | The crate **already depends on sha2** — `flash.rs:24` does `use sha2::{Digest, Sha256}` and `flash.rs:139` (`image_sha256`) is the same function. The comment "avoids pulling a crate into the no_std-adjacent serial crate" (watch.rs:952) is factually wrong inside this crate, and `lib.rs:54-59` states the crate is host-std by construction. The hand-roll also copies the whole image (`msg = data.to_vec()`, watch.rs:971) — a needless 6.5 MB clone per gate. `sha2` is `#![no_std]`-compatible (std/cpufeatures are optional), so the future embassy/STM32 goal is not blocked either. [`ring` 0.17.14](https://crates.io/crates/ring) is a heavier C/asm build for zero gain here — skip. |
| 2 | Telnet IAC framing, `watch.rs:35-220` (`telnet_strip_iac`, `telnet_escape`, `TelnetFramedIo` with split-read `raw_tail`) | **KEEP, harden** | [`telnet` 0.2.5](https://crates.io/crates/telnet) (maintained, Jul 2026, https://github.com/SLMT/telnet-rs); [`libtelnet-rs` 2.0.0](https://crates.io/crates/libtelnet-rs) (stale since 2021 — reject) | The code is ~150 lines, live-fire proven (the 0xFF-YMODEM-loss lesson), pure and unit-tested. `telnet-rs` is a full event-driven negotiation parser — a shape mismatch for a strip/escape codec, and another dep to cross-verify on the embedded path. Two hardening obligations if kept: (1) the suboption skipper (`watch.rs:48`, `tftp`-side `telnet_strip_iac` at watch.rs:46-52) scans for a bare `0xF0` and does not handle `IAC IAC` *inside* SB — malformed/hostile input can terminate the suboption early; (2) the split-read `raw_tail` logic (watch.rs:106-157) has **no regression test** (see §c). Alternative: adopt `telnet-rs`'s parser only if real negotiation (WILL/DO responses beyond the one-shot BINARY request) is ever needed. |
| 3 | Read-only TFTP server, `tftp.rs` (RFC 1350 + blksize RFC 2348) | **KEEP core, refactor sans-io** | [`tftpd` 1.0.0](https://crates.io/crates/tftpd) (active, Apr 2026, https://github.com/altugbakan/rs-tftpd — has `Config.read_only`, RFC 2347/2348/2349/**7440 windowsize**, lib+bin); [`async-tftp` 0.4.2](https://crates.io/crates/async-tftp); [`ttftp` 0.2.0](https://crates.io/crates/ttftp) (sans-io but **client-only**) | No crate satisfies both requirements simultaneously: read-only **and** portable to embassy+smoltcp later. `tftpd` is the right answer for a host daemon today (battle-tested option negotiation incl. windowsize, which U-Boot can use), but it is threaded/std — dead end for STM32. The in-house `serve_one` is already close to a sans-io core (pure-ish engine + a thin `UdpSocket` shell, unit-tested with a loopback client). Refactor so the block/OACK/retry state machine is a pure function over an abstract send/recv seam; keep the std shell; port to smoltcp later without touching the engine. Steal `tftpd`'s semantics/tests as conformance vectors (esp. exact-multiple terminator, which your loopback test currently does *not* cover — see §c). |
| 4 | Serial port layer, `io.rs` | **KEEP — already adopts the right crate** | [`serialport` 4.10.1](https://crates.io/crates/serialport) (serialport-rs, actively maintained); [`tokio-serial` 5.5.0](https://crates.io/crates/tokio-serial) (maintained, Jun 2026) | `io.rs:25` already uses `serialport-rs` — nothing was reinvented here. The `ConsoleIo` trait (io.rs:149) is exactly labgrid's ConsoleProtocol seam (prior-art §5.1) and is the right extension point. `tokio-serial` only pays off in a full async rewrite of the supervisor; the current thread-per-leg design is adequate for a 1 s bootdelay (in-process fire, no subprocess hop) — do not migrate for its own sake. One gap worth closing: RFC2217 (telnet-based) remote serial, which labgrid's `NetworkSerialPort` speaks — would unify `tcp://`, `telnet://` and RFC2217 under the framing layer you already built. |
| 5 | Expect/pattern engine + recipe supervisor, `watch.rs` (`contains`, `Supervisor::expect`, `run_actions`) | **KEEP (it's the product); borrow expectrl for tests only** | [`expectrl` 0.9.0](https://crates.io/crates/expectrl) (May 2026, active); [`rexpect` 0.7.1](https://crates.io/crates/rexpect) (active under rust-cli, but Unix + *process-spawn* oriented) | In-process firing on a 1 s bootdelay rules out pexpect/rexpect process-spawn models. expectrl 0.9.0 *can* wrap foreign I/O (`Session::new(process, stream)` takes any `S: Read`; full `Expect` needs `S: Read+Write+NonBlocking` — [docs](https://docs.rs/expectrl/0.9.0/expectrl/session/struct.Session.html)), so it is *technically* adoptable under `ConsoleIo` — but it would demote the declarative recipe/trigger/cooldown/fire-state model into code, for no reliability gain on the matching itself (literal byte matching is the *right* semantics for binary consoles; regex is a recipe foot-gun). Adopt **expectrl in the test harness** (§c) to drive fake devices; keep the engine. |
| 6 | Pacing/sleep loops (`pace_ms`/`pace_bytes` loops watch.rs:801-806, 883-897; `Sleeper` seam console.rs:75) | **KEEP pacing; consolidate the loops** | [`governor` 0.10.4](https://crates.io/crates/governor) (GCRA rate limiter, no_std option); [`quanta` 0.13.0](https://crates.io/crates/quanta) (fast clocks) | The paced writes are not rate limiting — they are a bench-tuned inter-write gap that *is the protocol* (echo-storm/NOSTTY lessons). GCRA would "correct" for jitter the bench data says matters. What's actually wrong is duplication: two copies of the paced-send loop in `watch.rs` plus `send_paced_line` in console.rs, each subtly different. Consolidate onto one `paced_write` using the existing injectable `Sleeper` seam so tests can virtualize time. `governor` is worth considering later only for probe-line cadence if consoles prove jitter-sensitive. |
| 7 | *(bonus)* Recipe JSON model, `watch.rs:228-388` | **ADOPT tooling** | [`schemars` 1.2.3](https://crates.io/crates/schemars), [`serde_with` 3.24.0](https://crates.io/crates/serde_with) | Recipes have no `schema_version` field and rely on serde silently ignoring unknown keys (the `_comment` fields). Generate a published JSON Schema (schemars) for recipe authors and lint cross-references at load time — see R4. |
| 8 | *(bonus)* YMODEM, `uboot.rs:144-294` | **KEEP** (no maintained Rust YMODEM crate exists; `crc16_xmodem` is vector-tested) | — | Correctness risk is in the untested handshake state machine, not the framing — see §c. |

**One-line summary of the table:** you reinvented exactly one wheel you shouldn't have (SHA-256 — and it contradicts your own Cargo.toml); everything else is either already on the right crate, or is a legitimately special-purpose ~200-line engine whose real gap is *tests and structural refactor*, not replacement.

---

## (b) Ranked refactor list (by reliability gain)

### R1 — Fix the window-drain discipline: one latent panic, one silent-miss class *(highest gain; the exact live-fire bug class)*
The 64 KiB rolling window (`watch.rs:507-510`) drains from the front, but every marker offset in the module is a **plain index** into a buffer that shifts underneath:
- **Latent panic:** `run_watch` matches triggers with `&s.window[trigger_scan_from..]` (`watch.rs:1129`) where `trigger_scan_from = s.window.len()` was captured at fire time (`watch.rs:1137`). If >32 KiB flows during/after a fire (a loady transcript is appended into the same window at `watch.rs:605`), the drain shrinks `window.len()` below `trigger_scan_from` → slice index out of bounds. You fixed this class in `recent_since` (the `65411 > 32849` lesson) but missed this site.
- **Silent miss:** `recent_since(before)` (watch.rs:528) clamps with `.min(len)` — after a drain, bytes that arrived *after* the mark can sit at indices `< before`, so the RDY/CK-i/gate marker waits (`watch.rs:783, 820, 845, 905`) can time out on a healthy box.

**Refactor:** track a monotonic stream position. Keep `window: Vec<u8>` plus `base_offset: u64` (absolute index of `window[0]`) and `total_seen: u64`; every "mark" is an absolute offset (`mark = s.total_seen`); `recent_since(mark)` returns `window[(mark.saturating_sub(base_offset))..]`. Clamp is then provably correct, drain is an implementation detail, and the property test in §c pins it. Convert `trigger_scan_from` to the same representation.

### R2 — One read loop, one error policy, one error type
There are at least **five** "read until deadline" loops with **three different** fatal-error policies:
| Loop | Site | On `Err` (non-idle) |
|---|---|---|
| `Supervisor::read_secs` | watch.rs:496-516 | `_ => sleep(20ms)` — **swallows transport death**, keeps looping to deadline; the caller then reports "expect timeout" for a dead TCP bridge |
| `read_for` | uboot.rs:74-96 | `break` — silently stops reading mid-window (the 2026-10-24 false-negative bug you already hit once) |
| `read_secs` | detect.rs:55-76 | `break` — same |
| `reboot_wedged_bounded` / `drain_until_quiet` | recovery.rs:158-203 | propagate `Err` — correct |
| `collect` | console.rs:278-306 | propagate + **deadline reset semantics** (a distinct contract) |

**Refactor:** a single `ConsoleReader` (or free function `read_until(io, deadline, sink, policy)`) with an explicit `ErrorPolicy::{TreatAsIdle, Break, Propagate}` chosen per call site, plus injectable clock (the `Sleeper` trait already exists — extend it to `now()`). Then a typed error taxonomy — today the crate mixes `thiserror` (`ConsoleError` io.rs:37, `FlashError` flash.rs:80), hand-rolled Display (`UbootError` uboot.rs:31, `RecoveryError` recovery.rs:219), `Result<(), String>` (`run_actions` watch.rs:559), and `Vec<String>` (`serve_until` tftp.rs:199). Define `WatchError { TransportDead, ExpectTimeout{pattern,tail}, GateFailed{marker}, GateNoVerdict, HostShaMismatch, ReceiverCannotArm{reason}, RecipeInvalid{..} }` and make **transport death abort the recipe immediately** — right now a bridge that drops mid-`StreamChunks` burns every remaining chunk marker timeout (120 s each) before failing.

### R3 — Per-action and whole-recipe deadlines; scoped TFTP server lifetime
- `run_actions` (watch.rs:559) has no per-action timeout and no overall budget: `Spaces` is bounded, but `SendLine`+`settle_secs` chains can stretch arbitrarily, and one wedged action eats an unbounded slice of the rescue window.
- **TFTP thread + socket leak:** in `Action::TftpBoot`, the early returns (`?` at watch.rs:620 bind-parse, **watch.rs:644 the `Bytes transferred` expect**, and the stat error at 638) exit without `stop.store(true)`/`server.join()` — the parked server thread and its UDP socket live until process exit, and a retry re-fires into "address in use".
- **detect.rs contradicts the framing doctrine:** `detect.rs:122-125` still negotiates telnet BINARY on **every** `tcp://` endpoint, while `io.rs:14-19` documents `tcp://` as a *raw* relay and `watch.rs:1049-1053` deliberately wraps only `telnet://` (the Codex P2 round-2 decision). On a raw bridge, detect injects `FF FB 00 FF FD 00` garbage into the console. Route detect through the same `telnet://`-only `TelnetFramedIo` wrapper.
- Dead code that will mislead the next reader: `before_ok` no-op block (watch.rs:647-650), `let _ = before` (watch.rs:1122-1124), duplicated doc lines in recovery.rs:210-232, `chrono_local()` returning unix seconds (watch.rs:551).
- Weak gate: `iminfo` success is `contains(&s.window, b"OK")` against the **whole window** (watch.rs:651) — "OK" matches unrelated earlier output (e.g. any `rtk network on ... OK`). Scope it to `recent_since` after R1, or match the canonical `## Verifying Checksum ... OK` line.

### R4 — Recipe schema versioning + validate-then-arm
Add `"schema_version": 1` to `Recipe` (`watch.rs:352`), generate/ship a JSON Schema (schemars), and add a `validate(&self) -> Result<(), RecipeInvalid>` that checks everything checkable **before the port opens** (prior-art §1.2: a config error must never cost you the 1 s bootdelay window): sha256 fields are 64-char hex, `image_path`/`file`/`serve_dir` exist with matching sizes, `chunk_bytes`/`pace_bytes` > 0, `pace_ms`/`pause_ms` non-zero, `max_fires`/`cooldown_secs` sane, `bind` parses, `boot_trigger` non-empty. The CLI currently parses-and-prays (`main.rs` in the diff: `serde_json::from_str(...).unwrap_or_else`).

### R5 — Delete the hand-rolled SHA-256 (Adopt #1 above)
Mechanical: `sha256_hex()` → `crate::flash::image_sha256`, keep the three known-vector tests, delete 78 lines and the `tftp.rs:222` re-export shim. Also removes the whole-buffer clone.

### R6 — TFTP sans-io core + conformance tests
Split `serve_one` into a pure `TftpSession` state machine (input: packet bytes; output: packets to send + transfer state) and a thin UDP shell. This is the STM32/embassy+smoltcp portability plan *and* the testability plan (golden packet-sequence tests with no sockets). While there: U-Boot's tftp client also requests `tsize` (RFC 2349) — silently ignoring it is legal (RFC 2347: answer only what you accept) but advertising it is friendlier; and the retry loop resends DATA on *any* non-matching packet including stale duplicate ACKs — fine — but a lost final ACK currently costs a full 8×1 s retry cycle with no logging. Add `trivial errors are counted, not stringified` while R2's taxonomy lands.

### R7 — Consolidate paced writers and YMODEM send loops
One `paced_write(io, data, pace_bytes, pace_ms, sleeper, progress)` used by `Stream`, `StreamChunks`, and flash.rs's chunk loop; one YMODEM loop with an explicit mini state machine (`AwaitInvite → Header → Data(blkno) → Eot → EndBatch`) instead of the current sequential awaits — the EOT dance (`uboot.rs:285-293`) currently ignores whether the 10 EOT attempts ever got their ACK before proceeding to the null batch.

### R8 — Cleanup pass
Remove R3's dead code; make the `marker_lines_defeat_command_echo` test (watch.rs:1341-1360) assert on the **actual generated lines** from `run_actions` — today it hand-writes the *old* quote-split form (`'R''DY'`) while the generator now emits var-concat (`A=R; B=DY`, watch.rs:769-773), so the test can no longer catch a regression in the generator (this is also a §c gap).

---

## (c) Test-harness proposal — what live-fire bug classes have NO regression test, and the CI design

### Live-fire bug classes with no regression coverage today

| Live-fire lesson (fixed in anger) | Regression test today? |
|---|---|
| Telnet binary framing: 0xFF bytes lost to ser2net's telnet parser | Partial — pure `strip/escape` round-trip + a **single-read** `EchoIo` test (watch.rs:1251). The split-read `raw_tail`/`incomplete_tail_len` logic (the Codex P2 fix) has **no test feeding a frame split at every byte boundary**. |
| Rolling-window drain panic (`65411 > 32849`) | **None.** No test pushes >64 KiB through `Supervisor`; `recent_since` clamp semantics and the **still-live panic at watch.rs:1129** (R1) are unexercised. |
| TCP idle-timeout false negatives (dead bridge read as silence) | **None.** The three divergent `Err` policies (R2 table) are untested; no test kills a fake transport mid-action. |
| TFTP OACK desync (block-0 ACK) | Covered indirectly by the loopback e2e test (tftp.rs:262). |
| TFTP exact-multiple final block (Codex P2 zero-length terminator, tftp.rs:176-192) | **None** — the e2e test uses 5000 B @ blksize 1024 (not a multiple). |
| Echo-matching false positives (command echo satisfies markers) | **Stale** — watch.rs:1341 tests the abandoned quote-split line shape, not the generator (R8). |
| Missing-stty canonical-mode kill (RDY/NOSTTY handshake, watch.rs:777-798) | **None** — no test drives the chunk handshake against a fake receiver. |
| Bootdelay burn (fire-in-process on 1 s window) | **None** — `run_watch`'s trigger/cooldown/cross-process `.fired` marker logic (watch.rs:1076-1165) is untested. |
| YMODEM survival (C-invite, block-0 ACK-then-C ordering, EOT dance) | **None** — only pure frame builders + CRC vectors are tested; the handshake state machine (uboot.rs:225-294) never runs in CI. |

### Design: four tiers, all CI-runnable on ubuntu/macos (expectrl's CI matrix precedent — pty tests run on unix, Windows compile-only)

**Tier 0 — property tests** (`proptest` 1.12.0, pure functions, <1 s):
1. `telnet_escape ∘ telnet_strip_iac == id` for arbitrary byte strings (dense in 0xFF/0xFA/0xF0), and `TelnetFramedIo` fed the escaped stream **split at every possible offset** yields the original — pins the `raw_tail` fix.
2. Window-drain: feed 1-10 MB in random-sized chunks through a `Supervisor`-like window with random drain points; assert (post-R1) `recent_since(mark)` never misses a marker appended after `mark`, and no panic — plus a regression case for watch.rs:1129.
3. `sha256_hex == sha2::Sha256` on random inputs while the hand-roll exists (deleted after R5).
4. `parse_total_size` / `parse_device_sha256` against recorded-format fuzzed lines.

**Tier 1 — MockConsole + golden transcripts** (labgrid's `FakeConsoleDriver` pattern — their `labgrid/driver/fake.py` is <100 lines: an `rxq` the test appends canned console bytes to, a `txq` capturing writes, plus a pattern-responder; their `test_ubootdriver.py` does exactly `d.console.rxq.append(b"U-Boot 2019\n")` then asserts `txq.pop() == b"run bootcmd\n"` — https://github.com/labgrid-project/labgrid/blob/master/labgrid/driver/fake.py):
- `MockConsole: ConsoleIo` with (a) a scripted byte timeline (offsets in *virtual* time), (b) a small responder table (rx bytes matching a pattern enqueue a reply after a virtual delay), (c) fault injection (`Err(ConnectionAborted)` at a chosen virtual instant — the dead-bridge class), (d) full tx capture.
- **Golden transcript replay:** you already write transcripts (the `run_watch` transcript file) — commit the bench rescue logs as fixtures (`tests/fixtures/transcripts/gs1900-*.log`) and replay them through `classify()`, the trigger matcher, `expect`, and `parse_total_size`. This is where detect's classifier gets real-world coverage (bracketed-paste/ANSI pollution cases from prior-art §5.2 can be added as synthetic overlays).
- Virtual time: extend the existing `Sleeper` seam (console.rs:75) to a `Clock { now(), sleep() }` and thread it through `Supervisor`/`read_for` — tests run in milliseconds, no timing flakes. (This falls out of R2.)
- Targets: full `run_watch` cycle incl. cooldown + `.fired` cross-process marker; `StreamChunks` RDY/NOSTTY handshake; `TftpBoot` happy path with the real `serve_until` on a loopback socket; `ArmScript` two-round retry.

**Tier 2 — PTY fake-device harness** (expectrl's own strategy — its whole test suite spawns `cat`/`sleep` over ptys, https://github.com/zhiburt/expectrl/tree/main/tests; use [`portable-pty` 0.9.0](https://docs.rs/portable-pty/latest/portable_pty/) (wezterm, cross-platform incl. a serial module) or [`pty-process` 0.5.4](https://crates.io/crates/pty-process)):
- `conwrt-fake-uboot`: a tiny helper binary run on the slave side of a pty pair that speaks the RTL838x console for real: boot signature lines → 1 s autoboot window (interruptible by space) → `RTL838x#` prompt → `loady` C-invite + ACK-per-STX-frame + `## Total Size = N` → `iminfo` … OK → `bootm` → OpenWrt banner; scriptable fault knobs (drop every k-th ACK, CAN at frame n, stale-echo mode, no-stty mode).
- Open the **master via the real `serialport` backend** (`/dev/pts/N`): this exercises `SerialPortIo`, real tty semantics (echo, canonical mode, line buffer), YMODEM over a real pty, and the `reset_input_buffer` path — the classes mocks cannot see. lib.rs already promises `tests/pty_driver.rs`; this generalizes it from driver-level to device-level.
- Transport matrix over the same fake device: raw `tcp://` (loopback relay thread), `telnet://` (a ~50-line ser2net simulator that does IAC negotiation and doubles 0xFF — this alone would have caught the original live-fire loss), local pty. Three transports × one device script.
- TFTP: keep the loopback e2e and add the exact-multiple case + a lossy client (drops ACK n) to exercise retries.

**Tier 3 — hardware-gated** (esptool's convention: everything hardware-free runs by default; device tests live behind options/markers and are skipped in CI — https://github.com/espressif/esptool/blob/master/test/conftest.py): `CONWRT_TEST_PORT=/dev/ttyUSB0` env or `--features hw-tests`; same test bodies as Tier 2 with a real box. Keep this small on purpose — OpenOCD is the cautionary tale here: their hardware-in-loop suite "had not been updated since around 2014" and was deleted wholesale (https://github.com/openocd-org/openocd/blob/master/testing/obsoleted-tests.txt); what survived is a tiny always-runnable "dummy adapter" suite. Fund Tiers 0-2 first.

**CI wiring:** `cargo test` (T0+T1, all OS) → `cargo test --test pty_harness` (T2, linux+macos; windows compile-only, expectrl precedent) → clippy/fmt. Fixture blobs (YMODEM payload images) generated at session start (esptool's `bin_builder.py` idea) rather than committed.

---

## Reconciliation with `prior-art-report.md`

- **Endorse and sequence their P0s:** #1 rescue transaction marker (SWUpdate/RAUC), #2 pre-flight gate block, #3 chunk-protocol hardening (per-chunk seq+CRC, resume ledger) — all three are compatible with and partially enabled by R2/R4 here (typed errors + validate-then-arm are prerequisites). #3 in particular belongs *inside* the `StreamChunks` refactor of R7.
- **Their #4 (validate-then-arm, OpenOCD 1.2) = my R4** — same recommendation from two directions; the schema_version + schemars piece is the concrete mechanism.
- **Their 5.1 (protocol-trait split)** is already 90% true in the codebase (`ConsoleIo`, `BreakIo`); the missing consumer is the classifier, which currently reads raw windows — agree, low-cost.
- **Their report did not cover dependency adoption at all** (it was pattern-mining, not crate-mining) — §(a) here fills that hole and should be read as complementary: e.g. their #8 control-surface and #7 power-resource are *ops features*, correctly P2, and deliberately not reliability blockers in my ranking.
- **One gentle correction to their 6.1:** expect/pexpect are cited as "blocking-read, one-shot … spawns subprocesses" — true of pexpect, but expectrl 0.9's `Session::new(P, S: Read)` accepts foreign streams; the reason to keep the in-house engine is the declarative recipe model and the trigger/cooldown/fire-state supervisor, not a library limitation.
- Their dropped-item list (on-box stub helper, delta transfers, full coordinator) — concur with all three drops at current scale.

---

## (d) Bottom line (10 lines)

1. You hand-rolled SHA-256 in a crate that already depends on `sha2` — delete it; every other "wheel" is either already on the right crate (serialport-rs) or a justified special-purpose engine.
2. Keep the telnet codec, TFTP server, YMODEM, expect engine, and pacing — but each with a named hardening debt, not a free pass.
3. The window-drain bug class is **not actually fixed**: `recent_since` clamps, but `watch.rs:1129` still panics and drained windows can silently swallow RDY/CK markers — move to absolute stream offsets (R1) before the next bench day.
4. Five read loops with three error policies means the next transport-death bug will be found live, not in CI — unify into one reader with an explicit policy and a typed `WatchError` (R2).
5. Action execution needs per-action deadlines and a scoped TFTP server lifetime; `detect.rs` still speaks telnet on raw `tcp://` and contradicts the framing doctrine (R3).
6. Recipes need `schema_version` + validate-then-arm so a config error never costs the 1 s bootdelay window again (R4, = prior-art #4).
7. The single highest-leverage *new* artifact is the MockConsole + golden-transcript tier — labgrid's `FakeConsoleDriver` pattern maps 1:1 onto `ConsoleIo` and covers the untested live-fire classes (dead bridge, NOSTTY handshake, fire/cooldown state machine).
8. Add the PTY fake-`conwrt-fake-uboot` tier for the real-serialport/YMODEM/telnet-sim classes mocks can't see; gate real hardware behind env flags and keep it small (OpenOCD's deleted HIL suite is the warning).
9. Property tests for telnet split-decoding and window drain turn your two worst live-fire lessons into invariants; expectrl/portable-pty/proptest/schemars are the only new deps proposed — all actively maintained.
10. Net: the architecture's doctrine (on-box gates, ethernet-for-bytes, in-process firing) is sound and bench-proven; its risk is concentrated in duplicated timing loops and untested state machines — R1-R4 are cheap and remove most of it.

### Key links
- Crates: [sha2](https://crates.io/crates/sha2) · [ring](https://crates.io/crates/ring) · [serialport](https://crates.io/crates/serialport) · [tokio-serial](https://crates.io/crates/tokio-serial) · [expectrl](https://crates.io/crates/expectrl) ([Session docs](https://docs.rs/expectrl/0.9.0/expectrl/session/struct.Session.html)) · [rexpect](https://crates.io/crates/rexpect) · [tftpd](https://github.com/altugbakan/rs-tftpd) · [telnet-rs](https://github.com/SLMT/telnet-rs) · [libtelnet-rs](https://crates.io/crates/libtelnet-rs) · [governor](https://crates.io/crates/governor) · [quanta](https://crates.io/crates/quanta) · [portable-pty](https://docs.rs/portable-pty/latest/portable_pty/) · [pty-process](https://crates.io/crates/pty-process) · [schemars](https://crates.io/crates/schemars) · [proptest](https://crates.io/crates/proptest)
- Harness prior art: [labgrid fake.py](https://github.com/labgrid-project/labgrid/blob/master/labgrid/driver/fake.py) · [labgrid test_ubootdriver.py](https://github.com/labgrid-project/labgrid/blob/master/tests/test_ubootdriver.py) · [expectrl tests](https://github.com/zhiburt/expectrl/tree/main/tests) · [expectrl CI](https://github.com/zhiburt/expectrl/blob/main/.github/workflows/ci.yml) · [esptool test/conftest.py](https://github.com/espressif/esptool/blob/master/test/conftest.py) · [esptool contributing](https://docs.espressif.com/projects/esptool/en/latest/contributing.html) · [OpenOCD obsoleted-tests.txt](https://github.com/openocd-org/openocd/blob/master/testing/obsoleted-tests.txt)
- Internal: `prior-art-report.md` (this dir) · `docs/lessons/2026-10-24-gs1900-lockout.md` · `recipes/SERIAL-TRANSFER-DOCTRINE.md`
