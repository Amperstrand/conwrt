# conwrt-serial → STM32F746 no_std portability research report

Date: 2026-10-25 · Scope: `src/{tftp,watch,uboot,detect,io}.rs` (read in full) + web research on
embedded Rust crates/prior art. All crate claims were verified via docs.rs / crates.io API / GitHub
fetches (crates.io HTML is JS-only; API and docs.rs used throughout). Research tooling notes: no
zread/browser MCP was available in this session; webfetch on canonical URLs (docs.rs, GitHub raw,
crates.io `/api/v1`) was used instead. Every section cites sources.

**Verdict up front:** nothing in the ecosystem blocks the port. The engines can be made sans-io
pure cores + thin executor shells; the only true rewrite is `io.rs` transports (host glue by
design). No maintained no_std TFTP *server*, no declarative expect-engine, and no alloc-free
JSON-with-tagged-enums crate exist — we own those three problems, and each has clean prior art to
pattern after (smolapps, atat, postcard).

---

## (a) Per-question findings

### Q1 — Embedded TFTP prior art

**Does smoltcp ship a TFTP example? No.** The `examples/` dir contains exactly:
`benchmark.rs, client.rs, dhcp_client.rs, dns.rs, httpclient.rs, loopback.rs,
loopback_benchmark.rs, multicast.rs, multicast6.rs, ping.rs, server.rs, sixlowpan.rs,
sixlowpan_benchmark.rs, slaac.rs, tcpdump.rs, utils.rs` — no TFTP, and a 2020 proposal to add an
`apps` layer "in case anyone decides to implement … TFTP" was never merged (PR #342, SNTP client,
closed). Source: https://github.com/smoltcp-rs/smoltcp/tree/main/examples ,
https://github.com/smoltcp-rs/smoltcp/pull/342 . smoltcp 0.14 (2026-10-17) is no_std, "does not
need heap allocation at all"; its UDP socket is the canonical sans-io shape:
`Socket::new(rx_buffer, tx_buffer)` ring buffers, `bind()`, `can_recv/can_send`, zero-copy
`send(len, meta)`, `recv() -> (usize, UdpMetadata)`, plus waker registration for async integration
— https://docs.rs/smoltcp/latest/smoltcp/socket/udp/struct.Socket.html . The matching polling
doctrine lives on `Interface`: `poll(timestamp, …)`, `poll_at() -> Option<Instant>` (soft
deadline), `poll_delay() -> Option<Duration>` (advisory wait) —
https://docs.rs/smoltcp/latest/smoltcp/iface/struct.Interface.html . **This `next-deadline`
pattern is exactly the shape our extracted core should expose.**

**no_std TFTP crates (none maintained for servers):**

| Crate | What it is | no_std | Status | Link |
|---|---|---|---|---|
| **smolapps** | TFTP **server** on smoltcp UDP sockets — *the key prior art* | yes (heap optional via `managed`) | dormant, 0.1.4 (2020-05), old smoltcp API | https://github.com/plorefice/smolapps |
| **ttftp** | sans-io, no_std, **no-alloc** TFTP state machine — client only, no options | yes, alloc-free | 0.2.0 (2024-11) | https://docs.rs/ttftp |
| **tftp** (ivan770) | packet codec only (`Message` enum, `TryFrom<&[u8]>`), no OACK | yes + optional alloc | abandoned, 0.1.0 (2021) | https://github.com/ivan770/tftp |
| **tftp-packet** | RFC 1350 codec-only | parser, std | 0.1.0 (2022) | https://github.com/haasal/tftp-packet-rs |
| **async-tftp** | std/async; implements RFC 2347/2348/2349 (**blksize**, tsize) + RFC 7440 windowsize; pluggable `Handler` trait | no (std) | 0.4.2, active | https://github.com/oblique/async-tftp-rs |
| **tftp-ro** | read-only server "for serving binary images to a dev board running u-boot" — our exact host use case | no (std) | 0.2.1 (2020) | https://github.com/gridbugs/tftp-ro |
| **rs-tftpd / r-tftpd / tftp_client** | std servers/clients, popular but host-oriented | no | active 2025–26 | https://github.com/altugbakan/rs-tftpd |

**smolapps' server (verified from source:**
https://raw.githubusercontent.com/plorefice/smolapps/master/src/tftp/mod.rs ,
`src/wire/tftp.rs` **) is the cleanest extraction reference even though it's dormant:**
- codec/transport split: zero-copy `Packet<T>` wire view + `Repr` enum with
  `parse/emit/buffer_len`, mirroring smoltcp's own `wire` conventions;
- storage abstracted from protocol: `trait Context { open(filename, …) -> Handle }` /
  `trait Handle { read(&mut [u8]) }` — `read` is guaranteed a 512-byte buffer, so flash/RAM can
  back the server with no filesystem;
- one UDP socket on :69, sessions (`Transfer { block_num, last_data, retries, timeout }`) demuxed
  by peer endpoint (TID), `serve()` called after each `Interface::poll()`, `next_poll()` sleep hint
  — i.e. a pure state machine driven from outside;
- ACK-paced lockstep with cached last block for retransmit (`MAX_RETRIES=10`,
  `RETRY_TIMEOUT=200ms`), duplicate-ACK ⇒ resend, duplicate-DATA ⇒ re-ACK.
- **Limitations:** RFC 1350 only — no OACK/blksize negotiation (we need it; U-Boot asks). OACK
  semantics (RFC 2347/2348/2349/7440) are best documented in **async-tftp** (std) — use it as the
  behavioral reference for option negotiation, block-0 ACK, and rollover.

**Embassy UDP server structure** (example: `ethernet_w5500_udp.rs`, verified source
https://raw.githubusercontent.com/embassy-rs/embassy/main/examples/rp/src/bin/ethernet_w5500_udp.rs
):

```rust
let mut socket = UdpSocket::new(stack);
socket.bind(1234, ListenSocketAddr::UNSPECIFIED).unwrap();
loop {
    let (n, ep) = socket.recv_from(&mut buf).await.unwrap();
    socket.send_to(&buf[..n], ep).await.unwrap();
}
```

App tasks own sockets and `.await` them; a spawned `net_task` does the internal select/poll over
all stack resources (embassy-net README, no_std/no-alloc:
https://raw.githubusercontent.com/embassy-rs/embassy/master/embassy-net/README.md — note the
README now describes the stack as built on "xarxa"; smoltcp 0.14 remains the standalone sans-io
alternative). No TFTP example exists in embassy either. **Mapping for our port:** one
`UdpSocket::new(stack)` bound to 69; `recv_from` → feed pure session state machine → `send_to`
with the packet the core produced; TID demux like smolapps if we ever serve concurrent rescue
clients (we serve one — our `serve_one` model suffices).

**Implication for `src/tftp.rs`:** the codecs (`parse_request` tftp.rs:31, `oack_blksize` :59,
`data_packet` :68, `err_packet` :21, `is_safe_name` :75) are already pure — the extraction target
is `serve_one` (:86) whose block/OACK/retry loop is fused to `UdpSocket` + `std::fs`
(`File::open/read_to_end` :108–111). Also preserve the two hard-won protocol invariants as core
unit tests: OACK-must-consume-block-0-ACK (:126–143, "found by the loopback test") and the
terminating zero-length block for exact-multiple files (:176–192, "Codex P2"). The embedded core
should take the image as `&[u8]` (or a `Handle`-style read trait à la smolapps — flash-backed),
never a `Path`.

### Q2 — Recipe format on embedded (JSON today, what on STM32?)

Current model: `Recipe`/`Action` (watch.rs:229–377) — serde internally-tagged enum
(`#[serde(tag="type")]`, 8 payload-carrying variants), `String`/`Vec<String>` fields, `f64`
seconds, parsed by `serde_json` (watch.rs:1278).

| Crate | no_std | alloc needed | Tagged-enum (~8 payload variants) | Maintenance | Link |
|---|---|---|---|---|---|
| **serde_json** 1.0.154 | yes (`default-features=false, features=["alloc"]`) | **yes** | full | very active (dtolnay) | https://docs.rs/serde_json |
| **postcard** 1.1.3 | yes (primary design goal) | **no** (heapless/slice default; `alloc` opt) | ideal — 1-byte varint discriminant; avoid `flatten`/`skip` attrs | active, 1.5k★, stable wire spec + schema tooling | https://docs.rs/postcard , https://github.com/jamesmunns/postcard |
| **serde-json-core** 0.7.0 | yes | no | **C-like enums only** (docs) — data-carrying tagged enums unsupported | active (rust-embedded-community) | https://docs.rs/serde-json-core |
| **minicbor** 2.3.1 | yes | no (alloc opt) | yes, but own `Encode`/`Decode` derives (not serde) | active; BlueOak license | https://docs.rs/minicbor |
| **ciborium** 0.2.2 | yes | **yes** (`Value`/`Map` = Vec) | yes (serde) | current, slow cadence | https://docs.rs/ciborium |
| **serde_cbor** 0.11.2 | yes | opt | yes | **ARCHIVED 2021** — README says use ciborium/minicbor | https://github.com/pyfisch/cbor |
| **miniconf** 0.22.0 | yes | no (core) | poor fit — "enums with named fields … should stay leaves" | active | https://github.com/quartiq/miniconf |
| **heapless** 0.9.3 + `serde` feature | yes | no | n/a (containers; `String<N>`/`Vec<T,N>` serde impls) | active (rust-embedded) | https://docs.rs/heapless |

What real OTA stacks use: Zephyr MCUmgr/SMP payloads are CBOR maps — evidence CBOR dominates the
*protocol* space (Rust: mcumgr-smp https://github.com/Gessler-GmbH/smp-rs ,
mcumgr-toolkit https://github.com/Finomnis/mcumgr-toolkit ) — but neither is a reusable *manifest*
format for us. postcard's ecosystem (postcard-schema 0.2.5, postcard-derive:
https://docs.rs/postcard-schema ) is the only one with a deliberate "author on host, compiled
blob to target, schema-validated tooling" story, incl. built-in `to_vec_crc32` / COBS framing.

**Recommendation — JSON on host, compiled postcard blob on target (not CBOR everywhere):**
1. Recipes stay authored/inspected as JSON (serde_json on host, current UX unchanged; the
   `#[serde(tag="type")]` attribute is a JSON-representation concern — postcard encodes
   externally-tagged variants as index+payload regardless, and both formats deserialize the same
   derived type).
2. New host command `conwrt recipe compile` → `postcard::to_vec_crc32::<Recipe>(&recipe)`
   (COBS+CRC32 framing built in) → blob flashed/staged next to the image.
3. Target type mirrors the core model with `heapless::String<N>` / `heapless::Vec<Action, N>`
   fields; `postcard::from_bytes::<Recipe>(&blob)` is fully alloc-free.
4. Discipline: add a `format_version: u16` field; never reorder enum variants (discriminants are
   ordinal); no `serde(flatten)`/`skip_serializing_if` (postcard README, tracking issue #125).
5. Why not CBOR everywhere: ciborium needs alloc on target, minicbor forks the derive stack, and
   serde_cbor is archived — you'd pay dual-format complexity for interoperability we don't need.
   Why not serde-json-core on target: its documented type support stops at C-like enums, so our
   8-variant payload-carrying `Action` would need hand-rolled deserialization.

### Q3 — Time and pacing without `std::thread::sleep`

Our std usage today: `Instant` deadlines + `thread::sleep(20ms)` polls (watch.rs:606–625
`read_secs`, uboot.rs:74–96 `read_for`, detect.rs:55–76), inter-write pacing
`sleep(pace_ms)` (watch.rs:929, 1011), BREAK hold (io.rs:505), plus a parked TFTP thread
(watch.rs:752). The port needs three layers:

- **Layer 1 — sans-io cores expose deadlines, never sleep.** Precedent: smoltcp
  `Interface::poll_at()/poll_delay()` ("harmless … to call before; potentially harmful … after" —
  https://docs.rs/smoltcp/latest/smoltcp/iface/struct.Interface.html ). Every core fn returns
  `next_deadline: Option<Duration>`; the executor decides how to wait.
- **Layer 2 — embassy-time on STM32F7.** v0.5.1 (2026-09), no_std, one global time driver
  (embassy-stm32 provides it on F7 via `time-driver-any`/tim features —
  https://docs.embassy.dev/embassy-stm32/ ). `Timer::after(d).await` replaces one-shot sleeps;
  **`Ticker::every(pace)` with drift-free `next().await` is exactly our `pace_ms` inter-write
  pacer**; `with_deadline`/`with_timeout` wrap expects; `Instant/Duration` arithmetic is
  drop-in for `std::time`. https://docs.rs/embassy-time ,
  https://docs.rs/embassy-time/latest/embassy_time/struct.Ticker.html
- **Layer 3 — bare-metal (non-embassy) alternative:** **rtic-monotonics** 3.0.0 (+`rtic-time`
  queue, re-exports **fugit** instants, deps **portable-atomic**) —
  https://docs.rs/rtic-monotonics ; fugit 0.6.0 (no_std time vocabulary, wrapping-aware
  instants) — https://docs.rs/fugit ; cortex-m 0.7.10 is *not* deprecated (2026-10-22 release —
  https://docs.rs/cortex-m ) but only gives blocking SysTick delay, not a monotonic queue.
  portable-atomic 1.15 (taiki-e, no_std, `AtomicU64` fallback on M-profile —
  https://docs.rs/portable-atomic ) underpins governor/rtic/embassy.

**Rate limiting:** **governor IS no_std** — documented "no_std mode … implement the `Clock` trait
for your platform", state = one `AtomicU64` via non-optional portable-atomic; repo now
boinkor-net/governor ( https://docs.rs/governor/latest/governor/_guide/index.html ,
https://github.com/boinkor-net/governor ). **quanta is not for MCUs** (OS clocks/TSC, deps
libc/windows-sys/web-sys — https://docs.rs/quanta ). Verdict: our needs (fixed `pace_ms`,
chunk `pause_ms`, cooldown) are simple deadlines — implement in-core deadline returns; adopt
governor only if a real token-bucket requirement appears (a custom `Clock` over embassy-time is a
~20-line impl; `NotUntil` even yields the next deadline).

### Q4 — OTA verification doctrine to steal

| Framework | Model | no_std | STM32F746 | Link |
|---|---|---|---|---|
| **MCUboot** | the canonical swap-with-revert: verify (SHA-256 + optional sig) **before** swap; new image boots in *trial* state; app must set `image_ok` or bootloader **reverts** on next boot; anti-rollback via security counters | C core (Rust port mcuboot-rs dormant 2023; smp-rs active for the mcumgr protocol) | yes via Zephyr/Mynewt ports | https://github.com/mcu-tools/mcuboot , https://github.com/mcu-tools/mcuboot-rs , https://github.com/Gessler-GmbH/smp-rs |
| **rustBoot** | A/B slots, ECC-signed update candidates (RustCrypto ECDSA P-256 + SHA-256) verified **before** an image is ever booted; version anti-rollback; power-interruptible swap with guaranteed fallback | 100% Rust no_std | **explicit `boards/bootloaders/stm32f746`** | https://github.com/nihalpasham/rustBoot |
| **embassy-boot** (+embassy-boot-stm32 0.8) | partitions BOOT/ACTIVE/DFU/STATE; `FirmwareUpdater::verify_and_mark_updated()` (ed25519 + SHA-256) then power-fail-safe swap on reboot; trial boots + rollback built in | yes | yes — embassy-stm32 0.6 has 89 `stm32f7*` chip features incl. `stm32f746*` | https://github.com/embassy-rs/embassy , https://docs.rs/embassy-boot-stm32 , https://docs.rs/crate/embassy-stm32/latest/features |
| **ESP-IDF OTA** (doctrine reference) | staged commit: write inactive slot → verify → atomically flip `otadata` (sequence counter survives power-cut) → boot in `PENDING_VERIFY` → app must `esp_ota_mark_app_valid_cancel_rollback()` else any reset ⇒ ABORTED + fallback | n/a | n/a | https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/ota.html |
| **fiducial-ota** | closest to our engine: 43-byte ed25519-signed manifest commits image by SHA-256 **before any flash write** ("a bad offer costs zero flash writes"); resumable idempotent transfer (duplicate chunks ACKed); `TrialState` boot budget; `mark_booted(self_test_passed)` — *booting ≠ healthy*; pure state machine, host-unit-testable | yes, no alloc | (STM32WL PKA example) | https://lib.rs/crates/fiducial-ota |
| esp-hal-ota / esp-ota / embedded-update | variants: CRC32 **read-back verify before activation** (esp-hal-ota); drogue "embedded-update" serial protocol lib pairing with embassy-boot | yes (except esp-ota) | n/a | https://lib.rs/crates/esp-hal-ota , https://lib.rs/crates/embedded-update |

("swarm-router" does not exist on crates.io/lib.rs; nearest drone finds are unrelated OTA-less
DTO crates.)

**Doctrine mapping for conwrt:**
- *Our switch-rescue side* already follows the "verify fully before granting write access" school
  (host sha pre-gate + on-box `sha256sum` gate before `sysupgrade`; `Bytes transferred = N` and
  `iminfo` as size/header gates — watch.rs `StreamChunks`/`TftpBoot`). Steal two additions from
  fiducial-ota/MCUboot: (1) **idempotent resume semantics** — duplicate/resent chunks ACKed, not
  rejected (flaky-link live-lock avoidance); (2) a **confirmation budget**: treat the switch's
  post-sysupgrade state as a *trial* — require a positive health signature (new-version boot
  line) within a budget, else automatically re-arm the rescue recipe (our `max_fires`/
  `cooldown_secs` machinery already approximates this; make it an explicit trial/confirm state).
- *The STM32's own firmware*: A/B via rustBoot (F746 board exists) or embassy-boot-stm32; both
  give power-fail-safe swap + rollback so a botched rescue-engine update can't brick the
  supervisor.

### Q5 — Embedded expect/console-interaction libraries

**No crate — embedded or host — provides a declarative, transport-agnostic expect/send
conversation engine.** The landscape splits in two:

- **atat** 0.25.0 ( https://github.com/FactbirdHQ/atat , https://docs.rs/atat ) — no_std,
  heapless-based. Architecture worth stealing: an `Ingress` task reads any
  `embedded_io_async::Read` and feeds a pluggable **`Digester` trait** (byte-fed state machine →
  classified `DigestResult`: response vs unsolicited URC vs custom error); digested items go to a
  response slot / pub-sub channel; `Client` sends `AtatCmd` with **per-command `timeout_ms`**;
  docs literally prescribe "create a state machine … (idle, waiting_response, data_mode)". But:
  one-command-in-flight, AT-line-oriented, hard deps on embassy-time/sync/futures — **reuse the
  shape, not the crate**.
- **expectrl** 0.9 ( https://github.com/zhiburt/expectrl ) and **rexpect** 0.7.1 (
  https://crates.io/crates/rexpect ) — the right *API surface* (`expect(pattern)` with
  literal/Regex/Eof pattern enum, `send_line`, timeouts) but std+pty/process-bound. Mirror the
  naming/ergonomics, don't link it.
- PPP/chat-scripts: dead end in Rust — the `ppp` crate is HAProxy PROXY-protocol (not PPP),
  `pppos` doesn't exist, no `chat(8)` port exists.
- **Matchers for the rolling window:** **memchr** 2.8.3 (no_std, `default-features=false`;
  `memmem::find(haystack, needle)` and prebuilt `memmem::Finder` — core-only, no alloc;
  https://docs.rs/memchr ) replaces our hand-rolled `windows().any()` (`contains()` watch.rs:576,
  uboot.rs:121/132, detect.rs:78) with SIMD on host and a fast portable path on F7.
  **aho-corasick** 1.1.5 (no_std *with* alloc; https://docs.rs/aho-corasick ) scans a whole
  marker *set* in one pass — good for multi-trigger scanning on host/alloc builds.
- **Transport seam:** `embedded-hal-async` 1.0 has **no serial traits** — the sanctioned seam for
  a byte-stream console is **`embedded-io` / `embedded-io-async` `Read`/`Write`**
  ( https://docs.rs/embedded-io-async ), which is exactly what atat's ingress consumes. Our
  `ConsoleIo` (io.rs:162 — read/`write_all_bytes`/`reset_input_buffer`/close, `Ok(0)` = idle not
  EOF) is semantically aligned already; a no_std variant should return its own error enum instead
  of `std::io::Result`.

**Verdict:** keep our in-process engine (we found none on the host side either — confirmed), but
re-found it as an **atat-style byte-fed state machine**: inputs = bytes + ticks, outputs =
writes/events/`next_deadline`, matcher = `memmem::Finder`, patterns limited to literals (expectrl
shows the enum surface if we ever want regex/EOF).

### Q6 — Cleanup-by-adoption scan (adopt NOW, with exact feature flags)

| Concern | Adopt | Version | Flags for no_std | Notes |
|---|---|---|---|---|
| sha256 | **sha2** (RustCrypto) | 0.11.1 (2026-10-12) | `default-features = false` (0.11 has no `std` feature at all; core-only) + pin `digest` 0.11 | M7 has no SHA accelerator ⇒ compact-II soft path regardless; `asm` feature is x86/aarch64 only. https://crates.io/crates/sha2 , https://crates.io/crates/digest |
| CRC32 (per-chunk) | **crc32fast** | 1.5.3 (2026-10-20) | `default-features = false` | CPU detection is std-gated; F7 compiles slicing-by-8 portable path. https://crates.io/crates/crc32fast . Keep hand-rolled `crc16_xmodem` (uboot.rs:161 — `crc16` crate is unmaintained since 2018). `crc` 3.4 only if configurable poly needed; **crc-any needs alloc — skip** |
| byte-window matching | **memchr** | 2.8.3 | `default-features = false` (`memmem` core-only) | replaces `windows().any()` scans. https://crates.io/crates/memchr . `twoway` is deprecated ("use memchr"); aho-corasick only with alloc |
| fixed-size buffers / windows | **heapless** | 0.9.3 | no_std by design, `serde` feature for String/Vec impls | `HistoryBuf` (write-only ring — the rolling console window), `Deque`, `spsc::Queue`, `String`+`format!`. Tracks latest stable Rust (no fixed MSRV). https://docs.rs/heapless |
| recipe blob codec | **postcard** | 1.1.3 | default is no_std/no-alloc (heapless out of the box) | `to_vec_crc32`, COBS framing, schema tooling. https://docs.rs/postcard |
| hex encoding | `hex` 0.4.3 *or* nothing | — | `default-features = false` (`encode_to_slice`) | prefer comparing raw digest bytes on target, or `heapless::String` + `write!({:02x})`; skip the dep if possible. https://crates.io/crates/hex |
| target logging | defmt 1.2 + defmt-rtt 1.3 | — | no_std | replaces `eprintln!` in engine logs. https://crates.io/crates/defmt |
| target executor/HAL | embassy-executor 0.10, **embassy-stm32 0.6** (stm32f746 features confirmed), static_cell 2.1 | — | no_std | when target work starts. https://docs.rs/crate/embassy-stm32/latest/features |

---

## (b) Portability plan

Architecture: **one workspace, three layers** —
`conwrt-core` (no_std, sans-io engines, heapless-typed model, `next_deadline` outputs) ·
`conwrt-std` shell (current CLI: serialport-rs, std::fs, threads, serde_json) ·
`conwrt-embassy` shell (later: embassy-stm32 + embassy-net UDP + embedded-io-async UART + defmt).
Host-only glue that **stays in the std shell**: all of `io.rs` transports
(SerialPortIo/TcpIo/ReplayIo), transcript & fired-marker files, `TftpServerGuard` thread, image
reads via `std::fs`, `chrono_local`, CLI arg parsing.

### P0 — extract now (unblocks everything, all testable on host)

1. **`tftp-core`: pure session state machine** (from tftp.rs `serve_one` :86–195).
   `struct Session { state, block, blksize, retries, last_pkt }`;
   `fn on_packet(&mut self, pkt: &[u8], peer: Tid, now: Tick) -> Step` +
   `fn on_timeout(&mut self, now) -> Step` where
   `Step { send: Option<&[u8]>, done: bool, next_deadline: Option<Duration> }`.
   Data source = `&[u8]` image or smolapps-style `Handle` read trait (flash-backed on target).
   Move codecs (:21–81) in verbatim; promote to core tests: OACK-consume-block-0 (:126–143),
   zero-length terminating block (:176–192), WRQ refusal, safe-name, blksize clamp 8..=65464.
   Std shell keeps `serve_until` wrapping a `UdpSocket`; embassy shell later wraps
   `UdpSocket::recv_from/send_to` (Q1 pattern). Packets: replace `Vec<u8>` builds with
   `heapless::Vec<u8, 516>` (blksize>512 ⇒ size on max negotiated, or 65464+4 when OACK
   enabled — parameterize `const N`).
2. **`watch-core`: event-driven supervisor/recipe engine.** Convert `Supervisor::read_secs`/
   `expect`/action loop (watch.rs:599–658, 685–1054) into a state machine fed
   `Event::Bytes(&[u8]) | Event::Tick(Tick)` and emitting `Output { write: Option<&[u8]>,
   log, next_deadline }`. Rolling window: `heapless::HistoryBuf<u8, 32768>` (replaces Vec +
   drain at :616–619). Matcher: `memchr::memmem::Finder` per literal (triggers, prompts,
   markers). Telnet codec (:35–160) moves to core with `heapless::Vec` pending/raw_tail
   (keep the incomplete-tail parser and the property test — they're portability gold).
3. **`ymodem-core`: buffer-based frames + handshake FSM.** `crc16_xmodem` (uboot.rs:161) and
   `parse_total_size` (:312) move as-is (core-compatible); `build_frame` (:178) becomes
   `build_frame_into(buf: &mut [u8; 1029])`. `loady_ymodem` (:225–309) becomes an FSM over
   `(byte, now)` with states WaitC → Block0 → Data{n} → Eot → NullBatch — preserve the
   loader-dependent ACK-before-C acceptance (:250–268) and the EOT-ACK tracking (audit R7,
   :288–306). Error type: own enum + `core::error::Error` (drop `std::error::Error` :72).
4. **`model`: heapless-typed Recipe** per Q2 — same file, dual-format serde derive; host JSON
   unchanged; add `format_version`; `validate()` splits into format checks (portable) vs
   existence checks (host-only — `Path::exists` watch.rs:416/432/453 stays in shell).

### P1 — adopt now (makes the port a re-compile)

5. Swap `contains()` scans → `memchr::memmem::Finder`; swap Vec windows/buffers → `heapless`
   (`HistoryBuf`, `Vec`, `String`); adopt `sha2`/`crc32fast` with `default-features=false`
   behind our `image_sha256`/gate shims (tftp.rs:222, watch.rs:1071) so host and target share
   one digest path; add crc32fast per-chunk CRC to `StreamChunks` markers (cheap incremental
   integrity between sha gates).
6. Introduce the `embedded-io`-shaped transport trait in core (own error enum; `Ok(0)`=idle
   contract preserved); implement it for the existing std transports in the shell. This is the
   single seam the embassy shell plugs its UART into.

### P2 — target phase (later, no host churn)

7. `conwrt-embassy` shell: embassy-stm32 (stm32f746 feature) + embassy-time (`Ticker::every` for
   `pace_ms`/`pause_ms`; `with_deadline` for expects) + embassy-net UDP socket on :69 wrapping
   `tftp-core` + defmt logging; images and compiled postcard recipes in internal flash /
   SD. Recipes flow: `conwrt recipe compile` (host) → postcard+CRC32 blob.
8. Supervisor's own firmware: rustBoot (stm32f746 board target exists) or embassy-boot-stm32 for
   A/B + rollback; adopt the fiducial-ota trial/confirmation doctrine for the switch-rescue
   state machine (health signature required after sysupgrade, else re-arm).

**What explicitly does NOT move:** serialport-rs, std::net, std::fs, threads, `Instant`/
`thread::sleep` calls (replaced by `next_deadline` at the core boundary), `OsString`/`Path`
handling, transcript persistence, serde_json (host only), thiserror's std usage in shell errors.

---

## (c) Top-5 adopt-now crates

1. **heapless** 0.9 (`serde` feature) — https://crates.io/crates/heapless — `HistoryBuf` rolling
   windows, `String`/`Vec` recipe fields, `spsc` queues; the container vocabulary of the core.
2. **memchr** 2.8 (`default-features=false`) — https://crates.io/crates/memchr — `memmem::Finder`
   literal matching for triggers/prompts/markers; core-only, host SIMD for free.
3. **postcard** 1.1 (+ postcard-schema on host) — https://crates.io/crates/postcard — compiled
   recipe blobs (`to_vec_crc32`), alloc-free `from_bytes` into heapless types on F7.
4. **sha2** 0.11 + `digest` 0.11 (`default-features=false`) — https://crates.io/crates/sha2 —
   the sha-gate primitive, identical code path host/target.
5. **crc32fast** 1.5 (`default-features=false`) — https://crates.io/crates/crc32fast — per-chunk
   CRC complement to the sha gates (fast, incremental, tiny on M7).

Runner-ups (adopt at target time): `embedded-io`/`embedded-io-async` (transport seam),
`embassy-time` (pacing), `defmt`+`defmt-rtt` (logging), `embassy-stm32` (stm32f746 confirmed),
`portable-atomic`, `governor` (only if true rate-limiting beyond fixed pacing appears).

---

### Source-file anchors (our code)

- tftp.rs: codecs :21–81; `serve_one` :86–195 (OACK block-0 :126–143; zero-block :176–192);
  `serve_until` :199–218; loopback e2e test :262–307.
- watch.rs: telnet codec :35–160; `Action`/`Recipe` :229–377; `validate` :383–485;
  `Supervisor::read_secs` :605–625; `expect` :641–657; `TftpServerGuard` :671–683; action loop
  :685–1054 (pacing sleeps :929/:954/:1011); `run_watch` :1077–1221 (fired marker :1126–1145).
- uboot.rs: `read_for` :74–96; `break_to_prompt` :112–142; `crc16_xmodem` :161–174;
  `build_frame` :178–189; `loady_ymodem` :225–309; `parse_total_size` :312–326.
- detect.rs: `classify` :92–114 (already pure); `read_secs` :55–76.
- io.rs: `ConsoleIo` :162–185; std transports :189–509.

### Research provenance summary

smoltcp examples/API: github.com/smoltcp-rs/smoltcp (+tree/main/examples, PR #342) ·
docs.rs/smoltcp (socket/udp, iface/Interface). smolapps: github.com/plorefice/smolapps (src/tftp,
src/wire/tftp.rs). ttftp: docs.rs/ttftp. async-tftp: github.com/oblique/async-tftp-rs. tftp-ro:
github.com/gridbugs/tftp-ro. embassy UDP example: embassy-rs/embassy examples/rp
ethernet_w5500_udp.rs; embassy-net README. Serialization: docs.rs/{serde_json,postcard,
postcard-schema,serde-json-core,miniconf,ciborium,serde_cbor,minicbor,heapless};
github.com/pyfisch/cbor (archived); github.com/jamesmunns/postcard. Time/pacing:
docs.rs/{embassy-time,cortex-m,rtic-monotonics,portable-atomic,fugit,quanta};
docs.rs/governor + github.com/boinkor-net/governor. OTA: github.com/mcu-tools/{mcuboot,mcuboot-rs};
github.com/nihalpasham/rustBoot; docs.rs/embassy-boot-stm32 + embassy-stm32 features;
docs.espressif.com (ESP-IDF OTA); lib.rs/crates/fiducial-ota, esp-hal-ota, embedded-update;
github.com/Gessler-GmbH/smp-rs; github.com/Finomnis/mcumgr-toolkit. Expect/console:
github.com/FactbirdHQ/atat + docs.rs/atat; github.com/zhiburt/expectrl; crates.io/crates/rexpect;
docs.rs/{memchr,aho-corasick,embedded-io-async}. Adoption scan: crates.io JSON API + docs.rs for
{sha2,digest,crc32fast,crc,crc-any,memchr,towoway→twoway,heapless,hex,defmt,defmt-rtt,
embassy-executor,embassy-stm32,static_cell,portable-atomic}. Fetch-failure disclosure: crates.io
HTML pages and GitHub search UI are JS-only — the crates.io `/api/v1` endpoints, docs.rs, and
GitHub raw/contents-API were used instead; all URLs above were successfully retrieved.
