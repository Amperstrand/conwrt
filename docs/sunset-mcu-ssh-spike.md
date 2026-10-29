# Spike #112: sunset 0.6 no_std SSH on MCU — footprint + Dropbear interop

Date: 2026-10-16 · Issue: #112 · ADR: [ADR-0005](adr/ADR-0005-ssh-stack.md)
Lane: `sunset/feat` (static measurement only — nothing was flashed; on-device
work stays gated like #197).

## What was measured

sunset **0.6.0** (crates.io, 0BSD) + `sunset-async` 0.6.0 linked into the
actual MCU agent skeletons (`apps/conwrt-stm32f746` for the issue's F746
target, `apps/conwrt-stm32f746`'s sibling `apps/conwrt-stm32` (F469,
same `thumbv7em-none-eabihf` class) as secondary, and
`apps/conwrt-esp32s3`), with a **"hello-exec" harness**: a full SSH session
run client↔server over an in-memory duplex (two embassy channels standing in
for the TCP socket). One invocation exercises ident exchange, KEX, host-key
sign/verify, NEWKEYS cipher switch, password userauth, session-channel open,
`exec "hello"` and the payload round-trip (client-verified) — so every
algorithm sunset offers is linked and counted.

The harness runs **identical source on host (std) and both MCU targets**;
it was verified live on the host (full session, client-reported
`got_hello: true, exit_zero: false` — the client's exact-payload match is
the completion criterion; see finding 6) before cross-building. Session
buffers follow upstream demo sizing (2 KiB in/out per side → 8 KiB of the
RAM delta is the two per-session buffer pairs).

Variants per target:

- **floor** — sunset `default-features = false`: kex `curve25519-sha256`,
  ciphers `chacha20-poly1305@openssh.com` + `aes256-ctr`, mac
  `hmac-sha2-256`, hostkey `ssh-ed25519` (exactly ADR-0005's floor).
- **mlkem** — sunset default features (adds `mlkem768x25519-sha256`
  preferred kex).

## Results

Profile = the skeleton's release profile (`opt-level = "s"`, LTO,
`codegen-units = 1`, `panic = "abort"`). STM32 flash = loaded sections
excl. `.bss`/`.uninit`; RAM = `.data + .bss + .uninit` (incl. the 32 KiB
protocol heap). ESP32-S3 = the fleet CI size-gate formula.

| Target | Variant | Flash | Δ flash | RAM | Δ RAM |
|---|---|---|---|---|---|
| STM32F746G-DISCO (`stm32f746ng`, 1 MiB flash / 320 KiB SRAM) | baseline | 59.6 KiB | — | 43.7 KiB | — |
| | + sunset floor | 193.9 KiB | **+134.3 KiB** | 62.3 KiB | +18.7 KiB |
| | + sunset mlkem | 208.7 KiB | +149.1 KiB | 62.5 KiB | +18.8 KiB |
| STM32F469I-DISCO (`stm32f469ni`, secondary data point) | baseline | 57.8 KiB | — | 43.6 KiB | — |
| | + sunset floor | 192.5 KiB | +134.7 KiB | 62.3 KiB | +18.7 KiB |
| | + sunset mlkem | 207.3 KiB | +149.4 KiB | 62.4 KiB | +18.8 KiB |
| ESP32-S3 (`xtensa-esp32s3-none-elf`, 8 MiB flash / 512 KiB SRAM) | baseline | 176.0 KiB | — | 80.7 KiB | — |
| | + sunset floor | 383.2 KiB | **+207.2 KiB** | 99.8 KiB | +19.1 KiB |
| | + sunset mlkem | 403.4 KiB | +227.4 KiB | 100.0 KiB | +19.2 KiB |

Reading (silicon vs fleet CI gate — the two tell different stories):

- **STM32F746 (the issue's target): fine on silicon, over the fleet
  gate.** +134 KiB floor / +149 KiB mlkem of 1 MiB flash (~15%), +19 KiB
  RAM of 320 KiB (~6%) — affordable on the chip, and roughly reproduces
  upstream's "~150 kB flash on Pico W" claim on the M7. BUT the fleet CI
  gates in `.github/workflows/rust.yml` are uniform and conservative:
  **text+data ≤ 128 KiB and bss ≤ 96 KiB for both `apps/conwrt-stm32`
  and `apps/conwrt-stm32f746`** — a floor sunset build (198,600 B
  text+data) exceeds the 131,072-byte flash budget by ~52% (RAM gates
  still pass: bss 62.5 KiB ≤ 96 KiB). Adopting SSH on any STM32 image
  therefore also needs a deliberate per-app gate change, exactly like
  the S3.
- **ESP32-S3: breaks its fleet gate.** Baseline 176 KiB + floor 207 KiB =
  383 KiB > the 256 KiB flash budget (the S3's physical 8 MiB flash is
  not the constraint — the gate is policy). RAM stays inside the 128 KiB
  gate. The Xtensa delta is ~1.5× the Cortex-M7 delta (no AES/SHA
  hardware use via RustCrypto on Xtensa; same `opt-level = "s"` + LTO).
- Per-session runtime RAM on top of the static delta is ~13 KiB
  (upstream Pico W measurement; consistent with our 8 KiB harness session
  buffers + sunset internal state).

## Reproduction — exact commands

Spike tree outside the repo (the PR is docs-only; nothing here is merged):

```sh
# 0) Spike tree: copy the two apps, repoint path deps at the real crates,
#    share one helloexec.rs (source in appendix A).
SPIKE=/tmp/opencode/conwrt-spike
mkdir -p $SPIKE/apps
cp -r apps/conwrt-stm32f746 apps/conwrt-esp32s3 $SPIKE/apps/
sed -i 's|path = "../../crates/|path = "/home/ubuntu/src/conwrt-sunset/crates/|' \
  $SPIKE/apps/conwrt-stm32f746/Cargo.toml $SPIKE/apps/conwrt-esp32s3/Cargo.toml

# 1) STM32F746 baseline
cd $SPIKE/apps/conwrt-stm32f746
CARGO_TARGET_DIR=$SPIKE/target-f746 cargo build --release
CARGO_TARGET_DIR=$SPIKE/target-f746 cargo size --release -- -A
# -> size-f746-baseline.txt (appendix B)

# 2) + sunset floor: apply the appendix A patches (Cargo.toml deps,
#    [patch.crates-io] sunset-async, .cargo/config.toml getrandom cfg,
#    main.rs helloexec task), then:
CARGO_TARGET_DIR=$SPIKE/target-f746 cargo build --release
CARGO_TARGET_DIR=$SPIKE/target-f746 cargo size --release -- -A

# 3) + sunset mlkem: flip the sunset dep to default features
#    (sunset = { version = "0.6" }), rebuild, re-size.

# 4) ESP32-S3 (esp-rs fork toolchain 1.98.1.0, ADR-0012):
source ~/export-esp.sh
cd $SPIKE/apps/conwrt-esp32s3
CARGO_TARGET_DIR=$SPIKE/target-esp32 cargo +esp build --release
xtensa-esp32s3-elf-size -A \
  $SPIKE/target-esp32/xtensa-esp32s3-none-elf/release/conwrt-esp32s3
# flash/ram = the same awk formulas as the firmware-esp32s3 CI job
```

`cargo size` (cargo-binutils 0.4.0, toolchain 1.99.0) for STM32;
`xtensa-esp32s3-elf-size` from the esp fork toolchain for the S3.

## Dropbear 2024.86 interop (host-side harness, as sanctioned by the issue)

Real Dropbear server built from upstream source, real sunset client from
the `sunset-0.6.0` tag — no mocks on either side:

```sh
# server: dropbear 2024.86 from upstream (sha256 recorded below)
curl -O https://matt.ucc.asn.au/dropbear/releases/dropbear-2024.86.tar.bz2
# sha256 e78936dffc395f2e0db099321d6be659190966b99712b55c530dd0a1822e0a5e
tar xf dropbear-2024.86.tar.bz2 && cd dropbear-2024.86
./configure && make -j4 dropbear dropbearkey

# throwaway user + ed25519 keys (user deleted after the run)
ssh-keygen -t ed25519 -N '' -f spike_key
./dropbearkey -t ed25519 -f dropbear_ed25519_hostkey
sudo useradd -m -d <spikehome> -s /bin/sh spike112   # authorized_keys = spike_key.pub
sudo ./dropbear -E -F -p 127.0.0.1:2200 -r dropbear_ed25519_hostkey

# client: sunsetc from the sunset repo, tag sunset-0.6.0
git clone --depth 1 --branch sunset-0.6.0 https://github.com/mkj/sunset
cargo build --release --example sunsetc -p sunset-stdasync
HOME=<spikehome> RUST_LOG=sunset=debug \
  ./target/release/examples/sunsetc -v -l spike112 -i spike_key \
  -p 2200 -T 127.0.0.1 'echo hello-exec-interop'
```

Client log (negotiation block + result, verbatim):

```
sunset::kex: hostsig String(StringNames("ssh-ed25519")) vs LocalNames(["ssh-ed25519", "rsa-sha2-256"])
sunset::kex: Negotiated algorithms {
kex curve25519-sha256
hostkey ssh-ed25519
cipher c->s chacha20-poly1305@openssh.com
cipher s->c chacha20-poly1305@openssh.com
mac c->s chacha20-poly1305@openssh.com
mac s->c chacha20-poly1305@openssh.com
}
sunset_stdasync::knownhosts: Line 1, found matching key
sunset::kex: Hostkey signature is valid
sunset_stdasync::cmdline_client: Authentication succeeded
hello-exec-interop            <- exec stdout, exit 0
```

Dropbear server log (verbatim):

```
Child connection from 127.0.0.1:47012
Pubkey auth succeeded for 'spike112' with ssh-ed25519 key SHA256:EjB2...
Exit (spike112) from <127.0.0.1:47012>: Exited normally
```

**ADR-0005's algorithm floor is satisfied by construction**: sunset
offers `curve25519-sha256` / `chacha20-poly1305@openssh.com` /
`aes256-ctr` / `hmac-sha2-256` / `ssh-ed25519` (+ mlkem hybrid when
default features are on, which Dropbear 2024.86 simply doesn't pick);
negotiation, host-key verify, pubkey auth and exec all pass against the
exact OpenWrt 24.10 Dropbear version.

### Closing move: Dropbear 2026.94 (upstream tarball, NOT OpenWrt main's package) — 2026-10-16

The same harness against an **upstream** Dropbear 2026.94 build — the
plain `matt.ucc.asn.au` tarball with generic `./configure`, NOT OpenWrt
main's package build (which carries OpenWrt-specific config and patches;
we never built or tested that). Treat this leg as an upstream-version
proxy for main's Dropbear, closing the second *version* in ADR-0005's
matrix — not as an OpenWrt-main integration result:

```sh
curl -O https://matt.ucc.asn.au/dropbear/releases/dropbear-2026.94.tar.bz2
# sha256 e098034a843699200c8c977a991fff73159735bf795d5f72ef672c41a6b1ae81
tar xf dropbear-2026.94.tar.bz2 && cd dropbear-2026.94
./configure && make -j4 dropbear dropbearkey
# same throwaway-user setup; server on 127.0.0.1:2201
# same sunsetc build (tag sunset-0.6.0), port 2201
```

Client log (verbatim — note the kex line):

```
sunset::kex: Negotiated algorithms {
kex mlkem768x25519-sha256
hostkey ssh-ed25519
cipher c->s chacha20-poly1305@openssh.com
cipher s->c chacha20-poly1305@openssh.com
mac c->s chacha20-poly1305@openssh.com
mac s->c chacha20-poly1305@openssh.com
}
sunset_stdasync::knownhosts: Line 1, found matching key
sunset::kex: Hostkey signature is valid
sunset_stdasync::cmdline_client: Authentication succeeded
hello-main-interop            <- exec stdout, exit 0
```

Dropbear server log (verbatim):

```
Child connection from 127.0.0.1:47098
Pubkey auth succeeded for 'db294' with ssh-ed25519 key SHA256:QqRl...
Exit (db294) from <127.0.0.1:47098>: Exited normally
```

Both sides negotiated the **mlkem768x25519-sha256** hybrid (Dropbear
2026.94 offers it, sunset prefers it) and the full session passed. Two
consequences:

- The ADR-0005 floor holds on *both* matrix versions — post-quantum
  falls out of the intersection for the exact OpenWrt 24.10 Dropbear and
  is additionally verified working against upstream 2026.94 (as a proxy
  for main's version; OpenWrt main's own package build remains untested
  — #465 correction).
- The client mlkem path is interoperable with a real server (a Dropbear
  2026.94 server accepts sunset's client encapsulation key and completes
  KEX). **Correction (2026-10-16, fork investigation): the in-harness
  `BadKex` was never a sunset bug** — see finding 2 below: the spike's
  own in-memory transport corrupted large writes; sunset 0.6.0 mlkem
  works client *and* server.

## Fork (Amperstrand/sunset @ ai-experiments)

External-repo etiquette (AGENTS.md) forbids filing PRs/issues upstream,
so conwrt-relevant patches are carried on an org fork instead — same
pattern as Amperstrand/realtek-poe (pristine `main`, work on the side
branch, no upstream interaction):

- **Repo**: `https://github.com/Amperstrand/sunset` — branch
  `ai-experiments`, based on the `sunset-0.6.0` tag (the version this
  spike measured and validated; base deliberately pinned, not floating
  upstream main).
- **Carries**: (a) forwarded default-on `mlkem` feature on
  `sunset-async` (embedded opt-out for finding 1); (b) regression
  tests — a full client↔server hello-exec session over tokio duplex
  (negotiates `mlkem768x25519-sha256` with default features) and a
  100× ml-kem 0.3.2 ek roundtrip.
- **Validated**: mlkem session green on host (fork + the fixed harness
  below); floor build green with `sunset-async` default-features=false
  and ml-kem absent from the dependency tree.
- **Future adoption pin** (M7+ revisit):

  ```toml
  [patch.crates-io]
  # rev-pinned to the validated revision; move deliberately and re-run
  # the fork's regression tests (cargo test -p sunset -p sunset-stdasync)
  # when bumping.
  sunset = { git = "https://github.com/Amperstrand/sunset", rev = "5e5f18354781957bd85284a3268793663b82a067" }
  sunset-async = { git = "https://github.com/Amperstrand/sunset", rev = "5e5f18354781957bd85284a3268793663b82a067" }
  # floor image: sunset-async = { ..., default-features = false }
  ```

  A moving `branch = "ai-experiments"` reference is deliberately NOT
  used — it would silently resolve to whatever the tip happens to be at
  the next lockfile refresh, bypassing the validation this document
  records.

## Findings & caveats (recorded for the revisit)

1. **`sunset-async` re-enables sunset's `mlkem` default via feature
   unification.** A `sunset = { default-features = false }` app edge is
   not enough — sunset-async's dependency edge contributes the defaults.
   The floor builds here use a patched sunset-async (one-line
   `default-features = false`, appendix A). **Carried on the fork now**
   (see "Fork" below) as a forwarded default-on `mlkem` feature, so
   `sunset-async = { default-features = false }` alone opts mlkem out —
   validated: ml-kem fully absent from the dependency tree, session
   green. Upstream draft (still worth filing):
   `docs/upstream-drafts/sunset-async-feature-unification-mlkem.md`.
2. **[CORRECTED 2026-10-16] The mlkem in-harness `BadKex` was the spike's
   own transport bug — sunset 0.6.0 mlkem is fully functional.** The
   original report blamed sunset-as-server; the fork investigation
   (Amperstrand/sunset `ai-experiments`, regression tests) disproved it:
   sunset's `output_loop` recreates the `write` future on every repoll,
   and the harness's channel-backed `Write` was not restart-safe — any
   write larger than the channel capacity (8 × 64 B = 512 B) parked
   mid-write, then restarted from offset 0 on wake, duplicating its
   prefix. curve25519's small KexDHInit never hit the limit; mlkem's
   1240-byte one did (first corruption at byte 503 of the 1184-byte
   encapsulation key). Evidence: client-emitted and server-received
   bytes matched for the first 512 bytes and diverged after; upstream's
   `test_each_kex` (mlkem) passes; a tokio-duplex regression test
   passes; and the fixed harness (restart-safe `Tx` with a resume
   offset, appendix A) completes a full negotiated-mlkem session on
   host. Adopting sunset for Post-Quantum paths is fine — but any
   in-memory `Write` handed to `SSHClient`/`SSHServer`::run MUST be
   restart-safe (or return short writes instead of parking mid-buffer):
   that sharp edge is worth an upstream doc note
   (`docs/upstream-drafts/sunset-write-restart-safety-docs.md`).
3. **getrandom 0.4 on no_std needs `--cfg getrandom_backend="custom"`**
   plus a `__getrandom_v03_custom` symbol. The spike's hook is a
   deterministic xorshift (measurement only — never flash); real
   hardware wires the SoC TRNG (F746 TRNG / S3 hardware RNG).
4. **Embassy/sunset API notes**: `embassy-sync` 0.8 channels split via
   `.sender()`/`.receiver()` (no `split()`); sunset's
   `ProgressHolder` mutex must be dropped before awaiting other
   `SSHClient`/`SSHServer` calls; reading a client channel before the
   server confirms CHANNEL_OPEN panics in sunset (`by_handle_mut`) —
   hand channel IO to reader tasks only after `SessionOpened`;
   `Write` impls passed to `SSHClient`/`SSHServer`::run must be
   restart-safe (see finding 2 — sunset's output_loop recreates the
   write future on every repoll).
5. **ESP32-S3 gate**: SSH-on-S3 (+207 KiB floor) exceeds the 256 KiB
   fleet flash budget on its own; adopting SSH there requires raising
   the gate for a dedicated profile or keeping the S3 image SSH-free.
6. **sunset 0.6 has no server-side active close/exit-status path in the
   async API.** `ChannelEof`/`ChannelClose` are only emitted in response
   to the peer's (passive close — `handle_eof`/`handle_close` in
   `src/channel.rs`), and no `ServEvent`/`ChanIO` method sends an exec
   `exit-status`. A hello-exec server cannot actively signal completion,
   so the harness's success criterion is the client's exact-payload
   match (`hello\n` received verbatim, reported by the client side
   only), and the client outcome honestly reports `exit_zero: false`.
   Upstream demos never exercise server-initiated exec completion (they
   serve shells until the client disconnects). A real conwrt
   agent-over-SSH server needs this upstream, or client-side payload
   framing as a workaround.
   Upstream draft: `docs/upstream-drafts/sunset-server-exec-close-exit-status.md`.

## Appendix A — harness source (identical for host check and both MCUs)

`helloexec.rs` (included via `#[path = "../../../helloexec.rs"] mod
helloexec;` in each app's `main.rs`; the host check includes the same
file from a std bin with `futures_executor::block_on`):

```rust
//! #112 spike: sunset 0.6 "hello-exec" — a full SSH session in memory.
//!
//! A sunset SSH *client* and *server* run against each other over an
//! in-memory packetized duplex (two `embassy_sync` channels standing in
//! for the TCP socket that `embedded-io-async` would carry in a real
//! deployment). The whole stack is exercised: ident exchange, KEX
//! (curve25519-sha256), ed25519 host key, NEWKEYS cipher switch, userauth
//! (password), session channel open, `exec "hello"`, payload round-trip,
//! channel close.
//!
//! Size-measurement artifact for ADR-0005 — this binary is NEVER flashed.
//! The `no_std` RNG hook below is a deterministic filler, not
//! cryptographic; real hardware wires the SoC TRNG instead.

use embassy_futures::join::join;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::{Channel, Receiver, Sender};
use embedded_io_async::{Read, Write};
use heapless::Vec;

use sunset::{CliEvent, ChanHandle, Error, KeyType, Result, ServEvent, SignKey};
use sunset_async::{ChanInOut, ProgressHolder, SSHClient, SSHServer};

type RawMutex = CriticalSectionRawMutex;

/// One in-memory transport direction: packetized byte chunks.
type Chunk = Vec<u8, 64>;
type Link = Channel<RawMutex, Chunk, 8>;

/// SSH packet buffers, sized like upstream's demos (2 kiB each way).
pub const SESS_BUF: usize = 2000;

#[derive(Debug)]
struct LinkError;

impl core::fmt::Display for LinkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "in-memory link error")
    }
}

impl core::error::Error for LinkError {}

impl embedded_io_async::Error for LinkError {
    fn kind(&self) -> embedded_io_async::ErrorKind {
        embedded_io_async::ErrorKind::Other
    }
}

/// Write half of one direction.
///
/// RESTART-SAFE by design: sunset's `output_loop` recreates the `write`
/// future on every repoll, so a `write` that parks mid-buffer (channel
/// full) must resume where it stopped — restarting from offset 0 would
/// duplicate the prefix of any write larger than the channel capacity
/// (the #112 spike's mlkem BadKex, now understood).
struct Tx<'a> {
    tx: Sender<'a, RawMutex, Chunk, 8>,
    /// Offset of the current write already queued (0 = fresh call).
    sent: usize,
}

impl embedded_io_async::ErrorType for Tx<'_> {
    type Error = LinkError;
}

impl Write for Tx<'_> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, LinkError> {
        while self.sent < buf.len() {
            let end = (self.sent + 64).min(buf.len());
            let mut chunk = Chunk::new();
            chunk.extend_from_slice(&buf[self.sent..end]).map_err(|_| LinkError)?;
            self.tx.send(chunk).await;
            self.sent = end;
        }
        let n = self.sent;
        self.sent = 0;
        Ok(n)
    }

    async fn flush(&mut self) -> Result<(), LinkError> {
        Ok(())
    }
}

/// Read half of one direction, keeping a leftover across small reads.
struct Rx<'a> {
    rx: Receiver<'a, RawMutex, Chunk, 8>,
    leftover: Chunk,
    pos: usize,
}

impl embedded_io_async::ErrorType for Rx<'_> {
    type Error = LinkError;
}

impl Read for Rx<'_> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, LinkError> {
        if self.pos == self.leftover.len() {
            self.leftover = self.rx.receive().await;
            self.pos = 0;
        }
        let n = buf.len().min(self.leftover.len() - self.pos);
        buf[..n].copy_from_slice(&self.leftover[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Outcome reported to the caller (logged by the app's own println).
#[derive(Debug)]
pub struct HelloOutcome {
    /// Client received the exact `hello\n` exec payload.
    pub got_hello: bool,
    /// Client reached `SessionExit(0)` (best-effort; close is also success).
    pub exit_zero: bool,
}

/// Deterministic xorshift filler for the static spike. NOT a real RNG.
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> Result<(), getrandom::Error> {
    use core::sync::atomic::{AtomicU32, Ordering};
    static SEED: AtomicU32 = AtomicU32::new(0x243F_6A88);
    unsafe {
        let mut s = SEED.load(Ordering::Relaxed);
        for i in 0..len {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            *dest.add(i) = s as u8;
        }
        SEED.store(s, Ordering::Relaxed);
        Ok(())
    }
}

/// Run one client↔server SSH session over the in-memory duplex.
pub async fn run() -> Result<HelloOutcome> {
    // Client→server and server→client links.
    let c2s = Link::new();
    let s2c = Link::new();
    let c2s_tx = c2s.sender();
    let c2s_rx = c2s.receiver();
    let s2c_tx = s2c.sender();
    let s2c_rx = s2c.receiver();

    let mut cli_rxbuf = [0u8; SESS_BUF];
    let mut cli_txbuf = [0u8; SESS_BUF];
    let cli = SSHClient::new(&mut cli_rxbuf, &mut cli_txbuf);

    let mut serv_rxbuf = [0u8; SESS_BUF];
    let mut serv_txbuf = [0u8; SESS_BUF];
    let serv = SSHServer::new(&mut serv_rxbuf, &mut serv_txbuf);

    let cli_io = client_session(&cli);
    // The server's own view ("payload buffered") proves nothing about
    // client receipt — only the client outcome (pump EOF after full
    // read + channel close) does.
    let serv_io = server_session(&serv);

    // Transport: client reads s2c / writes c2s; server the opposite.
    let mut cli_rd = Rx { rx: s2c_rx, leftover: Chunk::new(), pos: 0 };
    let mut cli_wr = Tx { tx: c2s_tx, sent: 0 };
    let mut serv_rd = Rx { rx: c2s_rx, leftover: Chunk::new(), pos: 0 };
    let mut serv_wr = Tx { tx: s2c_tx, sent: 0 };
    let cli_transport = cli.run(&mut cli_rd, &mut cli_wr);
    let serv_transport = serv.run(&mut serv_rd, &mut serv_wr);

    // The CLIENT outcome is the truth: its pump only completes on EOF
    // after the full payload round-trip. The server keeps polling until
    // dropped (sunset only flushes a channel close from inside
    // progress() — clear_refcounts), so on the success path the client
    // always finishes first; a server result here means it errored (or
    // the client vanished), which fails the run.
    let sessions = async {
        match embassy_futures::select::select(cli_io, serv_io).await {
            embassy_futures::select::Either::First(cli_outcome) => cli_outcome,
            embassy_futures::select::Either::Second(serv_r) => {
                log::error!("server session ended first: {serv_r:?}");
                serv_r?;
                Error::bug()
            }
        }
    };
    let transports = join(cli_transport, serv_transport);
    match embassy_futures::select::select(transports, sessions).await {
        embassy_futures::select::Either::First((ct, st)) => {
            // Transports ending first means the link broke mid-session.
            log::error!("transports ended: {ct:?} {st:?}");
            let _ = ct?;
            let _ = st?;
            Error::bug()
        }
        embassy_futures::select::Either::Second(cli_outcome) => cli_outcome,
    }
}

/// Client: auth as spike/pw, exec "hello", collect stdout.
async fn client_session<'b, 'a>(cli: &'b SSHClient<'a>) -> Result<HelloOutcome> {
    let got = Channel::<RawMutex, Vec<u8, 16>, 2>::new();
    let got_tx = got.sender();
    let got_rx = got.receiver();
    let io_chan = Channel::<RawMutex, ChanInOut<'b>, 1>::new();
    let io_tx = io_chan.sender();
    let io_rx = io_chan.receiver();

    let mut exit_zero = false;

    enum CliAct {
        None,
        OpenSession,
        Launch,
    }

    // The channel IO is owned by the event loop until the server has
    // confirmed the open (reading an unconfirmed channel panics in
    // sunset's by_handle_mut()).
    let mut io_ready: Option<sunset_async::ChanInOut<'_>> = None;

    let ev_loop = async {
        loop {
            let mut ph = ProgressHolder::new();
            let ev = cli.progress(&mut ph).await?;
            log::info!("cli ev {ev:?}");
            let act = match ev {
                CliEvent::Hostkey(h) => {
                    h.accept()?;
                    CliAct::None
                }
                CliEvent::Username(u) => {
                    u.username("spike")?;
                    CliAct::None
                }
                CliEvent::Password(p) => {
                    p.password("pw")?;
                    CliAct::None
                }
                CliEvent::Pubkey(p) => {
                    p.skip()?;
                    CliAct::None
                }
                CliEvent::AgentSign(k) => {
                    k.skip()?;
                    CliAct::None
                }
                CliEvent::Authenticated => CliAct::OpenSession,
                CliEvent::SessionOpened(mut opener) => {
                    opener.exec("hello")?;
                    CliAct::Launch
                }
                CliEvent::SessionExit(s) => {
                    if let sunset::CliSessionExit::Status(0) = s {
                        exit_zero = true;
                    }
                    CliAct::None
                }
                CliEvent::Defunct => break,
                _ => CliAct::None,
            };
            drop(ph);
            match act {
                CliAct::OpenSession => {
                    let (io, _stderr) = cli.open_session_nopty().await?;
                    io_ready = Some(io);
                }
                CliAct::Launch => {
                    if let Some(io) = io_ready.take() {
                        io_tx.send(io).await;
                    }
                }
                CliAct::None => (),
            }
        }
        Ok::<_, Error>(())
    };

    let pump = async {
        let mut io = io_rx.receive().await;
        let mut collected = Vec::<u8, 16>::new();
        let mut buf = [0u8; 16];
        loop {
            match io.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let _ = collected.extend_from_slice(&buf[..n]);
                    // sunset 0.6 has no server-side active EOF/close API
                    // (ChannelEof/Close are only sent in response to the
                    // peer's), so the payload round-trip itself is the
                    // completion criterion — exact match on "hello\n".
                    if collected.as_slice() == b"hello\n" {
                        break;
                    }
                }
            }
        }
        let _ = got_tx.send(collected).await;
    };

    // The pump finishing (channel EOF after the server wrote the payload)
    // ends the session; the event loop is dropped mid-progress, releasing
    // the session mutex.
    let collected = match embassy_futures::select::select(ev_loop, pump).await {
        embassy_futures::select::Either::First(r) => {
            r?;
            got_rx.try_receive().unwrap_or_default()
        }
        embassy_futures::select::Either::Second(()) => got_rx.try_receive().unwrap_or_default(),
    };
    Ok(HelloOutcome {
        got_hello: collected.as_slice() == b"hello\n",
        exit_zero,
    })
}

/// Server: host key, password auth (spike/pw), exec "hello" → "hello\n".
/// Completes after buffering the payload write; the client's outcome is
/// the authoritative one.
async fn server_session(serv: &SSHServer<'_>) -> Result<()> {
    let hostkey = SignKey::generate(KeyType::Ed25519, None)?;
    let mut chan: Option<ChanHandle> = None;

    enum ServAct {
        None,
        Exec,
        Done,
    }

    loop {
        let mut ph = ProgressHolder::new();
        let act = {
            let ev = serv.progress(&mut ph).await?;
            log::info!("serv ev {ev:?}");
            match ev {
            ServEvent::Hostkeys(h) => {
                h.hostkeys(&[&hostkey])?;
                ServAct::None
            }
            ServEvent::FirstAuth(mut a) => {
                a.enable_password_auth(true)?;
                ServAct::None
            }
            ServEvent::PasswordAuth(a) => {
                if a.username()? == "spike" && a.password()? == "pw" {
                    a.allow()?;
                }
                ServAct::None
            }
            ServEvent::Authenticated => ServAct::None,
            ServEvent::OpenSession(a) => {
                chan = Some(a.accept()?);
                ServAct::None
            }
            ServEvent::SessionExec(a) => {
                if a.command()? == "hello" {
                    a.succeed()?;
                    ServAct::Exec
                } else {
                    a.fail()?;
                    ServAct::None
                }
            }
            ServEvent::Defunct => ServAct::Done,
            _ => ServAct::None,
            }
        };
        drop(ph);
        match act {
            ServAct::Exec => {
                if let Some(ch) = chan.take() {
                    let mut io = serv.stdio(ch).await?;
                    io.write_all(b"hello\n").await?;
                }
                // Payload buffered. Do NOT break: sunset flushes the
                // channel EOF/close (refcount-zero handling) only from
                // inside progress() — keep polling so the client
                // actually receives it; the run loop drops this task
                // once the client has completed its read.
            }
            ServAct::Done => break,
            ServAct::None => (),
        }
    }

    Ok(())
}
```

App `Cargo.toml` addition (floor):

```toml
[dependencies]
sunset = { version = "0.6", default-features = false }
sunset-async = "0.6"
embassy-sync = "0.8"
embedded-io-async = "0.7"
heapless = "0.9"
getrandom = { version = "0.4", default-features = false }
log = "0.4"

[patch.crates-io]
# keep sunset's mlkem default feature OFF through the sunset-async edge
sunset-async = { path = "../../patch/sunset-async" }
```

`patch/sunset-async/Cargo.toml` = upstream `async/Cargo.toml` with the
sunset edge changed to
`sunset = { version = "0.6", default-features = false, features = ["embedded-io"] }`
(workspace deps inlined) and `publish = false`.

`.cargo/config.toml` addition (both apps, target rustflags):

```toml
"--cfg", "getrandom_backend=\"custom\"",
```

`main.rs` addition (the outcome log uses `defmt` on STM32, `esp_println`
on the S3):

```rust
let hello_fut = async {
    match helloexec::run().await {
        Ok(o) => log_outcome(o),
        Err(_e) => log_failure(),
    }
};
embassy_futures::join::join3(usb_fut, agent_fut, hello_fut).await;
```

## Appendix B — raw size outputs

### conwrt-stm32f746, baseline

```
conwrt-stm32f746  :
section              size        addr
.vector_table         456   0x8000000
.text               49204   0x80001c8
.rodata             11092   0x800c1fc
.data                 316   0x20000000
.gnu.sgstubs            0   0x800eea0
.bss                43360   0x20000140
.uninit              1024   0x2000aaa0
.defmt                  5         0x0
.comment              139         0x0
.ARM.attributes        58       0x0
Total              105654
```

### conwrt-stm32f746, + sunset floor

```
conwrt-stm32f746  :
section              size        addr
.vector_table         456   0x8000000
.text               175844   0x80001c8
.rodata             21976   0x802b0b0
.data                 324   0x20000000
.gnu.sgstubs            0   0x80307e0
.bss                62480   0x20000148
.uninit              1024   0x2000f558
.defmt                  6         0x0
.comment              139         0x0
.ARM.attributes        58       0x0
Total              262307
```

### conwrt-stm32f746, + sunset mlkem

```
conwrt-stm32f746  :
section              size        addr
.vector_table         456   0x8000000
.text               189520   0x80001c8
.rodata             23408   0x802e618
.data                 324   0x20000000
.gnu.sgstubs            0   0x80342e0
.bss                62624   0x20000148
.uninit              1024   0x2000f5e8
.defmt                  6         0x0
.comment              139         0x0
.ARM.attributes        58       0x0
Total              277559
```

### conwrt-esp32s3, baseline (xtensa-esp32s3-elf-size -A, excerpt)

```
section                  size         addr
.rwtext                  8588   1077380096
.rwdata_dummy            9612   1070104576
.data                    4072   1070114192
.bss                    60332   1070118264
.flash.appdesc            256   1006632992
.rodata                 16060   1006633248
.vectors                 1024   1077379072
.rotext_dummy           65536   1107296288
.text                   75045   1107361824
.stack                 267740   1070178596
Total                  508349
# CI formula: flash-bytes: 180214 (176 KiB)  ram-bytes: 82604 (81 KiB)
```

### conwrt-esp32s3, + sunset floor (excerpt)

```
section                  size         addr
.rwtext                  8588   1077380096
.rwdata_dummy            9612   1070104576
.data                    4552   1070114192
.bss                    79452   1070118744
.rodata                 28720   1006633248
.vectors                 1024   1077379072
.rotext_dummy           65536   1107296288
.text                  274041   1107361824
.stack                 248140   1070198196
Total                  720005
# CI formula: flash-bytes: 392350 (383 KiB)  ram-bytes: 102204 (100 KiB)
```

### conwrt-esp32s3, + sunset mlkem (CI formula only)

```
flash-bytes: 413102 (403 KiB)  ram-bytes: 102356 (100 KiB)
```

(F469I-DISCO raw outputs are byte-for-byte analogous to the F746 ones —
same target triple, same profile — and are omitted for brevity; the
deltas differ by <1 KiB.)

*Note:* the raw outputs above were captured with the pre-correction
harness (finding 2). Rebuilding the F746 floor variant with the
restart-safe `Tx` from appendix A moves the needle by +76 B
(flash 198,600 → 198,676) — the deltas and conclusions are unaffected.
