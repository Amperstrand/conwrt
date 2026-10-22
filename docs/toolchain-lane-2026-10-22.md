# Toolchain lane for the Rust zycast mipsel cross-build (NR7101)

Date: 2026-10-22 · Scope: conwrt worktree `~/src/conwrt-nr7101-detect`
(zycast.rs + conwrt_zycast.rs), informed by the tollgate-module-basic-go
build pipeline. All feed/channel claims below were verified live today.

---

## 1. How tollgate-module-basic-go pins/aligns with OpenWrt's pipeline

The mechanism has three parts (`~/src/tollgate-module-basic-go/`):

**a) Build inside digest-pinned official SDK containers.**
CI builds every arch row of the matrix inside
`openwrt/sdk:<target>-<release>@sha256:<digest>` images. The digests are
pinned per era in `packaging/build-inputs.json`
(`.openwrt_sdk.releases.{apk,ipk}.targets[<target>].digest`):
- apk era = **25.12.x** (primary), ipk era = **24.10** (installed base).
- `packaging/build-env.sh:sdk_image_ref()` resolves target+era → immutable
  image ref; nothing builds against a floating SDK tag.
- The mipsel row of their matrix is exactly our target:
  `{ arch: mipsel_24kc, sdk: ramips-mt7621 }`.

**b) The version-alignment trick: the feed is the toolchain authority.**
The SDK does not pin the language toolchain — the packages feed branch does
(`openwrt/packages` branch `openwrt-<series>`, e.g. `openwrt-25.12`).
`scripts/sdk-go-version.sh` reads the official Go version from two places:
- `print <series>` → feed **branch** Makefile (`lang/golang/...`) = what the
  next point release of that line will build with (alignment target);
- `released <release>` → the **released feed** at
  `downloads.openwrt.org/releases/<rel>/packages/...` = ground truth of the
  digest-pinned SDK image.
- `check` fails CI on drift vs the manifest's `go_per_release` map; `update`
  rewrites it from the live branches. `build-env.sh:sdk_go_version()` then
  feeds every build script one derived value — versions are never guessed.

**c) Two deliberate pins, one audit between them.**
`GO_VERSION` (what the repo's own compile job uses, bumped intentionally) vs
`sdk_go_version` (what the feed uses) — `check` pins the two together for the
release actually in use. Local lane mirrors CI via `scripts/build-sdk-package.sh`
(stage the packaging recipe into the SDK) + a reproducibility harness
(clean-roots byte-identity + reprotest). Note the real shipping package lives
in the FreedomTechFeed/packages feed pinning the repo by SHA; the module repo's
own packaging is test/repro lanes only.

## 2. The right mipsel lane for conwrt zycast

### Verified facts (2026-10-22)

| Fact | Evidence |
|---|---|
| NR7101 = `ramips/mt7621` → arch `mipsel_24kc`, OpenWrt **25** line | `models/zyxel-nr7101.json` (`openwrt.version: "25"`) |
| Feed rust on **openwrt-25.12 = 1.96.0**; **openwrt-24.10 = 1.94.0**; master = 1.96.0 | `raw.githubusercontent.com/openwrt/packages/<branch>/lang/rust/Makefile` `PKG_VERSION` |
| `rust-toolchain.toml` comment ("cross lane will pin 1.94.x matching the OpenWrt SDK") is **wrong twice**: 1.94 is the 24.10 line (and exactly 1.94.**0**, not 1.94.1), and the NR7101's line is 25.12 → **1.96.0** | see above; installed `1.94.1` matches no feed |
| **Upstream rust demoted `mipsel-unknown-linux-musl` to tier 3.** No rustup channel ships its std on ANY version: the 1.85.0 channel manifest still lists the target (29 refs) but marks the `rust-std` component **unavailable** — live `rustup target add` refuses with "component ... unavailable for download" (verified 2026-10-22; the channel-grep "present" reading was wrong — presence refs ≠ per-component availability) — and 1.94.1/1.96.0/1.99.0 have no refs at all (positive control `aarch64-unknown-linux-musl` installable on all) | `static.rust-lang.org/dist/channel-rust-<v>.toml` + live `rustup target add --toolchain 1.85.0` |
| OpenWrt's feed builds rustc + std **from source** for that target anyway — `RUSTC_TARGET_ARCH` is derived from the GNU toolchain triple (`mipsel-openwrt-linux-musl` → `mipsel-unknown-linux-musl`) in `lang/rust/rust-values.mk` | feed source |
| Docker 29.5.3 available on this host; tollgate's lane runs the same way | `docker --version` |
| Workspace MSRV = 1.85 (and `1.85.0` is installed — it is the MSRV verifier, not a mipsel lane: only x86_64 target installed) | `Cargo.toml` `rust-version`; `rustup target list --installed --toolchain 1.85.0` |

**Consequence:** the lane the rust-toolchain.toml comment imagined (a rustup
pin at the feed's version + `rustup target add mipsel-…-musl`) **cannot
exist** — upstream no longer ships std for mipsel musl. The only modern lane
that produces a correct mipsel-OpenWrt binary is the one OpenWrt itself uses:
its own patched rustc + std built inside the SDK.

### Recommended lane (tollgate parity, transposed to Rust)

**Build inside a digest-pinned `openwrt/sdk:ramips-mt7621-<25.12.x>` image
using the feed's `lang/rust` (1.96.0), linking with the SDK's
`mipsel-openwrt-linux-musl-gcc` → static musl binary → scp to the NR7101.**

- Same compiler, libc, and sysroot as any Rust package the 25.12 feed builds —
  "same pipeline as OpenWrt" is literal, not approximate.
- **Zero new rustup toolchains**: the compiler lives in the pinned image; the
  host's numbered pins (1.99.0 host lane, 1.85.0 MSRV) are untouched.
- For a bare scp'd binary you don't even need package staging — just use the
  SDK env (`staging_dir` gcc as `CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_MUSL_LINKER`,
  `--target mipsel-unknown-linux-musl`, static). Stage an `.apk` recipe only
  if/when the sender should become an installable package.
- One-time cost: compiling `lang/rust` inside the SDK is a multi-hour source
  build — cache the built toolchain (tollgate caches per target:
  `apk-sdk-<target>-<release>` cache key; do the same).

**Toolchain-sprawl actions:**
1. `rustup toolchain uninstall 1.94.1` — matches no feed and cannot cross to
   mipsel anyway (no std artifacts). Net count goes **down** by one.
2. Keep: `1.99.0` (host lane A), `1.85.0` (MSRV floor verifier),
   `esp` (xtensa fork, forced — ADR-0012). `stable`/`nightly` are optional
   cleanup candidates for whoever owns them host-wide (check other lanes
   first; `nightly` is only needed by the build-std fallback below).
3. Fix the stale `rust-toolchain.toml` comment when the lane lands: the
   OpenWrt lane is *not* a rustup pin at all — it's "SDK 25.12 image, feed
   rust 1.96.0, built in docker".
4. Port tollgate's audit: a `sdk-rust-version.sh` reading `PKG_VERSION` from
   `openwrt/packages@openwrt-25.12 lang/rust/Makefile` (+ the released feed
   once it lists rust), failing CI on drift vs the pinned SDK era. That
   single script is "the way to align versions".
5. Keep workspace `rust-version` (MSRV) ≤ feed rust (1.85 ≤ 1.96 ✓) so the
   same source can later go into a feed-built package without a version wall.

### Fallback lanes (workable, not recommended)

- **Nightly `build-std`**: `cargo +nightly build -Z build-std=std,panic_abort
  --target mipsel-unknown-linux-musl` + SDK/musl-cross linker. No new
  numbered toolchain, but ad-hoc std builds, a moving nightly pin, and no
  pipeline parity.
- ~~**Pinned 1.85.0 rustup lane** (last channel shipping mipsel-musl std)~~
  **DEAD — correction 2026-10-22 (session 2):** rustup refuses the
  mipsel-musl `rust-std` component on 1.85.0 too ("component unavailable
  for download", verified live). There is NO rustup mipsel-musl lane at
  any version; the SDK docker lane below is the only lane. Methodology
  lesson recorded: grep-presence in the channel manifest is not
  availability — the per-component `available` flag is the truth, and the
  live rustup refusal is the ground truth.

## 3. Does no_std matter here?

**No — for the mipsel build, `std` is correct, not a compromise.** The
NR7101 is a full Linux userspace; ADR-0002 already classifies OpenWrt musl as
Tier B ("constrained std"). no_std would cost sockets/timers and buy nothing.

The existing structure is already right and needs no change:

- **Core encoder** (`crates/conwrt-protocols/src/zycast.rs` outside the
  `#[cfg(feature = "std")]` block): pure `core` byte math — header packing,
  CRC, chunk layout. CI-gated no_std via the thumbv7em-none-eabihf
  `--no-default-features` check on `conwrt-protocols` (Makefile `rust-ci` +
  `rust-nostd-parity` guard vs rust.yml).
- **Sender runtime** (`pub mod sender`, `#[cfg(feature = "std")]`) + the CLI
  bin (`apps/conwrt-cli/src/bin/conwrt_zycast.rs`): std + `socket2`
  (SO_BINDTODEVICE), clap, std::net — correct for a Linux/OpenWrt tool.
- **MCU future**: preserved by the same split xmodem already uses — a future
  embassy/smoltcp MCU sender implements a send-bytes-at-rate driver over the
  identical packet-generation core. The only standing watch item is the
  existing one: don't let socket2/std types leak into the encoder half
  (feature gate enforces it).

One source tree, three consumers: host rustc 1.99.0, SDK feed rust 1.96.0
(OpenWrt), embassy targets — all above the 1.85 MSRV floor.

---

### Evidence index
- `~/src/tollgate-module-basic-go/packaging/build-env.sh` (sdk_image_ref,
  sdk_go_version, GO_VERSION), `packaging/build-inputs.json` (SDK digests,
  go_per_release), `scripts/sdk-go-version.sh` (feed audit), `.github/workflows/build-package.yml`
  (matrix rows incl. mipsel_24kc/ramips-mt7621, `image: openwrt/sdk:…@digest`,
  SDK cache keys)
- Live checks 2026-10-22: openwrt/packages branches `openwrt-25.12` /
  `openwrt-24.10` / `master` `lang/rust/Makefile` (PKG_VERSION 1.96.0 /
  1.94.0 / 1.96.0); `channel-rust-{1.85.0,1.94.1,1.96.0,1.99.0}.toml`
  (mipsel-musl std present only in 1.85.0; aarch64-musl control present in
  all); latest point release 25.12.6 (downloads.openwrt.org)
- conwrt: `rust-toolchain.toml` (1.99.0 pin + stale 1.94 comment),
  `.github/workflows/rust.yml` (no_std gate, esp pin), `Makefile` (rust-ci,
  rust-nostd-parity), `docs/adr/ADR-0002` (tier boundaries),
  `docs/adr/ADR-0012` (esp fork), `models/zyxel-nr7101.json` (ramips/mt7621,
  version "25"), `crates/conwrt-protocols/src/zycast.rs` (no_std core,
  `#[cfg(feature="std")] sender`), `apps/conwrt-cli/src/bin/conwrt_zycast.rs`
- Host state: `rustup toolchain list` (stable, nightly, 1.85.0, 1.94.1,
  1.99.0, esp); installed targets per toolchain; docker 29.5.3

---

## 4. Host-pin policy: numbered pin vs "stable" vs none (research 2026-10-22)

Question raised after the lane fix: org/MCU projects default to 1.99.0 —
keep the numbered pin, switch the string to `"stable"`, or not pin at all?

| Source | Fact (verified 2026-10-22) |
|---|---|
| **embassy-rs/embassy** — the framework conwrt's MCU tier builds on | pins an exact numbered stable in `rust-toolchain.toml`: `channel = "1.92"` + components (`rust-src`, `rustfmt`, `llvm-tools`) + 9 targets; a separate `rust-toolchain-nightly.toml` exists only for nightly CI. Docs: "Embassy requires Rust version 1.92 or later" — pin and MSRV move together, deliberately. |
| **esp-rs/esp-hal** | no repo toolchain pin; the Xtensa lane is fork-locked regardless (espup-installed `esp` toolchain; conwrt at 1.98.1.0 per ADR-0012 — that lane *cannot* follow "stable" even if the org wanted it to). Latest esp-rs/rust tag scheme has moved (`xtensa-v0.2.0`, alpha). |
| **rustup book** (overrides) | a toolchain-file channel resolves per invocation: numbered = frozen, `"stable"` = whatever is stable that day; **no file = host default toolchain**, i.e. an implicit float. |
| Org incident 1 (2026-10-13 cargo-cache writeup, cited in rust-toolchain.toml) | floating "stable" meant every `rustup update` silently recompiled the whole dep tree into the shared machine-wide cache, orphaning the old artifact universe — multiplied across ~30 worktree lanes on this host. |
| Org incident 2 (PR #149, cited in rust.yml) | CI running @stable vs the local numbered pin mismatch broke the no_std gate. |
| Fleet reality (grep of `~/src/*/rust-toolchain.toml`) | 1.99.0 is the dominant pin (13+ repos incl. every conwrt-* and ccid-* MCU lane); outliers: 1.94.1 (fips, tollgate-rs), 1.97.1 (cdk), `"stable"` (embassy-stm32f469i-disco, tmbr-*, tollgate-module-basic-rust). |
| Current stable (host) | **1.99.0** (2026-09-28) — the org pin *is* current stable today; it drifts one step behind every ~6 weeks by design. |
| Community | app/firmware teams pin exact versions for reproducibility; the "clippy-on-stable catches drift" argument is for *libraries* — conwrt is an app+firmware workspace, not a consumed library, so it doesn't apply. The compatibility contract for consumers stays the Cargo.toml `rust-version` MSRV (1.85), not the toolchain file. |

**Verdict: keep the numbered pin `1.99.0`. Do not use `"stable"`. Never unpinned.**

- `"stable"` is a float: 6-week drift, documented recompile churn on the
  shared host, documented CI/local mismatch (#149) — and it buys nothing
  here because the pin already equals current stable.
- No pin is strictly worse than `"stable"`: it degrades to the host default
  toolchain — an *implicit* float plus cross-lane surprises.
- Per-lane numbered pins remain the org pattern: workspace/host **1.99.0**,
  esp fork **1.98.1.0** (forced), OpenWrt SDK **1.96.0** (feed-pinned, now
  audited by §2's script), MSRV floor **1.85** (the consumer contract).
- Bump deliberately (the rust-toolchain.toml's own rule). Triggers: a
  dependency needs newer (embassy's MSRV is the one to watch — 1.92 today),
  a security release, or falling >2 stables behind.

## 5. Fixes applied 2026-10-22 (worktree conwrt-nr7101-detect)

1. `rust-toolchain.toml` — stale "will pin 1.94.x matching the OpenWrt SDK"
   comment replaced with the SDK-lane reality (no rustup lane exists:
   tier-3 demotion; feed 1.96.0; audit pointer).
2. `scripts/openwrt-toolchain.json` (new) — pin manifest: eras apk
   25.12.6 / ipk 24.10.8 (ramips-mt7621), `rust_per_release`
   {25.12: 1.96.0, 24.10: 1.94.0}. SDK image digests land here with #109.
3. `scripts/sdk_rust_version.py` (new) — tollgate `sdk-go-version.sh`
   pattern ported: `check` / `update` / `print <series>` + `--self-test`
   (5 seeded-divergence steps, stubbed feed, no network). Branch-only by
   design: OpenWrt publishes no rust toolchain in released feeds (verified:
   25.12.6 x86_64 feed carries rust-BUILT apps but no rustc/cargo pkgs).
4. `Makefile` — `openwrt-toolchain-check` target (live check + self-test),
   added to `.PHONY`.
5. `.github/workflows/rust.yml` — audit step after the nostd-parity step
   + path filters for both new files (PR and push).
6. **Correction to §2**: 1.94.1 was NOT uninstalled — `fips`,
   `fips-campaign`, `tollgate-rs`, `tollgate-rs-whichversion` pin
   `channel = "1.94.1"` (shared host; those lanes own it). conwrt simply
   no longer references it.

Verification: self-test 5/5 PASS; live `check`/`print` vs feed OK
(25.12=1.96.0, 24.10=1.94.0); `make openwrt-toolchain-check` OK;
`make lint` OK; pyright (hub venv 1.1.414 — system pyright absent,
pre-existing env gap, so `make typecheck` itself can't run here) reports
0 errors on the new script; manifest JSON + rust.yml YAML parse; the
edited `rust-toolchain.toml` still resolves 1.99.0.

## 6. SDK docker lane scaffold added 2026-10-22 (session 2)

- **SDK digests pinned** in `scripts/openwrt-toolchain.json`:
  `openwrt/sdk:ramips-mt7621-25.12.6@sha256:0d28e4f8…` (apk era) and
  `…24.10.8@sha256:40a1aae0…` (ipk era) — same digest-pinning discipline
  as tollgate's build-inputs.json.
- **`scripts/zycast-mipsel-build.sh`** — the ready-to-run lane:
  `preflight` / `bootstrap` (feeds + lang/rust into the named volume
  `conwrt-sdk-ramips-mt7621`; hours, paid once) / `build` (SDK rustc +
  mipsel gcc → static musl `data/bin/conwrt-zycast-mipsel` + sha256).
  Hard df preflight (25G bootstrap / 8G build), named container, detached
  launch recipe in the header. Stage-2 env (std location, RUSTFLAGS) is
  probed and fails loudly — tuned on first successful bootstrap.
- **Bootstrap NOT yet executed — disk gate.** Host is at 98% (11G free);
  the rust bootstrap needs 10-20G+. Reclaim path: `dev-session.sh sweep`
  shows ~7.5G of idle-but-DIRTY lane `target/` caches (ucport 4.4G,
  arpprobe 1.6G, rusttest 955M, asuflash 524M) — all PROTECTED, so the
  sweep will not touch them; owners retire lanes or `rm -rf` their own
  `target/` first, then run `bootstrap`.
