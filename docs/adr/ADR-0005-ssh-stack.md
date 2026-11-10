# ADR 0005: SSH stack — russh (std) + sunset (no_std), scp-over-exec

Status: accepted
Milestone: M2 (russh), M5+ (sunset on MCU if needed)

## Context

SSH is conwrt's primary management channel to OpenWrt targets, which run
**Dropbear** (OpenWrt 24.10 = 2024.86; main = 2026.94). 1.x has three
duplicated Python SSH layers; 2.0 consolidates into provider code. Dropbear
on OpenWrt ships `/usr/bin/scp` (bundled since 2013) but **no sftp-server**;
`scp -O`-style exec transfer is the portable path (AGENTS.md documents the
`scp -O` requirement). Existing `scp` crate is yanked (2019, AML license).

Research findings (2026-10-12, source-verified):
- **russh 0.64** (Apache-2.0, Eugeny/russh, active — 0.64.1 released
  2026-10-05): pure-Rust std SSH client+server, tokio-native.
- **sunset 0.6** (0BSD, **authored by Matt Johnston, the Dropbear
  maintainer**): `no_std` + no-alloc core, client+server, ed25519 +
  curve25519 + chacha20-poly1305 + aes256-ctr + hmac-sha256; measured
  ~150 kB flash / ~13 kB RAM per session on Pico W; `sunset-stdasync`
  targets tokio; SFTP is server-side/alpha.
- Dropbear defaults (`src/default_options.h` @ 17549ea): curve25519=1,
  ed25519=1, chacha20poly1305=1, aes128/256=1, rsa-sha1=0, sha1-hmac=0.
  OpenWrt builds additionally enable ED25519/CURVE25519/CHACHA20POLY1305/SCP
  by default (Config.in, openwrt-24.10).

## Decision

1. **std provider uses russh** (`providers/conwrt-local-ssh`): connection,
   exec channels, host-key verification hooks feeding the trust ladder
   (ADR-0007 pattern), and later an optional server mode for agent-over-SSH.
2. **MCU agents use sunset** only when SSH-on-device is actually required
   (deferred — MCU agents start as USB-CDC/COBS agents per ADR-0004; sunset
   is the designated path when network SSH from an MCU becomes a milestone).
3. **Algorithm floor** (both stacks): kex `curve25519-sha256`; ciphers
   `chacha20-poly1305@openssh.com` or `aes*-ctr`; host keys `ssh-ed25519`
   or `rsa-sha2-256/512`. Never offer ssh-rsa/SHA-1 (Dropbear defaults
   disable it; russh exposes it only as legacy opt-in — we do not enable it).
4. **File transfer = scp-over-exec** (~150 LOC module: `scp -t`/`-f`
   acknowledge protocol over an exec channel) — works against every Dropbear
   without extra packages. `russh-sftp` is used opportunistically when the
   target has `openssh-sftp-server` installed (feature-detected). Raw
   `dd | ssh` streaming remains the last-resort fallback (1.x precedent).
5. **Host-key trust ladder is engine policy** (adopted from tollgate-
   installer's model, reimplemented): explicit pin → persistent store →
   refuse-with-fingerprint-and-instruction; changed key = always refuse;
   different key *type* handled as a distinct case (Dropbear serves one key
   per algorithm).

## Consequences

- One SSH implementation per tier instead of three; testable against fixture
  sshd (dual-key fixture pattern) and the QEMU VM's real Dropbear.
- sunset is pre-1.0 with a one-person bus — but that person maintains
  Dropbear itself; risk consciously accepted and revisited per milestone.
- russh 0.x API churn is contained inside the provider crate.

## Alternatives considered

- **ssh2/libssh2 bindings**: rejected — C linkage fights musl/MCU cross
  builds.
- **openssh crate (shells out)**: rejected — wrong shape for a framework,
  no host-key control at the level we need.
- **thrussh**: rejected — predecessor, lives on Pijul, effectively legacy.
