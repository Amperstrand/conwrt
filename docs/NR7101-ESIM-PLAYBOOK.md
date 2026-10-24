# NR7101 eSIM Playbook — OpenWrt + silent.link/nadanada on a 9eSIM, reader-free

**The pitch:** provision a current OpenWrt image on the Zyxel NR7101, then buy
and provision eSIM profiles (silent.link, nadanada) onto a physical **9eSIM
(ECP3 eUICC)** seated in the NR7101's SIM slot — **using only the NR7101's own
modem as the smartcard reader**. No external reader, no SIM removal. The
profile download + enable path is **proven end-to-end on hardware**
(nadanada, 2026-10-23); the silent.link payment→activation flow is automated
and its audit is linked below.

If you were handed this document with "with this and opencode you should be
able to provision the latest OpenWrt and get silentlink/nadanada working on a
9esim using only the card reader in the nr7101" — this is the map. Everything
below cites the exact commits that were tested and separates them from
improvements that landed since and are still pending hardware re-validation.

## The chain

    silent.link / nadanada purchase (host)
        │  activation code (SMDP host + matching ID)
        ▼
    lpac (host) ── SGP.22 ──► pcscd ──► libifd_modemifd.so (ifd-modemifd)
        │                                       │  TCP :7002
        ▼                                       ▼
    9eSIM (ECP3 eUICC) ◄──── AT+CSIM ◄──── procd AT bridge (socat)
    seated in the NR7101 modem              OpenWrt (built by conwrt)

## Tested state — "I tested this at commit X, Y, Z" (2026-10-23)

| Component | Repo | Tested commit | What was proven that day |
|---|---|---|---|
| OpenWrt image, flash flow, AT bridge scripts | Amperstrand/conwrt | `fe4a66f` (HEAD at the time) | NR7101 running the conwrt image; modem AT port bridged to TCP 7002 (procd `modem-at-bridge`, ttyUSB auto-detect) |
| pcscd IFD driver (the reader) | Amperstrand/ifd-modemifd | **`3a475eb` (v4.0)** | **Full SGP.22 profile download + enable + notification through the modem reader, one-shot, ~60 s, zero transport errors** (nadanada → 9eSIM). Plus: pySim-shell full-card soak (~60 EFs), 300/300 small-APDU, 150/150 BPP-shaped STORE DATA. See its README "Status" evidence table |
| silent.link checkout/payment automation | Amperstrand/silentlink-lib | `acddfc1` | BTC-LN checkout flow (stock→fee→trocador→discount→checkout→BTCPay status polling) + `parse_order.sh` (activation code) + `provision_order.sh`. **First hardware run pending** (audit: `docs/BENCH-GAP-REPORT.md` in that repo once merged) |
| The card | — | 9eSIM (ECP3 eUICC) | nadanada profile enabled, 1 GB roaming, registered and passing live traffic through the modem |

The card-safety doctrine that governed that run (and must govern yours):
Amperstrand/ccid-firmware-rs `AGENTS.md` §"Card-Handling Doctrine" — never
loop secure-channel-class commands, one-shot provisioning discipline,
sacrificial SIM for anything soak/fault-injection shaped.

## Reproduction runbook

1. **OpenWrt on the NR7101** — use conwrt's own flow:
   `recipes/zyxel/nr7101/` + `docs/NR7101-FLEET.md` (flash, network, modem
   AT cookbook). Build the image conwrt currently targets; don't hand-roll.
2. **AT bridge up** — the procd `modem-at-bridge` service (from the
   retired C-spike heritage; the driver was removed upstream, the *service*
   pattern lives on). It auto-detects the modem AT ttyUSB (the port shuffles
   across resets — never hardcode). If the service is missing after reflash/config
   churn, restore it first; **nothing works without it**.
3. **Driver** — build ifd-modemifd and install:
   `cargo build --release` → `target/release/libifd_modemifd.so` →
   `/usr/local/lib/`, reader.conf.d entry with the router `ip:7002` (see its
   README). Use **`3a475eb`** for bit-identical-to-tested behavior, or master
   tip with the caveats in "Improvements" below.
4. **Validate before anything one-shot** — `tests/hardware/validate.sh` in
   ifd-modemifd (phased, read-only gate: channel behavior, PIN state without
   retry consumption, APDU shapes). Do not skip this on a fresh bench.
5. **Pay** — silentlink-lib `checkout.sh` (BTCPay BTC-LN; prints the invoice
   and polls up to 900 s) → `parse_order.sh <order_urltoken>` → SMDP host +
   matching ID. For nadanada: their web flow gives the same activation code.
6. **Provision** — lpac against the pcscd reader (select the reader by
   friendly name, never first-found): profile download with the activation
   code, then enable, then let the notification go out. The v4.0 run did
   exactly this in one shot through the modem reader.
7. **Switching profiles (nadanada ↔ silent.link)** — lpac `profile disable`
   (old) + `profile enable` (new) on the eUICC, then refresh the modem's SIM
   session (AT+CFUN cycle, or slot re-select) so the modem re-reads. The
   eUICC-side steps are standard ECP3 behavior and the driver path is the
   same one already proven; **the combined switch procedure has not yet been
   exercised on hardware** — run `validate.sh` first and treat the first
   switch as the experiment.

## Improvements since the tested commits (software-verified, hardware-pending)

Landed on ifd-modemifd master *after* `3a475eb`, all mock-tested (17/17),
**not yet re-validated on the NR7101** — PR Amperstrand/ifd-modemifd#2:

- `fa42259` **v3.4 — no-resend transport semantics + strict CSIM framing**:
  an AT+CSIM whose line was fully written is never silently re-sent
  (duplicate-APDU elimination for GP/eSIM/PIN flows); declared-length
  validation (TS 27.007 §8.45); echo-correlated parsing (stale-response
  aliasing bounded); 8 KiB read cap; transport failures surface as
  COMM_ERROR instead of synthetic 6F00.
- `2d50e52` **v3.4.1 — APDU log security**: logging off by default, 0600,
  no-symlink, APDU hex behind its own opt-in.

Same campaign, other reader (not in this chain): ccid-firmware-rs PR #457
(nucula host driver: frame-bounds P0, retry semantics, response decode).

In flight (branches, see the tracker in ccid-firmware-rs
`docs/ENGINEERING_HARDENING_TRACKER.md` §session-2): Phase-3 IFDHandler
conformance tests, the sacrificial-SIM suite + `validate.sh` split (Class-A
zero-risk vs eSIM-provisioning gate), release-gate docs, silentlink-lib
bench-gap audit.

## Current bench state / known gaps (2026-10-24)

- The NR7101's AT bridge is **down right now** (unit was reconfigured during
  unrelated failover testing; no socat service running). Step 2 restores it.
- Dual-SIM slot switch command for this RG502Q-EA firmware: identify via
  read-only `AT+QUIMSLOT=?` / `AT+QSIMCFG=?` probes when the box is free —
  never guess AT syntax against a live modem.
- First silent.link end-to-end run = real money + one-shot provisioning
  discipline: owner-gated, after `BENCH-GAP-REPORT.md` lands.

## Reading order for a newcomer

1. This playbook.
2. Amperstrand/ifd-modemifd `README.md` — v4.0 evidence table + "Modem
   findings baked into the driver" (basic-channel A4/B0 filter, CSIM pacing,
   CGLA swallow — these will save you days).
3. Amperstrand/silentlink-lib `README.md` + `PROJECT_WRITEUP.md`.
4. conwrt `docs/NR7101-FLEET.md` + `recipes/zyxel/nr7101/notes.md`.
5. ccid-firmware-rs `AGENTS.md` — the card-safety doctrine, before any
   hardware session.
