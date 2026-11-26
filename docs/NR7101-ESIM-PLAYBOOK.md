# NR7101 eSIM Playbook — OpenWrt + silent.link/nadanada on a 9eSIM, reader-free

> **Deployment counterparts:** the supported SIM modes — local 9eSIM,
> physical ice+ card, and an Android phone over Bluetooth SAP — are in
> [NR7101-SIM-MODES.md](NR7101-SIM-MODES.md). That guide owns the UCI plans,
> the phone pairing/permissions and the recovery steps; this playbook is the
> eSIM download/enable deep dive.

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

## Gate 0 — card state, BEFORE anything else (2026-11-24)

**Species lesson (paid for with a lost profile):** when a modem dies
mid-UIM-session, it can drive VALID destructive profile operations on the
way down — during a 2026-11 incident the dying modem executed three ES10c
DeleteProfile ops through the still-open session, and the seated eUICC
carried them out. The paid profile was lost conclusively (single-use
activation code consumed; SGP.22 has no un-delete). The card itself
survived HEALTHY (ISD-R, crypto, and cert chain all fine afterward).

What this means for you:

1. **Diff the card state before and after every session** — profile map
   vs expectation (`lpac profile list` / `wwandctl sims`). A silent
   profile-store wipe is a real failure mode and diffing is the only
   detector.
2. **Never seat an eUICC in a modem that is not just-proven-stable**, and
   never mid-experiment. An abnormal session termination is not
   necessarily passive — the card may execute whatever the dying modem
   sends.
3. **A wiped card is not a dead card.** "No profiles / placeholder ICCID"
   after an incident is consistent with a fully healthy ISD-R; recovery is
   re-provisioning (activation code), not card repair.
4. Species-level card-state gate: [MODEM-AS-READER-PLAYBOOK.md](MODEM-AS-READER-PLAYBOOK.md)
   §"Universal gates" gate 0 — run it first on every card, every time.

## The chain

    silent.link / nadanada purchase (host)
        │  activation code (SMDP host + matching ID)
        ▼
    lpac (host) ── SGP.22 ──► pcscd ──► libifd_modemifd.so (ifd-modemifd)
        │                                       │  ssh:// (dropbear exec) — chosen
        ▼                                       │  legacy: TCP :7002 + socat bridge
    9eSIM (ECP3 eUICC) ◄──── AT+CSIM ◄──── modem AT tty (/dev/ttyUSBx)
    seated in the NR7101 modem              OpenWrt (built by conwrt)

## Transport decision — on-device lpac (at_csim) now; ssh:// was 24.10-era and is REMOVED

**CURRENT (2026-11-20+): on-device `lpac` with `LPAC_APDU=at_csim`** —
lpac runs ON the router, driving the modem's own AT tty directly. No
host-side relay, no stty, no socat, no network in the card path. The
HTTP leg (SM-DP+ download) uses the esim-http-relay (lpac
`LPAC_HTTP=stdio` piped through an interneted host) when the router has
no data of its own. Full matrix: conwrt-bench `docs/nr7101/REMOTE-ESIM-TOOLBOX.md`.

> **The `ssh://` transport below is 24.10-era and BROKEN on 25.12.x**
> (#856): the busybox relay requires `stty` (absent on 25.12.x default
> images — the tty stays canonical+echo, producing AT ERROR storms),
> `timeout` (absent — no watchdog), and the docs' `opkg` snippets
> predate the apk era. The section is kept for the historical record
> and for 24.10.x units that still carry the applet.

**Historical: `ssh://` exec transport** (ifd-modemifd v3.5, PR #22,
`a02d669`). The driver opens a BatchMode, host-key-pinned dropbear session
and execs a busybox relay (`stty -F <tty> raw -echo; exec 3<><tty>;
cat <&3 & exec cat >&3`) that owns the modem AT tty directly.

Why this beats the alternatives:

| Option | Verdict | Why |
|---|---|---|
| Plaintext TCP + socat listener (old) | **retired** | Unauthenticated raw AT console on the network; security depends entirely on firewall discipline; the service dies with every reflash/config churn (exactly the 2026-10-24 outage) |
| Local TCP over WireGuard only | rejected middle step | Re-adds a listener without adding authentication — if we have a tunnel, we can have SSH through it |
| **SSH exec (chosen)** | **now** | Zero listeners; zero router-side software (dropbear is base image, already key-only); encrypted + host-key-pinned; topology-independent (LAN/VLAN/WG); remote side is busybox ash + cat, nothing to cross-compile |
| On-device pcscd + direct tty | destination | No network in the card path at all — see below |

SSH's known limits, accepted deliberately: one session per reader (no
multiplexing — keep exactly one reader open); a new SSH handshake per
reconnect (fine at pcscd cadence); the pinned `/dev/ttyUSBx` can go stale
when the modem shuffles ports (re-pin or probe after modem resets — the
port-shuffle finding is in ifd-modemifd's README).

> **25.12.x regression (2026-11-26): this relay cannot run as written on an
> OpenWrt 25.12.4 image.** The image ships **no `stty`** (also no `timeout`,
> `socat` or `microcom`; the package manager is `apk`), so the relay's
> `stty -F <tty> raw -echo` fails and the tty stays in canonical mode with
> echo on — which produces echo-driven `ERROR` storms with more than one AT
> command per open fd. Tracked in issue #856. Until that is fixed, provision
> with an on-device LPA instead (see `docs/LPAC-OPENWRT-UPDATES.md`: a
> libc-only `lpac` AT-only build, staged in `/tmp`), or run the relay against
> a busybox that has the `stty` applet.

**The destination: run it all on the router.** The end state is pcscd +
ifd-modemifd on the NR7101 itself, opening `/dev/ttyUSBx` directly — no
network in the card path; clients reach it via a WG/SSH-forwarded pcscd
socket or a small API. Why we lean **more heavily into Rust** for that
future: the driver is already std-only Rust with zero external crates
(trivially cross-compiles for the router's target), lpac ships OpenWrt
packages, and v3.5's `ModemLink` trait is deliberately the on-ramp —
`tcp://` (legacy) → `ssh://` (now) → direct `tty` (on-device) are three
implementations of one interface, same AT engine, same tests (the fake
relay already speaks stdio, which *is* the on-device shape). The two
frictions to plan for: `/overlay` headroom on this species is a few MB
(packages must be lean; kmod-usb-serial already resident) and direct tty
needs termios, i.e. adding `libc` for the unix target when that third
impl is built.

## Tested state — "I tested this at commit X, Y, Z" (2026-10-23)

| Component | Repo | Tested commit | What was proven that day |
|---|---|---|---|
| OpenWrt image, flash flow, AT bridge scripts | Amperstrand/conwrt | `fe4a66f` (HEAD at the time) | NR7101 running the conwrt image; modem AT port bridged to TCP 7002 (procd `modem-at-bridge`, ttyUSB auto-detect) |
| pcscd IFD driver (the reader) | Amperstrand/ifd-modemifd | **`3a475eb` (v4.0)** | **Full SGP.22 profile download + enable + notification through the modem reader, one-shot, ~60 s, zero transport errors** (nadanada → 9eSIM). Plus: pySim-shell full-card soak (~60 EFs), 300/300 small-APDU, 150/150 BPP-shaped STORE DATA. See its README "Status" evidence table |
| silent.link checkout/payment automation | Amperstrand/silentlink-lib | `acddfc1` | BTC-LN checkout flow (stock→fee→trocador→discount→checkout→BTCPay status polling) + `parse_order.sh` (activation code) + `provision_order.sh`. **First hardware run pending** (audit: `docs/BENCH-GAP-REPORT.md` in that repo once merged) |
| The card | — | 9eSIM (ECP3 eUICC) | a paid nadanada profile downloaded + enabled through the modem reader, registered and passing live traffic (the physical card's current profile/allowance state is unit-level — track it in the operator's private registry, not here) |

The card-safety doctrine that governed that run (and must govern yours):
Amperstrand/ccid-firmware-rs `AGENTS.md` §"Card-Handling Doctrine" — never
loop secure-channel-class commands, one-shot provisioning discipline,
sacrificial SIM for anything soak/fault-injection shaped.

## Reproduction runbook

1. **OpenWrt on the NR7101** — use conwrt's own flow:
   `recipes/zyxel/nr7101/` + `docs/NR7101-FLEET.md` (flash, network, modem
   AT cookbook). Build the image conwrt currently targets; don't hand-roll.
2. **Transport up** — **preferred: none needed.** v3.5's `ssh://`
   transport requires zero router-side services: dropbear (base image,
   key-only) is the whole story. Ensure the host's SSH key is in the
   router's `authorized_keys` and IP reachability exists (LAN/VLAN/WG).
   *Legacy fallback* (only if ssh:// is unavailable): a socat TCP
   bridge the operator must build and pin — there is NO shipped service:
   install `socat` on the router, expose the modem AT port, and lock the
   listener to the bench host:
   ```
   opkg/apk: socat
   socat TCP-LISTEN:7002,fork,reuseaddr,range=<bench-host-ip>/32      FILE:/dev/ttyUSB2,raw,echo=0,b115200     # tty via the auto-detect probe below
   ```
   plus a uci firewall rule allowing 7002 from the bench/VPN source
   ONLY — never the wan zone (the historical whole-wan exposure was the
   finding that retired this path; the 2026-09-27 spike writeup in
   AGENTS.md documents the full bridge shape, including the procd
   wrapper that auto-detects the AT tty).
3. **Driver** — build ifd-modemifd and install:
   `cargo build --release` → `target/release/libifd_modemifd.so` →
   `/usr/local/lib/`. reader.conf.d entry:
   `DEVICENAME ssh://root@192.168.1.1/dev/ttyUSB2` (v3.5, recommended —
   see "Transport decision") or `DEVICENAME 192.168.1.1:7002` (legacy
   bridge). Optional: `IFD_MODMIFD_SSH_KEY=/path/to/id` for a dedicated
   identity. Use **`3a475eb`** for the bit-identical hardware-proven
   build, master tip for v3.4+ hardening and the SSH transport
   (software-tested; first live validation pending).
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

Landed on ifd-modemifd master *after* `3a475eb`, all mock-tested, **not
yet re-validated on the NR7101**:

- `a02d669` (PR #22) **v3.5 — `ssh://` exec transport**: encrypted,
  key-authenticated modem access with zero router-side software; the
  socat bridge becomes unnecessary (see "Transport decision"). Suite
  33/33 green incl. an end-to-end exchange through the pipe link.
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

## Current bench state / known gaps

- **(2026-11-24) Card-state discipline is Gate 0 above** — the specimen
  card's profile store was wiped by modem-driven deletes during a modem
  death (paid profile lost; card healthy and since re-proven end-to-end).
  The items below this line are the 2026-10-24 record, kept for history.
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
