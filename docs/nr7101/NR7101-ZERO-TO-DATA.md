# NR7101 zero-to-data — the on-ramp (one page, three SIM paths)

> You have a Zyxel NR7101 and ONE of: **(A)** a 9eSIM (removable eUICC)
> card, **(B)** any ordinary physical SIM, or **(C)** an Android phone
> whose SIM you want to borrow without removing it. This page walks you
> from boxed hardware to passing traffic, linking the deep guide for
> each stage instead of duplicating it. Species-level: nothing here
> assumes our bench.
>
> Hardware-proven combos (dates): A+B on bench 2026-11-05 (both slots,
> cold-boot), C 2026-11-05 (Pixel 10/Android 17), eSIM provisioning
> end-to-end 2026-10-23..27 and re-proven 2026-11-20/21.

## What you need before starting

| Thing | Notes |
|---|---|
| NR7101 (any state: stock / OpenWrt / bootlooping) | IP68 shell, 4 screws |
| 802.3at PoE injector or PoE switch port | the box has ONE port, PoE-powered |
| A host with ssh + this repo | Linux/macOS both work |
| **Somewhere safe to plug the unit in** | the flash is stock at 192.168.1.1 with DHCP armed — pick a topology first: `docs/PROVISIONING.md` §2 (direct cable / spare OpenWrt flash host / bench switch) |
| Your SIM source (A/B/C) | see the path table below |
| (only if flashing from stock) USB-serial 3.3 V adapter | rescue lifeline; zycast itself needs no serial |

## The path table (pick your row, follow the stages)

| SIM source | Stage 3 path | Extra stages | Data-ready time from boxed |
|---|---|---|---|
| **A: 9eSIM** | SIM-MODES Mode A + Stage 4 below | buy a profile (free test first!) | ~1.5 h |
| **B: physical SIM** | SIM-MODES Mode B | none | ~1 h |
| **C: Android phone (BT SAP)** | SIM-MODES Mode C | phone prep (pairing, SAP grant) | ~1.5 h + phone quirks |

## Stage 1 — OpenWrt on the box (skip if already current)

The flash is **two-stage by design** — the first boot after flashing is
RAM-only (nothing persists, DHCP armed at 192.168.1.1); keep the unit on
an isolated port/VLAN until Stage 2:

1. **Stock/dark unit** → zycast multicast flash of the initramfs-recovery
   image: `recipes/zyxel/nr7101/` (self-documenting; mechanism + why in
   `docs/zycast.md` §1c). Already-OpenWrt units skip straight to 2.
2. **Stage 2 (the permanent image, carries your identity atomically)** —
   build the overlay with YOUR LAN address, key, and DHCP-silence, then
   sysupgrade:
   ```sh
   PYTHONPATH=scripts python3 -c "
   from profile.overlay import build_overlay_tarball
   print(build_overlay_tarball(disable_dhcp=True,
         authorized_keys=open('/root/.ssh/id_ed25519.pub').read().strip(),
         lan_ip='192.168.5.1'))"
   scp -O /tmp/conwrt-overlay-*.tar.gz root@192.168.1.1:/tmp/
   ssh root@192.168.1.1 "sysupgrade -n -f /tmp/conwrt-overlay-*.tar.gz /tmp/<sysupgrade.bin>"
   ```
   First boot of the permanent image creates the overlay → persistence
   begins, host keys stabilize, the unit answers on YOUR address with
   DHCP quiet (never competing on 192.168.1.1). Details: `docs/zycast.md`
   §1c-§1e; validation status of the `lan_ip` leg: issue #781.

## Stage 2 — the cellular stack (wwand)

Follow `NR7101-CELLULAR-GUIDE.md` §0.1 — the complete, bench-proven
deployment recipe (the fork pin, the REQUIRED datapath add-on, per-card
`wwand_sim` sections). Nothing to decide there; do what it says. After
this stage `wwandctl status` shows your modem and SIM state.

## Stage 3 — your SIM mode

`docs/NR7101-SIM-MODES.md` owns this in full (read its "Common facts"
first — two slots/one active, PIN handling, netiquette). The short
version per path:

- **A (9eSIM in the slot)**: seat the card, then
  `conwrt sim render local_esim_silentlink` → apply the printed plan →
  continue to Stage 4.
- **B (physical SIM)**: seat the card,
  `conwrt sim render local_physical_ice` (override `--apn` for your
  carrier) → apply → verify `AT+COPS?` shows your network.
- **C (phone over Bluetooth SAP)**: do the phone prep FIRST
  (SIM-MODES §Mode C: airplane OFF, BT ON, WiFi OFF, SAP-server grant —
  including the Pixel-class hidden-API workaround if Settings never
  asks), pair + trust from the helper host, verify the SAP path
  (`rsim-card --list`), then `conwrt sim render remote_android_sap`.

Apply discipline (all modes): render with `--show-secrets` only in a
private terminal; `uci revert network` baseline first; read back every
value with `uci get` before committing; keep an independent management
path (wired SSH or serial) alive while committing.

## Stage 4 — eSIM profiles (path A only)

> **Gate on this first: has Stage 2 actually run?** On a unit where the
> cellular stack is absent (no `wwandctl`, no `network.wwan0`, no `wwan0`
> data interface, `network.wan` pointing at a nonexistent device), a profile
> can be downloaded and installed but **cannot be enabled-and-attached** — so
> the "attach to a real production network" half of the rehearsal below is
> unobservable. Do Stage 2 before spending any code. Measured example with
> the exact checks: `nr7101/STAGE2-MISSING-BLOCKS-PROFILE-VERIFY.md`.

### No internet on the device? The toolchain problem

The eSIM toolchain (lpac, the AT helper, curl with TLS) is NOT in a
stock OpenWrt image, and the device may have no internet until the eSIM
is provisioned. Three options, pick by situation:

| Option | When | How |
|---|---|---|
| **Bake it** (fleet) | you control the image | ASU/imagebuilder `PACKAGES=` + `FILES=` carries the toolchain; the conwrt ASU request path supports this |
| **Side-load bundle** (recommended default) | stock image, no internet | host builds a tarball with the per-arch lpac + deps + install script; `scp -O` + one `ash install.sh`. The lpac-openwrt repo produces the artifacts; the driver is `conwrt esim-bundle` (in development, #856) |
| **WiFi-STA bridge** (works, hacky) | any interneted AP reachable | the QUICKSTART Phase-1 shape; unpinned checks ride WiFi — only wwan-pinned checks are truth |

Do these **in order**; each has a gate:

1. **Card-state gate (Gate 0)** — `docs/MODEM-AS-READER-PLAYBOOK.md`
   gate 0: profile map matches expectation before AND after every
   session. A card that came back from another modem gets diffed, not
   trusted.
2. **Free rehearsal** — download/enable a free production profile (see
   the profile-source table below). Proves the whole chain (card →
   transport → TLS → authentication → download → install → enable →
   attach to a real production network). **Free profile ≠ free data**:
   the profile connects to a real tower, gets a real IP, and resolves
   DNS — but data transit is blocked until you buy a plan from the
   provider (it's a dormant commercial subscription; useful for chain
   verification and as a base you can later activate through the
   provider's account/payment page). Single-quoted LPA string.
3. **Paid profile** — the cheapest real test is **nadanada $0.99**
   (self-serve, no account, crypto/card, validity starts at first use).
   silent.link works too but costs more. One-shot discipline: a failed
   paid download is STOP-capture-diagnose, never retry.

### Free profile sources (what they actually are)

**Important: "free test profiles" are NOT test profiles in the SGP.22 sense.**
They are **free production profiles** — signed by the GSMA production
certificate chain, connecting to real production networks, with a real
IMSI and real authentication. What makes them "free" is that the profile
itself costs nothing — but the **data costs money** (a dormant commercial
subscription until you buy a plan). The SGP.22 test-profile infrastructure
(test CI, test SM-DP+, `testProfileSupport` flag) is a separate system
we are not using here.

What a free profile actually gives you:
- ✅ Registration on a real production tower (e.g. Telia 242/02)
- ✅ Bearer with a real IP (CGNAT)
- ✅ DNS resolution through the provider's resolver
- ❌ **Data transit blocked** — no plan purchased, no bytes forwarded
- ✅ **Useful as a base** — some providers (BetterRoaming) let you
  activate the same profile later through their account/payment page,
  turning the dormant subscription into a working one

| Source | Profile | What you get | Matching ID notes |
|---|---|---|---|
| osmocom known-test-profiles | BetterRoaming | Free production profile (1GLOBAL/Truphone chain). **Connects to real tower, DNS resolves, data blocked** — dormant subscription; buy a plan through betterroaming.com to activate data later | `QRF-BETTERROAMING-PMRDGIR2EARDEIT5` — **per-EID download policy**: first download to a new card works; re-downloads to the same EID may be refused |
| osmocom known-test-profiles | Speedtest Travel | Same class as BetterRoaming (Ookla/Truphone promo). The published code is the **short** form — see the measured note below before believing any "live long format" | `QRF-SPEEDTEST` (measured 2026-11-27 by decoding the QR at the source page; the long form circulating in forum posts is not what the provider publishes) |
| **nadana.me** ($0.99) | nadanada | **The cheapest real data test** — pay $0.99, get a profile with actual data. Self-serve, no account, no KYC | Fresh matching ID per purchase (no refusal risk); validity starts at first use, activate within 6 weeks |
| **silent.link** | DATA.PLUS / PAYG | Pay-per-MB, no expiry. More expensive but no time pressure | Fresh matching ID per order |

Deep mechanics: `NR7101-ESIM-PLAYBOOK.md` + `MODEM-AS-READER-PLAYBOOK.md`.

### Verify an activation code at the source, not in a forum post

Forum reposts of "the live long-format Speedtest ID"
(`QRF-SPEEDTEST-PMRDGIR2EARDCIT5`) are not what the provider publishes. Measured
2026-11-27 by fetching and decoding the QR image at
<https://www.speedtest.net/esimqr>: it encodes `LPA:1$rsp.truphone.com$QRF-SPEEDTEST`
— the short form — and the osmocom manual lists the same short form as the
Speedtest entry. Decode the QR at the provider's own page before spending a
single-use download attempt:

```sh
curl -sL https://www.speedtest.net/esimqr | grep -o 'src="[^"]*qrcode[^"]*"'
curl -sL -o qr.png https://www.speedtest.net/s/images/speedtest/esim/esim-qrcode.png
python3 -m venv /tmp/qrv && /tmp/qrv/bin/pip install -q zxing-cpp pillow
/tmp/qrv/bin/python -c "import zxingcpp;print(zxingcpp.read_barcodes('/tmp/qr.png')[0].text)"
```

Either way both forms are refused for the reason in
`FREE-PROFILE-AVAILABILITY.md`: the refusal is a per-EID policy at
`authenticateClient`, not a stale-ID error — so the exact string is not what
would unblock a download.

## Stage 5 — verify you are done

```sh
wwandctl status                      # CONNECTED/READY, SIM named
ping -I wwand0 -c 3 1.1.1.1          # 0% loss
conwrt esim status                   # serving cell / operator (AT read)
```

Troubleshooting: SIM-MODES §Troubleshooting first (ordered table), then
`NR7101-GOTCHAS-AND-FIXES.md`-class failure catalogs live in the private
bench repo; the species-level gotchas that matter most on a fresh unit:
carrier blackhole sessions (re-roll once, then stop), 5G-vs-LTE position
dependence, and the modem reset rules (`docs/NR7101-SIM-MODES.md`
"Common facts": `AT+CFUN=1,1` is forbidden after profile ops; the
documented gentle ladder is in the wedge research notes).

## Where each deep doc lives

| Topic | Doc |
|---|---|
| Flash mechanics, two-stage why, identity overlay | `docs/zycast.md` §1b-§1e |
| Cellular stack (wwand) complete recipe | `docs/nr7101/NR7101-CELLULAR-GUIDE.md` |
| SIM modes A/B/C + apply discipline + troubleshooting | `docs/NR7101-SIM-MODES.md` |
| eSIM provisioning chain + safety gates | `docs/NR7101-ESIM-PLAYBOOK.md`, `docs/MODEM-AS-READER-PLAYBOOK.md` |
| Serial rescue / baud / wiring | `docs/serial-console.md` |
