# Zyxel eSIM Management — Species Research (NR7302 family + NR7101 relevance)

> Status: **research-only candidate** — the org owns no NR7302-class unit today.
> Everything below came from public sources (software-only, 2026-11-09 session);
> no device ops, no external interactions. If a donor is acquired, a
> `models/*.json` gets created then and this doc becomes its evidence base.
>
> Why this matters to us: (a) Zyxel's consumer line ships a **router-side LPA**
> — the same architecture class as the ZTE MF286D `-lpad` daemon under RE
> (EXP-034/035) — making it prior art for "how a CPE vendor wires eSIM
> provisioning into firmware"; (b) the org's proven NR7101 (Quectel RG502Q-EA)
> sits in the same Quectel module family as Zyxel's eSIM models, so Zyxel's
> stack hints at capabilities our own modules may already have.

## 1. The architecture: Zyxel Air app + router-side LPA

- **Zyxel Air** (iOS `id1562099515`, Android `com.zyxel.zyxelair`) advertises
  "consumer eSIM activation" and "eSIM profile management".
- The flow (NR7302 owner report, tweakers.net): the app scans the carrier QR,
  hands it to the router, and **the router downloads the eSIM profile itself**
  (it asks for WiFi credentials to reach the SM-DP+). That is a router-side
  LPA, not a phone-relay — same shape as ZTE's `-lpad`/`CI_SIM_PRIM_DOWNLOADPROFILE`.
- An NR7101 owner reports the Air app offering eSIM activation "via iPhone 12
  or later with its hotspot" (community.zyxel.com/p/24145) — an
  app↔router↔phone composition variant; the activation failed for that user
  and no resolution is recorded.
- Cloud side: Nebula manages the NR-class CPEs but **has no eSIM story**;
  official Zyxel staff statement: "The Nebula NR5101 and FWA510 do not support
  eSIM. eSIM functionality requires specific hardware support"
  (community.zyxel.com/p/23712). eSIM is per-model HW, not a firmware feature.

## 2. NR7302/7301/7303 hardware variants — the eUICC is on the modem module

From davidohne/Zyxel_NR7302 (community RE repo, read-only reference):

| Variant | Modem revision | eUICC chip | USB-C |
|---|---|---|---|
| DTAG (Telekom DE) | RG520F-EB **Q1-C0752** | **NOT soldered** | no |
| A1 (AT), Telenor (NO) | RG520F-EB **Q1-C1751** | **soldered** | Telenor: yes (populated) |

- So Zyxel eSIM = **soldered eUICC on the Quectel RG520F**, carrier-SKU
  dependent — identical lesson to our MF286D findings: eSIM policy/hardware is
  per-carrier-variant, not per-model-name.
- Repo suggests an **eUICC retrofit** candidate for chip-less units: ST
  `ST4SI2M0020TPIFW` (untested; hardware-class risk, no software undo).
- **EID lives in the device's ROM-D config partition** — the cross-flash
  procedure explicitly says "Backup ROM-D Configuration (**eID is saved inside
  of this file**)" and clear it before flashing another carrier's firmware.
  Treat ROM-D as identity-critical on this species.
- Telenor units ship locked-down: `BootFromFactoryDefault=true` wipes config
  every boot, DHCP off, management WAN-only — all fixable by editing
  `/xdata/zcfg_config.json` (repo has the exact edits) once you have a shell.

## 3. Firmware internals + RE path (all public, host-side)

- Firmware `.bin` (e.g. Telekom `V1.00(ACHA.5)b1`, 161 MB zip publicly hosted
  on telekom.de help pages; also Zyxel Download Library) unpacks with
  **binwalk → `oemapp.ubi` → `rebuild_oemapp.sh -e` → squashfs-root**
  (repo ships `rebuild_oemapp.sh` + `rebuild_firmware.sh`; ubi_reader required).
- Rootfs is ZCFG-based: `/xdata/zcfg_config.json` is the config store;
  `/etc/init.d/zcmd.sh` is a boot hook the repo uses for instrumentation.
  Repack CRC warnings (Header-CRC/Image-CRC) are expected/normal per repo.
- The router OS talks to the RG520F modem over USB; **ADB runs on the router
  OS** (adbd) and DIAG/EDL belong to the modem — mirrors the MF286D two-OS
  split.
## 3b. Firmware walk findings — Telekom `V1.00(ACHA.5)b1_F0` (done, 2026-11-09)

Container is a ZIP: `oemapp.ubi` (Zyxel OEM layer, 19 MB) + `sdxlemur-{sysfs.ubi,
boot.img}` + `NON-HLOS.ubi` + `multifota.bin` + `fotaconfig.xml`. **Platform:
Qualcomm SDX ("sdxlemur") single-chip** — router Linux and modem in one SoC
(RG520F = SDX-class, consistent with §2). Extraction: unzip →
`ubireader_extract_images oemapp.ubi` → squashfs 4.0 → 416-file zcfg OEM layer.

**The eSIM stack (all inside oemapp):**

| Component | Role |
|---|---|
| `usr/bin/thales_lpad` + `usr/lib/libLPA_SDK.so` | **Thales LPAd** — router-side LPA. Transport to card: **`AT+CSIM`** raw APDUs. APIs: `lpaDownloadProfileWith{DefaultSMDP,SMDS}Address`, `lpaGetEUICCInfo`, get/set SM-DP+/SM-DS. |
| `etc/lpad/lpa_config.ini` | SM-DP+ default `gckoem.prod.ondemandconnectivity.com` (Thales/Gemalto OEM), cert `/etc/lpad/Gemalto_LIVE_CI_BASE64_cer.crt`. |
| `bin/esmd` | eSIM state: `AllowedProfiles`, `CurrentProfile`. |
| `lib/vendor_modules/libvdr_quecsoc_module.so` | Quectel vendor data-model module — drives the **modem-side LPA via `AT+QESIM`**: `"eid"` read, `"lpa_enable",0/1`, and full profile ops (`ESIM_PROFILE_{ENABLE,DISABLE,DELETE,BRIEF,DETAIL,NICKNAME}`, `ESIM_LPA_STATUS`, download flag). |
| `lib/channel_wrap/libchanl_qlatc_channel.so` | Quectel AT channel wrapper (generic ATC: QCFG usbcfg etc.). |
| zcfg schema (`etc/config.config`) | Build gates: `CONFIG_PACKAGE_{quectel_lpad,quectel_thales_lpad,thales_lpad,xs_thales_lpad}` (**pluggable LPA provider**), `CONFIG_ZYXEL_{CELLWAN_SUPPORT_ESIM, CELLWAN_ESIM_SMDS_DOWNLOAD, WEB_GUI_CELLWAN_SUPPORT_ESIM, CM_SUPPORT_ESIM, SUPPORT_FACTORY_RESET_KEEP_ESIM_STATUS}`. |
| `bin/zupnp`, `bin/zhttpd`, `bin/genXML` | web/UPnP fronts referencing lpad (Air-app + WebUI entry points). |

**Reading:** Zyxel treats the LPA as a **build-time-selectable component** —
router-side Thales LPAd (card via `AT+CSIM`) *or* modem-side Quectel LPAd
(control via `AT+QESIM`) — converging on `esimObj` in the zcfg data model,
gated per carrier via build CONFIGs (the Zyxel analogue of ZTE's runtime
policy gating).

**Direct payoff for the org's NR7101 (RG502Q-EA):** Zyxel's own production
flow proves the **`AT+QESIM` route is a complete profile-management surface**
on Quectel modules of this generation. The read-only probe for our units is
now concrete: `AT+QESIM="eid"` → `AT+QESIM="lpa_enable",1` semantics per the
Quectel RG50xQ LPA app note. If the RG502Q-EA firmware answers, NR7101
profile management goes modem-native and the pcscd/ifd-modemifd chain retires
for that species. (Caveat stands: LPAd usually manages the **embedded** eUICC;
removable 9eSIM support must be confirmed by the probe.)

Prior-art value for the MF286D `-lpad` hunt (EXP-034/035): a shipping CPE
LPAd is a small daemon (one INI + one cert + one SDK .so) whose card
transport is just `AT+CSIM` — reinforcing that ZTE's `-lpad` is likely
equally drivable once its entry points are found.

Artifacts (stable, until lane closeout): `~/scratch/zyxel-nr7302/`
(`rootfs/` = oemapp tree, `sysroot/` = sdxlemur-sysfs base tree).

## 3c. Runtime wiring — how Zyxel actually drives the LPA (full prior-art blueprint)

Base system (`sdxlemur-sysfs`, 2411 files): stock Quectel Qualcomm SDX userspace
— `atfwd_daemon` + `MCM_atcop_svc` (systemd `atfwd.service`, auto-started) are
the AT-forwarding channel to the modem. **No eSIM code lives in the base
system** — the whole eSIM stack is an oemapp-layer OEM addition.

Control flow end-to-end:

    WebUI / Zyxel Air app → zcfg data model (esimObj)
      → libvdr_quecsoc_module.so  (vendor data-model module)
        → spawns `thales_lpad <verb>` ON DEMAND (no resident daemon needed)
          → card transport AT+CSIM / module-LPA AT+QESIM
            → atfwd_daemon / ATC → modem → eUICC

Complete `thales_lpad` verb set (quoted from the vendor module's spawn
strings — this IS the production control surface):

| Verb | Operation |
|---|---|
| `-E` | get EID |
| `-A %s` | download by activation string (SM-DP+ address / AC) |
| `--smds` | discovery download via SM-DS |
| `--getprofile` | list profiles |
| `--enable %d` / `--disable %d` | enable/disable profile by id |
| `--delete %d` | delete profile |
| `--nickname %d <name>` | rename profile |

`bin/esmd` tracks state (`AllowedProfiles`, `CurrentProfile`) for the
data model; `zupnp` references lpad (UPnP-adjacent surface, not explored
further).

**Blueprint value for the MF286D `-lpad` hunt (EXP-034/035):** in a shipping
CPE, the LPA is (a) oemapp-layer, not base-system; (b) spawned **on demand
with CLI verbs by the data-model vendor module** — no init.d entry, no unix
socket, no resident service; (c) transported over the ordinary AT channel.
When mapping ZTE's `-lpad`, look first for a **caller in the modem-Linux
userspace data/RIL layer** that shells it with arguments — that caller is the
drivable entry point, exactly as libvdr_quecsoc_module is here.

## 4. Recovery ladders (family-wide zycast; serial is NOT the first rung)

- **zycast** = Zyxel bootloader multicast flash protocol, present across many
  Zyxel devices (OpenWrt ships `firmware-utils/zycast.c`; the NR7302 repo
  documents it as the standard soft-brick recovery for "no SSH/WebUI"). The
  NR7302's equivalent of the MF286D U-Boot TFTP blank-download.
- **NR7302 deep rung = soldered USB, not serial**: most units ship without a
  USB port but the pads exist at header **J3**; without VCC you get
  **fastboot** (router OS) + **EDL** (modem, with pin-short), with VCC also
  ADB + DIAG. Telenor units have USB-C populated from factory. No serial rung
  is documented for this family at all.
- **One-way door warning (repo)**: changing the modem's `usb_composition`
  (root tool; e.g. `9025` = DIAG+adb, kills WAN while active) — some
  compositions **brick the modem with no way back**. Never iterate compositions
  blindly; one variable per change, recovery path identified first.
- **NR7101 (org-proven species)** ladder, per OpenWrt wiki: OEM SSH
  (root@172.17.1.1:22022, supervisor password obtainable) → copy OpenWrt to
  the **recovery partition** (no serial needed) → **Z-Loader** (vendor U-Boot
  1.1.3, `ZLB>` prompt; halt with ESC on serial console; `ATNR 1,<image>`
  TFTP-pulls from 10.10.10.3, `ATGU` → U-Boot menu → tftp RAM boot). Serial
  exists inside the IP68 case but is the third rung.

| Device | No-access recovery | Deep rung | Serial? |
|---|---|---|---|
| NR7302/01/03 | zycast multicast (LAN) | solder J3 USB → fastboot/EDL | not documented |
| NR7101 | OEM-ssh → recovery partition | Z-Loader ESC + ATNR/ATGU TFTP | yes, rung 3 (case open) |
| ZTE MF286D | U-Boot TFTP blank-download | EDL 9008 + boot pads | last resort (org-proven no-serial flow) |

## 5. Quectel LPAd — the org-relevant capability question

- Quectel publishes an **eSIM LPA Application Note for RG50xQ & RM5xxQ
  series** (V1.0; module-firmware LPAd + AT commands, incl. `AT+QESIM`-class
  profile operations). Our NR7101's modem is the **RG502Q-EA — in-family**.
- Caveats before celebrating: LPAd classically manages the **embedded eUICC**;
  whether it manages a **removable** eUICC (our 9eSIM in the slot) is
  unverified (community: `AT+QUIMSLOT` switches physical slots only). LPAd
  availability also depends on module firmware version (NR7101 ships
  RG502QEAAAR13A0x; Quectel forum has version notes).
## 5b. NR7101 `AT+QESIM` probe — exact procedure for the device owner

Verbs below are quoted from Zyxel's production code (§3b); probe order is
read-only, owner-executed, one port-session, no `lpa_enable` (write-class).

Port: re-detect per playbook gate 3 (`AT+CPIN?` sanity, never bare `AT`);
the bench units carry the `/dev/modem-at` symlink.

```sh
# read-only QESIM probe — run on the NR7101 (OpenWrt) against its modem AT port
PORT=/dev/modem-at   # re-detect per session; fallback: ttyUSB2/3
for cmd in 'ATI' 'AT+CPIN?' 'AT+QESIM=?' 'AT+QESIM?' 'AT+QESIM="eid"' 'AT+QCCID'; do
  printf '%s\r' "$cmd"; sleep 1
done | socat - "$PORT,crnl"   # or: atinout / picocom manual entry
```

| Result of `AT+QESIM=?` / `"eid"` | Meaning | Next |
|---|---|---|
| `+CME ERROR: operation not supported` / bare `ERROR` to `=?` | no QESIM in RG502Q-EA module firmware | modem-native path dead; keep pcscd/ifd-modemifd |
| `ERROR` to `=?` but `"eid"` returns `+QESIM: "eid",<32 hex>` | partial: EID readable, LPAd control present | owner-gated: try `lpa_enable` per app note |
| `+QESIM: "eid",<32 hex>` and `=?` lists test-mode ranges | LPAd present on module | full modem-native candidate — walk the app-note ops |

**Honest caveat (Quectel support, forums.quectel.com/t/61290):** the module-side
LPAd is **restricted-distribution software** — "it has limitation and I don't
have permission to release it; contact your supplier" — i.e. `AT+QESIM`
existing does NOT guarantee the full profile-download stack is loaded on a
given RG502Q-EA firmware. The probe's real job is to sort those three rows
cheaply. Also remember LPAd canonically manages the **embedded** eUICC; a
removable 9eSIM in the slot may be out of its scope even when present —
that answer only comes from the probe row 2/3 follow-ups.

## 6. Donor-buying guidance (if we extend the program to NR7302)

1. Buy **Telenor Norway or A1 Austria** NR7302 variants: eUICC chip soldered
   (Q1-C1751); Telenor additionally has USB-C populated.
2. Telenor lockout (`BootFromFactoryDefault`) is a solved problem (repo §2)
   but budget one shell session to clear it.
3. On arrival, before ANY experiment: backup **ROM-D** (carries the eID) via
   the WebUI Backup/Restore the repo documents.
4. DTAG units are fine for firmware/RE work (public Telekom firmware,
   zycast recovery) but have **no eSIM hardware** — do not expect eUICC ops.

## Sources

- Telekom NR7302 firmware V1.00(ACHA.5)b1_F0 (telekom.de/hilfe/downloads/firmware-5g-outdoor-router-nr7302, extracted 2026-11-09)

- davidohne/Zyxel_NR7302 (README, firmware/README.md, usb/README.md) —
  https://github.com/davidohne/Zyxel_NR7302
- Zyxel community: /p/23712 (no-eSIM-HW statement), /p/15351 (NR7101 eSIM
  ask, unanswered), /p/24145 (Zyxel Air iPhone-activation attempt)
- Zyxel Air app: apps.apple.com id1562099515; apptopia com.zyxel.zyxelair
- NR7302 eSIM download flow (NL): gathering.tweakers.net/forum/list_messages/2295410/1
- zycast utility: lxr.openwrt.org/source/firmware-utils/src/zycast.c
- NR7101 recovery/install: openwrt.org/toh/zyxel/nr7101 (fetched via
  headed-Chrome pass, session artifact nr7101-wiki.html)
- Telekom public firmware: telekom.de/hilfe/geraete/router/weitere/zyxel
  (V1.00(ACHA.5)b1, 161 MB)
- Quectel RG50xQ&RM5xxQ eSIM LPA Application Note V1.0 (scribd mirror +
  forums.quectel.com/t/esim-lpad-software/61290, /t/esim-at-command-set/13313)
- Cross-reference: MODEM-AS-READER-PLAYBOOK.md (NR7101 production flow,
  MF286D negative species result), mf286d-work EXP-034/035 (`-lpad` hunt).
