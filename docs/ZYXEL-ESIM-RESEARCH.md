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
- Not yet done (next step if we want deep RE): pull the ACHA.5 firmware, walk
  squashfs-root for the eSIM/LPA components (Zyxel Air backend endpoint,
  esim/lpa-named daemons, the AT/QMI plumbing into the RG520F) and document
  the control surface the same way EXP-034 did for ZTE.

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
- **Cheap read-only probe for the NR7101 device owner** (when convenient, no
  urgency): `AT+QESIM=?` and the LPA-status query from the app note on
  `/dev/ttyUSB2`. If LPAd is present and slot-eUICC-aware, profile management
  on the NR7101 could become modem-native — retiring the ifd-modemifd chain
  for that species. Until then the pcscd/ifd-modemifd path stays production.

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
