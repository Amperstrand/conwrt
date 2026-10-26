# GL.iNet GL-E750 "Mudi" — Bench Notes

Species-level notes only. No unit MACs, serials, or bench subnets — see
AGENTS.md ("Specimen Inventory ... Belongs in a Private Project").

## Hardware (measured on a live unit, 2026-10-25)

- SoC: `Qualcomm Atheros QCA9533 ver 2 rev 0` (`cpu model: MIPS 24Kc V7.4`)
- RAM: 128MB
- Flash: NAND 128MB (mtd5 `ubi`, erasesize 0x20000) + kernel mtd3 4MB
- Ethernet: 1x 10/100 (`eth0`, measured at 100baseT)
- WiFi 2.4GHz: QCA9533 integrated (ath9k, `platform/ahb/18100000.wmac`)
- WiFi 5GHz: **QCA9887** over PCIe (ath10k) — see the failure mode below
- LTE: `Quectel EM060K-GL` (USB, QMI on `/dev/cdc-wdm0`)
- USB: USB-A 2.0 host (mass storage enumerates)
- Power: internal battery + USB-C charging
- MAC OUI observed: `94:83:C4` (GL.iNet)

## OpenWrt

- Target: `ath79/nand`
- Device: `glinet,gl-e750`
- Profile: `glinet_gl-e750`
- Measured running: 25.12.5 `r33051-f5dae5ece4`, kernel 6.12.94, `mips_24kc`
- Default LAN IP (stock): `192.168.8.1`
- `board_name`: `glinet,gl-e750`; `model`: `GL.iNet GL-E750`

## Partition table (from `/proc/mtd` on the measured unit)

```
mtd0: 00040000 00010000 "u-boot"
mtd1: 00010000 00010000 "u-boot-env"
mtd2: 00010000 00010000 "art"
mtd3: 00400000 00010000 "kernel"
mtd4: 00ba0000 00010000 "reserved"
mtd5: 08000000 00020000 "ubi"
```

## Serial console

- `ttyS0` at **115200 8N1**; U-Boot supplies its own banner on the same port.
- `/etc/inittab` drives the console with `::askconsole:` (`/usr/libexec/login.sh`)
  — i.e. the **askfirst** class: a passive read shows nothing until the console
  is activated.
- **Measured caveat**: on the unit tested, the link was **TX-only**. The unit's
  own output (kernel messages, boot log) arrived byte-clean, but a marker
  transmitted *into* the port never reached the unit — verified by running
  `stty -F /dev/ttyS0 raw 115200; timeout 6 cat /dev/ttyS0 > /tmp/rx.txt` on the
  box while sending from the adapter; the file stayed empty. `/proc/consoles`
  agreed: `ttyS0 -W- (EC a)` (write-only).
- Consequence: **do not assume you can drive a shell over serial on this
  model.** Treat capture as reliable and input as unproven until *your own*
  wiring passes a loopback test (AGENTS.md: "Serial Wiring: Verify Before
  Connecting"). When SSH is up, prefer it.

## Radio: the 5 GHz QCA9887 may not probe at all

Observed on the measured unit, reproducibly across boots:

```
ath10k_pci 0000:00:00.0: qca9887 hw1.0 target 0x4100016d chip_id 0x004000ff sub 0000:0000
ath10k_pci 0000:00:00.0: board_file api 1 bmi_id N/A crc32 546cca0d
ath10k_pci 0000:00:00.0: failed to read device EEPROM at 0000
ath10k_pci 0000:00:00.0: failed to read calibration data from EEPROM: -22
ath10k_pci 0000:00:00.0: otp calibration failed: 2
ath10k_pci 0000:00:00.0: failed to run otp: -22 (download-cal-data)
ath10k_pci 0000:00:00.0: could not init core (-22)
ath10k_pci 0000:00:00.0: could not probe fw (-22)
```

When it fails there is **no `phy0` and no 5 GHz interface at all**. `iw dev`
shows a single interface; `iw dev`/`/sys/class/ieee80211` expose only the 2.4GHz
ath9k phy. Do not write a recipe that assumes two radios.

Also note the 2.4GHz radio is commonly a **client (STA)** uplink on this model,
not an AP — check `iw dev` for `type`.

### Do NOT "fix" it by installing calibration files (measured trap)

Dropping a `pre-cal-pci-*.bin` / `cal-pci-*.bin` into
`/lib/firmware/ath10k/QCA9887/hw1.0/` does **not** revive the radio, and it
**adds a second failure**:

```
ath10k_pci 0000:00:00.0: failed to get board id: -122
```

`-122` is `-EDQUOT`, and no ath10k function returns it — it is a value coming
back from the target firmware through `ath10k_bmi_execute()`. A `pre-cal-*` file
selects `ATH10K_PRE_CAL_MODE_FILE`, which switches the board-id query to
`BMI_PARAM_GET_FLASH_BOARD_ID`, and the target refuses it.

The association is two-sided, measured across four boots: with the files
present `-122` appears; with them absent (stock image, and again after a
reflash) it is gone, while the original `-22` remains either way. So the
calibration failure is **not** what the files address.

Full evidence: `felixfelix-bot/e750-repair` → `docs/EVIDENCE.md` §3 and
`evidence/`.

## What is NOT verified — do not invent it

- **No flash method has been exercised on this model.** `tested_hardware` in
  `models/glinet-gl-e750.json` is deliberately empty.
- **No U-Boot recovery/HTTP/TFTP path has been verified.** No recovery IP, no
  reset-button timing, no bootdelay interrupt key. Do not add one to
  `devices/` until someone tests it with working serial input.
- Consequently there is **no `devices/glinet/e750.json` rescue profile**: the
  rescue ladder needs a verified console interrupt, and input on this unit
  could not be proven.

## Method used

Identity, partition table, radio state and serial behaviour were read from a
live unit over SSH (`/tmp/sysinfo/*`, `/proc/mtd`, `/proc/consoles`,
`/etc/inittab`, `iw dev`, `dmesg`) plus closed-loop serial marker tests. Nothing
here is copied from a datasheet or inferred from a version number.
