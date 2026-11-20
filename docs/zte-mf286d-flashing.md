# ZTE MF286D — OpenWrt install & recovery via stock U-Boot blank-download (TFTP)

Species-level, validated procedure. No serial console and no case opening
required. Community-proven path (ispreview/eko.one.pl lineage) + first-party
RE; our bench flashed a Nordic-B09 unit to OpenWrt 25.12.6 with it, zero
bricks, with nothing but this flow.

## How it works (one paragraph)

The stock IPQ40xx bootloader has a factory blank-download mode: when it boots
and the rootfs UBI **attaches but contains no `kernel` volume** (interrupted
flash, deliberately staged trigger UBI, or a download-mode boot state), it
runs its own recovery script (`lr`): it TFTP-pulls an image named
`root_uImage` from **192.0.0.1:69**, erases+rewrites the NAND `web`
(0x1000000+0x800000) and `rootfs` (0x1800000+0x1D00000) partitions, then sends
an ASCII UDP packet `OK:zte blank download is done` back to the server.
**The NOR chain (SBL/QSEE/APPSBL) is never touched by this mode** — that is
what makes it safe and retryable.

## The image

`root_uImage` wrapper, **exactly 38,797,312 bytes**:

```
[0x000000 .. 0x800000)   web region (8 MiB)  — stock cramfs, or all-0xFF for OpenWrt builds
[0x800000 .. 0x2500000)  rootfs UBI (29 MiB) — volumes: kernel (FIT, ~23 LEB max),
                                              rootfs (squashfs, ~32 LEB max),
                                              rootfs_data (empty, autoresize)
```

The OpenWrt community image for `zte_mf286d` already uses this wrapper
(builder: ilblogdicristiangallo/ZTE-MF286D-root_uImage-Builder documents the
ubinize layout). **Always pin and verify the sha256 before serving.**

## Procedure

1. Host: assign `192.0.0.1/8` to the interface that will face the device
   (direct cable or an isolated switch — never a shared LAN).
2. Start the hardened server (nothing else may own 192.0.0.1:69):
   ```sh
   python3 scripts/zte-blankdl-flashd.py \
       --image root_uImage#sha256:<hex-of-your-image> \
       --log-dir runs/mf286d-<unit-tag>
   ```
3. Put the unit into the blank-download state:
   - **Interrupted-flash trigger**: stage a small UBI (valid layout volume, no
     kernel volume) to the rootfs partition, then power-cycle. Do NOT just
     erase rootfs — a fully-erased UBI fails attach *before* the kernel-volume
     check and the bootloader will not pull.
   - Or use the unit's existing download-mode state if it is already in one
     (sticky FOTA flag, E3 download env).
4. Wait for the RRQ (any filename is aliased to your pinned image — the
   bootloader may derive a per-boot 4-hex name), the ~10 s bulk transfer
   (blksize 1468 + 5 s timeout, RFC 2348/2349), and the fin packet. The
   daemon exits 0 on `OK:zte blank download is done`.
5. The device reboots itself into the flashed image. OpenWrt comes up on
   192.168.1.1 (WAN = port 1).

## Rollback

Serve a full-stock `root_uImage` (e.g. the Telia/Nordic kit image, same
wrapper format) over the identical path — the bootloader rewrites both
partitions again. Keep the stock image + sha256 staged before any flash
window.

## Safety rules

- **Never** serve an image whose sha256 you have not pinned. The server
  enforces this; do not work around it.
- One server per subnet; the fin packet is the only success oracle.
- The trigger image must leave a *valid* UBI layout volume — this is the
  difference between a retryable state and a prompt-hang.
- Take a full partition backup first when root access exists (NAND mtd0-11 +
  NOR mtd12-19).
- Modem note for post-flash config: QMI works on modem firmware B11/B12 and
  below; **B14 breaks QMI under OpenWrt** — check `ATI` on the AT port
  (/dev/ttyUSB2) before configuring wwan. Use proto `qmi`, PDP type `ipv4`.

## Partition map (for backups and staging)

NAND 128 MiB (128 KiB blocks; runtime mtd0–11): `fota-flag` 0x0+0xA0000,
ART 0xA0000+0x80000, mac 0x120000+0x80000, reserved2 0x1A0000+0xC0000,
cfg-param 0x260000+0x400000, log 0x660000+0x400000, oops 0xA60000+0xA0000,
reserved3 0xB00000+0x500000, **web 0x1000000+0x800000 (mtd8)**,
**rootfs 0x1800000+0x1D00000 (mtd9)**, data 0x3500000+0x1900000,
fota 0x4E00000+0x3200000.
NOR 2 MiB (mtd12–19): SBL1 0x0+0x40000, MIBIB 0x40000+0x20000,
QSEE 0x60000+0x60000, CDT 0xC0000+0x10000, DDRPARAMS 0xD0000+0x10000,
APPSBLENV 0xE0000+0x10000, **APPSBL 0xF0000+0xC0000 (mtd18, U-Boot)**,
reserved1 0x1B0000+0x50000.

## Model

See `models/zte-mf286d.json` for the machine-readable species definition
(signatures, OUI, capabilities).
