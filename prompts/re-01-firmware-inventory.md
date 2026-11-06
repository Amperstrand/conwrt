# RE prompt 01 — firmware acquisition & first-pass inventory

Use when a new router lands on the bench and the goal is a fast, structured
understanding of its firmware surface before any live probing. Safe by
design: everything here is offline or read-only.

## Inputs to collect first

1. **Vendor images** (OTA packages, factory zips, "download files" kits from
   forums): they are signed, structured and often contain the full rootfs.
2. **Community dumps** (mtd dumps shared on forums): note the provenance and
   generation — a dump from another unit answers species questions, never
   unit questions.
3. **Live device** (if accessible): `/proc/mtd`, `uname -a`, web UI version
   strings. Record the *component* versions (bootloader, kernel, web assets,
   modem) — a single "firmware version" string regularly hides a hybrid
   state where only some components were updated in the field.

## Extraction ladder

- `binwalk -E` first for an entropy overview; then targeted extraction with
  `binwalk -e`, `ubireader_extract_images` (UBI), `unsquashfs` (squashfs),
  `7z x` (cramfs), `ubireader_extract_files`.
- For each flash partition: identify the filesystem, extract to a working
  dir, and keep a manifest of sha256s.
- `/etc/`, `/usr/bin`, `/sbin` listings and the init scripts give you the
  daemon inventory in minutes: web server, TR-069/OMA-DM, update agents,
  factory-mode helpers.

## Questions to answer in the first pass (write them down)

- Which web server binary (`goahead`, `lighttpd`, `uhttpd`, vendor)? Where
  are its handler tables / CGI mappings?
- Which daemons parse network input (LAN/WAN/factory ports)?
- What is the update/FOTA chain: who verifies signatures, who writes flash,
  which components does a delta touch?
- Bootloader: which recovery/reflash paths exist, and what triggers them?
- Busybox version and applet list (run the *actual* binary — string-matching
  a listing is unreliable; `qemu-arm -L <rootfs> <rootfs>/bin/busybox
  --list` works without hardware).
- What is unit-unique on this flash (calibration/ART/MAC/certs) — the
  partitions you must never overwrite without a verified backup.

## qemu trick worth remembering

An ARM rootfs + `qemu-arm -L <rootfs>` lets you execute the device's exact
binaries (busybox applets, shell scripts, mtd-utils) on the bench to settle
behavioral questions (flag parsing, semantics) without touching the device.
Run potentially dangerous binaries only in a container.

## Output

A one-page species brief: hardware, partition map, daemon inventory, web
surface, update chain, bootloader recovery paths, unit-unique partitions —
plus the extracted trees on disk for the next prompts.
