# MF286D — OpenWrt install over Ethernet only (no serial)

Status: **bench-validated 2026-11-06** on a Telia/Nordic unit (B09 rootfs /
B12 web-modem hybrid state), case never opened, no serial connection at any
point. Species-level procedure; unit-specific identifiers redacted.

The overview of the device, partition map and history lives in
[notes.md](notes.md). This runbook covers only the install path.

## The vendor recovery flow (what makes no-serial possible)

The ZTE U-Boot (any firmware generation we inspected: 2020-03 and 2021-07
builds) contains a recovery handler reachable without serial:

1. At boot the bootloader attaches UBI on the rootfs partition
   (`ubi.mtd=rootfs`, mtd9).
2. If the UBI attaches but the **`kernel` volume is missing**, the handler:
   - prints its derived identity (see below),
   - sets `serverip=192.0.0.1`,
   - runs the default-env script `lr`:
     `tftpboot 0x84000000 ${dir}root_uImage && nand erase 0x1000000 0x800000
     && nand write_partition 0x84000000 0x1000000 0x800000 && nand erase
     0x1800000 0x1D00000 && nand write_partition 0x84800000 0x1800000
     0x1D00000`
   - after the flash it returns a **fin packet** — UDP to the TFTP peer:
     `OK:zte blank download is done` — then resets.
3. `root_uImage` is the combined image = web partition (first 0x800000) +
   rootfs UBI (0x1D00000). The OpenWrt community image blanks the web
   partition by design (OpenWrt does not use it).

**The `&&` chain matters for safety**: if the TFTP pull fails, nothing is
erased. A failed recovery attempt leaves flash untouched.

## Triggering recovery without serial

Recovery is entered whenever boot finds a UBI that attaches but has no
`kernel` volume. Two vendor-sanctioned ways to get there:

- **Serial** (community method): interrupt U-Boot, `nand erase` the rootfs
  region or the kernel volume, boot.
- **From the running system with root**: write a *kernel-volume-less* UBI to
  mtd9 and reboot. A minimal image (2 layout PEBs + one dummy volume) is
  enough — `ubinize -p 128KiB -m 2048 -O 2048` with a single non-kernel
  volume. This is the method we validated. (How root is obtained on stock
  firmware is out of scope here — see the private research repo.)

A fully erased (all 0xFF) rootfs partition is **not** equivalent: on some
generations `ubi part fs` then fails before the recovery handler and the
bootloader sits at a prompt with no serial attached — treat full erase as a
brick risk.

## The recovery client's identity (do not assume 192.0.0.2)

The handler derives a **per-boot identity** with sprintf-style builders:

- IP: `192.X.Y.Z`
- MAC: `00:aa:bb:X:Y:Z`

X/Y/Z change per boot (and per firmware generation). Any allowlist,
static ARP or firewall rule pinned to `192.0.0.2` will silently fail.
Match on the MAC prefix `00:aa:bb:` or the whole /8 instead.

## Timing: warm vs cold boot

- Warm reset (reboot from the OS): recovery network phase in **~1 minute**.
- **Cold boot (power cycle): the network phase opens ~8 minutes after
  power-on** (bootloader update-path timeout ladder runs first). Watchers
  that give up after 1–2 minutes will misread this as a dead device.

## TFTP server requirements (fence)

Validated server: `factory_tftp.py` (rehearsed against a device simulator in
`harness/`, session 2026-11-02). Requirements learned the hard way:

- Bind the address the bootloader targets (`192.0.0.1`), serve a **whitelist**
  (`PROBE.txt`, `root_uImage`), verify the image sha256 at serve time, log
  every packet, support RFC2348 `blksize` + `timeout` OACK (the client
  negotiates `blksize=1468`).
- Serve small files small: `PROBE.txt` is a liveness probe answered with
  `OK\n`; serving a 38 MB image to a probe aborts the session.
- The transfer is fast and reliable: 38,797,312 B in **10.3 s** at blksize
  1468 with per-block ACKs.
- Expect the fin packet on the same UDP flow ~15 s after the last block
  (that gap is the NAND erase+write time).

## Bench networking checklist (each item bit us once)

1. **Host firewall**: on Ubuntu/ufw the INPUT policy is DROP; a TFTP server
   tested from the bench host itself passes via the loopback path and masks
   the rule gap. Allow the TFTP ports on the *device-facing* interface and
   re-test from an external source.
2. **No local alias on the client subnet**: if the bench interface holds an
   address inside the client's range (e.g. a secondary `192.0.0.2/8`), UDP
   replies to the client are delivered *locally* and never reach the wire.
3. **One IP per subnet**: the same IP on a bridge and its port creates
   ambiguous routes and ARP answers.
4. **Frame size**: some bridge stacks emit short ARP replies as runts; if a
   client seems deaf while its requests arrive, answer ARP yourself with
   padded (60-byte) frames injected on the physical port.
5. **Single-threaded servers**: a TFTP implementation that blocks on a
   stalled transfer drops subsequent requests; the device retries every ~5 s
   only a bounded number of times.

## Success signals, in order

1. `PROBE.txt` RRQ (probe) — server liveness answered with `OK\n`.
2. `root_uImage` RRQ with `blksize` option from a `00:aa:bb:` MAC.
3. Per-block ACKs to completion (26k+ blocks).
4. Fin packet `OK:zte blank download is done`.
5. Link bounce, then the new system boots (first boot after a fresh UBI can
   take a couple of minutes; a power cycle is a legitimate first response to
   a silent first boot).

## Rollback

Serve a different `root_uImage` from the same fence: a stock image restores
the vendor system (web + rootfs). The modem is never touched by this flow.
Keep pre-flash backups of all partitions before starting (see the private
acquisition runbook); the unit-unique partitions (ART, mac, cfg-param)
cannot be regenerated from any public image.
