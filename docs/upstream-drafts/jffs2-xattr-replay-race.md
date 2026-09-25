# Upstream bug-report draft: jffs2 xattr replay after unclean power

> **HUMAN SUBMISSION ONLY — DO NOT AUTOMATE.**
>
> This document is a DRAFT for a human operator to review, sanitize-check, and
> submit by hand. Per the repository's external-etiquette rules (AGENTS.md),
> automation must NEVER post this to linux-mtd, LKML, or any OpenWrt tracker,
> and must never open issues, comment, or interact with repositories outside
> the Amperstrand organization. The only acceptable automated action on this
> file is editing it in place.
>
> **Reference:** https://github.com/Amperstrand/openwrt/issues/3
>
> **Sanitization status:** no passwords, password-hash fragments, public keys,
> MAC addresses, or link-local addresses appear below. Devices are referred to
> as "the affected unit" and "the reference unit". Private bench IP details are
> omitted where they add nothing technical. All quoted log lines are verbatim
> from the archived evidence; the two MAC-bearing lines that normally bracket
> the affected unit's boot (eth0/eth1 ART warnings) are omitted on purpose.

---

Everything below the line is the report body. It is self-contained: all
evidence is quoted inline, so a maintainer does not need access to our
archives to evaluate it.

---

Subject: jffs2: unchecked/orphan xattr entries persist across clean mounts
after an unclean power cut; intermittent boot hang suspected in mount-time
xattr rebuild (overlayfs upper on SPI-NOR, ARM, 6.12.94)

Subsystem: fs/jffs2 (interacts with fs/overlayfs as the OpenWrt root overlay)

Report class: filesystem consistency / boot-reliability defect. No panic, no
oops, no corruption message — the failure mode is a silently degraded or
stalled early boot after an unclean power loss during overlay writes, plus
mount-time xattr bookkeeping that does not converge back to a clean state
across subsequent clean boots.

Severity: medium. Recoverable (typically by further power cycling), no kernel
crash, but it renders an unattended embedded device unreachable for its
management plane while it keeps forwarding/announcing on the network, which
makes it look like a network or auth problem rather than a filesystem one.

## 1. Summary

On an embedded ARM device (Qualcomm IPQ4029, 32 MiB SPI-NOR) running OpenWrt
with the standard layout — squashfs read-only lower layer, JFFS2 "rootfs_data"
MTD partition as the overlayfs upper — an unclean power cut during (or seconds
after) JFFS2 overlay writes leaves the filesystem in a state where every
subsequent mount reports a population of unchecked and orphan xattr entries:

    jffs2: notice: (235) jffs2_build_xattr_subsystem: complete building xattr
    subsystem, 53 of xdatum (26 unchecked, 26 orphan) and 65 of xref
    (16 dead, 15 orphan) found.

Two problems are bundled:

1. **Non-convergence.** The unchecked/orphan counts persist across *many*
   subsequent *clean* boots (observed over ~28 hours and dozens of mounts,
   including verified graceful reboots). They never returned to zero/zero on
   their own; only an explicit reformat of the overlay (sysupgrade -n) did.
   The counts drift slightly upward as new overlay writes add fresh xattr
   nodes on top of the unrepaired residue (24/15 → 26/26 → 27/23 → 27/25
   across one day; exact chain quoted in section 5).

2. **Intermittent boot hang.** Immediately after the original dirtying event
   (a factory reset of the overlay followed by an unclean power cut seconds
   after a config commit), the unit spent an extended window — multiple
   consecutive boots — in a state where the kernel was up, IPv6 router
   advertisements were still being emitted, and dropbear was listening and
   accepting TCP connections on port 22, but every SSH session was closed at
   the authentication step (`Remote closed the connection` from the client
   side). No auth method worked. A later power cycle booted the same
   hardware/firmware into a fully healthy state, at which point dmesg showed
   the dirty-xattr state above.

Our working attribution (hypothesis, evidence-limited — see section 8) is
that the boot-time overlay bring-up races the mount-time xattr rebuild: on
some boots the rebuild completes and userspace sees a writable overlay
(healthy); on others it stalls before `/etc` is usable, and services that
started anyway (dropbear) run without their overlay-resident state — host
keys and shadow — and refuse all sessions at auth. We were not able to
capture serial console output during the hung state, so the exact stall point
is not proven; section 7 lists what we plan to capture on the next
occurrence.

We are reporting this because (a) the persistent unchecked/orphan population
after a single unclean cut may indicate that the mount-time xattr repair never
actually completes or writes back its cleanup, and (b) if the intermittent
hang is real and in the xattr rebuild path, it is a filesystem bug that
OpenWrt's boot sequence cannot defend against.

## 2. Environment

- Hardware: Extreme Networks WS-AP3915i access point, Qualcomm IPQ4029
  (4x Cortex-A7), 512 MiB RAM, 32 MiB SPI-NOR (Macronix MX25L25635E).
- Flash layout (from a healthy boot's console log):
  `0x000000b90000-0x000001fe0000 : "rootfs_data"` — a raw MTD partition of
  ~20.3 MiB on the SPI-NOR device; JFFS2 sits directly on this MTD partition
  (no UBI volume for rootfs_data).
- Kernel banner options: `jffs2: version 2.2 (NAND) (SUMMARY) (LZMA)
  (RTIME) (CMODE_PRIORITY)` — i.e. JFFS2 write-buffer/NAND support and
  summary support are compiled in even though the medium is SPI-NOR.
- Root filesystem: OpenWrt overlayfs — read-only squashfs lower (`/rom`),
  JFFS2 upper (rootfs_data). The upper-filesystem relationship is visible in
  the boot log: `overlayfs: upper fs does not support tmpfile.` Overlayfs is
  the notable *writer* of xattrs on this filesystem: it stores
  `trusted.overlay.*` metadata (whiteouts/opaque dirs) on the JFFS2 upper, so
  every package install or file replacement that shadows a read-only file
  creates xattr-bearing nodes. That is why a minimally-configured OpenWrt
  device still has dozens of xdatum on its overlay.
- Affected versions:
  - Primary observations: Linux **6.12.94** (OpenWrt **25.12.5**,
    `r33051-f5dae5ece4`, target `ipq40xx/generic`), both on a customized
    image and on the stock 25.12.5 sysupgrade image.
  - The nonzero-orphan phenomenon is also present on a second, healthy unit
    of the same model running Linux 6.6.x (OpenWrt 24.10.2): its mount-time
    line reports `0 unchecked, 5 orphan` after ordinary operation. The
    boot-hang symptom was only observed on the 6.12.94/25.12.x unit, so we do
    not claim the hang exists on 6.6 — only that the unchecked/orphan xattr
    bookkeeping is version-spanning.
- Boot flow context (OpenWrt): preinit → `mount_root` switches root to the
  overlay → procd starts services (dropbear among the first). On a healthy
  boot the relevant timestamps are:

      [   12.058145] jffs2: notice: (235) jffs2_build_xattr_subsystem: ... found.
      [   12.064355] mount_root: switching to jffs2 overlay
      [   12.095118] overlayfs: upper fs does not support tmpfile.
      [   12.286854] procd: - early -
      [   13.054844] procd: - init -

  i.e. normally the xattr rebuild-to-procd gap is well under a second.
- Known-unrelated noise on this platform (so nobody chases it): the kernel
  cmdline carries a `ubi.mtd=0` remnant from the stock bootloader
  environment, producing `ubi0 error: failed to attach mtd0, error -22` at
  every boot; and `mtd: partition "rootfs" doesn't start on an erase/write
  block boundary -- force read-only` for the squashfs partition. Neither
  affects rootfs_data.

## 3. Trigger

An unclean power loss that interrupts (or lands seconds after) writes to the
JFFS2 overlay. Two concrete instances on the affected unit:

- **Incident A (worst case):** a factory reset of the overlay (OpenWrt
  `firstboot`: wipe rootfs_data, reformat-on-next-boot) followed by a power
  loss *seconds after* a config commit on the fresh overlay.
- **Incident B (milder):** ordinary overlay traffic (adoption: SSH keys,
  password, uci commits) followed by a bench-wide unclean PoE power cut.

After either, every mount reports unchecked/orphan xdatum (counts in
section 5), and — for incident A only — the intermittent auth-dead boot state
described next.

## 4. Symptom (incident A)

During the auth-dead window, from the network side:

- The device continued to emit IPv6 router advertisements (odhcpd alive) and
  answered ARP/NDP.
- TCP port 22 was open; dropbear presented its banner and accepted the
  connection.
- Every session was closed at the authentication step, for password auth and
  public-key auth alike; the client-side error was `Remote closed the
  connection`.
- No other access path existed on this image (no LuCI on :80 in the stock
  image class, no reset button wired in the device tree, bootloader TFTP
  fallback not reached because flash boot succeeds).

A deliberate power cycle later produced a fully healthy boot on identical
hardware and firmware, and the device then survived both a graceful reboot
and a cold power cycle with its config intact. This matches the recorded
internal assessment: the state is *boot-nondeterministic* — the mount-time
repair races, retries across boots, and frequently a single power cycle
lands on a completed replay.

## 5. Evidence chain

All times CEST 2026. `unchecked/orphan` below abbreviates the xdatum counts
from the `jffs2_build_xattr_subsystem` notice; full verbatim lines are
quoted where we hold the raw log. Both incidents are on the same physical
unit ("the affected unit").

| # | When | Event | xdatum (unchecked, orphan) | Source |
|---|------|-------|---------------------------|--------|
| 1 | 09-22 | Incident A: factory reset of overlay + unclean power seconds after a config commit; extended auth-dead window (multiple boots, TCP:22 open, all sessions closed at auth) | — (state itself never captured) | session record, see below |
| 2 | 09-22 (recovery) | dmesg after the boot that finally came up healthy | **24 unchecked, 15 orphan** | incident record |
| 3 | 09-22 evening | Adoption verified; graceful reboot PASS (~70 s, keys+config intact); cold PoE cycle PASS (~85 s) | — | recovery evidence set |
| 4 | 09-23 11:42 | Full boot captured on serial console; unit healthy this boot (overlay up, network up ~32 s, root shell) | **26 unchecked, 26 orphan** (xref: 16 dead, 15 orphan) | archived serial log |
| 5 | 09-23 afternoon | Fleet sweep dmesg readback | **27 unchecked, 23 orphan** | sweep record |
| 6 | 09-23 ~16:18 | After a separate event (spontaneous reboot + watchdog reset loops, see note) self-recovered; dmesg readback | **27 unchecked, 24 orphan** | event record |
| 7 | 09-23 17:55 | Pre-flash baseline, dmesg readback seconds before a deliberate clean reflash | **27 unchecked, 25 orphan** (xref: 19 dead, 12 orphan) | archived preflight capture |
| 8 | 09-23 19:26 | After `sysupgrade -n` (fresh image + deterministic overlay reformat), dmesg of the fresh boot | **0 unchecked, 0 orphan** | archived gate readback |
| 9 | 09-23 ~20:46 | Bench power distribution failed and self-recovered → involuntary unclean power cut of the (otherwise idle) unit; subsequent mounts report | **11 unchecked, 2 orphan** (xref: 2 dead, 0 orphan) | archived outcome record |

Note on row 6: between rows 5 and 7 the unit spontaneously rebooted and
spent ~35 minutes in bootloader watchdog reset loops, with flash-boot
attempts halting after the bootloader printed `JFFS2 loading
/home/config/shadow`. That halt is in **U-Boot's own JFFS2 reader** (a
separate implementation the stock bootloader environment uses to probe for
stock-firmware config), not the kernel's JFFS2; it is included only as
corroboration that the same dirty-flash window existed, and we do not claim
it as kernel evidence.

Verbatim kernel log lines held in our archives:

Serial console capture of a healthy boot (2026-09-23 11:42), showing the
dirty state on a boot that nevertheless completed:

    [    0.095340] jffs2: version 2.2 (NAND) (SUMMARY) (LZMA) (RTIME) (CMODE_PRIORITY) (c) 2001-2006 Red Hat, Inc.
    ...
    [   12.058145] jffs2: notice: (235) jffs2_build_xattr_subsystem: complete building xattr subsystem, 53 of xdatum (26 unchecked, 26 orphan) and 65 of xref (16 dead, 15 orphan) found.
    [   12.064355] mount_root: switching to jffs2 overlay
    [   12.095118] overlayfs: upper fs does not support tmpfile.

Pre-flash baseline readback over SSH (2026-09-23 17:55), same unit, same
day, after only clean reboots in between:

    [   12.196939] jffs2: notice: (234) jffs2_build_xattr_subsystem: complete building xattr subsystem, 52 of xdatum (27 unchecked, 25 orphan) and 65 of xref (19 dead, 12 orphan) found.

Post-reflash fresh overlay (2026-09-23, read back ~80 minutes after the
sysupgrade; first boot on the new image):

    jffs2: notice: (1868) jffs2_build_xattr_subsystem: complete building xattr subsystem, 0 of xdatum (0 unchecked, 0 orphan) and 0 of xref (0 dead, 0 orphan) found.

First mount-state readback after the involuntary unclean cut (2026-09-23,
late evening; boot following the bench power blip, config verified intact):

    13 xdatum (11 unchecked, 2 orphan) 16 xref (2 dead, 0 orphan)

Cross-version data point (same model, second unit, OpenWrt 24.10.2 /
kernel 6.6.x, ordinary operation, no incident): `0 unchecked, 5 orphan`.

Kernel/version line of the affected unit (from the serial capture):

    [    0.000000] Linux version 6.12.94 (builder@buildhost) (arm-openwrt-linux-muslgnueabi-gcc (OpenWrt GCC 14.3.0 r33051-f5dae5ece4) 14.3.0, GNU ld (GNU Binutils) 2.44) #0 SMP Mon Jun 29 12:59:20 2026
    [    0.000000] CPU: ARMv7 Processor [410fc075] revision 5 (ARMv7), cr=10c5387d
    [    0.000000] OF: fdt: Machine model: Extreme Networks WS-AP3915i
    [    0.027340] Memory: 503452K/524288K available (...)

What we take from this chain:

- A single unclean cut permanently changes the mount-time xattr bookkeeping
  (rows 2→7: counts persist and drift across ~28 h of mostly-clean boots).
- The residue is mount-report-only: no CRC errors, no "jffs2_scan_eraseblock"
  complaints, no I/O errors — the filesystem otherwise behaves normally.
- The overlay is functional while dirty (row 4 boot was healthy in every
  observable way), so the unchecked/orphan population alone does not break
  the system; the hang appears to be a *race*, not a deterministic
  consequence of the counts.
- Reflation to 0/0 (row 8) followed by one more unclean cut (row 9) produces
  a fresh nonzero population — cause and effect are reproducible in
  direction, if not in hang outcome.

## 6. Reproduction (bounded; disposable hardware only)

Equipment: any disposable ipq40xx-class NOR device (or any board where JFFS2
on MTD is the overlayfs upper), serial console attached and logging from the
bootloader onward, ability to cut power to the DUT out-of-band (PoE or a
switchable supply), and a known recovery path (bootloader TFTP or serial
reflash) prepared *before* starting. Do not attempt this on hardware you
cannot reflash.

1. Flash OpenWrt 25.12.x (or current), boot, SSH in. Confirm a clean overlay
   baseline: `dmesg | grep jffs2_build_xattr_subsystem` → expect
   `0 unchecked, 0 orphan` after a fresh install.
2. Generate overlay writes continuously for a minute — e.g. loop
   `echo $i > /etc/probe; uci commit; sync` a few hundred times, or install
   and remove packages (package operations create overlayfs whiteouts with
   `trusted.overlay.*` xattrs, which is exactly the node population seen in
   the field data).
3. Mid-write, cut power (no shutdown, no sync). This is the dirtying event.
4. Power on. Record, for every boot: the full serial console log, the
   `jffs2_build_xattr_subsystem` line, whether `mount_root: switching to
   jffs2 overlay` appears, the time from kernel start to `procd: - init -`,
   and whether SSH auth works.
5. Observe across up to 10 clean boots whether unchecked/orphan counts
   return to zero. In our data they did not.
6. **Bounding rules from the field:** cap total unclean cycles at 2; if a
   boot reaches userspace, treat the box as recoverable and capture dmesg
   before touching anything; if SSH accepts TCP but closes at auth, capture
   the serial state (section 7) rather than power-cycling blind — each
   additional dirty cut deepens the state.

Expected outcome (based on the field data): nonzero unchecked/orphan counts
on every subsequent mount, persisting across clean reboots. The auth-dead
hang is intermittent — we observed it once in the field, in the window
immediately after the original dirtying event; a targeted repro may need to
cut power specifically between the overlay's reformat/first commits.

## 7. Suspected area and what we could not capture

Suspected area: the mount-time xattr rebuild in `fs/jffs2/xattr.c`
(`jffs2_build_xattr_subsystem`, called from the mount/scanning path) and its
interaction with (a) the summary fast-mount path — a torn summary from the
unclean cut may select a different, slower scan path or leave half-verified
nodes — and (b) the ordering between that rebuild, the overlayfs upper
becoming writable, and userspace service start.

Two candidate mechanisms for the observed auth-dead state, ranked by our
internal assessment:

- **H1 (leading, per our incident record):** the mount-time xattr rebuild
  stalls on some boots before the overlay switch completes; services that
  started against a not-yet-writable (or ROM-only) `/etc` run without their
  overlay-resident state — dropbear without host keys closes every session
  at the auth/kex step while still accepting TCP.
- **H2 (alternative):** the overlay mounts but the JFFS2 upper is
  effectively unwritable (or serving stale nodes) after the dirty replay —
  host keys and shadow exist but writes/reads through the overlay fail, so
  dropbear regenerates/loads nothing usable and refuses sessions.

Evidence limitations, stated plainly:

- No serial console was attached during the auth-dead window (incident A
  predates our serial rig). The exact stall point — kernel scan, xattr
  rebuild, mount_root, or overlayfs — was never observed directly; H1/H2 are
  inferences from network-side symptoms plus the dirty-xattr dmesg state on
  the recovered boot.
- No sysrq/task dump, no `/proc` state, no console log from the hung state.
- No raw flash image of a dirty rootfs_data was captured before the
  deliberate reflash (row 8) — so there is no offline-reproducible artifact.
  The post-reflash dirty state (row 9) still exists on the device and can be
  dumped on request.
- The auth-dead state occurred exactly once across two incidents; the
  non-convergence of counts, by contrast, is deterministic and repeatedly
  observed.

Capture plan for the next occurrence (serial is now permanently attached to
the affected unit): full console log of the hung boot; sysrq-t (`echo t >
/proc/sysrq-trigger` via the serial shell, or the BREAK+t sequence) to dump
task state and identify whether a jffs2/overlayfs worker is stuck; a raw
`dd` of the rootfs_data MTD partition for offline replay (mtdram/nandsim)
before any reformat.

## 8. Questions for maintainers

1. Is a persistent nonzero `unchecked/orphan` xdatum population at every
   mount — surviving arbitrarily many clean unmounts/reboots — expected
   JFFS2 behavior after one unclean power cut on SPI-NOR with summary
   enabled? Our reading of the mount path suggested the rebuild verifies/
   reclaims these, but the field data shows the same population (plus
   drift from new writes) at every mount for over a day. If reclamation is
   supposed to happen lazily (GC/access), what triggers it, and can it be
   promoted at mount time?
2. Is there a known way for `jffs2_build_xattr_subsystem` (or the scan/summary
   path feeding it) to stall without progress messages for minutes-to-hours
   on a flash image with torn xattr/xref nodes — e.g. a retry loop in
   erase/reclaim of dead xref nodes — such that the mount call blocks
   indefinitely? We could not find one in code review, but the observed
   userspace state (services up, `/etc` state missing/unwritable) fits a
   mount-path stall that OpenWrt's preinit eventually times out around or
   a read-only fallback.
3. Could the torn summary node select the full-scan path and change the
   mount-time behavior after an unclean cut? (If so, a deterministic repro
   may be as simple as truncating the summary sector in a flash image.)
4. Is an mtdram/nandsim replay of a dumped dirty rootfs_data an acceptable
   artifact for debugging, and is there a preferred way to produce one for
   SPI-NOR?

## 9. Filing notes for the human submitter (do not include in the email)

- Primary target: linux-mtd mailing list (jffs2); cc LKML. Run
  `./scripts/get_maintainer.pl` against a patch-like body at submission time
  to pick up current maintainers — do not rely on addresses in this draft.
- Cross-file (or link) on the OpenWrt tracker as well: the symptom surfaces
  through OpenWrt's boot ordering (preinit/mount_root/procd) and has burned
  OpenWrt users as an "auth death" recovery incident; the OpenWrt-side
  mitigations (delay dropbear until the overlay is verifiably writable;
  document the `Remote closed at auth` signature) belong there even if the
  root cause is kernel-side.
- Before sending: re-check that no MAC/password/key material leaked into
  quoted lines (the draft was sanitized at write time); convert this
  markdown to plaintext, wrap at ~72 columns, and attach the two full
  verbatim kernel log excerpts rather than retyping them.
- Internal lab-notes copy: the Amperstrand/openwrt fork issue for this
  finding (pending at draft time) and the evidence directory referenced in
  the provenance header of this file.
