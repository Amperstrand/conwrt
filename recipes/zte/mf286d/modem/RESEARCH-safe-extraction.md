# MF286D Modem Protected-Flash Research — Safe Paths into mtd{1,2,3,5,6}

**Date:** 2026-11-09 · **Mode:** software-only research, zero device access (overseer owns the device)
**Target:** ZTE MF286D mPCIe modem card — Qualcomm MDM9650 (MDM9x50 family), ZTE fw
`BD_TELIAMF286DV1.0.0B12`, modem Linux 3.18.31 armv7l (QTI LE, MDM9650.LE.1.2.c1 BSP),
ADB root (adbd 5.0.2-class), router-side adb client 1.0.32 (exec-out broken).
**Known MTD state (matches community table exactly — eko.one.pl pid 270451):**

| mtd | name | size | adb `dd` result (our session) | community (Leo-PL, Nordic fw) |
|---|---|---|---|---|
| 0 | sbl | 0x280000 | **OK** | OK |
| 1 | mibib | 0x280000 | **INSTANT PANIC/REBOOT (even 4KB)** | **instant reboot** ("for some models even reset to QDLoader 9008") |
| 2 | efs2 | 0xb00000 | zero-byte fail (presumed crasher) | **instant reboot** |
| 3 | tz | 0x380000 | zero-byte fail (presumed crasher) | **dumped OK** |
| 4 | rpm | 0x340000 | not tried? | dumped OK |
| 5 | efsbak | 0xb00000 | zero-byte fail (presumed crasher) | (likely = efs2 class; not named) |
| 6 | aboot | 0x100000 | zero-byte fail (presumed crasher) | **dumped OK** |
| 7-16 | boot…system | — | mtd9 (modem), mtd16 (system) OK | all OK |

> ⚠️ Discrepancy worth re-examining: Leo-PL dumped **tz and aboot fine** and names only
> **EFS + MIBIB** as crashers. If our tz/aboot/efsbak attempts produced *zero bytes
> without a panic*, that is a different failure (e.g. `-EBADMSG` ECC return → dd writes
> nothing, no crash) and changes the hypothesis ranking. Recover the exact symptom per
> partition (panic-reboot vs. clean 0-byte read) from session logs before anything else.

---

## Q1 — msm-3.18 MTD stack: mtdBLOCK vs mtdCHAR read paths

Sources: CAF msm-3.18 mirror `github.com/android-linux-stable/msm-3.18` @ master,
`drivers/mtd/mtdchar.c` and `drivers/mtd/mtdblock.c` (fetched 2026-11-09):

- raw mtdchar.c: <https://raw.githubusercontent.com/android-linux-stable/msm-3.18/master/drivers/mtd/mtdchar.c>
- raw mtdblock.c: <https://raw.githubusercontent.com/android-linux-stable/msm-3.18/master/drivers/mtd/mtdblock.c>

### The two read paths diverge BEFORE reaching the NAND driver

```
dd if=/dev/mtdN        →  mtdchar_read()            [mtdchar.c]
                            └─ mtd_read(mtd,...)     (or mtd_read_oob in RAW mode)
                               └─ nand/qpic driver _read

dd if=/dev/mtdblockN   →  block layer (512B sectors) → mtdblock_readsect()
                            └─ do_cached_read()      [mtdblock.c]
                               └─ mtd_read(mtd,...)  ← SAME entry into NAND driver
```

**mtdchar.c never touches mtdblock.c code and vice versa.** The only shared code is
`mtd_read()` and below (nand_base → QPIC driver). Therefore:

1. **A vendor guard living in `mtdchar.c` (or keyed off the char-device open) can never
   fire on a `/dev/mtdblockN` read.** mtdblock has its own open path (`mtdblock_open`),
   its own file operations, and calls `mtd_read()` directly.
2. Conversely, **a crash inside the NAND/QPIC driver (or common `mtd_read`) would panic
   on BOTH paths** — mtdblock does not bypass the driver, only the char layer.
3. ECC behavior differs *above* the driver and is diagnostic in itself:
   - `mtdchar_read()` explicitly **tolerates** ECC errors — comment in source:
     *"Nand returns -EBADMSG on ECC errors, but it returns the data. For our userspace
     tools it is important to dump areas with ECC errors!"* → `if (!ret ||
     mtd_is_bitflip_or_eccerr(ret))` still `copy_to_user`s the data. A plain
     uncorrectable-ECC read via mtdchar yields data + error, **not zero bytes, not a
     panic** (vanilla code).
   - `do_cached_read()` in mtdblock.c does `if (ret) return ret;` — it is *stricter*
     (any -EUCLEAN/-EBADMSG aborts the sector read). So "block path succeeds where char
     fails" can only mean **char-layer guard**, never ECC handling.
4. **Vanilla CAF msm-3.18 mtdchar.c contains NO anti-tamper, partition-name check,
   panic, or security hook whatsoever.** Nothing in the public MTD core panics on read.
   If the guard exists, it is ZTE-added (their GPL kernel is the ground truth — see
   "ZTE kernel source" below) or it lives in the QPIC NAND driver
   (MDM9x50 LE uses the QPIC NAND controller driver, `drivers/mtd/nand/qpic_nand.c`
   class; not present in the AOSP-flavored mirror — LE BSP kernels are CAF `msm-3.18`
   mdm branches).

### Known vendor anti-tamper patterns (Qualcomm/ZTE)

- No public source documents a ZTE `mtdchar.c` panic guard. Community behavior on this
  exact hardware (instant reboot on `dd` of mibib/efs2, sometimes dropping to QDLoader
  9008) is consistent with a deliberate guard (panic/force-reset on access to
  identity/boot-metadata partitions) OR a QPIC driver crash on ECC-uncorrectable pages.
  Two discriminators (see "The discriminating test") settle it without disassembly.
- Leo-PL's EDL dumps via the **loader's own NAND read path** show *"ton of ECC errors,
  at least one per erase block"* on this NAND (eko 21790 pid 286231) — the raw flash
  genuinely contains many ECC-uncorrectable (possibly erased-with-ECC-on) blocks. The
  patched qtools loader **tolerates** them; the running kernel's QPIC driver may not.
  adron's qtools fork exists specifically because of "the ECC errors problem of reading
  and writing dumps" (pid 286050, repo github.com/adron-s/qtools).
- Secure boot on the observed units is **OFF** ("Secure Boot: Off", "scm call to check
  secure boot fuses failed" in SBL/LK logs, eko 21790 pid 270433/270485). A TZ-based
  read interdiction (Secure Monitor trap on NAND DMA windows) is possible in principle
  but there is zero public evidence of one on MDM9x50; rank it last.
- **ZTE's house style is to patch the NAND driver itself** — the MF286D router's boot
  log (OpenWrt wiki, fetched 2026-11-09 via headed Chrome, saved as
  `mf286d-wiki.txt`) shows their QPIC driver (`msm_nand_version_check ... qpic 1.4`)
  carrying ZTE additions: `msm_nand_scan: wanglei: zte_nand_flash_id = 0x9580f12c`,
  and a **partition-name-keyed read hook**:
  `zte_nand_local_read(): Reading Flash for Calibraton data from 0x0 and partition
  name is mac`. That is the router (ipq40xx) kernel, not the modem's — but it proves
  ZTE engineers ship name-keyed logic *inside* the msm_nand/QPIC layer, where
  **mtdblock does NOT bypass it**. This makes the mtdblock discriminator even more
  valuable: a router-style guard would sit below both device nodes (H2), while a
  modem-firmware guard in mtdchar would sit above (H1).
- Wiki corroboration: chipset listed as "Modem chipset MDM9250" (same silicon family
  as MDM9650 — ZTE/marketing naming varies across sources); **B14 firmware has a
  community-documented QMI regression** ("Several people reported problems with QMI
  connection establishment after updating to Nordic B14 … worth continuing to use
  Nordic B12") — our B12 unit is on the good version; do NOT OTA it during this
  campaign. Source: <https://openwrt.org/toh/zte/mf286d>.

### Hypotheses, ranked

| # | Hypothesis | Fits "mtd0 sbl reads fine" | Fits Leo-PL reading tz/aboot OK | Verdict driver |
|---|---|---|---|---|
| H1 | ZTE guard in `mtdchar.c`/char-open keyed on partition name or index (list grew between fw versions: B11→B12 added tz/aboot?) | yes (sbl not in list) | yes if list is fw-version-dependent | **mtdblock test: block read succeeds** |
| H2 | QPIC NAND driver crash on ECC-uncorrectable page in those regions (driver BUG()/null-deref in error path) | weak — sbl also on same NAND, but maybe has no bad blocks | possible (block condition varies per unit) | **mtdblock test: block read ALSO panics** |
| H3 | Zero-byte-but-no-panic results were plain `-EBADMSG` (ECC) propagating differently than assumed | yes | yes (matches Leo-PL exactly) | re-read session logs; no new device risk |

---

## Q2 — Community knowledge: MF286/MF286D/MDM9x50 dumps

### eko.one.pl thread id=21790 ("Modem od routera MF286D", 36 pages, 897 posts)

- **adb dd crash confirmed independently, same device+path** — Leo-PL, 2022-06-14,
  pid 270451: *"I was able to dump all of the partitions on my modem, except for EFS
  and MIBIB, trying to dump which caused instant reboot, and for some models even
  reset to QDLoader (9008) mode."* — <https://eko.one.pl/forum/viewtopic.php?pid=270451#p270451>
  Same partition table (identical sizes/names) posted there from `adb shell cat /proc/mtd`.
- **Full modem dump via EDL/qtools is proven** — Leo-PL, pid 286231: dumped "the first
  partitions (up to fota)" and continued "13 to 16" via qtools `qrflash`; the crasher
  partitions dump fine through the **loader's** NAND path. <https://eko.one.pl/forum/viewtopic.php?pid=286231#p286231>
- **Software EDL entry from modem Linux is proven** — hiloa, pid 283922:
  *"I entered into EDL mode with the command `adb reboot edl`"* (9008). <https://eko.one.pl/forum/viewtopic.php?pid=283922#p283922>
- **Software EDL entry via DIAG memory pokes** (no disassembly, works from normal mode):
  `qdload.exe -k12 -q -pX` then `qcommand -pX -c "m 193d100 1"` and `-c "d 7980000 4"`
  over the ZTE Diagnostic port → 9008 (stich86, first post, id=21790). Physically: two
  boot-point pads (test-point short to GND, photos in thread p1).
- **Tools/loaders**: Maks-2012/qtools (+ English mirror haise0/qtools) with modded
  loaders incl. MF286D (`MF286D_qtools-2022-03-1-win.7z`, modded loader in stich86's
  MEGA); **adron-s/qtools** fork fixes the MF286D NAND **ECC** read/write problem
  (pid 286050; also explains why bkerler/edl "wouldn't talk" — Leo-PL pid 286082).
  qtools components: `qrflash` (read flash by partition map), `qrmem` (address-space
  dump), `qefs`/`efsio`/`efs2_imei_patcher` (EFS + IMEI), `mibibsplit`, `qnvram`.
- **NV (QCN) backup/restore over network — no raw mtd** — stich86, pid 270455: dumped
  NV via ZTE "Sales NETport" (network serial redirector), pointed QPST at
  `192.168.32.1:10005`, full Software Download QCN backup; restored with EFS
  Professional (IMEI rewrite) — pids 270455, 283637, thread p1 recovery guide.
  Leo-PL's socat TCP-forward of the router's `/dev/ttyUSB0` (diag) achieves the same
  from OpenWrt (pid 270451/270082).
- Firmware package internals (Nordic/Telia update pkg, pid 270433): full NAND image set
  (`NON-HLOS.ubi` modem, `mdm9650-boot.img`, `mdm9650-sysfs.ubi`, `zterwfs`,
  `recoveryfs`, `partition_nand.xml`, `partition.mbn`, `sbl1.mbn`, `tz.mbn`, `rpm.mbn`,
  `appsboot.mbn`, `efs.mbn`, …) — i.e. everything EXCEPT unit-unique EFS2 content is
  already public in carrier update packages. Boot chain: PBL→SBL1(QSEE+RPM)→LK(aboot)
  with fastboot available (`fastboot flash boot/modem/system/...` all proven, pids
  270433, 286231).

### OpenWrt forum / other

- OpenWrt wiki `openwrt.org/toh/zte/mf286d` — router-side (ipq40xx) OpenWrt target;
  router and modem flash are separate; router-side MTD backup threads
  (forum.openwrt.org/t/172922, t/215044) are about the **router's** 22 partitions, NOT
  the modem's 17. Don't conflate.
- ispreview thread 38435 / eko 21847: `AT+FOTACTR` delta-update flow pushes via
  `adb push delta.package /cache/` → proves **adb sync/push works** on this adbd.
- 4pda thread 964271 (ZTE MF286): IMEI wipes during flashing recovered from modem
  dumps; standard QPST/QCN lore. (Login-walled; treat as background only.)

### ZTE kernel source (ground truth for H1)

- ZTE publishes MF286D OSS notice: `download.ztedevices.com/.../ZTE_MF286D_OpenSource_NoticesV1.1.pdf`
  — covers the **router** side (linux-2.6.31-era list is the *modem's* notice? it lists
  ADB-1.0.26/busybox — that's the router's GPON-era stack, not the 3.18 modem). The
  **modem** kernel (QTI LE msm-3.18) source request channel: `tech.sp@zte.com.cn` /
  opensource.ztedevices.com (GPL offer, 3 years from purchase). If ZTE ships it, diff
  `drivers/mtd/mtdchar.c` + the QPIC driver against CAF — this settles H1/H2 without
  touching the device. No public mirror of the MF286D modem kernel was found today.

---

## Q3/Q4 — NV/EFS without raw MTD (DIAG/QMI/AT)

*(Background subagents for this section were cancelled twice by the environment; this
section is assembled from the primary sources already gathered inline.)*

- **Proven for this exact device (community, multiple times): full-NV QCN backup via
  the DIAG port with zero mtd involvement.** stich86 dumped NV via the ZTE "Sales
  NETport" network-serial redirector and ran QPST Software Download against
  `192.168.32.1:10005` for a complete QCN backup + restore (eko 21790 pid 270455);
  Leo-PL's socat TCP-forward of the router's diag tty achieves the same from OpenWrt
  (pid 270451). A `.qcn` carries the NV item store (IMEI/MEID, RF calibration, band
  masks) — i.e. the irreplaceable content of efs2 — though not the EFS filesystem
  verbatim. QPST + EFS Professional (IMEI rewrite) flow documented end-to-end in
  thread p1 recovery guide.
- **The DIAG protocol primitives are public and implemented in open source**: qtools
  ships `qefs.c`/`efsio.c`/`qnvram.c`/`efs2_imei_patcher.c` (github.com/adron-s/qtools
  file list, verified 2026-11-09) — DIAG NV read/write and EFS file access over the
  Qualcomm command/diag channel; `qrflash`/`qrmem` read flash and address space via
  dload-mode loaders. Legacy codes: NV_READ = diag subsys 0 cmd 0x41, NV_WRITE 0x4B
  (classical DMSS); EFS2 file ops = diag subsystem 13 (DIAG_SUBSYS_FS) — the same
  surface QPST/QXDM use. On-device `/dev/diag` (diagchar) with root can speak these
  from modem userspace (QCSuper demonstrates local-diag from root on Qualcomm Linux);
  on this box the diag port is ALSO exposed to the router over USB (port0 = ZTE
  Diagnostic), which is how QPST-in-the-middle works without touching modem Linux.
- **qmicli/uqmi**: neither exposes generic NV-item or EFS reads (qmicli's dms/uim
  surfaces are curated: --dms-get-*, --uim-*-card/APDU; uqmi likewise has no NV
  read). QMI is therefore a status/AT-adjacent channel here, not an extraction path —
  with one exception: **AT+CRSM / qmicli --uim-send-apdu** relay SIM APDUs (Q6).
- **ZTE AT surface observed live on MF286D** (eko threads): AT+ZCDRUN (USB
  composition/diag-mode switch — `at+zcdrun=8` then `at+zcdrun=F` re-enumerates the
  diag ports), AT+FOTACTR (delta-update control, pushes via `adb push … /cache/`),
  AT+ZCAINFO/AT+ZRSSI/AT+ZNLOCKBAND (status/band-lock), AT+CGMR/ATI (fw version), plus
  standard AT+CRSM. No public AT command reads raw NV/EFS on ZTE MF286-class modems.
- **Ranked Q3/Q4 conclusion**: (1) QCN backup over diag (proven, do first);
  (2) on-device /dev/diag EFS2 file reads with a small root tool (Linux-native
  equivalent of QPST; validate against QCN); (3) EDL loader path (qtools) for the
  raw partition images incl. mibib/efs2.

---

## Q5 — adb 1.0.32 / adbd 5.0.2-class capabilities (inline research)

- **`adb forward` (host-side listener → device target)**: implemented by the `forward`
  service in adbd — present since the earliest adbd versions (Android 1.x era), long
  predates 5.0. Works over the same ADB USB transport as `shell:`, independent of
  `exec:`. Given our `adb shell` works, `adb forward tcp:PORT tcp:PORT` (relay into
  modem's loopback) is the safest tunnel primitive — no new adbd codepaths beyond
  service registration. (ADB protocol/services reference:
  android.googlesource.com/platform/superproject/+/main/system/core/adb — services
  `forward:`, `forward-tcp:`, list via `host:list-forward`.)
- **`adb reverse`**: introduced in Android 5.0 / adb 1.0.32 (protocol 0x01000000) —
  requires adbd to implement the `reverse:` service. Lollipop-vintage adbd *may* have
  it, but vendor-stripped LE builds frequently don't. One-shot test: `adb reverse
  tcp:X tcp:X` — if it errors "closed"/unknown service, it's stripped. Do not rely on
  it until proven.
- **`adb pull`/`push` (sync service)**: `sync:` is ancient and proven working on this
  box (community pushes delta packages via `adb push` to /cache; eko 21847 guide).
  `adb pull /dev/mtdN out.bin` uses the sync `RECV`/STAT path — usually works for char
  devices on old adbd and is ~10x faster than `dd | base64` through the shell stream.
  Low-risk upgrade for the *already-proven-readable* partitions; do NOT try it on the
  crasher set (same kernel read path underneath).
- **`exec-out` broken**: `exec:` service appeared with shell-v2-era adbd; this adbd
  only speaks the legacy `shell:` stream — consistent with observed behavior.
- **QTI LE userland**: modem images are busybox-based (busybox applets incl. dd, cat,
  base64 observed live; ZTE OSS notice lists busybox for the platform family). socat is
  NOT stock; busybox `nc` availability must be checked (`adb shell 'which nc; nc -h'`).
  Persistent tunnel design: `adb forward tcp:LOCAL tcp:MODEMPORT` + a busybox-nc
  listener on the modem (or target an already-listening modem service) — no exec-out
  dependency; survives until adbd restart.

## Q6 — Stretch: UIM/SAP-over-QMI remote-SIM feasibility (inline, verified bits)

- QMI UIM (svc 0x0B) exposes host→SIM APDU exchange: `qmicli --uim-open-logical-channel`
  and `--uim-send-apdu=(slot,channel,apdu)` are in the official qmicli man page
  (<https://www.freedesktop.org/software/libqmi/man/latest/qmicli.1.html>), and the
  lpac-libqmi-wrapper project drives eSIM profile management through exactly this
  surface (<https://github.com/z3ntu/lpac-libqmi-wrapper>). FrOSCon 2024 "eSIM
  management on Qualcomm phones" documents the same technique. `AT+CRSM` (observed
  live on this modem) is the 3GPP-standard equivalent over AT.
- **Direction caveat — this is SIM-on-modem, APDUs-from-host.** For **remote SIM
  (SIM lives on the AP/host, modem consumes it)** you need the modem's UIM task to
  act as a *client* of an external SIM server (BT-SAP client role / UIM redirect).
  No public msm-3.18/QMI message set on MDM9x50 exposes that; QMI "UIM SAP
  connection" is not implemented in libqmi and not documented for data modems.
  Kernel side has no UIM/SAP driver for this (UIM QMI is userspace qmiservices).
- Net: **host-driven APDU relay to the local SIM: YES (qmicli/lpac/AT+CRSM). Remote
  SIM hosting on the AP: NOT reachable via any documented surface** — would need a
  custom modem-side daemon or firmware work. Park it.

---

## The discriminating test — mtdblock hypothesis (H1 vs H2)

**Question:** does the panic live in the *char-device layer* (ZTE guard → mtdblock will
bypass it) or in the *driver/common mtd layer* (→ mtdblock will also panic)?

**Preconditions (overseer-executed; one partition per boot; no other changes):**

1. Confirm the node exists and capture the baseline FIRST — all read-only, zero risk:
   ```
   adb shell 'ls -l /dev/mtdblock* /dev/mtd*; grep mtd /proc/devices; cat /proc/mtd'
   ```
   If `/dev/mtdblockN` does not exist → H1 test unavailable via block path; fall back
   to the offset test (below) and treat "no mtdblock support compiled in" itself as
   weak evidence of a deliberately minimal MTD config.
2. **The test — smallest possible read of the least-identity-critical crasher, mtd1
   (mibib):**
   ```
   adb shell 'dd if=/dev/mtdblock1 bs=4096 count=1 2>/dev/null | base64'
   ```
   - **Outcome A — banner of base64 returns, modem stays up** → the panic trigger is
     in the char path (mtdchar.c guard or char-open hook): **H1 confirmed**. Full
     extraction of mtd1/2/3/5/6 via `dd if=/dev/mtdblockN | base64` is now sanctioned
     (still chunk-wise, one partition per boot, verify ECC-clean by re-read hash).
   - **Outcome B — instant panic/reboot like the char read** → the crash is at/below
     `mtd_read()` (QPIC driver or common MTD layer): **H2 confirmed**. Stop all
     kernel-path reads of the crasher set; the only safe read paths are off-CPU
     (EDL/qtools loader, DIAG EFS2).
   - Watch for the intermediate: **read returns but takes the modem down seconds
     later** — log exact time-to-crash; suggests watchdog, not BUG() (still H1/H2
     ambiguous; do not scale reads).
3. **Second discriminator (only if step 2 was inconclusive or mtdblock absent) —
   offset probe on the char device:**
   ```
   adb shell 'dd if=/dev/mtd1 bs=4096 skip=64 count=1 2>/dev/null | base64'
   ```
   (64 × 4KB = 256KB in, past the first erase blocks.) A name/index guard trips
   regardless of offset; an ECC/driver fault tied to specific blocks will spare
   clean regions (mibib is 0x280000 = 40 blocks, so this reads real content, not
   past-EOF).
4. **Cheapest existing-evidence check (zero device risk):** recover from session
   logs whether mtd2/3/5/6 reads *panicked* or merely returned 0 bytes. 0-bytes-no-
   panic + dd exit≠0 ⇒ ECC return propagating (vanilla char semantics would still
   print data — so no-panic-AND-no-data actually implies a read error at the driver
   that the char layer surfaced) ⇒ re-rank H3 upward.

**Abort criteria:** any read that panics the modem ends the day's testing for that
hypothesis branch; never re-try the exact same failing command; never stack a second
partition read after a panic in the same boot. (Standard bench canon: one variable per
boot, evidence before iteration.)

---

## Ranked safe-extraction recommendations

1. **Don't read protected partitions from the running kernel at all — take the proven
   off-CPU paths first.** In descending order of safety:
   a. **QPST/QCN over the DIAG port** (socat/NETport from router, community-proven on
      MF286D): yields the full NV store (IMEI, RF cal, band masks) — this is the actual
      irreplaceable payload of efs2 — with zero mtd exposure.
   b. **DIAG EFS2 file reads on-device via `/dev/diag`** (subsys-13 EFS2 ops / NV_READ
      0x41) with a small root userspace tool — same data as (a), Linux-native, no
      Windows. Validate against (a) on a couple of files.
   c. **EDL/qtools full-NAND dump** (`adb reboot edl` → 9008 → adron-s/qtools `qrflash`)
      — captures *everything* incl. mibib/efs2/efsbak/tz/aboot through the loader's own
      NAND path, proven end-to-end by Leo-PL. Heavyweight: needs the modem USB
      re-enumeration path (router USB host or mPCIe→USB adapter) and loader ECC noise
      handling (use the adron-s fork). Treat as the archive-grade capture, not the
      daily driver.
2. **mtdblock discriminating test** (above) — cheap, one command, and if Outcome A
   lands, the crasher set opens up to normal adb dd for free. Worth one boot.
3. **Everything non-unique is already public** — sbl/tz/rpm/aboot/modem/system images
   ship inside carrier update packages (partition_nand.xml + *.mbn/*.ubi, eko pid
   270433). Don't spend device risk re-dumping what a firmware package already
   contains; only efs2/efsbak (unit-unique identity/calibration) truly need the box.
4. **Request ZTE's modem-kernel GPL source** (tech.sp@zte.com.cn /
   opensource.ztedevices.com) — the mtdchar.c diff settles the guard question
   permanently and safely.
5. **Never** re-attempt `dd if=/dev/mtd1|2|5` from the running kernel outside the
   controlled discriminating test; a panic mid-write elsewhere (e.g. against a mounted
   UBI volume) is how units die.

## Sources

- eko.one.pl thread 21790 (MF286D modem): p1, p12 (pid 270433/270451), p26 (pid 286050,
  286082, 286231), p27 (pid 283922) — URLs inline above.
- CAF msm-3.18 mirror: github.com/android-linux-stable/msm-3.18 (mtdchar.c, mtdblock.c raw).
- qtools: github.com/adron-s/qtools (README), github.com/Maks-2012/qtools, haise0/qtools.
- OpenWrt wiki/forum MF286D pages; ispreview 38435 + 37795; 4pda 964271 (background).
- ZTE MF286D OSS notice PDF (download.ztedevices.com).
- Q3-Q6 verification notes: /tmp/opencode/deepaccess/NV-EFS-DIAG.md, ADB-TUNNEL-UIM.md.
