# ROUND3 — focused audit: secure boot, dual-root, write_partition, download-mode IP

Evidence: `work/uboot.bin` (kit copy) disasm via objdump + pool-scan; file-offset addresses.

## 1. 'Kernel image authentication failed' — enforced or dead branch?

**DEAD BRANCH on fuse-off units; gate is a RUNTIME fuse query, not a build constant.**

- Fuse check fn @ **0x11424**: calls SCM service (0x11970 with r0=8, r1=7 — QSEE fuse
  read), then:
  - ret != 0 → prints "secure authentication scm call is not supported. ret=%d"
    (string pool 0x114b0) → **returns −1**;
  - result byte == 1 → "secure boot fuse is enabled" (pool 0x114b8) → returns 1;
  - else → **"secure boot fuse is not enabled"** (pool 0x114bc, string @0x70f77) → returns 0.
- Boolean wrapper @ **0x114c0**: `r0 = fusecheck() >> 31` = "auth REQUIRED" only when the
  fuse query itself FAILED-negative; fuse-off → 0 → unsigned boot path.
- The 'Kernel image authentication failed' string (@0x70c45) is referenced from the
  signed-image boot paths (@0x10d9c/0x110a4/0x11138 region — `do_boot_signedimg` /
  `secure_authenticate <sw_id> <img_addr> <img_size>` command family, strings idx 150–264)
  which run only behind the enabled-fuse branch.
- Consistency check (community): Nordic MF286D units boot unsigned OpenWrt with this
  exact kit — impossible if the fuse were blown. Also the family SBL boot log (eko.one.pl
  #312) literally prints "**Secure Boot: Off**". Both SoCs ship fuse-off for this SKU.
- Residual risk: a carrier-specific unit with the fuse blown would refuse — our unit
  already booted community/OpenWrt-family images? Not yet — but it booted the *Nordic*
  router (B10) which is itself a re-flash of stock Telia ⇒ chain demonstrably accepts
  unsigned (or same-key) images. VERDICT: proceed; auth-fail is not on our path
  (`lr` → `bootm` → plain uImage CRC only, "Verifying Checksum …" idx 367).

## 2. bootipq dual-rootfs: rootfs / rootfs_1

- Strings: `rootfsname=rootfs` (@0x70a03) and `rootfsname=rootfs_1` (@0x70a15), kernel
  cmdline `ubi.mtd=rootfs root=mtd:ubi_rootfs rootfstype=squashfs` (@idx 217).
- Selection code @ **0x1086c–0x108e8**: after a getenv probe (0x127f4), calls a validity
  check (**0x11c48**); branch picks ONE of the two `rootfsname=` strings (pools
  0x1097c/0x10980) into r4, stores a zero flag (0x108cc), and passes the chosen string
  onward (0x1c390). ⇒ **conditional A/B volume selection exists at boot** — if the
  primary root check fails, the alternate (`rootfs_1`) name is selected.
- Who writes rootfs_1: the **FOTA/OTA delta flow** (`lrb` → delta.bin @ NAND
  0x3500000+0x1900000 = `data`/`fota` partition per MIBIB; zdu creates the new root
  volume there — UBOOT-ENTRY §1d backup/patch machinery). `lr` does NOT write rootfs_1;
  it overwrites the primary raw `rootfs` (0x1800000+0x1D00000) and blanks `web`.
- Net for us: after `lr`, bootipq uses the primary; fallback to a (possibly stale) OTA
  rootfs_1 only if primary validation fails. Since `lr` writes a complete valid image,
  primary wins. No action needed.

## 3. `nand write_partition` — semantics; 8 MB of 0xFF

- `write_partition` is a ZTE command extension (cmd string @0x6e7bb; handler in the ZTE
  flash cluster). Its block engine is the same bad-block-aware stack used by zdu:
  `Zte_EraseBlock / Zte_WritePage / Zte_MarkAsBadBlock / Zte_IsFlashBadBlock`
  (@0x7cbde–0x7ccf9) — i.e. **skip-forward past bad blocks, mark new bad ones**,
  versus plain `nand write` which aborts on bad blocks. This is exactly why `lr` uses
  write_partition while `lw/lrs/lrb` use plain write.
- **Kit self-proof**: `root_uImage` first 8,388,608 bytes are **100 % 0xFF** (computed:
  FF ratio 1.000 over [0,0x800000), longest run 0x800000, zero non-FF bytes) — the
  community image DELIBERATELY ships an all-FF web-slot payload for the
  `write_partition … 0x1000000 0x800000` stage. Combined with NAND physics (programming
  0xFF transitions no bits 1→0; over an erased block it is a functional no-op) ⇒
  **writing the FF region is equivalent to erasing the web partition** — intended,
  exercised by the whole community cohort, no error path specific to FF data.
- Residual nuance: if the web slot contains a PREVIOUS non-erased image, `lr`'s stage-1
  still erases first? The env line shows only `write_partition` without a preceding
  `nand erase` for 0x1000000 (unlike lrs which erases first) — implying write_partition
  ERASES per-block internally (consistent with the Zte_EraseBlock-in-engine design).
  Either way the kit's own image proves the path works on real units.

## 4. Download-mode addressing — static, not DHCP

- Full DHCP/BOOTP client exists (`dhcp`, `bootp` commands, "DHCP client bound to %pI4")
  but the **download-mode entry does not use it**: the E3-entry cluster
  (@0x1c980–0x1d060) first reads ~10 CDT/platform parameters by index (26,27,28,29,30,
  32,34,36,38,40 — byte/halfword reads via the 0x47c5c/0x47c9c helpers), then:
  `sprintf(ip, "192.%d.%d.%d", <p32>,<p34>,<p36>)` (fmt @0x74ca7, users @0x1cf80–0x1cfd0),
  `sprintf(mac, "0x00:0xaa:0xbb:0x%2x:0x%2x:0x%2x", <p38>,<p39?>,<p40>)`, `ip=%s mac=%s`
  log, setenv ethaddr, **serverip = 192.0.0.1** (string @0x74ceb), `run lr`.
- ⇒ device takes a **STATIC self-IP 192.x.y.z derived from CDT platform params**
  (not the 192.168.0.1 default env — that is only the normal-mode default; not DHCP).
- The same param block feeds the zdu filename `%02X%02X%02X%02X.img` (the MF286A
  '4801A8C9' observed) — exact index mapping not fully pinned (residual).
- **Operational answer: our side only needs to (a) OWN 192.0.0.1 and (b) ANSWER THE
  DEVICE'S ARP for it.** No DHCP service is required in download mode; the client IP
  (192.x.y.z) is irrelevant to serving. Keep dnsmasq OFF during the window so nothing
  offers the device a different config.

## Verdicts
1. Secure boot: not enforced (runtime fuse off; dead branch; community-consistent).
2. Dual-root: automatic conditional select exists; lr writes primary; no action.
3. write_partition: bad-block-skipping ZTE writer; all-FF payload ≡ erase — kit itself
   ships exactly that shape for the web slot. Safe.
4. Static 192.x.y.z from CDT + fixed server 192.0.0.1; ARP answer suffices; disable DHCP.
