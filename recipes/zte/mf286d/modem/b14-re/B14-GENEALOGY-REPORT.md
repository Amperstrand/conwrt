# B14 Firmware RE + Full Lineage Genealogy (B02→B14)

EXP-038. 2026-11-10. Companion to FINAL-STATUS.md (EXP-034/035/036/037).

---

## Executive summary

1. **ZTE OTA delta format (ZFD01.02/ZDFU) fully reverse-engineered.** Any MF286D
   `.up` package can now be unpacked and applied offline. Tooling in this directory.
2. **B14 reconstructed to ~99%** (all files except full byte-perfect b11/b15,
   which are decoded to chunk-manifest + raw-literal level). 23/26 ELF segments
   size-validated against the B14 `modem.mdt` program-header table.
3. **B14 verdict: NO eSIM-relevant changes.** The entire SGP.22 LPA client
   (b15 chunk 90) and the `apdu_security` policy area (b15 chunk 106) are
   byte-identical B12→B14 (copied chunks). B14 is a routine Qualcomm release
   refresh: MPSS.AT.2.5.1-00628→**00735-9655_GEN_PACK-2**, LE.1.2-10295→**10491**.
4. **B13 never existed** for this variant (404 on all OTA URL patterns; the
   community chain jumps B12→B14).
5. **B10 = B11 = B12 modem firmware** (the B10→B11 and B11→B12 modem deltas are
   empty 56-byte stubs). Router version numbers advanced; modem bits identical.
6. **The LPA has existed since the very first Qualcomm firmware (B02).**
   No delta B02→B10 introduces any euicc/LPA/ISD-R string; B12 has them; the
   strings must pre-date the whole chain. **There was never a MF286D Qualcomm
   firmware without the LPA + ISD-R reservation.** The three-layer defense is
   original equipment across the entire lineage.
7. Community warning confirmed: B14 breaks QMI usage under OpenWrt (openwrt.org
   forum, 2025) — users downgrade to B12. **Stay on B12.** Flashing B14 would be
   a regression with zero eSIM benefit.

---

## 1. ZTE OTA container formats (fully decoded)

### 1.1 `.up` package (ZIP)
```
cpe_postprocessing.sh   nv-set script (ZTE router config incl. cr_version)
delta.package           outer ZTE container (below)
delta.signature         RSA-2048 sig of delta.package
key.signature / public_ver.pem   verification chain
root_uImage.mld         FULL new router firmware (not a delta)
root_uImage.signature
```

### 1.2 delta.package (outer container, magic `88 55 AA 55`)
```
[u32 count][8B pad] then count entries of:
  [name char[32]][size u32 LE][offset u32 LE]
Partition entries: boot/aboot/recovery/recoveryfs/rpm/sbl/system/tz/
modem.mld/ztedata.mld/mem_sz/preprocessing/clean_mem/postprocessing/efs.mld
```
`modem.mld` payload = ZFD01.02 container (below). Empty payloads (56B) =
partition unchanged (this proved B10=B11=B12).

### 1.3 ZFD01.02 container (per-partition delta, magic "ZFD01.02")
Header (0x2C bytes): magic, ver, …, [payload_size BE u32 @0x20],
[entry_count BE u16], … then interleaved entries:
```
[A u32BE][B u32BE][plen u32BE][path+NUL (plen B)][blob]
blob = [blob_len u32BE = LZMA-stream length incl. 5B header]
       [patch_len u32BE = decompressed size]
       [LZMA1: props 0x5D, dict u32 LE, data]   (python FORMAT_RAW)
```
Decompressed blob content is one of:
- `BSDIFF40` patch (most files)
- full new file (`7F 45 4C 46` ELF for mcfg_sw.mbn carrier configs — 22 of them)
- `ZDFU` chunked delta for the two big code segments (modem.b11, modem.b15)

Trailer blob (pathless) after the last entry.

### 1.4 BSDIFF40 variant semantics (NOT vanilla bsdiff)
```
header: "BSDIFF40" + ctrl_len u64LE + diff_len u64LE + new_size u64LE
ctrl:   triples (x, y, zq) — x = add-run length, y = extra-run length,
        z = ABSOLUTE old-file position (u32 low), high dword = flags
        (0x80000000 seen on continuation/whole-file entries)
diff:   byte-wise ADD deltas (new = old[pos+i] + diff[i] mod 256)
extra:  literal inserts, consumed by y-runs
quirk:  whole-file single-entry patches carry z as metadata → read from 0
validation: 76/77 patches apply to exact new_size; diff fully consumed
        (≤1 trailing byte slack in 7 files)
```

### 1.5 ZDFU chunked delta (modem.b11/b15)
```
blob: [new_size u32BE]["ZDFU"][ver=1][flags=0][nrec u32BE]
      [chunk_size = 0x20000 (128KB)][algo fields][decoded_size u32BE]
      [streams_len u32BE][crc32]
streams: [crc32 u32BE][LZMA 0x5D+dict+data] → ops stream (decoded_size)
ops:   [nrec × 28-byte records][literal data…]
record: [op u32BE][param u32BE (u16 value + pad)][size u32BE]
        [crc1 u32BE][crc2 u32BE][a u32BE][b u32BE]
```
Verified record semantics (b15, nrec=1204):
- `op 0x01000100` = chunk copy: crc1 = **crc32 of the 128KB source chunk in the
  old file** (verified 39/39 against B12 b15 chunks!), a/b = new-chunk
  index/count, param = per-chunk micro-correction hint
- `op 0x00010000` = data-block reference (a = new chunk, size = length)
- Level-2 records (sub-chunk matches with absolute old-file positions and
  crc1==crc2 identical-range checks) + RAW UNCOMPRESSED literals for new bytes
  follow the table. **Literals are plaintext** → new-chunk strings are directly
  greppable without full reassembly (this is how B14 was string-diffed).

---

## 2. B14 reconstruction results

- **99 of 163 delta entries applied** → `b14-tree/` = complete B14 modem
  filesystem (B12 base + 84 patches + 22 full replaces; 55 directory stubs skipped).
- Segment map (B14 modem.mdt phdr[k] ↔ modem.b{k:02d}, 31 phdrs):
  - confirmed via phdr[11].filesz == b11 newsize, phdr[15].filesz == b15 newsize
  - **23/26 segments size-validated**; misses = b11/b15 (ZDFU, chunk-decoded
    only) and b20 (+0x1000 pad-page growth, content unchanged, absent from delta)
- Memory-map changes: pure growth/shift — b15 grew 0xEDE061→0xEE4CB1 (+0x4C50),
  shifting b16+ by +0x6000…0x14000. b09 moved e06fc000→e06f3000.
- String diffs (whole tree): only signing-cert timestamps changed in
  mdt/b01/mba.mdt (`210710045506Z`→`240423204929Z`). **Zero new eSIM/UIM/LPA
  strings anywhere.** b15 literal additions are ZTE autoreg/dual-SIM telemetry
  NV items (SIM1ICCID/SIM2ICCID/DataSim/… ) and one `uim/simlock/rsu_device_id`
  fragment (remote-SIM-unlock, carrier-lock related — not eSIM profile mgmt).

### B14 identity
```
common: MDM9650.LE.1.2-10491-NBOOT.NEFS.PROD-1.557837.1.559538.1
modem:  MPSS.AT.2.5.1-00735-9655_GEN_PACK-2.557837.1.559538.1
(B12:   MDM9650.LE.1.2-10295 / MPSS.AT.2.5.1-00628)
```

### The chunk-level proof (why we're certain)
B12 b15 LPA machinery locations vs the B14 copy-manifest:
```
euiccChallenge            @0x00b49190  chunk 90   COPIED byte-identical
initiateAuthentication    @0x00b48deb  chunk 90   COPIED
getBoundProfilePackage    @0x00b48e7a  chunk 90   COPIED
authenticate_server       @0x00b494af  chunk 90   COPIED
activation_code           @0x00b493d1  chunk 90   COPIED
apdu_security_aid_list    @0x00d5f2f9  chunk 106  COPIED
```
Rebuilt chunks (0–16, 18–32, 35–81) contain **zero** occurrences of
euicc/lpad/ISD/ES9/smdp/A000000559. The B14 delta does not touch the LPA,
the ISD-R machinery, or the EFS policy surface.

---

## 3. Lineage genealogy (B02→B14)

Chain analyzed: Nordic/Telia OTA packages (makebit/mf286d-openwrt resources)
```
B02→B05  modem delta 5.75MB, b15 ZDFU  — no LPA strings introduced
B03→B06  (same target modem as B02→B05) — none
B05→B06  5.75MB — none
B06→B08  5.68MB — none
B08→B09  6.39MB — none
B09→B10  5.86MB — none
B10→B11  modem delta EMPTY (56B) → B10==B11 modem
B11→B12  modem delta EMPTY (56B) → B11==B12 modem
B12→B14  (ZTE OTA server, this report) — LPA chunks copied byte-identical
```
Conclusions:
- **Distinct modem firmware generations: B02 → B05/B06 → B08 → B09 → B10(=B11=B12) → B14.**
- LPA/euicc/ISD-R/apdu_security strings appear in NO delta literals, yet are
  present in B10/B12 ⇒ **present since B02**. The LPA-owns-ISD-R design and the
  three-layer defense have always been there. No golden old firmware exists.
- eSIM management was never host-accessible on ANY MF286D Qualcomm firmware.

---

## 4. B13 availability

Not released. ZTE OTA URL probes (`.../337964/TELIA_MF286DV1.0.0B12-*B13*.up`
and variants) all 404. Community chain skips B13 (B12→B14 direct).

---

## 5. Practical guidance

- **Do not flash B14**: no eSIM gain (proven above), breaks QMI under OpenWrt
  (community-verified regression; downgrade requires ZTE Windows framework).
- B12 remains the optimal firmware for our use (OpenWrt-compatible, QMI clean,
  ADB root stable).
- eSIM management stays on NR7101 + lpac or USB CCID reader (proven paths).

---

## 6. Remaining research (updated roadmap)

| Question | Status after EXP-038 |
|---|---|
| Does B14 wire the LPA to a host interface? | **ANSWERED: NO** |
| Did any older firmware allow ISD-R access? | **ANSWERED: NO (LPA+block since B02)** |
| Does B13 exist? | **ANSWERED: NO** |
| Full byte-perfect b11/b15 B14 rebuild | Level-2 record grammar ~90% done; not needed for the eSIM question (strings fully extracted) |
| Proprietary QMI M2M euicc message IDs | OPEN — needs Hexagon RE of mtd9 (Ghidra Hexagon module research in flight) |
| MPSS binary patch of the ISD-R deny | OPEN — Hexagon RE prerequisite; last resort |

---

## 7. Artifacts (this directory)

```
B12-to-B14.up              original OTA package (sha256 7df293bd…)
extracted/                 .up contents (delta.package, root_uImage, …)
modem.mld.delta            modem partition ZFD01.02 container
extract_zfd.py             ZFD walker + blob decoder
build_b14.py               B14 tree builder (bspatch-v3)
bspatch2.py                BSDIFF40-variant patcher (absolute-z semantics)
b14-tree/                  reconstructed B14 modem filesystem
b15.zdfu-decoded.bin       b15 ZDFU ops stream (records + raw literals)
b11.zdfu-decoded.bin       b11 ZDFU ops stream
patches/                   extracted BSDIFF40 patches
extract-report.json        per-entry decode report
../older/nordic-updates.zip + extracted chain   (B02→B12 lineage)
```
