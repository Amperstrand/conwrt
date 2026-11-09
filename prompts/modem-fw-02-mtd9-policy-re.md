# Prompt: offline RE of the MF286D modem firmware (mtd9) — find the ISD-R policy

Goal: locate, in the ZTE-customized Qualcomm MPSS image, the code that
implements the three-layer ISD-R denial, and determine whether it is gated by
an NV/config item (flippable via diag) or hard-compiled (patch class).

## The artifact

- Path (bench x280): `~/mf286d-work/evidence/modem-fw-re/live-b12/dumps/mtd9.img`
- Size 74,767,527 B; sha256 `55848f96b695c3470546d87b8b107ba12b01f4fc722317707a568689ab17ea15`
- Acquired: `adb shell cat /dev/mtd9ro` from modem Linux (read-only), 2026-11-09.
- It is a raw NAND partition dump (erase block 0x40000). Partition name "modem",
  size 0x04700000 per `/proc/mtd`.

## What to find (behavioral spec — match code to this)

1. **L1 — channel-open deny**: UIM OPEN LOGICAL CHANNEL handler checks the
   requested AID: length ≥ 7 AND first 7 bytes == `A0 00 00 05 59 10 10`
   → returns QMI error 82 (ACCESS_DENIED). Sub-7-byte prefixes pass through.
2. **L2 — fake card responses**: for channels whose SELECT response FCI
   contains an AID matching the ISD-R (the full 16-byte
   `A0000005591010FFFFFFFF8900000100` appears in the FCI), the UIM APDU path
   synthesizes canned SWs instead of forwarding: SELECT→`6A82`, STATUS→`6D00`,
   STORE DATA(E2)→`6A80`. (On non-flagged channels APDUs pass byte-faithful.)
3. **L3 — APDU payload scanner**: any SEND APDU whose data contains a SELECT
   by DF name with AID prefix ≥4 bytes `A0 00 00 05` is dropped (QMI err 1).
4. Optional 4th: whatever makes `AT+CCHO`/`+CSIM` fail at the ATCoP level.

## Suggested method

1. **Strings/byte scans first** (whole image, all alignments):
   - ISD-R AID bytes: `A0 00 00 05 59 10 10`, full 16-byte form, and ASCII/hex
     variants; also `59 10 10` alone to catch split constants.
   - The GSMA RSP RID `A0 00 00 05` — expect MANY hits (also used by ISD-P
     matching); triage by neighborhood.
   - Canned SW constants as u16/u32 immediates or tables: `82 6A`, `00 6D`,
     `80 6A`, and QMI error enums 82/80/1 near UIM strings.
   - ZTE markers: `ZTE`, `BD_TELIAMF286D`, build strings, and NV item name
     strings (ZTE builds often name their NV items — grep `isdr`, `euicc`,
     `esim`, `uim_` case-insensitively).
2. **Carve the container**: Qualcomm modem (MPSS/AMSS) images for NAND
   typically embed one or more ELF segments (Hexagon v5/v6 Q6 code) plus
   hash/hashtables (qsee/`08 00 00 00` style) — scan for `\x7fELF`, segment
   program headers, and the 0x40000-erased gaps to map sub-images (similar to
   the B02 Marvell FBF carve in `ANALYSIS-b02-kit-marvell.md` §1).
3. **Disassembly**: Hexagon (QDSP6). Options: Ghidra + the community Hexagon
   processor module; `hexagon-llvm-objdump` if you can get Hexagon SDK/CLANG
   tools; IDA with the hexagon plugin. For triage, plain byte-pattern
   reasoning around the AID-compare sites often suffices — these checks are
   memcmp-style, look for compare-with-immediate chains / crc-style matchers.
4. **NV gate determination**: if the deny path reads an NV/EFS item before
   deciding (typical ZTE/MCFG pattern), the flip is a diag NV write (we have
   `/dev/diag` + root on the modem) — verify item number, then plan a
   reversible single-item test. If no gate: it's the binary-patch class
   (EG25-G precedent) — document the exact patch site + needed hash-table
   re-sign implications, do NOT flash without a full modem backup + operator
   sign-off (modem brick = no recovery on this device).

## Deliverables

- Analysis doc under `~/mf286d-work/evidence/modem-fw-re/live-b12/` +
  ledger row (append-only, EXP-0xx).
- Precise addresses (file offset + load address) of L1/L2/L3 checks,
  the NV gate verdict, and updated TESTPLAN facts.
- Copy committable docs/scripts into `recipes/zte/mf286d/modem/` and PR.

## Cross-references

- Live behavioral spec + probe tooling: `prompts/modem-fw-01-mdm9650-live-access.md`,
  `recipes/zte/mf286d/modem/TESTPLAN-live-b12.md` (facts F1–F17).
- B14 .up OTA package (contains B12→B14 modem-side diffs incl. NV scripts):
  see `notes.md` "B14 continuation" — a static diff of the modem partition
  against this mtd9 base may directly reveal the policy structures.
- B02 Marvell generation analysis (different hardware, useful contrast):
  `recipes/zte/mf286d/modem/ANALYSIS-b02-kit-marvell.md`.
