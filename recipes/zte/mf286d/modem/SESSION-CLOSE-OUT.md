# ISD-R RE Lane — Session Close-Out (2026-11-11)

## What was committed and pushed (PR #664, now at 5e7cbce)

All work is on the `modem-fw/exp-035-policy-docs` branch. The push was
initially rejected (local had been rebased onto main) — resolved by rebasing
onto the remote tip. Final push: `1598f04..5e7cbce` (19 commits).

### Documents (all in recipes/zte/mf286d/modem/)
- FINAL-STATUS.md — complete campaign status + roadmap
- B14-GENEALOGY-REPORT.md — B14 reconstruction + firmware lineage
- B14-QMI-BREAKAGE-ANALYSIS.md — rootfs diff + leak-scan disposition
- B02-B12-ARCH-SPLIT.md — cross-linked architecture split (from modem lane)
- hexagon-re/ — all RE artifacts (see below)

### Hexagon-RE artifacts (recipes/zte/mf286d/modem/hexagon-re/)
- QSHRINK-DB-ANALYSIS.md — the debug-symbol database discovery
- UIM-MSGID-EXTRACTION.md — proprietary message ID extraction
- EXP040-FINAL-VERDICT.md — live external-reachability verdict (35/44)
- EID-GATE-DIAGNOSTIC-PLAN.md — decision table + crasher list + probe rules
- LPA-ENABLE-GATE-ANALYSIS.md — the Quectel reframe + QESIM→ID mapping
- uim-protocol-spec.json/.txt — ALL 84 message layouts decoded
- uim-aggregate-types.json — 76 nested struct definitions
- uim-name-map.md — semantic name assignments
- decode_idl.py — the QMI IDL decoder (reusable)
- uim_bitmap.c — v9 probe tool (9 modes: ver/probe/sweep/call/callslot/listen/regcall/regcall2/enablecall)
- Hunt.java / Hunt2.java — Ghidra xref dumper scripts
- vmap.py, mkelf.py, combine_elf.py — address-space + ELF tooling

### AGENTS.md
- L-PROBE-01 "Decode Before Probe" rule (5e7cbce) — institutional learning
  from the 0x6b and 0x67 crashes: mandatory protocol-decode + adversarial
  safety review gates before any undocumented-interface probe

## What is kept locally (regenerable, not in git)

| Artifact | Size | Regenerable from |
|---|---|---|
| full-disasm.txt | 260MB | combine_elf.py + llvm-objdump --triple=hexagon |
| qshrink-db.txt(.gz) | 21MB/4.6MB | qdsp6m.qdb + python3 -c zlib.decompress |
| uim_bitmap (ARM binary) | 594KB | uim_bitmap.c + arm-linux-gnueabi-gcc -static |
| b14-tree/ (B14 modem fs) | ~60MB | rebuild_final.py + B12 base |
| b14-rootfs/ (B14 modem Linux) | ~100MB | rebuild_final.py + B12 base |
| Ghidra project | 1.8GB | combine_elf.py + analyzeHeadless (on ai-legion-small) |

All source code and documentation needed to regenerate these is in the repo.

## Open items for the next session

### HIGH priority
1. **Device recovery**: device 1 is in a crash loop (issue #169). Recovery
   by the device lane. All further probes blocked until restored.

2. **LPA enable-gate test (v9 enablecall)**: the prime candidate (0x53)
   is ready to test. Sequence: state(0x63) → enable(0x53,{slot,u32=1}) →
   state → EID(0x65). If the state changes and EID returns → campaign
   essentially complete for profile management.

3. **DIAG F3 capture during EID attempt**: the 15-hash watch-list +
   decision table are ready. This is the definitive diagnostic if the
   enable-gate test doesn't resolve it. Requires DIAG port access
   (qfenix on the router).

### MEDIUM priority
4. **Name-map completion**: the 84 messages are shape-decoded but exact
   names come from the tail-merged IDL name pool. The offset table
   linking names to IDs is in b20 but not fully decoded.

5. **0x66 as alternate enable candidate**: same shape as 0x53
   ({slot, u32} → ACK). Test if 0x53 doesn't change the state.

6. **Profile operations driving**: once the gate is solved, drive
   0x34 (list profiles), 0x61 (enable), 0x62 (disable), 0x64 (delete),
   0x68 (nickname). All layouts decoded.

### LOW priority
7. **ZTEDATA partition**: the delta.package had a ztedata.mld entry
   (1781B) — may contain ZTE-specific config relevant to the LPA gate.

8. **UIM-Remote (RSIM) machinery**: full subsystem confirmed in firmware
   (qmi_uim_remote.c etc.) but gated by EFS `uim_remote_service_enable`.
   Documented as a separate capability path.

9. **Laptop modem**: ThinkPad X280 has Fibocom L830-EB (Intel XMM 7262,
   not Qualcomm) — different firmware ecosystem entirely. No eSIM support.
   Not RE-able with our existing toolchain.

## Session statistics

- Experiments: EXP-038 through EXP-044 (7 ledger entries)
- PR commits: 41 (modem-fw branch)
- GitHub issue comments: 6 across #672, #675, #677, #682
- Documents written: 12
- Tools built: uim_bitmap v1-v9, decode_idl.py, combine_elf.py, Hunt.java/Hunt2.java
- Crasher incidents documented: 3 (mtd1/mtd2, 0x6b bare-slot, 0x67 valid-u64)
- Live probes executed: ~60 (all read-only except 3 crashers)
- Messages decoded: 84 (full IDL protocol specification)
