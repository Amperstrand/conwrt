# Z-Loader STAGE-2 RE — FINDINGS (2026-11-10)

Campaign: `zloader-re` (README.md). Static analysis only. Target: STAGE-2 blob
(`stage2.bin`, 82432 B) extracted with `dd skip=0x23ee0` from
`/srv/bench-golden/donor/mtd0-bootbase.bin` (read-only source; nothing outside
this dir modified).

Evidence grades: **[P]=Proven** (disasm/decomp shown, addr cited) ·
**[S]=Strong** (consistent across ≥2 independent anchors) ·
**[I]=Inferred** (single anchor or heuristic) · **[X]=Refuted**.

---

## 0. Ground truth: load address & memory model  — basis for every addr below

| Claim | Status | Evidence |
|---|---|---|
| Stage-2 loads at **VMA base 0x84024000** (KSEG0, phys 0x04024000) | **P** | 165/165 absolute pointer words in data table (rel 0xe1fc–0xe568) land inside code/data rel ranges only for this base (brute-force score 165/165, 16KB-aligned); string pointers hit exact string starts, e.g. word @rel 0xe264 = 0x840315a0 → rel 0xd5a0 `"    : %02X\n"` |
| `_gp = 0x840323F0` | **P** | all 54 PIC prologues `lui gp,0; addiu gp,gp,D; addu gp,gp,t9` satisfy entry+D = 0x840323F0 (e.g. 0x8402a920+0x7ad0; 0x8402ac5c+0x7794; … census in `loadaddr_census.py` output) |
| Entry point = **0x8402A920** (rel 0x6920) | **P** | first PIC prologue; `lw t9,8(gp)` + `bal 0x84030c64` (bss-clear) + banner printf in first 0x30 bytes |
| Runtime state base **S = 0x84030120** (all strings/globals addressed S-relative via slot @0x84032404) | **P** | `lw $a0,0x14($gp)` (0x8402a964) + `addiu $a0,$a0,0xc20` (0x8402a970) → banner `"\n\nZ-LOADER V%d.%02d | %s %s\n\n"` @0x84030D40 = S+0xc20 ✓; `"DebugFlag"`@S+0xc70, `"Hit ESC…"`@S+0xc7c, `"\b\b%2d"`@S+0xc9c, `"CheckBypass"`@S+0xca4 all exact |
| Flash slot value @0x84032404 = 0x84030000 is the link-time init; runtime S=0x84030120 (0x120 offset = state-struct prefix, runtime-filled) | **I** | word @rel 0xe404 = 0x84030000 vs string math needing 0x84030120; bss-clear FUN_84030c64 covers 0x84032458–0x84032510 so prefix is not flash-resident |
| Stage-1 passes an **API descriptor in $k0**; `*(k0+0x20)` = function-pointer table; every I/O/flash/net op is a stage-1 callback | **P** | wall of wrappers `lw $t9,0x20($k0)` at 0x840308dc–0x84030c4c (printf=FUN_8403092c, delay=FUN_8403097c, getc=0x84030c8fc/0x84030c8ec, erase=FUN_84030bdc, memcpy=FUN_840309fc, flash-write=FUN_8402cc0c…) |
| `*(k0+0x10)` = memory/flash size word X; download buffers = `(X>>1)+base` | **P** | `lw $v0,0x10($k0); lui $v1,0x8100; srl $v0,1; addu` @0x8402fcb4-0x8402fccc (and 0x8402fddc, 0x8402ff08) |
| Stage-2 = **MitraStar/ZyXEL "Z-LOADER"**, family NBG4104/M4G-3301/NR7101 | **P** | strings `"Mitrastar Technology Corp"`@0x84030ca8, `"M4G-3301"`@0x84030cc8, `"NBG4104"`@0x84030d00, `"NR7101"`@0x8403105c, model gate `"7101"`@0x84030e80, banner `"Z-LOADER V1.30"` (V%d.%02d ← 1,0x1e) + build `"08:39:30"`,`"06/03/2020"`@0x84031d0c/d18 (matches uImage ts 2020-06-03 00:39) |
| Image layout: rel 0x6920–0xcca8 .text (6365 insns, 0 bad), 0xcca8–0xe568 .rodata/.data, 0xe568–0x14120 BSS (zero), tail 0xff = flash padding | **P** | region scan + Ghidra 12.2 import @0x84024000 (project `ghidra-stage2/`, 120 functions, `stage2_decomp.c`) |
| README lead "multicast constants @dump 0x1da75-ish" | **X** | that stage-1 area = TCP-option-kind table (01 02 04 05 07 08 0a 0b 0c 10 16 17 1a) + 0x2580(=9600 baud); no 224.x/239.x/01:00:5e constants anywhere in stage-2 (pattern hits at rel 0xa426/a496 are the layout-selector `sllv` code) |

## 1. zycast receive state machine (Q1)

| Claim | Status | Evidence |
|---|---|---|
| Listen window = **6 seconds**, 1 s ticks, `"\b\b%2d"` countdown | **P** | FUN_840306a8 @0x840306b0: `iVar7 = 6`; loop `FUN_8403092c(S+0xc9c,i)` + `FUN_8403097c(1000000)`; prints `"Multiboot Listening..."`(S+0x206c) |
| Transport: **UDP, dst port 0x15FF (5631)** | **P** | FUN_840302d0 @0x840302dc: `if (param_2 != 0x15ff) → "dest_port error"`(S+0x1ee0) |
| Magic: **3-byte `"zyx"`** at packet start | **P** | `FUN_84030a0c(pkt, S+0x1ef4, 3)` memcmp; sig bytes @0x84032014 = `7a 79 78`; fail → `"The signature is %s, wrong signature"`(S+0x1ef8) |
| Packet layout (big-endian fields): `+0 "zyx"`, `+4 u16 checksum`, `+6 u32 block seq`, `+0xa u32 payload len`, `+0xe u32 total size`, `+0x12 u32 type flag (uses &0xff00)`, `+0x15 u8 total-type mask`, `+0x16 2B cmd flags`, `+0x18 u8 cmd bits`, `+0x1e payload (1024B blocks)` | **P** | parse in FUN_840302d0 (0x840302e8–0x84030270): unaligned BE read @+0x12, `FUN_8402f718`(ntohl)@+6/+0xa/+0xe, checksum cmp vs BE u16@+4, memcpy src `+0x1e`; finalize tail reads +0x15/+0x16/+0x18 @0x8403021c–0x84030274 |
| **Checksum16 = byte-sum folded once**: `cs = (Σ payload bytes); cs = (cs>>16)+cs & 0xffff` | **P** | FUN_8402f740 @0x8402f740 |
| Sequence/reassembly: per-type 12-byte descriptor {u32 first_seq, u32 expect_seq, u32 last_block}; table of 8 (memset 0xff, 0x60) at *(0x8403251C); accept iff `seq == expect` (or expect==-1); payload → `buf + seq*0x400` (**1 KB blocks**); on match `expect = seq+1`; on `seq == last_block` → `expect = 0`; when `expect == first_seq` (all blocks) → type-complete bitmask `state+0x2494 |= type>>8` | **P** | FUN_840302d0: dup-check `(type>>8 & state+0x2494)→drop` @0x84030200-0x84030208; seq check @0x840301a0-0x840301c8; copy `bal 0xc9fc` (memcpy) dst `iVar15+seq*0x400` @0x8403014c-0x84030160; desc update @0x840301b4-0x840301c8; completion @0x840301e0-0x840301f8 |
| Rollback on out-of-order = print + reset descriptor (sender retransmits window) | **S** | strings `"Roll back to receive previous boot base/RAS/user-config/SP configuration packet ID: 0x0000"` @S+0x1cb9/S+0x1d25/S+0x1db1/S+0x1e3d printed at expect==0 re-receive paths |
| Stream completion: when `state+0x2494 == pkt[+0x15]` (sender's total-type mask) → apply cmd tail (`+0x16..0x18`), print `"------MultiBoot Download Finish------"`(S+0x1eb4), set completion flag `*(0x84032518)=1`, reset `state+0x2480=0` | **P** | 0x84030214 `bne $s2,$v0` gate; flag stores via `*(gp+0x134/0x138/0x13c/0x140)` @0x84030230–0x84030274; printf @0x84030284 (+0x1eb4); `sb 1,(v0)` w/ v0=*(gp+0x128) @0x84030298-0x8403029c |
| While downloading, listener blocks in `FUN_84030b7c()` (eth rx pump) until completion flag, then halts net and calls flash-commit FUN_84030404; success (`r!=0`) → `"Upgrade firmware finished and please restart system !!"`(S+0x2084) + callback `*(0x84032558)`; fail → `"Upgrade firmware fail!!"`(S+0x20bc) + callback `*(0x8403255c)`; jalr @0x84030854. **Lane-2 CORRECTION (supersedes prior swap):** success slot 0x84032558 / fail slot 0x8403255c, disasm `beqz v0` @0x84030820 + delay-slot loads @0x8403083c/0x84030850. Flash-.data defaults: 0x84032558 → FUN_8402f670 ("Erasing ROM-D configuration ..."!), 0x8403255C → FUN_8402f7a0 (LED error pattern); slots outside bss-clear (0x84032458-0x84032510) — likely stage-1-patched to real reboot/halt at handoff [I] (same patch class as proven state-slot 0x84032404 0x84030000→0x84030120) | **P** (branch+defaults) / **I** (runtime patch) | FUN_840306a8 @0x840307d0-0x84030854; .data words @0x84032550-0x8403255c |
| LED feedback: GPIO wrappers FUN_8402bc30(led 0xd/0xe/0xf); steady pattern while listening, blink while receiving, infinite blink = fatal `"Multiboot error, please reboot system.."` | **P** | FUN_8402f770/FUN_8402f790/FUN_8402f8c0/FUN_84030358 |
| MAC-layer: while listening, GDMA regs **0xBE000600/0xBE000620** bit 0x8000 toggled every 220e6 timer-units and on phase (mcast/broadcast accept control); no IP multicast group join in stage-2 | **P** | FUN_840306a8 @0x840306e0-0x84030730; absence of 224.x/239.x/01:00:5e constants (see §0) |

## 2. Accept conditions — what gets written vs ignored (Q2)

Ordered gate chain, all in FUN_840302d0/FUN_8402f9e0 unless noted. A packet is
DROPPED SILENTLY unless every check passes:

| Gate | Reject behavior | Status | Evidence |
|---|---|---|---|
| UDP dport == 5631 | print `"dest_port error"` | P | 0x840302dc |
| `"zyx"` magic | print wrong-signature | P | 0x840302e8 |
| type ∈ {0x100,0x200,0x400,0x800} (`&0xff00`) | print `"send file error."`(S+0x1c58)/`"Invalid type…"` | P | 0x8402fb00-0x8402fb6c |
| completion flag == 0 | total ignore | P | 0x84030214 (`**(gp+0x2b38)` = *(0x84032518)) |
| type not already complete (`type>>8 & state+0x2494 == 0`) | silent drop | P | 0x84030200-0x84030208 |
| `seq == desc.expect` (or -1) | silent drop (→ sender rollback+retransmit) | P | 0x840301a0-0x840301b8 |
| `checksum16(payload,len) == BE16@+4` | print `" checksum error! wait next file"`(S+0x1c6e), skip packet | P | 0x8402fbxx branches → LAB_8403001c |
| FLASH-COMMIT gates (FUN_84030404 + writers): size caps | `"Bootloader file size too large!!"` / `"Downloaded file size is too large!"` | P | 0x84030404: `(*0x8403253c)<<2 < size` (bootloader); `0x2000000-(*0x8403253c)*10 < size` (RAS) |
| RAS magic: firmware `0x30524448` / bootloader `0x34524448`, compared AFTER bswap (thunk FUN_8402eff0) ⇒ on-disk bytes are **BE-stored**: `30 52 44 48` ("0RDH") / `34 52 44 48` ("4RDH"); hex-dump-ASCII "HDR0"/"HDR4" = byte-swapped and FAILS | bootloader w/o magic: `"Invalid image! Skip upgrade."`(S+0xd98) ret −1; **RAS w/o HDR0: prints "Upgrade firmware from memory…" then returns −1 WITHOUT writing** (beqz s4 @0x8402f49c → epilogue; v0=−1 via delay slot @0x8402f4a0) — REFUTES earlier "still writes" note | P | FUN_8402f214-0x8402f230, FUN_8402f138-0x8402f154, 0x8402f49c; cross-validated: OpenWRT `zytrx.c` "MAGIC 0x30524448 /* HDR0 reversed, to be stored as BE */", header size 0x17c, crc32@+0x0c/+0x174, modelid@+0x11c (NR7101=0x07010001) |
| **Model-ID gate: RAS hdr field @img+0x11c (4 B, sprintf "%x") must equal flash model `"7101"`** | `"Wrong Model ID!! Skip upgrade."`(S+0x1aa4) → **this is the unit-refusal class** | P | FUN_8402f248-0x8402f2bc (fw), FUN_8402f168-0x8402f1dc (bootloader); model string @0x84030e80 |
| RAS header checksum (0x17c-byte header) + image/data checksum vs header fields | `"RAS header checksum…error! Skip.."`(S+0xdf4), `"Data checksum…error! Skip.."`(S+0xea4); pass → `"Bootloader image checking PASS!…"` | P | FUN_8402f38c-0x8402f45c |

## 3. Slots & boot selection (Q3)

Flash layout selector: `L = *(*(0x8403246C))` (dual-flag, runtime-set; 0=small,
≠0=big). All offsets below are flash-relative; spans are 32 MB (0x2000000).

| Claim | Status | Evidence |
|---|---|---|
| RAS firmware kernel1 slot: `L==0 → 0x28000`, `L≠0 → 0x140000`; kernel2 slot = kernel1 + **0x2000000** (32 MB) | P | FUN_8402f214 @0x8402f2f8-0x8402f34c: `(0x200<<5)|((0x800)<<6)` shifts → s3=0x28000/0x140000; s5=s3+0x2000000 (`lui a3,0x200`) |
| **Dual-slot write** (lane-2 precise): valid HDR0 RAS → **FULL image (0x17c header INCLUDED) + full flen** written to BOTH kernel1 and kernel2 via two `FUN_84030c0c` calls (`move a0,s0` both @0x8402f554/0x8402f588 — capstone-verified), each logged `"Upgrade firmware from memory 0x%08x to flash 0x%08x, file length %u, file type…"`(S+0x1b0c); RMA/MFG exception writes **header-stripped `buf+0x17c`** (len still full flen) to kernel1 only @0x8402f548 | P | 0x8402f478-0x8402f598; OpenWRT issue #8183 corroboration: "The RAS image header is written to flash" |
| Exception: image flagged RMA/MFG (match of 3-byte codes vs img+0x128, @S+0x1b60/0x1b64) → **skips kernel2 write** with `"This is RMA or MFG firmware! Skip upgrade kernel 2."`(S+0x1b68) | P | 0x8402f4bc-0x8402f544 |
| Bootloader stream (type 0x100) → flash op **2** (FUN_8402f138); RAS (0x400) → op **1** (FUN_8402f214); ROM-D (0x800) → op **4** (→FUN_8402b020, size < 0x100001, 1 MB cap); ops 3/6 = stubs, op 5 = `"!!Wrong File Type %d!!"` | P | dispatch table @state+0xc08 (flash rel 0xcd28, gp-relative offs −0x31dc/−0x32b8/−0x2e54/−0x3098/−0x3084/−0x2e54 → 0x8402f214/f138/f59c/f358/f36c/f59c); FUN_8402f0cc @0x8402f0e0; FUN_8402f020 size check `param_2 < 0x100001` |
| Erase-side layout (L-selected): user-config `L0:0x4020000/2 MB, L1:0x4100000/16 MB`; ROM-D `L0:0x4220000/128 KB, L1:0x5100000/1 MB` | P | FUN_8402f5d0 (`(0x200<<5)*8+0x4000000`…), FUN_8402f670 (`(0x200<<5)*0x88+0x4000000`…) via erase API FUN_84030bdc |
| Staging RAM buffers `X>>1 +`: bootloader **0x81000000**, RAS **0x81140000**, user-config **0x85100000**, ROM-D **0x86100000** (X=`*(k0+0x10)`) | P | lui/addu @0x8402fcb8 (0x8100), 0x8402fde0 (0x8114), 0x8402ff0c (0x8510), 0x84030058-region (0x8610) |
| Boot selection: env **"BootingFlag"** → `==1`: boot kernel2 flash base; else kernel1; address = `0xBE000000 + base(0x840324fc|0x840324f8) + L-shift` → sprintf "%x" → **run_command("bootm <addr>")** | P | FUN_8402ee7c: getenv(S+0x158c), `iVar3=-0x42000000`(=0xBE000000) both branches, kernel ptr slots 0x840324fc/0x840324f8, argv {"bootm"(S+0x1598), buf} → FUN_840309bc |
| After listener times out without traffic: boot attempt via FUN_8402ee7c; `<0` → force serial menu (menu-var=3) | P | entry tail 0x8402b04-0x8402b20 |

## 4. DebugFlag semantics (Q4)

| Claim | Status | Evidence |
|---|---|---|
| `getenv("DebugFlag")` value **N ∈ {1,9}** enables an **N-second** serial `"Hit ESC key to stop autoboot:  "` + `"\b\b%2d"` countdown (ESC=0x1b, 1 s ticks, delay 0xF4240 µs); the env VALUE IS the counter | P | entry 0x8402aa18-0x8402af0: `beq v0,1` / `bnel v0,9`, `sw v0,(slot 0x84032430)`, loop w/ `0x1b` cmp @0x8402aadc, `lui s2,0xf; addiu 0x4240` |
| ESC during countdown → serial menu, **zycast listener skipped**; countdown expiry or DebugFlag∉{1,9} → `getenv("CheckBypass")`; if 0 → menu-flag from FUN_84030c4c; if still 0 → **zycast 6 s listener runs, then boot** | P | 0x8402ab08 `bnez → 0x8402b68` (menu); fallthrough 0x8402ab14 getenv(S+0xca4); listener call FUN_840306a8 @entry+0x6b20-region (decomp lines 63-77) |
| Menu prints `"Boot Module Debug Flag  : %02X"`(S+0x148c) | S | string @0x840315ac + printf sites in menu dump fn |
| DebugFlag set is **password-gated**: `ATSE` (arg must be `"NR7101"`) seeds `state+0x2478 = timer & 0xffffff` and prints `"%06X"`+`"%s%02X%02X%02X"` (seed + MRD[0x71..0x73]); **password = FUN_8402ac5c**: `x=seed+0x10F0A563; n=MRD[0x73]&7; n× ROR1(x); pwd=(x ^ seed)&0xffffff`, echoed as `"passwd=%x"` | P | FUN_8402b5a8 (7-byte "NR7101" cmp, seed store, sprintf S+0xf18 "%06X"/S+0xf20, printf S+0xf30); FUN_8402ac5c @0x8402ac5c (rotate `(x>>1)+x*0x80000000`) |
| Failure strings: `"please run atse first"`, `"password is incorrect"`, `"flag is incorrect"` | P | @S+0xf44/0xf5c/0xf74 |

## 5. Undocumented header flags / opcodes (Q5)

| Claim | Status | Evidence |
|---|---|---|
| **zycast tail-command bits** (applied at stream-set completion, from last packet `+0x18`, stores @0x84030244-0x84030274): **bit0 → `*(0x84032528)`=bss 0x8403247E — NO consumer anywhere in stage-2 (dead in this build; protocol-family meaning "set DebugFlag" per OpenWRT zycast.c)**; **bit1 → "erase user configuration"** (`*(0x8403252C)`=0x8403247D `&2` → FUN_8402f5d0); **bit2 = gEngCleanROMD → "erase ROM-D configuration"** (`*(0x84032530)`=0x840324EC bit2 → FUN_8402f670; also REPLACES romd-stream write); **bits 3-7 masked away — no DebugFlag set, no BootingFlag write, no env access (no setenv exists in stage-2), no boot-slot select, no reboot from the tail** | P | stores @0x84030230-0x84030274; consumers FUN_84030404 (`(*PTR_DAT_8403252c & 2)` @0x8403058c, `(*PTR_DAT_84032530…)` @0x840304dc/0x8403059c/0x840305b0); gp+0x134/gp+0x138 referenced ONLY at the tail stores (census of full .text); `"gEngCleanROMD = %d"`(S+0x1e9d) printf @0x8403026c (arg = raw `flags&4`) |
| 2-byte field `+0x16` → `*(0x84032524)`=bss 0x8403247F..80, stored **byte-swapped** (`{pkt[0x17], pkt[0x16]}` @0x84030230-0x84030240); **NO consumer in stage-2 — dead in this build**. Protocol-family identity: 2-byte ASCII "country code" (OpenWRT zycast.c `cc[2]`) — earlier "romStartAddr override" reading **[X] refuted** | P | store @0x84030230-0x84030240; gp+0x134 census (single ref); zycast.c struct |
| Beyond-flash opcodes exist only as serial-menu AT commands: `ATER` erase ROM-D data, `ATBR` reset user config, `ATRM` restore default MRD, `ATSR` reboot, `ATSE/ATDB` debug-flag+password, `ATWZ` write MAC/country/EngDbgFlag/MAC-qty, `ATSN` serial number, `ATFL` EngDebugFlag, `ATGP` LED control, `ATHV` HW version, `ATQY` MAC qty, `ATCO` country, `ATBU/ATCB/ATSH/ATSB` MRD buf ops | P | help strings @S+0x16e8–0x1a5c (stage2_strings.txt); dispatch FUN_8402d0e0 |
| RMA/MFG firmware marker (3-byte code at RAS img+0x128) → kernel-2 write suppression | P | §3, 0x8402f4bc-0x8402f544 |
| `"trx_exist = %d"` / `"cp.b"` / `"autostart"` / `"filesize"` — stage-2 shims into u-boot env & commands (tftp/menu reuse of stage-1) | S | strings @S+0xd68/0xfb8/0xd40/0xd50; refs 0x8402b2ac/0x8402bb84/0x8402dbe4 |

## Artifacts / reproducibility

- `stage2.bin` — extracted blob (dd skip=0x23ee0 count=0x14200)
- `ghidra-stage2/` — Ghidra 12.2 project, MIPS:LE:32 @ 0x84024000, gp=0x840323F0 set program-wide (FixupStage2.java), 120 functions
- `stage2_decomp.c`, `stage2_functions.txt`, `stage2_strings.txt` — batch exports (DumpPseudoC.java)
- `loadaddr_census.py` — base/gp determination (capstone; run with /usr/bin/python3)
- Entry/disasm cross-checks: raw capstone dumps in session log; all `S+X` addresses = 0x84030120+X

## Open items for next cycle

- Stage-1 side: what sets `*(0x8403246C)` (layout/dual flag) and k0 descriptor (API table contents, X=*(k0+0x10)) — needs stage-1 Ghidra project follow-up (/tmp/ghidra-zloader, pre-existing, not touched)
- Exact L-flag ↔ flash-size mapping unverified (constants only)
- Stage-1 runtime patching of slots 0x84032558/0x8403255C (commit callbacks) and 0x84032404 (+0x120 state adjust) — confirmed only by inference; needs stage-1 trace

## 6. Lane-2 (2026-11-11): cmd-tail decode, type-gate verification, dual-slot condition — SPEC.md/TOOLING.md written

All static, capstone-verified (r2 rendering cross-checked; the `move a0,$s0`
vs `$s1` ambiguity at 0x8402f554/0x8402f588 was settled by capstone: `$s0`).

| Claim | Status | Evidence |
|---|---|---|
| Tail capture: from the packet whose acceptance makes `completed_mask == pkt[+0x15]`; stores read `lbu pkt[0x17]`+`lbu pkt[0x16]`+`lbu pkt[0x18]` @0x8403021c-0x84030228 | P | 0x84030214 `bne s2,v0` gate; disasm |
| Type byte is **+0x14** (type_bit ∈ 1/2/4/8/0x10), images bitmap is **+0x15** — BE32@+0x12 = `unused16<<16 \| type_bit<<8 \| images` (matches OpenWRT zycast.c `unusedbits/type/images` exactly) | P | unaligned lwl/lwr @+0x15 + bswap @0x8402fa20-0x8402fa34; mask 0xff00 @0x8402fb04 |
| **Type gate = exact match {0x100,0x200,0x400,0x800}** else `"send file error."`(S+0x1c58) → **backup 0x1000 REJECTED on this build; no alternate path** (single shared gate code, 4 entry copies); also `images==0` rejected earlier ("Invalid type of file flag or send file error. %x", S+0x1c04) | P | 0x8402fb04-0x8402fb70 (sltiu/beq/bne tree), 0x8402fa34-0x8402fa78; zycast.c "supported set of images vary among implementations" |
| Descriptor table = 8×12B @ `*(0x8403251C)`=0x840324B0, memset 0xff(0x60) at session start; desc idx map 0x100→0, 0x400→1, 0x200→2, 0x800→3; accept `seq==expect \|\| expect==-1`; expect update @0x840301a0-0x840301c8; completion `expect==first` @0x840301e0 | P | 0x8402faa0-0x8402fac4, 0x8402fbc0-0x8402fbd4 |
| Listener freezes 6 s countdown once `state+0x2490==1`, blocks in rx-pump until completion (transfer time unbounded) | P | 0x840307d0-0x840307f8 |
| Romd op4 writer: FUN_8402f020 — cap `flen < 0x100001`, else S+0x1a54 + ret −1; writes fixed 0x100000 bytes at ROM-D region (L0 0x4220000 / L1 0x5100000) regardless of flen | P | 0x8402f020-0x8402f0f8, 0x8402f358-0x8402f364 |
| RAS container = OpenWRT "zytrx" format: magic@+0 BE, len_h@+4, len_t@+8, **crc32_p@+0xc**, modelid@+0x11c (BCD), swVersionInt@+0x128 (first 3 bytes = RMA/MFG marker), swVersionExt@+0x148, **crc32_h@+0x174**, total 0x17c; CRC = CRC-32/IEEE reflected (u-boot crc32 == zytrx.c crc32buf) | P | stage-2 field offsets match zytrx.c struct exactly (0x11c/0x128/0x174/0x17c/0x0c); checksum API via gp+0x94→FUN_84030c3c |
| Model gate detail: `sprintf("%x", img[0x11c]<<12\|img[0x11d]<<8\|img[0x11e]<<4\|img[0x11f])` strcmp vs flash model (S+0xd60, "7101"); NR7101 modelid = 0x07010001 | P | 0x8402f248-0x8402f2bc; zytrx.c boards[] |
| **Deliverables: `SPEC.md` (canonical wire protocol), `TOOLING.md` (Rust sender improvements)** | — | this lane |
