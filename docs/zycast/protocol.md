# SPEC — ZyXEL "zycast" / Multiboot wire protocol

**Target implementation:** MitraStar/ZyXEL **Z-LOADER V1.30** stage-2, NR7101 class,
build 08:39:30 06/03/2020 (blob base 0x84024000, `stage2.bin`).
**Status:** every claim below is ground-truthed against disassembly (addresses cited)
unless marked `[fam]` (= protocol-family knowledge from OpenWRT `zycast.c`/`zytrx.c`,
same vendor protocol, independently RE'd — used only for naming/field semantics).
This document is the canonical reference for the Rust reimplementation; FINDINGS.md
holds the research narrative, this file holds the contract.

Notation: `BE`/`LE` = big/little endian on the wire. "Loader" is MIPS32 **little-endian**;
all protocol integers on the wire are **big-endian**.

---

## 1. Transport, addressing, timing

| Item | Value | Evidence |
|---|---|---|
| L3/L4 | UDP, **dst port 5631 (0x15FF)**; src addr/port arbitrary; dst is classically multicast 225.0.0.0 `[fam]` — any dst IP that passes the box's L2 filter is accepted (only dport is checked) | dport gate `param_2 != 0x15ff` @0x840302dc; MAC filter GDMA 0xBE000600/0x620 bit 0x8000 phase-toggle @0x840306e0-0x84030730 |
| Listener window | **6 s**, 1 s ticks, countdown printed `"\b\b%2d"`; started only if: ESC autoboot not stopped, `CheckBypass`==0, menu-flag==0 | `iVar7 = 6` + `FUN_8403097c(1000000)` loop @0x840306a8-region |
| Window freeze | On the **first accepted packet** the countdown loop blocks in the RX pump until stream-set completion → transfer time is **unbounded** once started | `lbu v1,0x2490(s4); bne v1,1` → `while(*completion==0) pump` @0x840307d0-0x840307f8 |
| Feedback | **None.** No ACK/NAK of any kind. Sender repeats blindly | no tx path in receiver |
| Post-completion | All further packets dropped (one-shot); listener halts net, runs flash-commit, then calls success/fail callback (§8.3) | gate @0x8402fa88; @0x84030800-0x84030854 |

## 2. Packet layout — 30-byte header + payload

```
 0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
+---------------+-------+-------------------------------+-----------+
| "z" "y" "x" 0 | csum16|         seq (packet id)       | unused16 |   BE fields
+---------------+-------+-------------------------------+-----------+
 16  17  18  19  20  21  22  23  24  25  26 .. 29  30..
+---------------+-----------------------+---------------+---------+
|  type   | img |     plen (u32)       | flen (u32)    | cc[2]   |
+---------+-----+---------------------+---------------+---------+
 26  27  28        29  30 .. 33   34 .. 37
+-------+--------+---------------+------------------+---- 0x1e: payload
| flags | rsvd[5]|  (plen/plen cont.)               |
+-------+--------+-----------------------------------+
```

Canonical field table (wire offsets, all integers BE):

| Off | Size | Name | Meaning | Loader code |
|---|---|---|---|---|
| +0x00 | 3+B | `magic` | ASCII `"zyx"`, 4th byte ignored | memcmp vs @0x84032014 `7a 79 78` @0x840302e8 |
| +0x04 | 2 | `csum` | checksum16 of payload (§4), BE | cmp @0x84030114-region |
| +0x06 | 4 | `seq` | block number, starts 0, +1 per block | ntohl, accept gate @0x8402fbdc-region |
| +0x0a | 4 | `plen` | payload length in **this** packet. Must be 1024 except last | memcpy len @0x84030120-region |
| +0x0e | 4 | `flen` | total file length of this stream | last-block = `(flen+0x3ff)>>10 - 1` @0x84030116-region |
| +0x12 | 2 | `unused16` | ignored by loader | mask 0xff00 @0x8402fb04 |
| +0x14 | 1 | `type_bit` | exactly one of 0x01,0x02,0x04,0x08 (0x10 rejected, §7) | `type = BE32(+0x12) & 0xff00` @0x8402fb04 |
| +0x15 | 1 | `images` | bitmap of all stream types in the transfer (bits = type_bit values). Must be ≠0; completion requires `completed_mask == images` | gate @0x8402fa34-0x8402fa38; completion @0x84030210/0x84030214 |
| +0x16 | 2 | `cc[2]` | 2 ASCII chars, "country code" `[fam]`; stored byte-swapped to bss, **never read** by this build | stores @0x84030230-0x84030240 |
| +0x18 | 1 | `flags` | post-completion command bits (§8) | stores @0x84030244-0x84030274 |
| +0x19 | 5 | `rsvd[5]` | ignored | — |
| +0x1e | plen | `payload` | file bytes `file[seq*1024 .. +plen]` | `memcpy(buf + seq*0x400, pkt+0x1e, plen)` @0x84030148-region |

Block size: **fixed 1024 (0x400)**; only the final block may be shorter. A short
non-final block leaves an unpatched gap (receiver copies exactly `plen` bytes).

## 3. Checksum16

```
sum = Σ payload[i] for i in 0..plen        (u32 accumulator)
csum = ((sum >> 16) + sum) & 0xFFFF        // ONE fold, no complement
```
Compare against BE `csum` field. Mismatch → print "checksum error! wait next file",
packet skipped (state unchanged — sender retransmit heals it). FUN_8402f740 @0x8402f740.

## 4. Stream types

| type_bit | wire `type` (`bit<<8`) | name | desc idx* | staging RAM (X = `*(u32*)(k0+0x10)`) | size field | commit op | flash target (§9) |
|---|---|---|---|---|---|---|---|
| 0x01 | 0x0100 | bootbase (bootloader) | 0 | `X/2 + 0x81000000` | state+0x2498 | 2 | 0x0, header-stripped |
| 0x02 | 0x0200 | rom (user-config) | 2 | `X/2 + 0x85100000` | state+0x24a0 | — (no flash write; only tail-flag erase path exists) | n/a |
| 0x04 | 0x0400 | ras (firmware) | 1 | `X/2 + 0x81140000` | state+0x249c | 1 | kernel1 **and** kernel2 (§9.2) |
| 0x08 | 0x0800 | romd | 3 | `X/2 + 0x86100000` | state+0x24a8 | 4 | ROM-D region, fixed 0x100000 length |
| 0x10 | 0x1000 | backup `[fam]` | — | **rejected** by this build (§7) | — | — | — |

\* descriptor index into 8×12-byte table at `*(0x8403251C)` → bss 0x840324B0
(mapping set at 0x8402fb04-0x8402fb6c: 0x100→0, 0x400→1, 0x200→2, 0x800→3).

`rom` note: type 0x200 is received and counted toward completion, and tail-flag
0x02 erases the rom region — but no commit op writes a downloaded rom image to
flash in this build (op table has no rom writer).

## 5. Receiver state machine

Per-type descriptor (12 B, memset 0xFF at first packet of a session):

```rust
struct Desc { first_seq: u32, expect: u32, last_block: u32 }  // last_block = (flen+1023)/1024 - 1
```

Session-global: `current_type` (state+0x2480), `completed_mask` (state+0x2494),
`receiving` flag (state+0x2490), `completion` one-shot (bss 0x8403247C via
`*(0x84032518)`), first-packet init at 0x8402fa90-0x8402fae0 (clears buffer
pointers, memsets descriptors, sets receiving=1).

Per accepted-packet flow (after gates of §7):

1. If this type has no buffer yet (first packet of type): assign staging buffer,
   store `flen`→size field, `desc.first_seq = seq`, `desc.last_block` per formula.
   (`expect` still 0xFFFFFFFF.)
2. `memcpy(buf + seq*0x400, payload, plen)`.
3. `desc.expect = if seq == desc.last_block { 0 } else { seq + 1 }` @0x840301a0-0x840301c8.
4. If `desc.expect == desc.first_seq` → `completed_mask |= type_bit` @0x840301e0-0x840301f8.
5. If `completed_mask == images(+0x15)` → apply **tail** (§8), print
   "------MultiBoot Download Finish------", `current_type = 0`, `completion = 1`
   @0x84030214-0x8403029c. Listener then commits exactly once.

Accept rule for seq (gate @0x8402fbd4-region): packet accepted iff
`desc.expect == 0xFFFFFFFF` (type not yet started) **or** `seq == desc.expect`;
otherwise **silent drop** (no state change). Sender heals by re-sending the whole
stream from block 0 in the next repetition cycle ("roll back" prints at
S+0x1cb9/0x1d25/0x1db1/0x1e3d are diagnostics of this recovery).
Duplicate/late packets of an already-completed type: dropped via
`completed_mask & type_bit` check @0x8402fba8-0x8402fbb8.

Mid-stream join is legal: first received seq becomes `first_seq`; completion fires
when the cycle wraps back to it. Sender should therefore loop the whole file
continuously until "long enough" (no completion feedback exists).

## 6. Gate chain (ordered; a packet is dropped silently unless stated)

| # | Gate | On failure | Code |
|---|---|---|---|
| 1 | UDP dport == 5631 | print "dest_port error" | 0x840302dc |
| 2 | `magic[0..3] == "zyx"` | print wrong-signature | 0x840302e8 |
| 3 | `images (+0x15) != 0` | print "Invalid type of file flag or send file error. %x" | 0x8402fa34-0x8402fa78 |
| 4 | `completion == 0` | silent | 0x8402fa88 |
| 5 | (first packet of session) init | — | 0x8402fa90-0x8402fae0 |
| 6 | `type = BE32(+0x12) & 0xFF00` ∈ {0x0100, 0x0200, 0x0400, 0x0800} **exact** | print "send file error." and return | 0x8402fb04-0x8402fb70 |
| 7 | `completed_mask & type_bit == 0` | silent | 0x8402fba8 |
| 8 | `desc.expect == -1 or seq == desc.expect` | silent (rollback) | 0x8402fbd4-0x8402fbe4 |
| 9 | `checksum16(payload, plen) == BE16(+0x04)` | print "checksum error! wait next file", skip (state unchanged) | 0x84030114-region → LAB_8403001c |

**Type gate corollary (Q: is `backup` 0x10 accepted?):** NO for this build.
`0x1000 & 0xFF00 = 0x1000` misses all four equality branches and falls out at
0x8402fb70 ("send file error."). Additionally `images` containing bit 0x10 can
never be satisfied (`completed_mask` only gains bits 1/2/4/8), so such a transfer
would never complete. There is exactly one handler implementation (four entry
copies 0x8402f9e0/0x8402f9ec/0x840302d0/0x840302dc share the gate code) — no
alternate accept path exists. Backup-type support is a per-model property `[fam]`;
this loader doesn't need it because RAS is auto-mirrored to both kernel slots.

## 7. Commit pipeline (FUN_84030404, runs once after completion)

Order: bootbase → ras → romd. `done_mask` (state+0x24ac) records per-type success;
overall success ⇔ `completed_mask == (completed_mask & done_mask)` → returns 1.

| stream | pre-cap (`W = *(0x8403253C)`→flash-size word) | action |
|---|---|---|
| bootbase (bit0) | `W << 2 ≥ flen` else "Bootloader file size too large!!" | op 2 → FUN_8402f138 |
| ras (bit2) | `0x2000000 − W*10 ≥ flen` else "Downloaded file size is too large!" | op 1 → FUN_8402f214; then **if tail-flag 0x02**: FUN_8402f5d0() erase rom |
| romd (bit3) | — | if tail-flag 0x04 set → FUN_8402f670() erase romd **instead of** writing; else op 4 → FUN_8402f020 (cap: `flen < 0x100001`, writes fixed 0x100000 bytes) |

### 7.1 op dispatch
`FUN_8402f0cc(buf, flen, op)`; jump table at state+0xC08 (words are gp-relative):
op1→0x8402f214 (RAS), op2→0x8402f138 (bootbase), op3→ret0 stub, op4→0x8402f358
(romd tail-call FUN_8402f020), op5→"!!Wrong File Type %d!!" print, op6→ret0 stub.

### 7.2 RAS writer (op1, 0x8402f214) — validation chain
All arithmetic on BE-read u32s (bswap thunk FUN_8402eff0):

1. `magic = BE32(img[0..3])`; if `!= 0x30524448` ("HDR0" stored BE → bytes
   `30 52 44 48` "0RDH" in a hex dump) → jump to write-skip → prints
   "Upgrade firmware from memory…" then **returns −1 without writing**
   (beqz s4 @0x8402f49c; v0=−1 via delay slot @0x8402f4a0).
2. model gate: `nib(img[0x11c..0x11f]) = b0<<12|b1<<8|b2<<4|b3`, sprintf `"%x"`,
   strcmp vs flash model string (S+0xD60, "7101") — mismatch → "Wrong Model ID!!
   Skip upgrade." return −1. For NR7101 `modelid = 0x07010001` → "7101" ✓
   (cross-validated: OpenWRT `zytrx.c` boards[] NR7101 = 0x07010001).
3. header CRC: crc32 of img[0..0x17c) with field `crc32_h`(+0x174) zeroed
   (`sw zero,0x174(s0)` @0x8402f39c) must equal stored BE u32 at +0x174;
   else "RAS header checksum … error! Skip upgrade.." return −1.
4. payload CRC: crc32 of img[0x17c..flen) must equal stored BE u32 at +0x0C
   (`lw a0,0xc(s0)` @0x8402f3dc); else "Data checksum … error! Skip.." return −1.
   CRC = standard reflected CRC-32 (poly 0xEDB88320, init 0xFFFFFFFF, final XOR)
   — u-boot `crc32`, identical to `zytrx.c` `crc32buf`.
5. Pass → "Image checking PASS! Start upgrading…", s4=1.
   (`kernelChksum` @+0x128 `[fam]` is not validated.)

### 7.3 Dual-slot write condition (the upstream "NOTE")
With s4=1 (valid HDR0 chain) and op=1:

- If `img[0x128..0x12b)` == `"RMA"` or `"MFG"` (3-byte compare vs S+0x1B60/0x1B64,
  0x8402f4b8-0x8402f52c): print "This is RMA or MFG firmware! Skip upgrade kernel
  2." → **single write**, header-stripped `img+0x17C`, at **kernel1 only**
  (0x8402f548→0x8402f590).
- Else **dual write**, FULL image (header included) + full `flen`, to
  **kernel1 and kernel2** (0x8402f554-0x8402f598): both
  `flash_write(buf, kernelN, flen)` and two "Upgrade firmware from memory 0x%08x
  to flash 0x%08x, file length %u, file type=%d" prints.

⇒ Condition in one line: `type_bit==0x04 AND magic==HDR0 AND model OK AND
headerCRC OK AND dataCRC OK AND img+0x128 ∉ {RMA,MFG}` → both slots receive the
identical full file. There is **no way to select a single kernel slot** via this
protocol on this build (backup type rejected, §6).

### 7.4 Bootbase writer (op2, 0x8402f138)
Requires magic `0x34524448` ("HDR4" stored BE → bytes `34 52 44 48` "4RDH"),
else "Invalid image! Skip upgrade." return −1. Then model gate, then the same
0x17c header/payload CRC chain, then single write of `img+0x17C` at flash
offset 0 (s3=0), length = full flen.

## 8. Completion tail (captured from the packet whose acceptance satisfies
`completed_mask == images`; header bytes +0x16/+0x18 of that packet)

### 8.1 Stores (0x8403021c-0x84030274)
```
cmd16 = pkt[0x17]<<8 | pkt[0x16]              ; cc[2], read as LE u16 pair
*(0x84032524)→bss 0x8403247F..80 = {pkt[0x17], pkt[0x16]}   ; NO consumer (dead)
bit0 = flags & 0x01 → *(0x84032528)→bss 0x8403247E          ; NO consumer (dead)
bit1 = flags & 0x02 → *(0x8403252C)→bss 0x8403247D          ; consumed §7 rom-erase
bit2 = flags & 0x04 → *(0x84032530)→bss 0x840324EC          ; gEngCleanROMD
bits 3..7 are masked away — no other tail effects exist
```
printf "gEngCleanROMD = %d" (value = raw `flags&4`) @0x8403026c-0x84030270,
then "------MultiBoot Download Finish------" @0x84030284.

### 8.2 Tail flag semantics on THIS build
| flag | effect | where |
|---|---|---|
| 0x01 | none (stored, never read). Family meaning "set DebugFlag" `[fam]` — **cannot** set DebugFlag here | store 0x84030244-0x84030250; zero other refs to gp+0x138 |
| 0x02 | erase **rom** (user-config) region after RAS commit | consumer @0x8403058c → FUN_8402f5d0 (0x8402f5d0: "Erasing user configuration ...") |
| 0x04 | erase **romd** region; suppresses writing a romd stream | consumers @0x840304dc/0x8403059c/0x840305b0 → FUN_8402f670 ("Erasing ROM-D configuration ...") |
| 0x08+ | ignored | masks `&1 &2 &4` |

**Env/boot-slot safety verdict:** the tail performs **no** `setenv` (no setenv
wrapper exists in stage-2; `BootingFlag`@0x840316ac and `DebugFlag`@0x84030d90
are getenv-only, consumed at 0x8402ee7c / entry), **no** boot-slot selection,
**no** reboot. zycast cannot influence boot slot choice except by *content*
(dual-slot mirror makes both slots identical, making `BootingFlag` moot for
zycast-pushed RAS). Destructive surface = flash writes + rom/romd erases only.

### 8.3 Post-commit callbacks
`r = commit()`; success (`r!=0`) → print "Upgrade firmware finished and please
restart system !!" then call `*(0x84032558)`; failure → "Upgrade firmware fail!!"
then call `*(0x8403255c)` (0x84030814-0x84030854). Flash-image defaults:
0x84032558 → FUN_8402f670 (ROM-D erase), 0x8403255C → FUN_8402f7a0 (LED error
pattern). These slots are outside bss and are expected to be runtime-patched by
the stage-1 handoff to real reboot/halt entry points (same class of patching as
the proven state-slot adjustment at 0x84032404); treat "reboot after commit" as
the behavioral norm, with the flash-default caveat noted.

## 9. Flash geometry (runtime layout flag `L = *(*(gp+0x7C))`; L==0 small, else big)

| region | L==0 | L!=0 |
|---|---|---|
| kernel1 (RAS slot 1) | 0x28000 | 0x140000 |
| kernel2 (RAS slot 2) | kernel1 + 0x2000000 | kernel1 + 0x2000000 |
| rom erase (flag 0x02) | 0x4020000, len 0x200000 | 0x4100000, len 0x1000000 |
| romd erase & romd write (flag 0x04 / op4) | 0x4220000, len 0x20000 erase / 0x100000 write | 0x5100000, len 0x1000000 erase / 0x100000 write |
| bootbase write | 0x0 | 0x0 |

Boot slot selection (outside protocol): stage-2 getenv `BootingFlag`==1 → bootm at
kernel2 base else kernel1 (`FUN_8402ee7c`, `0xBE000000+base+L-shift`).

## 10. Sender conformance requirements (Rust implementation MUST)

1. dport 5631; recommend multicast 225.0.0.0 `[fam]`.
2. 30-byte header, all ints BE, `magic="zyx\0"`.
3. Blocks of exactly 1024 bytes; final block `flen % 1024` (if ≠0).
4. `seq` restarts at 0 per stream; `images` constant across the whole transfer
   and equal to the OR of all `type_bit`s sent; `cc`/`flags` constant (tail is
   captured from whichever packet completes the set).
5. `csum` = folded byte-sum of THIS packet's payload.
6. Repeat the full cycle (all streams, in `images` order) indefinitely; target
   must be power-cycled/reset into the 6 s window (or already listening).
7. Inter-packet pacing ≥ ~10 ms default (receiver RX pump is slow; excessive
   burst → drops → rollback) — see TOOLING.md.
8. Expect **zero feedback**; completion is observed on the device console/LEDs only.
9. Validate images locally before sending (mirror §7.2/§7.4 gates) — see TOOLING.md.

## 11. Invariants for the mock receiver (integration tests)

- gate-6 exactness: any `BE32(+0x12)&0xFF00 ∉ {0x100,0x200,0x400,0x800}` drops.
- expect-transition: `expect(seq==last)=0 else seq+1`; completion iff
  `expect==first`; mask gains `type_bit`.
- tail captured only from the completing packet; flags masked to bits 0..2.
- one-shot: after `completion=1`, all packets ignored (even bad dport? — dport
  checked first; only packets passing gates 1-2 reach the completion check).
- checksum16 fold-once property: `(Σ) mod 0xFFFF` with single fold — test with
  sums > 0x1FFFFE (double-fold would differ).
- HDR0/HDR4 are BE-stored: bytes at img[0..3] are `30 52 44 48` / `34 52 44 48`.

## Appendix A — key addresses (stage-2 base 0x84024000)

| addr | role |
|---|---|
| 0x8402f9e0 / 0x840302dc | receiver entry copies (mcast / UDP-registered) |
| 0x8402fa34 / 0x8402fa88 | images≠0 gate / completion one-shot gate |
| 0x8402fa90-0x8402fae0 | session init (buffers, descriptors, receiving=1) |
| 0x8402fb04-0x8402fb70 | type exact-match gate |
| 0x8402fba8-0x8402fbb8 | completed-type dup drop |
| 0x8402fbd4-0x8402fbe4 | seq==expect accept gate |
| 0x84030114-region | checksum16 verify + memcpy + expect update |
| 0x84030214-0x8403029c | completion check, tail stores, finish print |
| 0x84030404 | commit pipeline |
| 0x8402f0cc | op dispatcher (table @state+0xC08) |
| 0x8402f138 / 0x8402f214 | bootbase / RAS writers |
| 0x8402f248-0x8402f2bc | model-ID gate (sprintf "%x" vs S+0xD60) |
| 0x8402f38c-0x8402f45c | header CRC (+0x174) / data CRC (+0x0C) chain |
| 0x8402f4b8-0x8402f52c | RMA/MFG 3-byte checks |
| 0x8402f478-0x8402f598 | write(s): printf + flash_write kernel1/kernel2 |
| 0x8402f5d0 / 0x8402f670 | erase rom / erase romd |
| 0x8402f740 / 0x8402f718 / 0x8402eff0 | checksum16 / ntohl / bswap |
| 0x840306a8-0x84030854 | listener window, RX pump, commit+callbacks |
| 0x84032518 / 24 / 28 / 2C / 30 | ptr→completion / cc[2] / flag0 / flag1 / flag2 |
| 0x84032558 / 0x8403255C | success / fail callback slots |
