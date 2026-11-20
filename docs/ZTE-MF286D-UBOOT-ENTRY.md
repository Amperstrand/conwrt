# UBOOT-ENTRY — ZTE download/blank-update engine in kit uboot.bin (ARM, ELF)

Binary: `/home/ubuntu/mf286d-vm/kit/UPDATE/uboot.bin` (ELF32 ARM, entry 0x87300000,
PH1: file 0x10000→vaddr 0x87300000, size 0x7bf2b; strings/code referenced in
**file-offset space** via `add rX,pc,rX` pools — pc-rel math below uses file offsets).
All addresses are FILE OFFSETS unless noted.

## Answers

### 1a. zte_getHandOffState / zte_setHandOffState — where, what value

- Strings @0x7cb54/0x7cb7f/0x7cbaf; set-function @ **0x5bbdc**, get-function ends @0x5bbcc.
- `zte_setHandOffState(val)` (0x5bbdc): memset(page,0xFF,2048) → page[0]=val (0x5bc08–0x5bc10);
  **bad-block scan loop** (0x5bc14–0x5bc38): probes blocks, `addne r7,r7,#0x20000` per bad block
  → offset = **first good 128 KiB block**; erase (blx [ctx+0x34]) + program 2048 B (blx [ctx+0x44]).
- `zte_getHandOffState` reads the same page back, returns 0/1 and logs `read data=0x%x from 0x%0x`.
- **WHERE (partition)**: the NOR/NAND master table `norplusnand-system-partition-ipq40xx.bin`
  (magic `ac9f56fe 7a127fcd`, entries = 16B name + off/size/attr in **128 KiB blocks**,
  table A @file 0x110, backup @0x510) contains a dedicated **`fota-flag` NAND partition:
  blocks 0–5 (0–640 KiB)**. Handoff state = first good block of `fota-flag`. (NAND side begins
  at `fota-flag` — attr 0x100xxxx marks the NAND bank; NOR side = 0:SBL1/MIBIB/QSEE/CDT/…/APPSBL.)
- Value semantics: single byte; consumed by the boot handoff check (get → branch). Exact
  "update needed" enum not fully traced — but state **3 = abort/error** (see 1b).

### 1b. Who calls Uaztemain / zdu_DoUpdate, and when

- `Uaztemain: enter into !` @0x7c72f; init block @ **0x5b070–0x5b108**:
  prints "enter into", copies params, inits the zte-dl global struct:
  `[g+0x8c]=**69**` (UDP port — own TFTP server), `[g+0x90]=**0x1000**` (4096 B blocks),
  `[g+0x84]=0`, `[g+6]=**0x200**`, then `b 0x5a784` = the **state-machine dispatcher**
  (switch r7∈0..5 @0x5a420 with handlers 0x589d4/0x5871c/0x5a534).
- RAM sanity gate @0x5b020–0x5b03c (load-addr vs memsize); **on failure → error print,
  set state=3 in two globals (0x5b040–0x5b068), return** — state 3 = terminal error.
- Invocation condition: entered from the ZTE boot-mode logic (same family as the E3 entry
  cluster @0x1cfc4–0x1e650 which references "192.0.0.1"/`run lr`). I.e. boot-time decision
  between: (a) `run lr` root_uImage flow, (b) uaztemain/zdu blank-delta flow — selected by
  the handoff/fota state + boot mode, not fully decompiled; empirically the E3 device ARPs
  for 192.0.0.1 (path a), while the goform **Download** verb arms the zdu path (b).

### 1c. DHCP or static? First filename? root_uImage too?

- The uaztemain/zdu stack runs its **own TFTP client on UDP port 69** ([g+0x8c]=69, 4096-B
  blocks, 0x200 sub-block) — server IP = **192.0.0.1** (string @0x74ceb, referenced by the
  E3 entry pool block 0x1cfe0–0x1d038 — an 8-entry parameter array right after it).
- Default filename: `sprintf(name,"%02X%02X%02X%02X.img", b0..b3)` — fmt @**0x7c5cc**,
  reached when no bootfile is set ("*** Warning: no boot file name; using '%s'" @0x7c5e1).
  **Byte source corrected**: xorshift32 PRNG over RAM (see §3 below), NOT CDT params and
  NOT the own-IP idiom. ⇒ serve-any-name + log remains the right server policy (and the
  executed flash used root_uImage via lr mode regardless).
- root_uImage is NOT tried by the zdu flow — it belongs to the separate `run lr` path
  (env `lr` @strings idx 34, referenced from 0x1e5d4/0x20ebc). Two different boot modes.

### 1d. Verify before write?

The zdu engine is a **validated delta applier**, not a raw flasher — strings @0x7cd31+:
- `zdu_DoUpdate_uboot_prepare_do … isOnlyValidation=%d isRestoreBackup=%d`
- `ua_dispatcher_read_patch … READ_PATCH_HEAD_ERROR / READ_ZERODIFF_ERROR`
- `zdu_DoUpdate_uboot_do version:%s is not match!` ← **version check**
- `need_backup_block_num / g_num_partition / g_full_package_size` + backup/remedy writers
  (`do_write_remedy_backup_data`, `do_normal_backup_restore_uboot`, `write_block_num`)
- Failure returns are typed enums (UA_UPDATE_*) and set error state (3) BEFORE mass-write;
  the engine writes per-block with **bad-block detection + marking** (`Zte_EraseBlock`,
  `Zte_WritePage`, `Zte_MarkAsBadBlock` @0x7cbde–0x7ccf9) and maintains a **resume/handoff
  state** across blocks (get/setHandOffState). Exact hash-vs-CRC of the downloaded file not
  pinned down — but patch-head validation + version match happen before flashing.

### 1e. "send fin to PC" — what/where

Code @ **0x5b1c0–0x5b218**: after "blank download is done" it takes the downloaded
buffer (memcpy to r5, strlen) → printf(fin msg @0x7c6ed) → `0x59d54(conn, data, port=**69**,
size=**0x1000**, …)` (args r2=[g+0x8c]=69, r3=[g+0x90]=0x1000). ⇒ **a UDP packet back to
the PC on the same :69 channel** — our factory_tftp.py will log it as
`[UDP-NON-TFTP]` — that's the success signal to watch for.

### 1f. Retry behavior

Stock U-Boot netretry strings embedded @0x7c527–0x7c57c: `TFTP error '%s'(%d)`,
`Not retrying...`, `%s; starting again`, `Retry count exceeded`, `tftpblocksize`,
`tftptimeout` (min 1000 ms). Behavior follows the `netretry` env: default = retry until
interrupted/`Retry count exceeded` then fall through to the state machine's error state
(state 3) — NOT a silent normal boot. Timeout floor 1 s/block; block size negotiable via
`tftpblocksize`.

## 2. web.img + norplusnand

- `web.img` = cramfs, 781 files extracted (`work/webimg/`) — the **web UI only** (same
  content family as mtd8). No 3535/8787 binders (only md5.js hex coincidences).
  ⇒ 3535/8787 remain unidentified in all offline dumps; identify live (banner probe).
- `norplusnand-system-partition-ipq40xx.bin` = **SBL flash partition table (MIBIB)**,
  magic `ac9f56fe 7a127fcd`, two copies. Decoded (units = 128 KiB blocks):
  NOR: SBL1(0,4) MIBIB(4,2) QSEE(6,6) CDT(12,1) DDRPARAMS(13,1) APPSBLENV(14,1)
       **APPSBL(15,12)** [U-Boot] reserved1(27,5)
  NAND: **fota-flag(0,5)** ART(5,4) mac(9,4) reserved2(13,6) cfg-param(19,32) log(51,32)
        oops(83,5) reserved3(88,40) **web(128,64)** **rootfs(192,232)** data(424,200) fota(624,400)
  — this table is the HWID-adjacent data the `lp` command writes, and rootfs@0x1800000
  size 0x1D00000 **exactly matches the `lr` erase/write ranges**, cross-proving both.

## 3. eko evidence '4801A8C9.img' — source of the 4 bytes

Format string xref'd at pools 0x5a4bc/0x5acdc (state-machine handlers) + 0x5b090 area
(uaztemain init). **CORRECTED (post-flash RE by the mf286d-re session — the CDT/own-IP
hypotheses below were WRONG):** the filename bytes, the `192.%d.%d.%d` self-IP and the
`00:aa:bb:…` MAC are all produced by an **xorshift32 PRNG seeded from the XOR of
128 KiB of RAM at 0x86000000..0x8601FFFF** (full derivation: private-repo
session2/work/CDT-FILENAME.md; the 0x1c980 CDT cluster is only a debug dumper).
The observed live self-IP 192.127.179.190 is PRNG output — consistent. Serve-any-name
+ log remains correct server policy; the executed flash used `root_uImage` (lr mode).

## Operational consequences for the planned flash

1. The zdu blank path and the `run lr` path are DIFFERENT modes; the goform Download verb
   arms zdu. Expect first RRQ `<4-hex-bytes>.img` (NOT root_uImage) on the zdu path.
2. TFTP server: bind 192.0.0.1:69, **serve any requested filename** (log it!), blksize
   negotiation, and watch for the **fin UDP packet** = success signal.
3. zdu validates patch-head + version before writing; failures go to error-state-3
   (recoverable by re-arming), and per-block writes are bad-block-aware with handoff
   resume. The `lr` path writes only the NAND `rootfs` partition (0x1800000+0x1D00000).
4. NOR chain (SBL1/QSEE/CDT/APPSBL) is only touched by the blank `.img` flow — that is
   the brick-risk surface; it only runs in blank mode, which our armed state is not.
