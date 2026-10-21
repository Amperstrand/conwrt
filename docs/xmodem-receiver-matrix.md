# XMODEM Receiver-Compatibility Matrix (#124)

Species-level matrix of every bootloader receiver this repo's models and
recipes actually name, with the mid-stream-abort / restart-safety verdict
required before any automated serial flash ships (issue #124, parity
matrix §5). **Source-level analysis only** — public source where it
exists, closed-source rows marked NEEDS-BENCH. No bench/specimen data
here; per-unit results go to bench evidence, species findings to the
model JSON `flash_methods` entry once bench-verified.

Driver policy counterpart: `crates/conwrt-protocols`
(`send_firmware_verified`, `serial_io::send_firmware_verified_async`) —
a sender-side `Ok` is a claim, not acceptance; only receiver-side
verification completes a transfer.

## Matrix

| Receiver family | Species (models/recipes) | Mid-stream abort behavior | Restart-after-abort safe? | Receiver-side verify primitive | Status |
|---|---|---|---|---|---|
| U-Boot `loadx` (xyzModem / RedBoot receiver) | zyxel-wx5600-t0, GS1900 family U-Boot, AP3915i 2012-era U-Boot — any `CONFIG_CMD_LOADB` build | **Strict.** Block-sequence mismatch or CRC error ⇒ retransmit request (`C` in CRC mode) retried up to 20×, then `xyzModem_sequence` abort; 3 consecutive CAN ⇒ cancel | **SAFE to RAM** — receiver state fully re-initialized per `loadx` (`xyzModem_stream_open` resets `next_blk`); aborts write nothing consumable; see NOR caveat below | `crc32 <loadaddr> <filesize>` readback; `filesize` env + `## Start Addr` echo on success | source-verified; NEEDS-BENCH (on-device confirm) |
| Zyxel ZyNOS BootBase `ATUP<addr>,<len>` | GS1920-24 (recipes/zyxel/gs1920-24) | Closed source — unknown | Procedure stages to RAM (`ATUP80100000`), restart = re-run `ATUP`; upstream install flow treats restart as the recovery of record | BootBase echo of received length | NEEDS-BENCH |
| Z-Loader V1.30 | NR7101 (models/zyxel-nr7101) | **XMODEM support itself unconfirmed** (open issue KU-001 in recipes/zyxel/nr7101/open-issues.md); zycast is the flash path | n/a until the loader's command set is enumerated on-device | n/a | NEEDS-EXPLORATION (serial-02 bootloader enum) |
| SiLabs EFR32 BGAPI bootloader (XMODEM-CRC) | Linksys MX4200 UART DFU (recipes/linksys/mx4200) | Closed source — unknown; reachable only with bootloader already present | unknown | BGAPI upload status | NEEDS-BENCH |

## U-Boot `loadx` — what the source says (verified)

Read at `master` of the U-Boot mirror (2026-10-21), files `cmd/load.c`
and `common/xyzModem.c`:

- `loadx` → `do_load_serial_bin` → `load_serial_ymodem(offset,
  xyzModem_xmodem)` → `xyzModem_stream_open/read/terminate/close`.
- **Sequence mismatch** (our pinned sender bug skips a block after a
  mid-stream NAK): `xyzModem_stream_read` compares `xyz.blk` to
  `xyz.next_blk`; equal ⇒ ACK + store + advance; duplicate (previous)
  ⇒ re-ACK; **anything else ⇒ `xyzModem_sequence`**, which lands in the
  retry loop: the receiver keeps sending retransmit requests
  (`xyz.crc_mode ? 'C' : NAK`) up to `xyzModem_MAX_RETRIES` (20) per
  read cycle, then aborts the stream with the sequence error.
  `load_serial_ymodem` then calls `xyzModem_stream_terminate` (CAN×4 +
  BSP×4 + flush on abort paths) and prints
  `## Binary (xmodem) download aborted` with exit code 1.
- **CRC/checksum error**: same NAK-retry-then-abort path
  (`xyzModem_cksum`).
- **CAN from the sender**: counted in `xyzModem_get_hdr`; 3 consecutive
  (`xyzModem_CAN_COUNT`) ⇒ `xyzModem_cancel`.
- **Restart safety**: `xyz` is re-initialized by every
  `xyzModem_stream_open` (`next_blk = 1`, counters zeroed for XMODEM
  mode) — a fresh `loadx` cannot inherit stale receiver state.
- **Write target**: `load_serial_ymodem` writes via `memcpy` to the
  load address. ⚠️ Under `CONFIG_MTD_NOR_FLASH`, if the load address
  falls inside a NOR flash map (`addr2info()`), chunks are written with
  `flash_write` **as they arrive** — a mid-stream abort at a flash
  address leaves a partial image. **conwrt policy: always `loadx` to
  RAM, verify, then flash in a separate step.**

### Interaction with the pinned xmodem-0.4 sender

The crate's sender treats ANY non-ACK response to a block — NAK, `C`,
CAN (source comment: `// TODO handle CAN bytes`), or timeout — as one
error and **advances to the next block** (`send_stream` in
xmodem-0.4.0). Against U-Boot's strict receiver that means a single
corrupted block ⇒ the receiver retransmit-requests a block the sender
will never resend ⇒ the sender's error budget (16) exhausts before the
receiver's retry budget (20) ⇒ `ExhaustedRetries` ⇒ the driver restarts
the whole transfer into a freshly-reset receiver. **Safe, at the cost
of one restart per corrupted block** — acceptable on a clean bench
line; noisy lines will restart repeatedly (measure before large
transfers; prefer short initramfs payloads).

### Receiver EOT latency (lrzsz cross-check finding)

The real-receiver cross-check (`tests/xmodem_lrzsz.rs`, lrzsz 0.12.21
`rx`) surfaced a timing class the scripted receivers can't show:
**lrzsz's rx deliberates ~1 s before ACKing EOT** (ZMODEM heritage),
and each EOT retransmission RESETS that deliberation — an engine read
deadline shorter than the receiver's EOT latency therefore deadlocks
the finish phase (16 × deadline → `ExhaustedRetries`). Rule: mount the
engine with a read deadline strictly greater than the target receiver's
EOT latency (U-Boot's xyzModem ACKs EOT immediately — source — so
serial-port defaults are fine there; lrzsz-class receivers need ≥1.5 s).

## Crate upgrade evaluation (#124 checkbox 4)

- The Rust `xmodem` crate's **latest release is 0.4.0** (crates.io,
  published 2025-07-31; owners awelkie/dancrossnyc). There is no
  post-0.4 version — **no drop-in upgrade exists**.
- The pinned limitations are confirmed in the 0.4.0 source itself
  (`send_stream`: non-ACK ⇒ `warn!` + `errors += 1` + advance; CAN
  unhandled mid-stream).
- Corroborating context: the **Python** `xmodem` package (tehmaze — a
  different project) fixed this same bug family in its own sender
  ("re-transmit in `send()` on NAK or timeout", 0.4.1; "sequence
  number miscalculation in `send()`", 0.4.7) — evidence this is a real
  sender-bug class, not a protocol choice.
- **Verdict: the wrapper approach stands.** `send_firmware_verified` /
  `send_firmware_verified_async` + receiver-side acceptance is the
  policy answer; the characterization pins in
  `tests/xmodem_fitness.rs` stay as-is. Revisit only if a post-0.4
  release lands (unpin the corresponding test with justification).

## NEEDS-BENCH register

Bench-verification items (tracked here until each lands; per repo rules,
hardware confirmation happens on the bench, species-level findings then
go into the model JSON `flash_methods` entry as `restart_safety`):

| # | Target | Procedure | Gate |
|---|---|---|---|
| B1 | U-Boot `loadx` (one device per family: WX5600 MTK, GS1900 RTL) | Bootloader prompt → `loadx <loadaddr>` → start `send_firmware` → abort mid-stream (Ctrl-C / line pull) at block ≥2 → re-run `loadx` + full transfer → `crc32 <loadaddr> <filesize>` compare | Fresh `## Ready for binary (xmodem) download` banner; clean second transfer; CRC match; no partial-flash symptoms on next boot |
| B2 | BootBase `ATUP` (GS1920-24) | Same shape over the ATUP procedure at 9600 (debug mode); include the 115200 "spam u during RAM test" recovery entry | Second `ATUP` accepts a full transfer after a mid-stream abort |
| B3 | Z-Loader V1.30 (NR7101) | `prompts/serial-02-bootloader-explore.md` enum: does the loader expose `xmodem`/`loadb`-class commands at all? | Row resolves to YES-with-procedure or NO (base64/zycast remain) |
| B4 | EFR32 BGAPI XMODEM-CRC (MX4200) | UART DFU per recipe notes with bootloader present | Documented abort/restart behavior |

## Sources

- U-Boot `cmd/load.c` (do_loadxloadyb / load_serial_ymodem / flash
  caveat): https://github.com/u-boot/u-boot/blob/master/cmd/load.c
- U-Boot `common/xyzModem.c` (receiver state machine, retry budgets,
  CAN count, per-open reset):
  https://github.com/u-boot/u-boot/blob/master/common/xyzModem.c
- xmodem crate (Rust) version history and 0.4.0 source:
  https://crates.io/crates/xmodem ,
  https://docs.rs/crate/xmodem/0.4.0
- Python xmodem changelog (bug-family corroboration only):
  https://github.com/tehmaze/xmodem/blob/develop/CHANGELOG.md
- Internal: `crates/conwrt-protocols/tests/xmodem_fitness.rs` (the
  pins), `crates/conwrt-protocols/src/serial_io.rs` (the adaptation),
  `recipes/zyxel/gs1920-24/notes.md` (ATUP procedure),
  `recipes/zyxel/nr7101/open-issues.md` (KU-001),
  `recipes/linksys/mx4200/NOTES.md` (BGAPI DFU).
