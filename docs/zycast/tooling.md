# TOOLING — Rust zycast sender: required improvements

Audience: the in-house Rust reimplementation of the zycast sender.
Contract: SPEC.md is normative. Each item below cites the SPEC/addresses that
motivate it. Items P0 are correctness/safety, P1 robustness, P2 ergonomics.

## P0-1. Local pre-validation of images (fail BEFORE touching the network)

The loader gives zero feedback and silently refuses bad images mid-commit
(SPEC §7.2/§7.4). Every gate it applies must be mirrored client-side and a
failure must abort before any packet is sent:

`fn validate(img: &[u8], kind: StreamKind) -> Result<Report, ValidationError>`

- RAS (0x04):
  - `BE32(img[0..4]) == 0x30524448` ("0RDH" bytes — warn loudly: ASCII "HDR0"
    hex-dumps are BYTE-SWAPPED stock and will be *printed then discarded* by
    the loader: beqz path @0x8402f49c returns −1 with no write).
  - model gate: `nib(img[0x11c..0x120])` formatted `"%x"` must equal the target
    model string ("7101"); keep a board table `{boardid, modelid}` seeded from
    OpenWRT `zytrx.c` (NR7101=0x07010001, LTE3301-PLUS=0x03030001, …) and make
    `--model` mandatory unless inferred from `--board`.
  - CRC32-IEEE (reflected 0xEDB88320, init 0xFFFFFFFF, final ~): recompute with
    field +0x174 zeroed → must equal BE u32@+0x174; recompute over
    `img[0x17c..]` → must equal BE u32@+0x0C.
  - size cap: `flen ≤ 0x2000000 − W*10` (W = flash-size word; expose
    `--flash-word` override, default assume the NR7101 layout).
  - report `rma_mfg: bool` (img[0x128..0x12b] ∈ {"RMA","MFG"}) — drives the
    dual-slot warning below.
- Bootbase (0x01): magic must be `0x34524448` ("4RDH" bytes); same CRC/model
  chain; cap `flen ≤ W<<2`. Default-refuse with `--i-know-this-flashes-the-bootloader`.
- Romd (0x08): `flen < 0x100001`.
- `images`-set consistency: every selected file must have passed its validator;
  refuse mixed valid/invalid transfers (completion requires ALL bits).

## P0-2. `--slot` semantics: document reality, don't fake selectability

The loader **cannot** be told which kernel slot to write (SPEC §6: type 0x10
backup is rejected at 0x8402fb70; §7.3: valid non-RMA RAS is mirrored to both
kernel1 and kernel2 unconditionally). Therefore:

- Do NOT implement `--slot kernel2` as if it selected a slot; it cannot work.
- Implement instead:
  - `--expect-slots {both,kernel1}` (default `both`): validation/dry-run output
    only — derived from `rma_mfg` (RMA/MFG ⇒ kernel1 only). Print the
    consequence table before sending.
  - `--single-slot-rma` escape hatch that (a) requires an image already tagged
    RMA/MFG, (b) prints "kernel2 will be left untouched = previous firmware
    retained" (this is the ONLY single-slot firmware path that exists).
- `--slot` as a flag name should be rejected with an explanatory error pointing
  at SPEC §7.3, to prevent silent misuse.

## P0-3. Concurrency lock (single sender per L2 segment)

Two senders interleave UDP streams with identical magic/type but different
payloads: the receiver's `seq==expect` state machine will thrash rollbacks and,
worse, interleaved *valid* packets from both can satisfy `completed_mask` with a
chimeric image (checksums still pass only if blocks are self-consistent — they
won't be, so the realistic failure is an infinite transfer; the worst case is a
corrupted-but-CRC-valid chimera only if the two senders send the SAME image —
benign but confusing).

- `flock` an exclusive lockfile, e.g. `/run/lock/zycast-<iface>.lock`
  (per-interface, since the collision domain is the L2 segment).
- `--force` to steal? No — hard-error instead; print holder PID.
- Inside one process: single-threaded send loop by construction; forbid
  concurrent bindings of the same socket (send socket is `connect()`ed, keep it
  in one task; no async fan-out).

## P0-4. Pacing enforcement (first-class, floored)

Receiver RX pump is a polling loop sharing the CPU with the 1 s tick; bursts
cause silent drops → rollback loops (SPEC §5 accept rule, §10.7).

- `--pace-ms` (default 10, HARD FLOOR 1 ms; reject 0 — no "line rate" mode).
  Between-packet `sleep`, monotonic scheduler, not wall-clock.
- Cycle pause: `--cycle-gap-ms` (default 500) between full repetitions of the
  multi-stream cycle, letting the receiver finish descriptor updates.
- Optional adaptive mode: none possible (no feedback) — do not pretend; keep
  fixed pacing and document the 6 s window entry problem (P1-1).

## P1-5. Window-entry handling

The listener window opens ~after ESC-check/CheckBypass/menu checks and lasts 6 s
(1 s ticks). A sender started after boot may miss it entirely.

- `--lead-in-secs N` (default 10): send no-op? — impossible, any packet is a
  stream packet. Instead: send the full cycle continuously for
  `max(N, cycle_time)` BEFORE the operator is told to power-cycle; print
  explicit "power-cycle the unit now (or within N s)" instructions.
- `--repeat-until-interrupted` must be the default mode (Ctrl-C exits), since
  completion is unobservable; log per-cycle progress.

## P1-6. Tail-flag safety interlocks (SPEC §8.2)

`--flags`/`-F` bitset for bits 0x01/0x02/0x04 must:

- default to **0**;
- require explicit confirmation for 0x02 (erase user-config) and 0x04 (erase
  ROM-D): `--allow-erase-rom`, `--allow-erase-romd` (or interactive y/N in TTY);
- print the exact consequence + affected flash ranges from SPEC §9 table;
- note 0x01 is a **no-op on Z-LOADER V1.30/NR7101** (stored at 0x8403247E,
  never read) — accept it for family compatibility but mark it inert in `--dry-run`.

## P1-7. Wire-correctness details checklist (unit tests against SPEC §11)

- header exactly 30 B, ints BE, `zyx\0` magic;
- 1024-B blocks, final short block allowed, `plen==0` forbidden;
- checksum16 = byte-sum + ONE fold (`(s>>16)+s & 0xffff`), property tests with
  accumulators ≥ 0x10000 and ≥ 0x1FFFFF;
- `images` bitmap constant across all packets of all streams and equal to OR of
  type bits; `cc`/`flags` constant (tail captured from completing packet);
- `seq` per-stream, starts 0;
- type values are the bit-shifted form (0x0100/0x0200/0x0400/0x0800) — reject
  client-side construction of 0x1000.

## P1-8. Mock receiver for integration tests

Implement the SPEC §5 state machine + §6 gate chain as an in-process test double
(`zycast-mock` bin: binds UDP 5631, prints state transitions, asserts
`completed_mask==images` and byte-identical reassembled buffers). Property tests:
packet loss (random drop p), duplication, reordering (rollback+retransmit
heals), mid-stream join (start seq=k), interleaved cycles. This is the only
way to regression-test pacing changes.

## P2-9. Dry-run / trace mode

`--dry-run`: validate everything (P0-1), print the intended packet #0 of each
stream as a hexdump + the full decision table (target buffers, caps, slots to be
written, erase actions), send nothing.

## P2-10. Misc

- `--iface` binding (SO_BINDTODEVICE) required for multicast on multihome hosts.
- `--ttl`, `--mcast-group` (default 225.0.0.0) passthrough.
- Exit codes: 0 ok, 2 validation failure, 3 lock contention, 4 usage.
- Embed SPEC.md revision hash in `--version` output so field logs identify the
  protocol contract the binary was built against.
