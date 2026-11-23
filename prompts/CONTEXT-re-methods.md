# RE method notes — context file

Companion to the re-01..re-06 prompts: concrete techniques that repeatedly
paid off, with pointers to the prompts that use them.

## Static analysis shortcuts

- **Handler tables first.** Embedded web servers dispatch from
  {fnptr, name} tables in .data with fixed stride. Find one known form
  name, walk the table, get the full handler inventory with addresses in
  minutes (`grep` the binary for goform-ish strings; the table sits next
  to them).
- **Sink strings before disasm.** `"cmd prefix%*s"` strings with `%s`
  inside a command-looking literal mark `snprintf+system` sinks; the
  prefix length is your payload budget once you read the buffer size
  from the `memset`/`sub sp` around the call.
- **Charset gates are tiny.** Read the validation function itself —
  typically 4–5 blocked characters applied dispatcher-wide, then
  per-handler format checks (digits-only, enum strcmp) that kill the
  *other* parameters. Enumerate every parameter of every handler.
- **PIC string references**: embedded ARM builds often use
  `ldr rX, [pc, #imm]` + `add rX, pc, rX` literal pools rather than
  movw/movt — xref scanners must follow that pattern (movw/movt-only
  scanners find nothing).
- **qemu-user executes the firmware's own binaries** (`qemu-arm -L
  <rootfs> <rootfs>/bin/busybox ...`) — settle behavioral questions
  (flag parsing, applet availability) without hardware. Run unknown
  binaries in a container.

## Known-plaintext delta RE (see re-05)

- Verify every parse level against owned images: declared sizes vs
  actual, per-block CRC pairs vs actual blocks, decoded copy-ranges vs
  both sides.
- Consecutive deltas often cross-verify through their CRC fields (delta
  N's target CRCs == delta N+1's source CRCs) — free integrity without
  intermediate images.
- Raw-byte scatter search (32-byte windows mapped piecewise-linearly)
  distinguishes "custom codec" from "raw bytes in a surprising order"
  in minutes.

## Live lab (see re-02/re-03)

- Observable ladder: form text → ICMP (bounded) → HTTP callback server →
  config-store readback oracle. Two independent channels before anything
  clever.
- The config-readback oracle (`nv set key=$(cmd)` + config-get) turns a
  blind channel into a shell — single-line values only (word splitting).
- Reboot-recovery behavior differs per mechanism: record whether state
  survives (nvram keys do, /tmp does not) before you rely on retries.

## Documentation cadence that survives context loss

- Append-only worklog with one-line verdicts per experiment; commit at
  every phase boundary; end each session with next-step briefs precise
  to the exact next command.
- Publish methodology prompts (like these) as the generalizable residue
  of each project; keep payloads/addresses in the private repo and point
  to it.

## OTA delta format RE (see re-05)

Multi-layer containers are the norm for embedded OTA:
- The outer package (ZIP or custom magic) wraps per-partition containers
- Partition containers wrap either block-level diffs (custom formats with
  CRC-verified block maps) or file-level patches (often bsdiff + LZMA)
- Update scripts (shell) are embedded and reveal daemon inventories,
  partition layouts, and factory defaults
- The diff format decoder ships in the product itself — find the update
  daemon/binary and its debug strings name every header field

Key technique: the debug/log strings in the update binary contain the
entire header field vocabulary (state=0 through state=6 in ZTE's ZFUSDK
named every writeUnitHeader field). Read the binary's log formats before
fighting the binary format.
