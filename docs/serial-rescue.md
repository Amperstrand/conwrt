# conwrt serial rescue — diagnose and recover old routers, agentless

Status: **fully tested on the Zyxel GS1900-8HP (A1)** across a 3-day
bench arc (2026-10-23..25). The same engine generalizes to other
devices via [device profiles](../../devices/README.md).

## The idea

Old routers bricked or wedged by bad firmware are recoverable through
their serial console almost universally — but the recovery is a
delicate, timing-sensitive ladder that usually lives in a human's head
and a pile of throwaway scripts. conwrt internalizes the ladder:

    listen on serial -> classify what's on the console ->
    fire a declarative recipe at the right moment ->
    transfer over the strongest available channel ->
    verify ON THE BOX -> flash in one self-firing line

All agentless: one Rust binary, no opencode, no expect scripts.

## The three entry points

    # 1. boot-watch ladder (box rebooting / wedged):
    conwrt flash-rescue --port telnet://host:7171 --device zyxel/gs1900-8hp \
      --sysupgrade img.bin --sha256 <sha> --initramfs init.bin \
      --serve-dir /srv/tftp --server-ip 192.168.1.10

    # 2. box parked at the U-Boot prompt: same, fires on attach

    # 3. box at a LIVE shell:
    conwrt flash-rescue --at-shell --device zyxel/gs1900-8hp \
      --sysupgrade img.bin --sha256 <sha> --server-ip 192.168.1.10

Diagnosis first when unsure:

    conwrt serial-detect --port telnet://host:7171 --devices
    # -> class (uboot_prompt / linux_shell / silent / booting ...)
    # -> matched device profile, kernel, OpenWrt release, MTD layout

## Why it is shaped this way (bench-proven doctrines)

- **Self-firing gates.** The sha check and `sysupgrade -n` run in ONE
  shell line on the box. Three box deaths lived in the host round-trip
  between "file arrived" and "flash it"; there is no round-trip anymore.
- **Fresh-boot = spaces immediately.** bootdelay on these boxes is
  1 s; probing for a shell first burns it and boots the wedged image.
- **Fire-mark expects.** An expect matches only bytes that arrive from
  trigger-fire time onward — a draining echo backlog replaying a
  pre-reboot prompt must never satisfy an action (live-fire lesson).
- **Telnet-IAC framing everywhere.** ser2net telnet consoles eat every
  0xFF; every byte path (including binary YMODEM frames) goes through
  TelnetFramedIo. `tcp://` is raw, `telnet://` is framed.
- **Transfer ladder by strength:** TFTP (8 s for 5.3 MB over the
  direct wire) > YMODEM (`loady`, ACK-paced, ~11 min) > serial chunks
  (needs a custom stty-enabled rescue image — official OpenWrt
  initramfs images ship NO stty; verified on-box on 24.10.2 AND
  25.12.6, and the canonical-mode fallback is dead: the tty echoes
  binary as caret notation and echo storms hard-lock the CPU).
- **Failure-depth taxonomy drives the reset lever:** config-wedge ->
  BREAK+sysrq-b; echo-storm lockup -> wait for drain (beware stale
  replay); CPU hard-lock -> power only. See
  docs/lessons/2026-10-24-gs1900-lockout.md.
- **Pre-flight refuses bad runs at ARM time** (profile quirks, missing
  served files, sha format, host-side image hash), and a rescue
  journal (`<transcript>.rescue`) records phases so a re-arm KNOWS a
  previous run died mid-ladder.
- **Transport death aborts immediately** (typed WatchError) instead of
  burning timeout windows as silence.

## The generality mechanism

`devices/*.json` profiles (family base + board overlay, inheritable)
feed the same engine: interrupt method, boot signatures, load address,
dual-partition commands, shell network setup, flash command, commit
banner, quirks. The unit test
`flash_rescue_recipe_generalizes_to_other_devices` builds the
dlink/dgs-1210-16 ladder (ESC+CTRL-C interrupt, no dual partition,
different load address) through the identical code path — new device,
new JSON, no new code.

## Evidence

- conwrt PR #545 (serial-watch + flash-rescue) — live-fire comments
  throughout, final end-to-end proof 2026-10-25.
- conwrt-bench #66 — the 3-day arc, postmortems, and the flash-race
  evidence.
- Live result: wedged 6.12.108 image -> OpenWrt 25.12.6 r33311, clean
  first boot, zero wedge ticks, all via
  `conwrt flash-rescue --at-shell --device zyxel/gs1900-8hp`.

<!-- CI-hang investigation note: see conwrt issue for the flaky matrix hang; merge-blocking, not branch-blocking. -->
