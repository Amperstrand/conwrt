# Device profiles

Device profiles are the generalization layer for conwrt's serial
rescue tooling: one recipe engine, every device, no per-device code.
A profile is a small JSON file describing how to recognize, interrupt,
transfer to, and flash a device; `conwrt flash-rescue --device <name>`
builds the whole rescue ladder from it.

Layout (vendor dirs, up to 3 levels deep):

    devices/
      realtek/rtl838x-base.json     <- family defaults (inheritable)
      zyxel/gs1900-8hp.json         <- board overlay
      dlink/dgs-1210-16.json        <- board overlay

## Inheritance

A board profile `inherits` family defaults and overrides what differs
(sections replace wholesale except `quirks`, which merges field-wise:
booleans OR, notes append). `zyxel/gs1900-8hp` inherits
`realtek/rtl838x-base` and changes almost nothing — the family carries
the boot signatures, U-Boot prompt, `rtk network on`, load address,
and the quirks (`stty_absent`, `echo_storm_lethal`).

## Fields that matter

- `console.bootdelay_interrupt`: `spaces` (Realtek), `esc`,
  `ctrl_c`, or `esc_then_ctrl_c` (vendor-CLI loaders) — drives the
  `Interrupt` action.
- `console.boot_signatures`: any match arms a `serial-watch` recipe.
- `uboot.load_addr` + `uboot.network_init` + `boot_cmd`/`verify_cmd`
  templates (`{load_addr}` substituted).
- `uboot.partition_select_cmd`/`partition_save_cmd`: dual-partition
  boards (Realtek `setsys bootpartition 0` + `savesys`); omit for
  single-partition devices.
- `uboot.shell_net_setup`: template run from a rescued initramfs
  shell to bring the rescue wire up (`{client_ip}` substituted) —
  U-Boot's network does not survive into Linux.
- `flash.sysupgrade_cmd`: template with `{image}`.
- `flash.sysupgrade_banner`: the line sysupgrade prints when it
  COMMITS (verdict marker for from-shell rescues; 25.12 says
  `upgrade: Sending TERM`, older images `Sending SIGTERM` — this
  cost a live-fire false-failure, make sure it matches your image).
- `quirks`: documented behavioral facts; `stty_absent` makes
  `--at-shell` pre-flight REFUSE `stream_chunks` recipes at arm time.

## Search path

`conwrt` resolves profiles from `./devices/` then
`~/.config/conwrt/devices/` (first hit wins) — drop a user profile
next to the shipped ones without touching the repo.

## Adding a device

1. Copy the closest existing profile (family base if one exists).
2. Fill in the real prompt, signatures, load address, interrupt
   method, flash command.
3. `conwrt serial-detect --port ... --devices` against the live
   console — it classifies and fingerprint-matches (board-level when
   unique, family-level when prompts are shared; ties reject as
   ambiguous rather than guessing).
4. `conwrt flash-rescue --device <yours> ...` — the ladder builds
   from the profile.

## Tested status

`zyxel/gs1900-8hp` is fully bench-tested (2026-10-23..25): BREAK
ladder, spaces interrupt, bundled-TFTP tftpboot, iminfo gate, bootm,
initramfs shell, wget, on-box sha gate, self-firing `sysupgrade -n`,
and the from-shell variant — agentless, one command, live-proven to
a clean 25.12.6 first boot. `realtek/rtl838x-base` carries the same
family's proven quirks. Other profiles are structural (same engine,
unit-tested construction) until fired on their hardware.
