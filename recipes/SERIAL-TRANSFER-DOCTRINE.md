# Serial transfer doctrine (researched 2026-10-24, OpenWrt forums/wiki/device commits)

Why `recipes/gs1900-8hp-rescue-tftp.json` is the primary path and raw
console streams are a last resort.

## Findings

1. **The canonical recovery for RTL838x switches is U-Boot-side TFTP**
   (forum thread 57875, GS1900 device commit messages, OpenWrt wiki):
   `rtk network on` (U-Boot's own stack — independent of any OpenWrt
   config), `setenv ipaddr/serverip`, `tftpboot 0x84f00000 <image>`,
   `bootm`, then sysupgrade from the running initramfs. Ethernet moves
   the image in seconds; serial YMODEM ~11 min; raw pipe ~27 min.

2. **Nobody streams large images raw over the console at 115200.** The
   community tools are protocol-paced (YMODEM `loady`, ACK per 1K) or
   ethernet (tftpboot/wget/scp). Bench correlation 2026-10-23/24:
   every YMODEM transfer (3/3) survived; every ~27-min raw stream
   ended in a box death at/near the end-of-stream sha compute — with
   all confounds removed (pristine kernel, self-firing script armed,
   Rust pacing). Mechanism: sustained RX saturation of the tty/console
   path followed immediately by CPU-heavy hashing = the death pattern;
   ACK-paced transfers never saturate.

3. **`Bytes transferred = N`** is U-Boot's own byte-count gate for the
   TFTP leg (parity with the YMODEM `## Total Size` gate).

## Rules for recipes

- Prefer `tftpboot` for any image that fits RAM (both initramfs and
  sysupgrade images do).
- If serial-only: use `loady` YMODEM (ACK-paced), never a raw pipe for
  multi-MB images.
- If a raw pipe is unavoidable: chunk the receiver (`head -c` segments
  with settle pauses) and verify per-chunk on-box so no continuous RX
  burst exceeds ~3 min and no heavy compute follows a saturated window.
- The self-firing receiver doctrine (sha gate + sysupgrade armed ON BOX
  before the transfer) stays regardless of transport.

## Recipe endpoints

Shipped recipes use `192.168.1.100` as a PLACEHOLDER for the rescue
host — substitute your host's address on the wire (or use `conwrt
flash-rescue --server-ip`, which takes it as an argument). Bench-
specific addresses never belong in the repo.

## 2026-10-25 definitive findings (on-box, 24.10.2 initramfs live shell)

- **ISIG is OFF on the rescue console**: a mid-line 0x03 echoes as a
  literal `^C` and does NOT signal the foreground process. Canonical
  mode therefore does not kill `head` on control bytes — but:
- **ECHO is ON and mangles binary**: 64 raw bytes came back as
  caret-notation garbage (`^C^E^F^^\^]...`) — every binary transfer
  over this tty is an echo storm, and echo storms hard-lock the CPU
  (proven 4x this week). Combined with **NO stty on any official
  image** (busybox multi-call dispatch refuses the applet — verified
  on 24.10.2 AND 25.12.6), serial-chunk binary transfer is CLOSED on
  official images. The enabler is a custom stty-enabled rescue image
  (image builder / ASU, ~30-60 min) — or just use the ladder:
  TFTP 8 s, YMODEM ~11 min.
- **fw_setenv/fw_printenv are ABSENT in initramfs** (permanent install
  has them): U-Boot-env transaction markers are not reachable from a
  rescue shell; conwrt keeps the rescue journal host-side
  (`<transcript>.rescue`) instead.
- **25.12 sysupgrade prints `upgrade: Sending TERM to remaining
  processes`** — not `Sending SIGTERM`. Commit banners are profile
  data now (`flash.sysupgrade_banner`).
- **From-shell rescue LIVE-PROVEN**: `conwrt flash-rescue --at-shell
  --device zyxel/gs1900-8hp` -> profile shell_net_setup -> wget
  6554382 B -> on-box sha verdict -> self-firing `sysupgrade -n` ->
  clean 25.12.6 r33311 first boot, 0 wedge ticks. The 3-day arc
  (wedge -> rescue) closed agentless.
