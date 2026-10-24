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
