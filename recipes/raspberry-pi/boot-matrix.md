# Pi boot matrix: SD vs USB vs network

Answers three questions that get conflated, and tests all three media on one
board:

1. **What is this Pi doing right now?** — OS up, netboot rescue shell, or
   silently looping.
2. **Which media can it boot?** — a firmware property.
3. **Which media will it actually try?** — a configuration property.
   (2) and (3) are independent, and the default configuration makes (3)
   narrower than (2).

Tooling: `scripts/pi_boot.py` (`probe`, `detect`, `capability`, `matrix`).

## The two gates

| Media | First beta | First **default** production bootloader |
|---|---|---|
| SD card | every Pi 4 bootloader | every Pi 4 bootloader |
| Network (TFTP) | 2019-09-23 | **2020-04-16** |
| USB mass storage | 2020-05-15 | **2020-09-03** (promoted 2020-09-14) |

Read that as: *USB boot implies netboot capability, but not the reverse.* A Pi
4 from the 2020-04 → 2020-09 window netboots fine and cannot boot USB at all.
Only 2019 / early-2020 firmware lacks both.

The second gate is `BOOT_ORDER`. The stock value is `0xf41`:

```
0xf41 -> sd (1), usb (4), restart (f)
```

Network (`2`) is **not in it**. So a fully capable Pi never attempts a netboot
until someone writes `BOOT_ORDER=0xf241` (SD → USB → network → restart) or
`0xf142` (network first). Capability without configuration is a dead end, and
this is the single most common misdiagnosis: "the Pi can't netboot" usually
means "the Pi was never told to".

## Quick start

```bash
# Which Pi is on this L2? (passive ARP; --sweep populates it first)
scripts/pi_boot.py scan --sweep 192.168.1.0/24

# Offline: what does a given firmware date + boot order allow?
scripts/pi_boot.py capability --firmware 2020-04-16 --boot-order 0xf41

# Something answers at this address — what is it?
scripts/pi_boot.py detect --host 192.168.1.50

# It booted. What did it boot from, and what else can it do?
scripts/pi_boot.py probe --host 192.168.1.50 --user pi

# Test all three media in turn (interactive media swaps, optional power hook)
scripts/pi_boot.py matrix --host 192.168.1.50 --user pi \
    --power-cmd 'labgrid-client -p <labgrid-place> power cycle' --json boot-matrix.json
```

`matrix` is deliberately semi-manual: no tool can insert an SD card. Each leg
prints its precondition and waits for Enter unless `--yes` is given.

## What each leg proves

| Leg | Precondition | Evidence | PASS means |
|---|---|---|---|
| `sd` | microSD with a bootable OS, USB removed | SSH + `root=` resolves to a `mmc` device | the card booted **and** was the medium |
| `usb` | USB device, SD removed | SSH + `root=` resolves to a `usb` device | the USB device booted |
| `net` | neither medium present, rescue server armed for the Pi's MAC | telnet on tcp/23 | the bootloader fell through to TFTP and ran the RAM kernel |

The leg verdict is on the **medium**, not on reachability. A Pi that answers
SSH during the SD leg but reports `boot medium usb` is a **FAIL** — that is
exactly the false green this tool exists to prevent (you would otherwise
certify "SD boot works" while the card was never read).

## Reading the output

`probe` prints:

```
Raspberry Pi 4 Model B Rev 1.4  (192.168.1.50)
  serial          10000000abcd1234
  os              Debian GNU/Linux 12 (bookworm)
  boot medium     usb   (root=PARTUUID=deadbeef-02)
  boot order      0xf41   sd -> usb -> restart
  bootloader      2020-04-16 12:00:00   version 5a4a8b3c (release)

  mode    firmware  ordered  verdict
  sd      yes       yes      capable and reachable — this medium will be tried
  usb     no        yes      firmware predates usb boot (first default release 2020-09-03) — boot an SD card and run rpi-eeprom-update
  network yes       NO       capable but NOT in BOOT_ORDER — ... Add 0x2 to BOOT_ORDER (e.g. 0xf241 ...)
```

Interpretation:

| Symptom | Meaning |
|---|---|
| `detect` says `rescue-shell` | RAM boot over TFTP. Nothing persists; this is a boot, not an OS. |
| `detect` says `silent` | No SSH, no telnet. Could be netboot-fallback (check the DHCP side) or no power. |
| `boot order` has no `network` | Netboot will never be attempted regardless of firmware. |
| `usb: no` but `network: yes` | Pre-2020-09 bootloader. Netboot is the only remote medium available. |
| `firmware unknown` | `vcgencmd` failed (not a Pi, permissions, or `sudo -n` unavailable) — not evidence of old firmware. |

## Traps

1. **`vcgencmd bootloader_version` is locale-dependent.** Its first line is
   `Apr 16 2020 12:00:00` on stock Pi OS but ISO `2020-04-16 12:00:00` on newer
   wrappers. `parse_fw_date` accepts both and returns `None` for anything else
   rather than guessing; an unrecognised month must never be mapped to a
   neighbour. `probe` reports `unknown` in that case, which is honest.

2. **A stock Pi 4B cannot be reached without an SD card — including by
   `rpiboot`.** The Pi 4B/Pi 400 have no `nRPIBOOT` jumper. USB device-mode
   rpiboot must first be *enabled* by an SD card (`make-pi4-rpiboot-gpio-sd`),
   and **that permanently burns the GPIO choice into OTP** — it cannot be
   undone. Do not treat rpiboot as a free recovery rung on a 4B.

3. **A non-bootable SD card does not block USB boot.** With `0xf41` the
   bootloader tries SD, fails to find bootcode, and falls through. A card with
   *damaged* bootcode can still hang, so remove it rather than trusting
   fallthrough when testing USB.

4. **The rescue boot is an initramfs.** Its `root=` is absent or `rootfs`, and
   `boot_medium` reports `net` for that case. Do not mistake it for an
   installed system — flash work belongs in `netboot-rescue.md`.

5. **The netboot TFTP tree lives in the router's tmpfs.** Arming it without
   recreating the tree crash-loops dnsmasq and takes DHCP/DNS down for the
   whole LAN. Always arm through `pi_netboot.py arm` (it uploads the tree
   first and rolls back), never by editing dnsmasq by hand.

6. **The Pi must be the one you think it is.** `probe` reports the board serial
   read from `/proc/cpuinfo`; match it against the inventory before any flash
   or EEPROM write.

## Recording the result

Paste the `matrix` verdict table into the lane note, with the bootloader date
and `BOOT_ORDER` from `probe`. A PASS without those two values is not
reproducible — the same board can fail the same leg after an EEPROM change.
