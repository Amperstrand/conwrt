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
Only 2019 / early-2020 firmware lacks both. Re-verified 2026-11-20 against
the primary source (rpi-eeprom @ 1a099a5a, the historical
`firmware/release-notes.md`): "2019-09-23 (BETA) Add support for network
boot", "Promote 2020-04-16 … default release for all users … supports network
boot", "2020-05-15 … beta with USB boot", and `releases.md`: "USB mass
storage boot requires the 2020-09-03 EEPROM images".

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
    --router 192.168.1.1 \
    --power-cmd 'labgrid-client -p <labgrid-place> power cycle' --json boot-matrix.json
```

`matrix` is deliberately semi-manual: no tool can insert an SD card. Each leg
prints its precondition and waits for Enter unless `--yes` is given.

Exit codes are uniform across subcommands: `0` a positive answer (every leg
PASS); `1` a negative answer — a FAIL **or an ERROR leg** is still evidence;
`2` the question could not be asked at all (bad arguments, unreadable router
log, empty neighbour table). Scripts must treat `2` as *inconclusive*, never
as *not found* — the two have opposite follow-ups.

## Replaying a dump

`probe --dump` saves the raw SSH output; `probe --from-file` renders it again
anywhere. A report from another site becomes evidence rather than a
paraphrase — and the parser can be exercised with no board attached:

```bash
scripts/pi_boot.py probe --host 192.168.1.50 --user pi --dump probe.txt
scripts/pi_boot.py probe --from-file probe.txt
```

The fixture set under `tests/fixtures/pi/` is the same format (Pi OS on USB,
Pi OS on SD, Ubuntu, a netboot initramfs with no block root, and a Pi whose
`vcgencmd` is unavailable).

## What each leg proves

| Leg | Precondition | Evidence | PASS means |
|---|---|---|---|
| `sd` | microSD with a bootable OS, USB removed | SSH + `root=` resolves to a `mmc` device | the card booted **and** was the medium |
| `usb` | USB device, SD removed | SSH + `root=` resolves to a `usb` device | the USB device booted |
| `net` | neither medium present, rescue server armed for the Pi's MAC | telnet on tcp/23 | the bootloader fell through to TFTP and ran the RAM kernel |

With `--router`, the net leg also reads the router's `dnsmasq-tftp` log. A
failed net leg then reports which of two very different things happened:
**"no TFTP fetches"** (the board never asked — power, cable, boot order, or a
medium still in the slot) versus **"router saw config.txt, kernel8.img"**
(it fetched and then died — bad kernel/dtb, or an incomplete tree). The two
are indistinguishable from the client side and have opposite fixes.

The leg verdict is on the **medium**, not on reachability. A Pi that answers
SSH during the SD leg but reports `boot medium usb` is a **FAIL** — that is
exactly the false green this tool exists to prevent (you would otherwise
certify "SD boot works" while the card was never read).

There is a third verdict, **ERROR**: if `--power-cmd` exits nonzero or hangs
(`--power-timeout`, default 120 s), the leg is recorded ERROR and the wait is
skipped entirely. A board that never cycled proves nothing about any boot
medium, so neither PASS nor FAIL is honest — and a swallowed power failure
used to surface three minutes later as a believable FAIL that blamed the
medium for a broken power hook.

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
| `ordered` shows `?` | `BOOT_ORDER` could not be read. The tool claims nothing: an unread config is not an empty one, and "NOT in BOOT_ORDER" here sent people to reflash EEPROMs whose real fault was the reading. |
| `usb: no` but `network: yes` | Pre-2020-09 bootloader. Netboot is the only remote medium available. |
| `firmware unknown` | `vcgencmd` failed (not a Pi, permissions, or `sudo -n` unavailable) — not evidence of old firmware. |

Every zero carries its numerator, so a count of zero cannot masquerade as
evidence: `scan` prints `inspected N neighbour entries; M match a Raspberry
Pi OUI` before any negative, and `detect` prints `among N MACs in the last L
DHCP log lines`. If a tool ever reports a zero without saying what it
inspected, treat that as a defect in the tool.

## The SD bootstrap (a board nothing can reach)

When `scan` and `detect` find nothing and the board has never booted an OS,
the SD card is the only entry point (trap 2). One boot can make it
network-manageable permanently:

1. Write Raspberry Pi OS to the card (same image and headless seeding as any
   Pi disk — `pi_image.py` documents the cloud-init layout).
2. Build an EEPROM package with the boot order you want:

   ```bash
   scripts/pi_eeprom.py build --boot-order 0xf241 --boot-uart --out /tmp/pi-eeprom
   ```

3. Copy the three files to the card's FAT boot partition:
   `recovery.bin`, `pieeprom.upd`, `pieeprom.sig`. The bootloader applies
   them on the next power-up, before the OS matters.
4. Boot, confirm with `probe`, then remove the package from the card. Leaving
   it is harmless (version match → skip) but it is a stale artifact that
   misleads the next person.

Do **not** try to deliver the same package through the netboot TFTP root:
without `ENABLE_SELF_UPDATE=1` in the *current* EEPROM the bootloader
downloads `pieeprom.upd` and never applies it — hardware-verified
2026-10-08. See `eeprom-and-security.md` § Delivering EEPROM updates.

With `BOOT_UART=1`, a 3.3 V USB-UART on GPIO14/15 at 115200 prints the
bootloader's boot-mode sequence. On a board that is otherwise silent, that is
the cheapest evidence available and it costs one wire.

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
