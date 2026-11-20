# Laptop-direct Pi lab (no router, no bench LAN needed)

Validating a Pi's boot when the bench LAN is not available or not wanted: the
**laptop itself** serves DHCP+TFTP over a direct ethernet cable, and boot
media is flashed and seeded on the same laptop. One power-cycle then tests
both boot paths at once.

Written 2026-11-20 from the first live run of this flow; every trap in it
was hit that day.

## Topology

```
Pi 4B ──ethernet──> laptop built-in RJ45   (lab link, its own /24)
Pi 4B ──USB/SD───> boot medium (flashed + seeded on the laptop)
laptop ──wifi───> everything else (unchanged)
```

The lab link gets its **own range** so it cannot collide with anything the
laptop already routes (bench wifi, legion link, router VLANs, MAAS). The
worked example uses `192.168.99.0/24` with the laptop at `192.168.99.1`.

## The netboot server (dnsmasq: DHCP + TFTP, no DNS)

```conf
# /tmp/opencode/pi-netboot/dnsmasq.conf
interface=enp0s31f6          # the built-in RJ45 facing the Pi
bind-interfaces              # do NOT grab :67 on other interfaces
listen-address=192.168.99.1
port=0                       # DHCP+TFTP only — never touch system DNS
no-hosts
no-resolv
dhcp-authoritative
dhcp-range=192.168.99.100,192.168.99.150,12h
dhcp-option=66,192.168.99.1  # TFTP server — the bootloader REQUIRES it
dhcp-option=67,config.txt    # bootfile name
enable-tftp
tftp-root=/tmp/opencode/pi-netboot/tftpboot
log-dhcp                     # DISCOVERs become visible before arming
log-facility=/tmp/opencode/pi-netboot/dnsmasq.log
pid-file=/tmp/opencode/pi-netboot/dnsmasq.pid
```

TFTP root: a RAM-boot rescue tree (`pi_netboot.py`'s deployed tree, or
`~/pi-rescue-kit/tftp-tree-openwrt` — key-only dropbear, verified on
hardware). Requests come as `<serial>/config.txt` first, then root; plain
dnsmasq handles the fallback.

Setup steps:

```bash
sudo ip addr add 192.168.99.1/24 dev enp0s31f6
sudo ip link set enp0s31f6 up
sudo ufw allow in on enp0s31f6 comment 'pi4 direct netboot lab'
sudo dnsmasq -C /tmp/opencode/pi-netboot/dnsmasq.conf
ss -lunp | grep -E ':67|:69'    # both must show dnsmasq on THIS interface
```

Traps:

- **ufw default-deny** eats the DISCOVER silently. Without the allow rule
  the server "works" and never answers anything.
- Another dnsmasq may already hold `:67` (libvirt's default network does).
  `bind-interfaces` + `interface=` keeps ours off theirs — verify with
  `ss -lunp` that OUR pid owns the interface-scoped socket.
- `port=0` matters: without it dnsmasq becomes the laptop's DNS resolver for
  whatever it binds and steps on systemd-resolved.

## Monitoring — and proving the monitor works

Run tcpdump on the lab link:

```bash
sudo tcpdump -i enp0s31f6 -en -l -n \
  '(udp port 67 or udp port 68 or udp port 69) or arp'
```

**A capture must prove it sees frames before its silence counts.** The
first capture of the live run had a BPF syntax error (`tftp` is not a
primitive everywhere), logged only its startup header, and would have
"reported" perfect silence forever. Read the log; expect unrelated ARP
traffic on a live link. `tftp` as a filter word is not portable — write
`udp port 69`.

Silence is a verdict only after **carrier=1 and a fresh power-cycle**. A
netboot-capable Pi DISCOVERs within ~15 s and never stops retrying, so once
the link is up: DISCOVERs = netboot works; 60–90 s of nothing = the EEPROM
never tries network. Before carrier, silence means nothing.

## The EEPROM reality (why the stick is the long game)

Stock `BOOT_ORDER=0xf41` is SD→USB→restart: the network is never tried, so
a stock board stays dark on this link no matter how good the rescue server
is. The fix travels **on the boot medium**: `recovery.bin` +
`pieeprom.upd` + `pieeprom.sig` on the boot FAT — the bootloader applies it
on the first power-up (`BOOT_ORDER=0xf241`, `BOOT_UART=1` in the rescue
kit's package). After that one boot, netboot rescue works forever.

Do **not** try to deliver the EEPROM package over TFTP instead: stock
EEPROMs have `ENABLE_SELF_UPDATE=0`, so the bootloader downloads
`pieeprom.upd` and never applies it (verified on hardware 2026-10-08 —
see `eeprom-and-security.md` § Delivering EEPROM updates).

## Flashing + seeding media on the workstation

`scripts/pi_media_flash.sh /dev/sdX` — removable-device gates, dd,
cache-evicted verify, and mtools injection of `user-data` + the EEPROM
package into the boot FAT **without ever mounting it** (raw `@@offset`
mtools). Overridable via `IMG` / `UD` / `KIT` env vars.

Traps, each earned in the live run:

1. **udisks auto-mounts and re-mounts.** Unmount ALL partitions yourself
   and never `partprobe` — re-reading the table is exactly what triggers
   the re-mount behind your back. Also note `lsblk -d <dev>` hides
   *partition* mounts; walk `/sys/block/<dev>/<part>` instead. mtools needs
   no kernel partitions at all.
2. **sudo's `$HOME` is `/root`.** A script run under sudo that builds paths
   from `$HOME` reads the wrong user's tree — resolve the real home from
   `SUDO_USER` (`getent passwd "$SUDO_USER"`).
3. **`mcopy -n` still prompts** when the target exists — and the prompt
   hangs forever on a closed stdin. `mdel` the targets first. This mtools
   (4.0.49) `mdel` has **no `-s` flag**; guard the rc instead.
4. **The raspios image ships its own cloud-init seed** (`user-data`,
   `meta-data`, `network-config` on the boot FAT — 3.2 KB of appliance
   config in the seedling image). Overwrite `user-data` with yours or the
   board boots someone else's appliance: wrong hostname, wrong user, wrong
   unlock flow.
5. **dd success ≠ byte correctness.** Verify cache-evicted
   (`blockdev --flushbufs` then hash) against the image hash. On mismatch,
   repair at 4K: scan in 16 MiB chunks, refine bad chunks to 4K blocks,
   rewrite **only differing blocks with 4K write commands** — a stick that
   ignored big-command writes committed them fine at 4K (2 differing 4K
   blocks converged in one repair round on 2026-11-20).
6. **After an unplug/replug the stick may serve stale pre-write pages** for
   regions nobody rewrote — byte-identity against the pristine image
   becomes unachievable *by design*. The bootability test is then:
   (a) injected files hash-match their sources via `mtype`, and
   (b) `e2fsck -fn` on the rootfs passes. One suspect region read
   identical twice → stable, ship it.
7. **Read-twice discriminator** (the #42 rule, run *without* writing in
   between): two consecutive device reads identical but ≠ image → stable
   wrong bytes, repairable. Two reads that differ from *each other* → the
   medium or link is failing; change port or medium — do not iterate
   software at it.

## The boot experiment (one power-cycle, both paths)

Cable the Pi to the laptop **and** give it the flashed medium, then
power-cycle once:

| Observation | Verdict | Next |
|---|---|---|
| TFTP fetches in the dnsmasq log (`config.txt`, `start4.elf`, `kernel8.img`) | EEPROM tries network → **rescue shell** | `ssh root@192.168.99.100` (baked key) |
| DHCP lease `192.168.99.100`, SSH banner, no TFTP | **Medium booted** (EEPROM ≥ 2020-09-03) — and that first boot applied `0xf241` | `ssh pi@192.168.99.100`, then `pi_boot probe --host 192.168.99.100 --user pi` |
| carrier up, total silence on both | EEPROM predates USB boot and never tries network | **SD bootstrap**: flash a microSD the same way (SD is in every Pi 4's BOOT_ORDER); the reader is a USB SD/MMC reader |

Then `pi_boot.py matrix --host <ip> --legs sd,usb,net` formalises the
per-medium verdicts (see `boot-matrix.md`).

## Teardown

```bash
sudo kill $(cat /tmp/opencode/pi-netboot/dnsmasq.pid)
sudo kill $(cat /tmp/opencode/pi-netboot/tcpdump.pid)
sudo ufw delete allow in on enp0s31f6
sudo ip addr del 192.168.99.1/24 dev enp0s31f6
```

Leave no rule behind: the ufw allowance and the address are the only host
state this lab creates.
