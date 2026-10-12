# Raspberry Pi netboot rescue playbook

Symptom this solves: a Raspberry Pi sits on the network doing endless
`DHCPDISCOVER -> DHCPOFFER` pairs (never `DHCPREQUEST`), is unreachable, and
has no screen. Validated end-to-end on a Pi 4, 2026-10-08.

## 1. Confirm what it is (network-only, 5 minutes)

The Pi may never get an IP — work from the router (or any host that can reach
the Pi's L2):

```bash
# Router: which MAC keeps DISCOVERing but never REQUESTs?
logread | grep dnsmasq-dhcp | tail -50

# Live fingerprint: the bootloader's PXE-style client
tcpdump -ni br-lan.13 -vv -s0 'ether host <pi-mac>'
```

Interpretation:

| Observation | Meaning |
|---|---|
| Vendor-Class (60) `PXEClient:Arch:00000:UNDI:002001`, option 97 GUID contains ASCII `Rpi4`/`Rpi5` | EEPROM bootloader netbooting. The Pi has never booted an OS. |
| DISCOVER/OFFER repeated, never REQUEST | The bootloader rejects plain OFFERs (needs TFTP options 66/67). The Pi is not broken networking — it is boot-fallbacking. |
| DHCP-only traffic, zero IPv6/mDNS/ARP | No OS has ever come up. Nothing to SSH to — unreachability is the same problem, not a second one. |
| `OFFER -> REQUEST -> ACK` + other traffic | A booted OS exists; troubleshoot that OS instead. |

Also rule out: dead SD (empty slot), wrong boot order, and check the
`tested` facts in `models/raspberrypi-4b.json`.

## 2. Arm the rescue server (dnsmasq TFTP on the OpenWrt router)

```bash
python3 scripts/pi_netboot.py arm --router <router-ip> \
    --tree <rescue-tree-dir> --mac <pi-mac>
```

The tree is a FAT-boot-equivalent file set: `config.txt`, `start4.elf`,
`fixup4.dat`, a kernel, dtbs, and an initramfs whose init brings up DHCP and a
telnetd (busybox). `~/pi-rescue-kit/` on the provisioning host holds a known
good tree; `REARM.md` there documents the manual equivalent.

Hard rules encoded in `pi_netboot.py arm` (each was learned by breaking a real
router):

1. Upload the tree **before** touching dnsmasq. On OpenWrt, dnsmasq runs in a
   procd ujail; a `tftp-root` that does not exist or is outside the
   jail-mounted conf-dir (`/tmp/dnsmasq.<section>.d`) crash-loops dnsmasq and
   the whole LAN loses DHCP/DNS.
2. Restart dnsmasq, then verify health (`pgrep`, port 69, tree file present).
   On failure, roll the config back automatically.

Then power-cycle the Pi. With no bootable medium it falls through to network
boot and lands in the rescue shell (telnet port 23, root, no password — the
Pi is RAM-only at this point).

## 3. Work in the rescue shell

The rescue shell (busybox) can do anything a small Linux can:

- Inspect attached disks (`cat /proc/partitions`, `lsblk` if present)
- Mount filesystems (vfat and ext4 are built into the rescue kernel)
- Transfer files over LAN with `nc`/`wget` — **note the direction**: some
  WiFi-provisioned hosts drop inbound connections from wired clients
  (AP client isolation). Have the Pi LISTEN (`nc -l -p <port> > file`) and
  connect out from the workstation instead.
- Flash disks: `xzcat image.img.xz | dd of=/dev/sdX bs=4M && sync`
- Re-read partitions after dd: `blockdev --rereadpt /dev/sdX; mdev -s`
- Apply an EEPROM update (see `eeprom-and-security.md`): place
  `recovery.bin` + `pieeprom.upd` + `pieeprom.sig` in the TFTP root and
  reboot — the bootloader applies it and skips re-application on version match.

## 4. Return the Pi to normal boot

```bash
python3 scripts/pi_netboot.py disarm --router <router-ip> --purge
```

Then reboot the Pi (from the rescue shell: `reboot -f`). It falls through to
its next boot medium. Arm again any time — this pair IS the network-boot
on/off switch; no EEPROM changes are needed to toggle it.

## Failure mode cheat sheet (from the 2026-10-08 incident)

| Clue | Diagnosis |
|---|---|
| DISCOVER loop + PXEClient + no other traffic | Boot medium missing/dead; bootloader netboot-fallback. Serve the tree. |
| Steady DISCOVER cadence for minutes | Firmware alive and looping, not power-cycling. |
| Pi hangs when a USB disk is attached; TCP resets, stale ARP | PSU brownout from bus-powered HDD. Use externally powered disk / official PSU. |
| dnsmasq crash loop after adding tftp-root | TFTP root missing or invisible to the procd ujail. Create tree under the dnsmasq conf-dir first. |

## RAM corruption masquerades as everything else (2026-10-08 incident)

A Pi 4 with a marginal memory chip produces a *suspicion-absorbing* cluster of
failures that look like five unrelated problems. Diagnose BEFORE re-flashing —
each reinstall "fixes" it until the next heavy I/O pass re-corrupts:

1. **tmpfs pattern test** (rescue shell, pure RAM, no disk involved):
   ```sh
   dd if=/dev/zero of=/tmp/rt bs=1M count=384 2>/dev/null
   cmp /tmp/rt /dev/zero && echo RAM_OK || echo RAM_FAIL
   ```
   A FAIL means non-zero bytes read back from zero-filled tmpfs — memory
   corruption, full stop. Test under memory pressure too: the fault may be
   region/pressure-dependent (384MB failed here while 64MB passed on a
   freshly-booted system).
   - **Faithful repro**: replicate the resident load as well, not just the
     test — the original failure only appeared with a 1.5GB tmpfs file
     resident:
     ```sh
     dd if=/dev/zero of=/tmp/big bs=1M count=1536 2>/dev/null
     dd if=/dev/zero of=/tmp/rt bs=1M count=384 2>/dev/null
     echo DIFFS=$(cmp -l /tmp/rt /dev/zero 2>/dev/null | wc -l)
     ```
   - **Cross-check with memtester** (locked memory, no swap, thorough
     patterns): `apt install memtester && memtester 1200M 2`. memtester PASS
     + pressure-repro FAIL points at the tmpfs/swap/compression path
     (zram) or kernel memory management rather than plain RAM cells.
   - **Discriminate disk-channel from RAM**: if corruption only appears on
     files written through USB after warm reboots, suspect the UAS
     warm-state bug below — tmpfs corruption with a *disconnected* disk
     cannot be the adapter.
2. **ext4 EBADMSG on a freshly-written image**: `grep /mnt/etc/passwd` →
   `Bad message` right after a checksum-verified dd means the corruption
   happened in the write path (RAM or USB adapter), not in your image.
3. **Spontaneous reboots of the rescue system**: paired DHCP
   DISCOVER/ACK cycles on the router with minute-scale gaps and no reboot
   commands issued. Commands over telnet "echo but don't execute" — the Pi
   died between your connect and the execution. (Caveat: an operator
   resetting the box produces the same log signature — correlate with the
   operator before citing this as evidence.)

Verdict in this incident: board-level memory fault; SSD content and the
provisioning procedure were verified correct independently.

## Resetting access on a provisioned OS (from the rescue shell)

If a Pi's OS locks you out (no ssh, unknown password), the rescue shell can
repair the rootfs directly:

```sh
mkdir -p /mnt && mount -t ext4 /dev/sda2 /mnt        # rootfs partition
# 1. guarantee sshd starts at boot:
ln -sf /usr/lib/systemd/system/ssh.service \
      /mnt/etc/systemd/system/multi-user.target.wants/ssh.service
# 2. guarantee a known user (generate the hash on the workstation:
#    openssl passwd -6 'newpassword')
grep -q '^ubuntu:' /mnt/etc/passwd || \
  echo 'ubuntu:x:1000:1000:Ubuntu Lab:/home/ubuntu:/bin/bash' >> /mnt/etc/passwd
grep -q '^ubuntu:' /mnt/etc/group  || echo 'ubuntu:x:1000:' >> /mnt/etc/group
grep -q '^ubuntu:' /mnt/etc/shadow || \
  echo 'ubuntu:<sha512-crypt hash>:19800:0:99999:7:::' >> /mnt/etc/shadow
mkdir -p /mnt/home/ubuntu/.ssh /mnt/root/.ssh
echo '<your public key>' > /mnt/home/ubuntu/.ssh/authorized_keys
echo '<your public key>' > /mnt/root/.ssh/authorized_keys
chmod 700 /mnt/home/ubuntu /mnt/home/ubuntu/.ssh /mnt/root/.ssh
chmod 600 /mnt/home/ubuntu/.ssh/authorized_keys /mnt/root/.ssh/authorized_keys
chown -R 1000:1000 /mnt/home/ubuntu
sync && umount /mnt && reboot -f
```

`scripts/pi_image.py provision` now bakes this in up front: a random
break-glass password (written to `<image>.credentials.txt`), an
`ssh_authorized_keys` entry, and a `runcmd` that force-enables sshd — so a
freshly provisioned Pi can never lock you out.

## RAM-netbooting a full OS: the kernel must support initrd

A Pi netboot chain (TFTP kernel + initramfs) can boot ANY sufficiently small
OS image — but only if the kernel has initrd support compiled in. **OpenWrt
release kernels strip initramfs support** (the build system's
`Kernel/SetNoInitramfs` removes all INITRAMFS config entries, which is also
why OpenWrt ships no initramfs images for bcm27xx). Verified 2026-10-10: the
full chain works (DHCP -> TFTP kernel 12MB + hand-built rootfs cpio 6.9MB,
verified transfers), but the kernel silently panics — no root, no network, and
without UART there is no panic visibility. Symptom: the Pi netboot-fetches in
a ~5-minute loop forever, never reaching the network. To RAM-netboot OpenWrt
the supported path is a buildroot build with `CONFIG_TARGET_ROOTFS_INITRAMFS=y`
(single kernel file, rootfs embedded — see netboot-full-os.md); booting stock
factory images from USB media remains the fallback.

## dropbear 2025.89 (OpenWrt 25.12): authorized_keys path and directory perms

Verified 2026-10-10 on RAM-netbooted OpenWrt 25.12.5 (dropbear 2025.89):

- The home-path `~/.ssh/authorized_keys` is REFUSED for key auth (silent
  rejection at the key-query phase; dropbear log shows no reason). The
  `/etc/dropbear/authorized_keys` path works.
- `/etc/dropbear` itself must be mode 700 (755 tripped
  "/etc/dropbear must be owned by user or root, and not writable by group or
  others" — the check is stricter than the message suggests). Files inside
  must be 600 root:root.
- Files injected via the buildroot `files/` overlay inherit the build user's
  umask (dirs 775, owned by the build user; fakeroot fixes ownership but NOT
  mode bits) — enforce modes with an `uci-defaults` script baked into the
  image, e.g. `chmod 700 /etc/dropbear; chmod 600 /etc/dropbear/authorized_keys`.
- RAM-booted systems regenerate host keys every boot → known_hosts churn for
  every client. Bake static host keys into the image (files/etc/dropbear/
  dropbear_*_host_key, extracted from a running instance) to keep SSH clients
  stable across reboots.
