# Ubuntu Server on a Raspberry Pi (headless, disk-boot)

Goal: Ubuntu Server (or any raspi-flavored OS) booting natively from a large
USB/SD medium attached to the Pi, provisioned entirely over the network.
Validated on a Pi 4 + 1TB USB HDD with Ubuntu Server 26.04.1 arm64+raspi
(2026-10-08).

## Image

Canonical source (note the `/ubuntu/` path segment):

```
https://cdimage.ubuntu.com/ubuntu/releases/<ver>/release/ubuntu-<ver>-preinstalled-server-arm64+raspi.img.xz
https://cdimage.ubuntu.com/ubuntu/releases/<ver>/release/SHA256SUMS
```

Always verify the sha256 against `SHA256SUMS`. The preinstalled image layout:
p1 = FAT boot (`system-boot`, holds config.txt + firmware + cloud-init files),
p2 = ext4 rootfs (grows to fill the disk on first boot).

## Provision onto a Pi-attached disk

If the Pi can SSH (normal OS or future rescue-with-sshd):

```bash
python3 scripts/pi_image.py provision --host <pi-ip> --device /dev/sda \
    --image ubuntu-26.04.1-preinstalled-server-arm64+raspi.img.xz \
    --sha256 <hash> --hostname pi4 --user ubuntu \
    --ssh-key ~/.ssh/id_ed25519.pub \
    --expect-mac dc:a6:32:xx:xx:xx
```

`--expect-mac` (or `--expect-serial`) is mandatory — provision refuses to
write without one. Read the specimen's MAC live from the running Pi
(`ssh root@<pi-ip> 'cat /sys/class/net/eth0/address'`, any interface listed
by `/sys/class/net/*/address`), or take the serial from `/proc/cpuinfo`
(`Serial:` line) / the unit's label — never from a guess or a port number.

If the Pi is in the netboot rescue shell (busybox + telnetd, no sshd), the
same steps run manually over telnet — this is what was actually done
(2026-10-08):

1. **Direction of transfer matters.** AP-side client isolation can block
   Pi-initiated connections to a WiFi workstation while the workstation can
   still connect OUT to the Pi. Have the Pi listen:
   ```bash
   # rescue shell
   setsid sh -c 'nc -l -p 9999 > /tmp/u.img.xz' < /dev/null > /tmp/dl.log 2>&1 &
   # workstation
   nc 192.168.13.240 9999 < ubuntu-image.img.xz     # or python socket sender
   ```
2. Verify: `stat -c %s` matches, `sha256sum` matches SHA256SUMS.
3. Write: `xzcat /tmp/u.img.xz | dd of=/dev/sda bs=4M && sync`
4. Re-read partitions: `blockdev --rereadpt /dev/sda; mdev -s`
5. Inject cloud-init (the rescue kernel has vfat built in):
   ```bash
   mkdir -p /mnt && mount -t vfat /dev/sda1 /mnt
   cat > /mnt/user-data <<'EOF'
   #cloud-config
   hostname: pi4
   manage_etc_hosts: true
   users:
     - name: ubuntu
       groups: [adm, sudo]
       shell: /bin/bash
       sudo: ALL=(ALL) NOPASSWD:ALL
       lock_passwd: true
       ssh_authorized_keys:
         - <your public key>
   ssh_pwauth: false
   chpasswd:
     expire: false
   EOF
   printf 'instance-id: pi4-ubuntu-001\nlocal-hostname: pi4\n' > /mnt/meta-data
   printf 'version: 2\nethernets:\n  eth0:\n    dhcp4: true\n    optional: true\n' \
       > /mnt/network-config
   sync && umount /mnt
   ```

## Boot it

- If BOOT_ORDER reaches USB before network: reboot and it boots from the disk.
- If the policy is network-first (see `eeprom-and-security.md`), DISARM the
  rescue server first — the Pi tries the netboot pass, finds nothing, and
  fails over to the disk. ARM the server again whenever rescue is wanted.

First boot takes a few minutes: cloud-init grows the rootfs to fill the disk
(several GB-class disks take a while), creates the user, applies the hostname.
Watch the DHCP lease hostname flip (`ubuntu` at DHCP time, `pi4` from
cloud-init), then `ssh ubuntu@<pi-ip>`.

## Gotchas

- **VIA Labs VL711 (2109:0711) bridge corrupts data on Pi 4 even in
  usb-storage mode** (2026-10-08 incident): a 1TB SATA SSD behind a VL711
  bridge produced ext4 `EBADMSG` on a freshly dd'd + sha256-verified image —
  on BOTH USB2 and USB3 ports, with the kernel's built-in quirk (2000000)
  applied and the `usb-storage` driver (not UAS). The same SSD's vfat boot
  partition wrote and read back fine (small files); the corruption appeared
  after the multi-GB rootfs write. The Pi's RAM was exonerated (memtester
  1200MB, 2 loops, 19 patterns, zero failures). Community consensus points
  the same way: JMicron and VIA Labs bridges are the problem children on
  Pi hardware; **ASMedia ASM1153E-class adapters are the go-to** (StarTech
  USB312SAT3CB, Ugreen, Ennotek, Neeyer). Bridge chipsets also change
  without a part-number change — verify with `lsusb` after purchase.
- **UAS warm-reboot silent corruption**: documented against JMS578-based
  USB-SATA bridges (LKML, 2026-09): after a *warm* reboot with the enclosure
  still powered, the UAS driver returns reproducibly wrong data with **no
  I/O errors** — which presents as ext4 `Bad message`/`EBADMSG` on a
  freshly-written image. Power-cycling the enclosure (or the whole Pi)
  restores correct reads. Permanent fix: disable UAS for the bridge — get
  the VID:PID from `lsusb`/`dmesg` and prepend to the OS's `cmdline.txt`:
  `usb-storage.quirks=152d:0578:u` (example). The same symptom cluster
  (writes corrupt after heavy load, clean after cold boot) is also caused by
  marginal PSU/cable on USB3 — check `vcgencmd get_throttled` for undervoltage
  bits and try a shorter/shielded cable or the other USB3 port before
  condemning hardware.
- The DHCP hostname is whatever the client announces — Ubuntu announces its
  image-default `ubuntu` before cloud-init renames it. Do not confuse the two
  boot generations when the same MAC boots different media.
- A bus-powered 2.5in HDD can brown out a weak Pi PSU mid-transfer: symptoms
  are hangs, TCP resets, stale ARP with no DHCP churn. Use externally powered
  disks.
- If port 22 stays closed after first boot completes, ssh may not be enabled
  in that image — enable it from the rescue shell by symlinking
  `ssh.service` into `multi-user.target.wants` in the disk's rootfs, or bake
  the `runcmd` from `scripts/pi_image.py` into user-data (it does this by
  default).
