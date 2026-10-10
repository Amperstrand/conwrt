# Raspberry Pi: netboot a full OS (RAM-only, factory-fresh every boot)

Verified end to end on a Pi 4B with OpenWrt 25.12.5 (kernel 6.12.94): the Pi
boots a complete OpenWrt with SSH and any baked-in services over pure TFTP in
~90 s from power-on, with no SD card or USB disk. Every boot is factory
state — the ideal test-router property.

This recipe assumes the rescue server basics from
[netboot-rescue.md](netboot-rescue.md) (arm/disarm, TFTP root, MAC allowlist).

## The kernel must match the boot style

An OpenWrt release kernel CAN load an external initrd
(`CONFIG_BLK_DEV_INITRD=y` is in the generic config) — the reason bcm27xx
ships no initramfs images is only that the target never wired up the image
generation, NOT missing kernel support. Two ways to RAM-boot a full OS:

1. **Hand-built cpio passed as a separate initramfs file** — possible but
   fragile: the release kernel + firmware hand-off gives no feedback without
   UART, and our 24.10.8 attempt died silently post-fetch. Debugging blind
   on 5-minute boot cycles is a bad trade.
2. **Buildroot with `CONFIG_TARGET_ROOTFS_INITRAMFS=y`** (recommended) — the
   build system assembles the rootfs the same way it does for every other
   target and embeds it in the kernel binary. Single file, known-good.

A full buildroot build takes ~22 min on 16 cores; rebuilds after `files/`
overlay changes take ~5 min (kernel objects are cached, only the image
relinks).

## Build

```bash
git clone --depth 1 --branch v25.12.5 https://github.com/openwrt/openwrt.git
cd openwrt
cat > .config <<'EOF'
CONFIG_TARGET_bcm27xx=y
CONFIG_TARGET_bcm27xx_bcm2711=y
CONFIG_TARGET_bcm27xx_bcm2711_DEVICE_rpi-4=y
CONFIG_TARGET_ROOTFS_INITRAMFS=y
EOF
make defconfig

# Generate the files/ overlay (network/dropbear/perms — see pi_overlay.py)
python3 scripts/pi_overlay.py init --output ~/pi-overlay \
    --authorized-key ~/.ssh/id_ed25519.pub \
    [--root-password <bench password>] [--host-key-dir <dir with dropbear keys>]
cp -r ~/pi-overlay/* files/

make -j$(nproc)
# artifact: bin/targets/bcm27xx/bcm2711/*-rpi-4-initramfs-kernel.bin
# matching DTB: build_dir/target-aarch64_cortex-a72_musl/linux-bcm27xx_bcm2711/image-bcm2711-rpi-4-b.dtb
```

What the overlay fixes (each line is a lesson from a failed boot):

- `etc/config/network` — eth0 as a DHCP **client** (uci name `lan` so the
  stock firewall's lan zone accepts inbound SSH). Stock boots 192.168.1.1
  static and DHCP-servers on your bench LAN.
- `etc/config/dhcp` — dnsmasq DNS-only, no pools.
- `etc/dropbear/authorized_keys` + `root/.ssh/authorized_keys` — dropbear
  2025.89 (OpenWrt 25.12) REFUSES the home path for key auth; older dropbear
  uses it. Bake both.
- `etc/uci-defaults/98-conwrt-perms` — the files/ copy preserves the build
  user's umask (775 dirs); dropbear rejects group-writable paths even
  root-owned. The script re-tightens modes at every boot (initramfs boots
  are always "first boot").
- `etc/dropbear/dropbear_*_host_key` — static host keys stop known_hosts
  churn across RAM reboots (extract from a running instance once).

## Deploy

```bash
python3 scripts/pi_netboot.py deploy --router <router-ip> \
    --kernel bin/targets/bcm27xx/bcm2711/*-rpi-4-initramfs-kernel.bin \
    --dtb build_dir/.../image-bcm2711-rpi-4-b.dtb \
    --mac <pi MAC> --ip <pinned lease IP> \
    --firmware-dir <dir with start4.elf + fixup4.dat>
```

The bootloader also fetches `start4.elf` and `fixup4.dat` over TFTP before
the kernel — once per TFTP root. Extract them from any OpenWrt bcm27xx
factory image's boot partition. `deploy` writes `config.txt`
(single `kernel=` line — no `initramfs` directive, the rootfs is embedded)
and `cmdline.txt`, and arms the dnsmasq block if needed.

Power-cycle the Pi. Kernel fetch appears in `logread | grep tftp` on the
router (first TFTP attempt often gets early-terminated by the firmware; the
retry completes). SSH lands ~90 s after power-on at the pinned IP.

## Test-rig usage pattern

A RAM-booted Pi is a disposable physical OpenWrt router: every session starts
factory-clean, tests deploy what they need over SSH, a reboot is the factory
reset. Anything installed at runtime vanishes on reboot by design — bake it
into the overlay (`files/usr/bin/...`, init scripts, uci-defaults) when it
must survive.

## Undo

`pi_netboot.py disarm --purge` removes the dnsmasq block and TFTP tree; the
Pi falls through to its next boot medium (USB/SD).
