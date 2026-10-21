# No-Serial Flash — VALIDATED Recipe (2026-09-21, lan4 unit, OpenWrt 24.10.2)

This is the step-by-step that produced a self-booting OpenWrt 24.10.2 AP3915i from
stock firmware with zero serial involvement. Follow it exactly; the details are
load-bearing (see RETROSPECTIVE for the failure modes that taught them).

## Prerequisites (on the GS1900-8HP switch)

```bash
# 1. VLAN L3 for the target port (lanN -> VLAN 100N), switch IP 192.168.1.2
ip link add switch.100N link switch type vlan id 100N   # if missing
ip link set switch.100N up
ip addr add 192.168.1.2/24 dev switch.100N              # if missing

# 2. FIREWALL: runtime VLANs are unzoned - without this, TFTP/DHCP servers
#    on these VLANs silently never receive anything (fw4 drops inbound UDP):
nft insert rule inet fw4 input iifname "switch.10*" accept

# 3. Per-port dnsmasq (DHCP + TFTP). NOTE: /etc/init.d/dnsmasq stop first or
#    the system dnsmasq (procd-respawned) conflicts on ports.
mkdir -p /tmp/tftprootN
# put openwrt-24.10.2-...-initramfs-uImage.itb there AS vmlinux.gz.uImage.3912
dnsmasq -p 0 --no-resolv -i switch.100N \
  --dhcp-range=192.168.1.100,192.168.1.150,255.255.255.0,30m \
  --enable-tftp --tftp-root=/tmp/tftprootN \
  --log-dhcp --log-facility=/tmp/dnN.log --pid-file=/tmp/dnN.pid
```

Watch /tmp space (tmpfs ~58MB): one initramfs copy per tftproot only; delete
duplicate names nothing fetches.

## Recipe

### 1. Catch the stock unit + backup
Stock WiNG APs: DHCP client, fall back to 192.168.1.20. Find via dnsmasq log /
ARP. SSH (through the switch as jump):

```bash
ssh -J root@<switch> -o HostKeyAlgorithms=+ssh-rsa \
    -o KexAlgorithms=+diffie-hellman-group1-sha1 admin@<unit-ip>   # pw: new2day
```

Backup: `dd if=/dev/mtd1 bs=64k | gzip > /tmp/cfg1.orig.gz` (+ mtd10/CFG2),
and capture env text: `dd if=/dev/mtd1 bs=64k | tr "\000" "\n" | grep = | grep -v mfg_ | sort`.

### 2. Build flash-phase CFG1 block
From the captured env, modify ONLY: `bootcmd=run boot_net`, `serverip=192.168.1.2`,
`ipaddr=192.168.1.1`, `WATCHDOG_COUNT=0`, `WATCHDOG_LIMIT=0`, `AP_MODE=0`,
`MOSTRECENTKERNEL=0`, `AP_PERSONALITY=identifi`, add
`boot_openwrt=sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000`,
strip `ubi.mtd=0` from bootargs + static_bootargs. Keep everything else.

Block format: CRC32-LE over bytes[5:] | byte4=0x01 | null-separated KEY=VALUE |
0xFF pad to 65536. Builder: see session logs or rebuild per cfg_block_format
in the model JSON.

### 3. Transfer + write (GATES at every step)
```bash
cd /tmp; tftp -g -r cfg_flash.bin 192.168.1.2     # needs firewall rule above
md5sum cfg_flash.bin                               # GATE: match build hash
flashcp -v cfg_flash.bin /dev/mtd1                 # GATE: exit 0
dd if=/dev/mtd1 bs=64k count=1 | md5sum           # GATE: FULL-64K readback match
reboot
```
Fallback transfer if tftp unavailable: printf-octal push in ~100-byte chunks
(expect: Tcl eats `\OOO` in double-quoted sends — write `\\OOO`).

### 4. TFTP boot + sysupgrade
Unit TFTP-boots the 24.10.2 initramfs (2-3 min, HTTP at 192.168.1.1 = up).
scp sysupgrade bin (sha256 gate) → `sysupgrade -n` → reboots → TFTP-boots again.

### 5. Final env (kmod-mtd-rw)
```bash
# kmod from releases/24.10.2/targets/ipq40xx/generic/kmods/6.6.93-1-eaef302ef5ab82928154706763925f63/
opkg install --force-depends /tmp/kmod-mtd-rw_*.ipk   # initramfs: kernel pkg absent from db
insmod $(find /lib/modules -name "mtd-rw.ko") i_want_a_brick=1
mtd write /tmp/cfg_final.bin CFG1                       # GATE + full readback
reboot
```
Final env = flash-phase env with `bootcmd=run boot_openwrt; run boot_net`.

### 6. VERIFY flash boot (the only proof)
Kill the port's dnsmasq → reboot → HTTP within ~2 min = TRUE flash boot.
(U-Boot answers ping during retry loops — ping is NOT proof. HTTP/SSH is.)
Restore dnsmasq afterward (the boot_net tail is the unit's permanent safety net).

## Version rule

**Flash-boot = OpenWrt 24.10.x ONLY** (kernel 6.6). 25.12.x (kernel 6.12) boots
via tftpboot+bootm but FAILS via sf read+bootm on this U-Boot family — see
model JSON warnings. Do not flash 25.x without serial attached.
