# Hardware Discovery Log

Findings from the 2026-05-24 hardware testing session on the GS1900-8HP switch rack.

## Port Mapping (Verified 2026-05-24)

Empirically verified on GS1900-8HP A1 running OpenWrt. The relationship between
OpenWrt interface names and the physical Realtek switch port names is:

```
lanN = phys_port_name p(7+N)
```

| Interface | Phys Port | Connected To | IP | Status |
|-----------|-----------|--------------|----|--------|
| lan1 | p8 | Server enp5s0 | 192.168.1.2 | Uplink |
| lan2 | p9 | AP3915i #2 | 192.168.13.254 | OpenWrt 24.10.2 (flashed) |
| lan3 | p10 | (empty) | | |
| lan4 | p11 | (empty) | | |
| lan5 | p12 | AP3915i #1 | 192.168.13.253 | OpenWrt 24.10.2 |
| lan6 | p13 | (empty) | | |
| lan7 | p14 | (empty) | | |
| lan8 | p15 | Stock switch | 192.168.13.3 | Blocked (unknown password) |

Verification command: `cat /sys/class/net/lanN/phys_port_name`

---

## AP3915i #1 -- lan5 (Already OpenWrt)

- MAC: B4:2D:56:25:47:A2
- IP: 192.168.13.253 (or 192.168.1.1 if on flash subnet)
- Status: OpenWrt 24.10.2, SSH key auth (rejects our key)
- PoE: ~4.9W on lan5
- Flashed via switch-initiated workflow (see tested_hardware in model JSON)

This was the second unit to be flashed successfully. Full flash log in
`SESSION-WRITEUP.md` and `SWITCH-FLASH-PLAN.md`.

---

## AP3915i #2 -- lan2 (OpenWrt 24.10.2, FLASH COMPLETE)

- MAC: B4:2D:56:25:86:BD
- IP: 192.168.13.254 (management subnet)
- Status: OpenWrt 24.10.2 (r28739-d9340319c6), running from flash
- PoE: ~5.4W on lan2
- SSH: password "conwrt", server ed25519 key installed
- DHCP: disabled on both lan and wan

### Flash history (2026-05-24)

1. Stock SSH → `rdwr_boot_cfg` broken (flag byte 0x05 vs expected 0x01)
2. Used `flashcp` fallback to write modified CFG1 with `bootcmd=run boot_net`
3. TFTP-booted OpenWrt initramfs from switch
4. `sysupgrade -n -f` with DHCP-disabled overlay
5. Installed kmod-mtd-rw → wrote permanent CFG1 with `bootcmd=run boot_openwrt; run boot_net`
6. Verified flash boot (no TFTP request on reboot)
7. Post-flash: SSH key → password → IP change to 192.168.13.254

### Stock firmware notes (pre-flash)

- Stock IP was 192.168.13.161 (DHCP from switch)
- Stock credentials: admin/new2day
- `rdwr_boot_cfg` EXISTS but BROKEN — `read_all` works but writes fail due to
  flag byte 0x05 (expects 0x01). Used flashcp fallback instead.
- Stock SSH requires legacy algorithms: `-oHostKeyAlgorithms=+ssh-rsa -oKexAlgorithms=+diffie-hellman-group1-sha1`

---

## AP3915i #3 -- lan8 (Behind stock switch, UNREACHABLE)

- MAC: B4:2D:56:25:4D:7E
- Connected via stock V2.90 GS1900-8HP on lan8
- Cannot reach from the OpenWrt switch (different L2 domain behind stock switch)
- Cannot control PoE remotely
- Cannot flash without either stock switch access or direct physical connection

To reach this AP, we would need to:

1. Factory reset the stock switch (physical button hold) to regain access
2. Or unplug AP3915i #3 from the stock switch and connect it directly to an
   OpenWrt switch port

---

## Stock Switch -- 192.168.13.3 (BLOCKED)

- MAC: 4C:9E:FF:F5:AC:D2
- Zyxel GS1900-8HP A1 running V2.90 firmware
- Password unknown -- likely set by the buggy `zyxel_encode_password` function
  (see `scripts/conwrt.py` oem_handlers.py fix)
- Requires physical factory reset (hold reset button 10+ seconds) to regain access
- Blocks all access to AP3915i #3

This is the same model GS1900-8HP as our OpenWrt switch but running stock firmware.
The stock ZyXEL web UI requires HTTP, not HTTPS. Default credentials would be
admin/password but this unit has been reconfigured.

---

## Network Topology

```
Server (Ubuntu)
  enp5s0: 192.168.1.2 (wired to OpenWrt switch lan1)
  wlp4s0: 192.168.13.218 (WiFi management link)
  |
  +-- OpenWrt GS1900-8HP (192.168.13.2)
       |
       +-- lan1 (p8) -- Server enp5s0
        +-- lan2 (p9) -- AP3915i #2 (192.168.13.254, OpenWrt 24.10.2) [FLASHED]
       +-- lan5 (p12) -- AP3915i #1 (192.168.13.253, OpenWrt 24.10.2)
       +-- lan8 (p15) -- Stock switch (192.168.13.3, password unknown)
                            |
                            +-- AP3915i #3 (unreachable, stock firmware)
```

The OpenWrt switch's br-lan bridges all ports on the same L2 segment. The server
has two paths: wired (192.168.1.2) and WiFi (192.168.13.218). The WiFi path is
on the 192.168.13.0/24 subnet alongside the switch and all switch-connected devices.

---

## conwrt-lite E2E Flash Plan for AP3915i #2

This is the sequence conwrt-lite needs to execute for a fully automated flash of
AP3915i #2 from the OpenWrt switch, with no human interaction.

### Step 1: Stock SSH preflight

Connect to stock WiNG firmware via SSH with legacy crypto options. Run:

- `rdwr_boot_cfg read_all` -- backup current U-Boot environment
- `cset sshtimeout 0 && capply && csave` -- disable SSH timeout so session
  doesn't drop during the flash
- `rdwr_boot_cfg write_var serverip=<TFTP_SERVER_IP>`
- `rdwr_boot_cfg write_var ipaddr=<TEMP_AP_IP>`
- `rdwr_boot_cfg write_var bootcmd=run boot_net`

### Step 2: Reboot

Either `reboot` command via SSH or PoE power cycle on lan2.

### Step 3: TFTP serve initramfs

Start TFTP server on the OpenWrt switch (dnsmasq or atftpd) serving the initramfs
file as `vmlinux.gz.uImage.3912` on the appropriate subnet. The AP's U-Boot will
request this file via TFTP after the DHCP+boot sequence.

### Step 4: Wait for SSH (initramfs booted)

Poll for SSH on the AP's expected IP. The initramfs boots as root@192.168.1.1
(OpenWrt default) or whatever ipaddr was set in the U-Boot vars.

### Step 5: MTD backup

Back up critical partitions from the initramfs: ART (radio calibration, irreplaceable)
and CFG1/CFG2 (U-Boot environment).

### Step 6: Generate overlay tarball

Create an overlay tarball that disables DHCP on first boot. This prevents the newly
flashed OpenWrt from becoming a rogue DHCP server on the LAN. See "Post-Flash DHCP
Isolation Strategy" below.

### Step 7: Sysupgrade with overlay

```bash
sysupgrade -n -f /tmp/overlay.tar.gz /tmp/firmware.bin
```

The `-n` flag forces a clean flash (no config preservation). The `-f` flag
applies the overlay tarball.

### Step 8: Wait for SSH (permanent OpenWrt)

Poll for SSH after reboot. The AP should now be running permanent OpenWrt from
SPI-NOR flash with DHCP disabled.

### Step 9: Post-flash configuration

- Install SSH authorized keys
- Set root password
- Change IP address from 192.168.1.1 to a known address on the management subnet
- Re-enable DHCP if desired

---

## Post-Flash DHCP Isolation Strategy

### The problem

Newly flashed OpenWrt defaults to 192.168.1.1 with DHCP server enabled on the
LAN interface. On a shared L2 segment (which is exactly what our switch rack is),
this means the freshly flashed AP immediately starts handing out 192.168.1.x leases
to anything that asks. That can break connectivity for every other device on the
segment during the brief window between reboot and post-flash SSH configuration.

### The solution

Pass an overlay tarball via `sysupgrade -n -f /tmp/overlay.tar.gz /tmp/firmware.bin`.
The overlay contains a modified `etc/config/dhcp` that disables the DHCP server on
both lan and wan interfaces:

```
config dhcp 'lan'
    option interface 'lan'
    option ignore '1'

config dhcp 'wan'
    option interface 'wan'
    option ignore '1'
```

This prevents any rogue DHCP leases before we get SSH access to reconfigure the
device properly.

### Implementation

Shell implementation lives in `lib/overlay.sh`, mirroring the existing Python
implementation in `scripts/overlay.py`. The shell version is needed because the
OpenWrt switch may not have Python installed.

---

## conwrt-lite Improvements Needed for E2E Workflow

These are gaps identified during the hardware testing session that conwrt-lite
needs to address for a fully automated end-to-end flash:

1. **Legacy SSH support**: The stock Extreme WiNG firmware requires
   `-oHostKeyAlgorithms=+ssh-rsa -oKexAlgorithms=+diffie-hellman-group1-sha1`.
   conwrt-lite's SSH module must accept arbitrary SSH options for stock firmware
   communication.

2. **Two-phase SSH**: The flash requires SSH to stock firmware (step 1) and then
   SSH to OpenWrt initramfs (step 4). These are fundamentally different SSH
   targets with different credentials, algorithms, and behaviors. The automation
   must handle both phases.

3. **Overlay tarball generation**: conwrt-lite needs a built-in mechanism to
   generate DHCP-disabling overlay tarballs. The Python `overlay.py` exists but
   needs a shell equivalent for switch-side execution, and the conwrt-lite
   orchestration layer needs to know when and how to use it.

4. **Multi-subnet TFTP**: The TFTP server must serve on the correct subnet.
   Currently the OpenWrt switch has br-lan on 192.168.1.0/24 (wired) and a WiFi
   interface on 192.168.13.0/24. The TFTP server must listen on the subnet the
   AP will be on after U-Boot sets its ipaddr.

5. **rdwr_boot_cfg integration**: When `rdwr_boot_cfg` is available (as it is on
   AP3915i #2), conwrt-lite should use it instead of raw MTD writes. When it's
   broken (as on Unit 1), fall back to flashcp. The flash method already documents
   both paths but the automation needs to detect and choose at runtime.

6. **Boot timing awareness**: The AP takes ~90 seconds to become SSH-accessible
   after PoE link-up. The SSH polling logic needs generous timeouts and retry
   intervals that account for this. Polling too aggressively wastes resources;
   polling too loosely adds unnecessary delay.

7. **PoE power control**: The OpenWrt switch has per-port PoE control via the
   realtek-poe package. conwrt-lite should be able to power cycle a target port
   as a recovery mechanism (kill power, wait, restore power, wait for boot).
