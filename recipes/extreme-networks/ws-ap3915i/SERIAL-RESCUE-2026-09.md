# Serial Rescue Runbook — Three Stuck AP3915i Units (2026-09-21)

Three WS-AP3915i units (labels confirmed) sit on the home GS1900-8HP (192.168.13.2)
with network-dead states. This is the pilot-first rescue plan: prove the flow on one
unit, then batch the rest. Prepared 2026-09-21; all remote diagnosis already done.

## Unit status (measured 2026-09-21)

| Port | MAC | PoE idle | Boot-window behavior | Working hypothesis |
|------|-----|----------|---------------------|--------------------|
| lan5 | dc:b8:08:6c:ea:7f | 96-98 mA | IPv6 RA immediately | **Healthy** — OpenWrt 24.10.2 at 192.168.1.1 (VLAN 1005). Reference unit. Do not touch. |
| lan6 | (unknown) | 66 mA flat | **Zero frames ever**, even at fresh boot | True unknown: U-Boot stuck, or kernel panic before net init. Most diagnostic value. |
| lan7 | b4:2d:56:25:47:a2 | 98 mA flat | Kernel IPv6 DAD for ULA `fda1:c616:883d::1`, MLD — then dark | OpenWrt boots, network config broken (interfaces fail post-init) |
| lan8 | b4:2d:56:25:86:bd | 100 mA flat | Kernel IPv6 + brief IPv4 `192.168.1.1` + UDP:4919 broadcast — then dark | OpenWrt boots, network config broken. **Recommended pilot unit** (most alive). |

Ruled out by experiment: TFTP-boot rescue (bootloaders boot kernel from flash,
never touch network — verified with live bait server across power cycles);
boot-window SSH race (150 ICMPv6 attempts, zero replies).

## Preconditions

### Switch state — re-apply after any GS1900 reboot

The GS1900 rootfs overlay is READ-ONLY; these live only at runtime:

```bash
# PoE + VLAN for lan8 (staged uci; re-run after reboot):
mount -o remount,rw /            # usually fails — overlay flag; uci staging still works
uci set poe.@port[7].enable='1'   # port index for lan8; verify with: for i in 0 1 2 3 4 5 6 7 8; do echo $i $(uci get poe.@port[$i].name); done
uci add_list network.vlan1008.ports='lan8:u*'
uci commit poe; uci commit network
ubus call network reload; /etc/init.d/poe restart
```

The rescue rig (auto-recreated by `/tmp/portmap.sh` on the switch, source in
conwrt `scripts/gs1900-portmap.sh`):

- Per-port VLANs: lanN → switch.100N, switch IP 192.168.1.2 in each
- TFTP bait: dnsmasq + TFTP on ports 6/7/8 serving real 24.10.2 initramfs
  (`/tmp/tftproot/`: `vmlinux.gz.uImage.3912`, `vmlinux`, full `.itb` name)
- serverip aliases: `10.0.0.1` and `192.168.1.10` on each port VLAN
- PoE control: `ubus call poe manage '{"port":"lan8","action":"disable|enable"}'`

### Serial (from models/extreme-networks-ws-ap3915i.json — verified from live unit)

- **115200 8N1**, console `ttyMSM0`. UART pads on board, 3.3V.
- Wiring: adapter TX→device RX, RX→TX, GND→GND. **Never VCC.**
- AGENTS.md rules apply: loopback test first, no VCC, one adapter = one port.

## Pilot: lan8 unit end-to-end

1. **Clip serial to the lan8 unit**, loopback-test the adapter, wire, then:
   `python3 scripts/serial-console.py /dev/cu.XXXX --baud 115200`
2. **Power cycle from the switch** (keeps hands off PoE hot-plug):
   `ssh root@192.168.13.2 'ubus call poe manage "{\"port\":\"lan8\",\"action\":\"disable\"}"; sleep 6; ubus call poe manage "{\"port\":\"lan8\",\"action\":\"enable\"}"'`
3. **Read the boot** — branch on what appears:
   - **`root@OpenWrt:~#`** (expected): diagnose network:
     `uci show network; logread | grep -i netifd; ip -4 addr; ip link`
     Fix per findings — likely a broken device reference (see AGENTS.md
     "Initramfs DSA Port Workaround") or wrong static config. Options:
     minimal `uci` fix, or `firstboot && reboot` for a clean slate.
   - **U-Boot prompt** (possible for lan6 later): `printenv` — SAVE OUTPUT FIRST.
     Then `run boot_openwrt` (direct SPI-NOR kernel boot). If flash kernel is
     bad: `setenv serverip 192.168.1.2; setenv ipaddr 192.168.1.99; run boot_net`
     (TFTP bait already serves the initramfs). Then fix env per model JSON
     CRITICAL warnings — bootcmd = `run boot_openwrt; run boot_net`.
   - **Kernel spew then silence**: capture where it dies; may need
     `run boot_net` from U-Boot after all.
4. **Verify network**: after fix, from the switch:
   `ping -c2 -I switch.1008 192.168.1.1` then SSH with the Mac key via jump:
   `ssh -J root@192.168.13.2 root@192.168.1.1` (route-pin switch.1008 first).
5. **Record**: `python3 scripts/inventory.py add ...` with recovered state,
   then decide sysupgrade vs keep.

## Then: batch

- **lan7 unit**: same as pilot (same signature). Likely same fix.
- **lan6 unit**: treat as bootloader-class suspect; serial tells within seconds.
  If U-Boot: follow SWITCH-FLASH-PLAN.md / no-serial-openwrt.md procedures in
  this directory (they document the full flash from U-Boot).

## Why they got stuck (see AGENTS.md "U-Boot Env Writes" section)

The units date from the May-June bench era (HARDWARE-DISCOVERY.md). The bricked
history and model JSON warnings point at bootcmd/network-config mistakes during
that work. Whatever the exact fault per unit, the fix rules are now codified.

---

## Update (end of 2026-09-21): revised recovery outlook after the lan3/lan4 campaign

Ping6 methodology is now POSITIVE-CONTROL VALIDATED (healthy units answer
ff02::1 on their VLANs) - the earlier boot-window races were sound: lan7/8's
stacks genuinely go dark after the ~15s boot window. No unvalidated-probe
excuse remains.

Recovery assessment with current knowledge:

- **lan7/lan8**: OpenWrt already installed; ONLY /etc/config/network is broken.
  Serial console = root shell (no password on OpenWrt consoles) -> fix config
  or `firstboot` -> done. ~10 minutes per unit. NO reflash, NO env writes,
  NO flash risk - this is the CHEAPEST possible recovery.
- **lan6**: zero frames ever (incl. bootloader phase) - pre-kernel stall or
  worse. Serial diagnoses; if U-Boot prompt reachable, the proven
  boot_net+TFTP rig handles it from there.
- No-serial options are exhausted for all three (DHCP/ARP/ping6/boot-window
  races/bait all validated-negative; no reset button in DTS; failsafe needs
  console input; their bootcmds carry no boot_net path to bait).

One serial adapter recovers all three units AND closes the sf-read
bootloader mystery. Highest-leverage purchase on the bench.

## Race addendum (final no-serial sweep, late 2026-09-21)

Boot-window races on lan8 with validated tooling (positive controls run first):
- ICMPv6 echo to link-local, 150 attempts across window: negative
- HTTP :80 (busybox wget -T 2, ~1Hz through a fresh PoE-cycle window): negative
- TCP :22: bounded-nc attempts (busybox nc lacks -w/pgrep — job-control traps
  documented); combined with :80 negative and procd ordering, dropbear-alone-
  alive is implausible
- The UDP:4919 emitter is a CLIENT (ephemeral source port -> broadcast dest),
  not a listener: nothing to talk to
Conclusion: every network channel is validated-exhausted for lan7/8. The
config break lands before procd's service wave completes. Serial remains the
only door (10-minute console fix per unit - OpenWrt consoles are root shells).

Alternative hardware paths (same cost as serial, less coverage): SOIC8 SPI
clip + CH341A reader could dump/edit/reflash the NOR externally - viable but
strictly dominated by the FTDI adapter (which also covers lan6 + the
bootloader mystery).
