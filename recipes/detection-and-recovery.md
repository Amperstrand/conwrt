# Detection & recovery patterns for dark OpenWrt devices (no serial required)

> Species knowledge distilled 2026-10-20 from a live fleet recovery
> (WS-AP3915i class). All patterns are model-agnostic unless noted.
> Bench-specific facts (IPs, MACs, ports) deliberately NOT included —
> they live in the private bench registry.

## Truth 0: "dark" is a hypothesis, not a state

A device that answers no ping has exactly one proven property: it does
not answer ping. Before reaching for serial, classify WHY it is dark.
Every technique below has produced a door on real hardware without
opening a case.

## 1. Power-draw classification (PoE switches)

Read per-port draw before anything else:

- Stock Zyxel V2.90: `cmd=773` re-polls are the ONLY truth (775 lies;
  see tollgate_lab zyxel_stock). SSH CLI swallows non-interactive output.
- OpenWrt + realtek-poe: `ubus call poe info`.

Interpretation table (watts are device-class specific — record your
fleet's signatures):

| Draw | Meaning | Action |
|---|---|---|
| 0 mW | unpowered / port off | fix power first |
| flat low (e.g. 3.4W on AP3915i) | "stalled" OR booted-into-low-power-OS | do NOT assume brick — capture boot (§3) |
| normal typical | OS booted | go find its L3 identity (§2, §4) |

## 2. L2-adjacent probing (the routed-probe blind spot)

Routed probes (ping from your host) CANNOT see a device whose static
sits on a subnet nobody routes. Fix: alias the device's SUSPECTED subnet
onto the L3 interface that shares its L2, then ping/ARP and match by MAC:

```
ip addr add <suspected-subnet>.2/24 dev <l2-adjacent-iface>
ping -c3 -I <alias> <suspected-static>
ip neigh show dev <l2-adjacent-iface>   # match the reply MAC, not just IP
```

Suspected subnets to try, in order: the last static in the device's
record; the OpenWrt default LAN (192.168.0.0/24 family); stock defaults
(192.168.1.0/24 family); any legacy bench subnet the device once used.
Match the ANSWERING MAC against the device's known MAC — an IP answer
without a MAC match is someone else.

## 3. Boot-capture classification (tcpdump on the seat)

Put the unit on an isolated VLAN with an SVI, start tcpdump on the SVI,
power-cycle once. A ~40-120s capture classifies the unit:

- **IPv6 DAD + MLD + Router-Solicitation from the unit's MAC** (typically
  30-60s after power-on): LINUX KERNEL IS UP. The device is not a brick;
  its problem is L3 config. Go to §2/§4.
- **v4 ARP `who-has <gw> tell <static>`**: userspace up, static config.
  The <static> value is your next §2 probe target; <gw> tells you which
  subnet it thinks it lives in.
- **UDP broadcast from 192.168.1.1 shortly after boot**: portal-style
  config announcing itself (product-specific beacon).
- **Zero frames across a cold boot**: pre-kernel class. Serial is the
  only remaining door. (On boot-roulette devices, repeat 2-3x before
  concluding — some units alternate working/dead boots.)

## 4. Door creation by DHCP (for DHCP-configured lineages)

Run a DHCP server on the seat SVI (dnsmasq), MAC-pinned to a
deterministic address. If the device's config has a DHCP client, it
takes the lease on its next retry/boot — no hands. If a capture shows it
never DISCOVERs, its wired interface has no client (config bug class:
portal-bridging rewires) — fix via console or reflash.

## 5. Stock-fallback boot class (dual-image devices)

Devices flashed via the two-stage method keep vendor firmware on NAND.
If the primary boot chain (U-Boot env → OpenWrt partition) is damaged,
the BACKUP bootloader silently boots the STOCK firmware, which:
- is network-invisible on your lab subnets (its own default world),
- may emit a `login:`/`password:` spray with timeout lines on serial,
- may REBOOT PERIODICALLY without a controller.

Consequence: the U-Boot `boot_net` TFTP-rescue DOES NOT FIRE in this
class (the backup env lacks the fallback). Do not spend cycles arming
TFTP servers for a stock-fallback unit — detect it via §3 + serial, then
repair `bootcmd` (`run boot_openwrt; run boot_net`) from the stock
console using the vendor-default credentials documented in the model.

## 6. Serial-splice probing without a USB adapter (device-to-device)

One healthy unit can host the console of a dark sibling (null-modem,
TX↔RX crossed, GND common, NEVER VCC — both units self-powered):

- **RX validation**: reader on the host's UART; power-cycle the target;
  any bootloader output within seconds proves the target→host direction.
- **TX validation (round-trip)**: echo everything received straight back
  out the host's TX during the target's boot. If the target's own boot
  banner interrupts its U-Boot autoboot countdown ("Hit any key"), TX
  works and you are effectively at a prompt.
- **Marker test**: send a unique string at a login prompt; absence of
  echo/reaction is WEAK evidence only (prompts may not echo).
- **Instrumentation illusions**: a `BusyBox vN.N multi-call binary`
  "banner" is nc's USAGE ERROR (unsupported option, e.g. %zone on some
  builds) — not a listener. Always validate a relay path with a known
  source before trusting its output.

## 7. Virgin stock unit onboarding (no serial)

Seat the unit on an ISOLATED VLAN whose SVI shares the vendor-default
subnet (e.g. 192.168.1.x). Probe the defaults; if the vendor web/SSH
answers with documented default credentials, the standard two-stage
flash (SSH → rdwr_boot_cfg → TFTP initramfs → sysupgrade) onboards it
without ever opening the case. Keep the seat isolated until the first
OpenWrt boot — stock images may run their own DHCP server.

## 8. Infrastructure-switch wedge class (bench switch as a DUT)

A PoE switch running a vendor-fork daemon can wedge its CONTROL PLANE
while its forwarding ASIC and PoE MCU keep working autonomously. Seen on
GS1900-8HP A1 (OpenWrt + realtek-poe fork), three times in one session:

- **Trigger pattern**: bursts of PoE-daemon activity — service restarts
  and rapid `set_port_config` toggle sequences. Death follows within
  minutes; single spaced toggles are usually tolerated.
- **Signature** (diagnostic gold): a powered DUT behind the switch still
  answers while the switch's own management IP does not. Brain dead,
  spine alive.
- **Recovery**: power cycle. Config survives; all PoE DUTs cold-cycle —
  make every DUT self-healing (init-enabled services) so a switch
  recovery costs nothing but time.
- **Discipline**: batch PoE changes, one restart maximum, never burst;
  keep the serial console physically attached and VERIFIED (see below);
  run the liveness watch OFF the switch — an on-box guard cannot fire
  when the whole CPU plane hangs.
- **Console wiring rule**: a console silent with TX/RX swapped in both
  directions usually means GND is missing. Verify by watching a full
  boot BEFORE the day you need it; a wedge produces no console output
  after the hang, so capture the boot that leads INTO it.

### 8. L3-offload wedge: overlapping subnets kill the stack (kernel alive)

Root-caused 2026-10-20 on GS1900-8HP (OpenWrt snapshot r33051, kernel
6.12.94): adding a subnet that OVERLAPS an already-routed prefix — e.g.
`ip addr add 192.168.13.2/24 dev switch.1008` while 192.168.13.0/24 is
routed elsewhere — wedges the whole network stack within seconds
(openwrt/openwrt#26061). The earlier "PoE activity bursts" trigger theory
for pattern 7 is RETIRED: the PoE daemon is exonerated (healthy counters
through the kill); every incident coincided with netdev/L3 config events.

- **Signature upgrade**: "brain dead, spine alive" splits further —
  kernel-alive (printk keeps flowing, timers run, PHY polling continues,
  console input echoes briefly) vs network-dead (ICMP/SSH/ubus). Serial
  console is the discriminator; keep a timestamped journal running.
- **Prevention**: never re-use a routed subnet on a second SVI/alias.
  Guard tooling belongs at the operator layer (preflight before any
  SVI add: lab prefix inventory + live addr/route/neigh tables).
- **Recovery**: power cycle only — even WITH the internal watchdog armed.
  Tested 2026-10-20 23:51Z on a custom image with CONFIG_REALTEK_OTTO_WDT=y
  (driver bound, procd feeding, both verified): the wedge left the kernel
  alive (printk/timers continued 16+ min) yet the watchdog NEVER fired.
  Internal WDT is insufficient for this class; MAGIC_SYSRQ over serial also
  did not respond during the wedge. The working mitigations: preflight
  overlap guards (avoidance) — and note the vendor does NOT have a secret
  watchdog either: the V2.90 GPL drop shows GS1900 stock ships with
  CONFIG_WATCHDOG unset and no WDT board code at all; stock simply lacks
  the DSA L3-offload path that deadlocks. An external GPIO watchdog would
  be new hardware, not a config flip. Evidence: openwrt/openwrt#26061.

### 9. MCU crash survives soft reboots (PoE manager class)

GS1900-8HP: a crashed PoE management MCU (UART silent, ports down,
daemon spins "No response / Trying a reset" every 30 s) does NOT
recover from a warm reboot — the PoE domain is not reset by REBOOT.
Only a full power cycle restores it (clean handshake on cold boot).
Detection: `replies_ok` frozen at 0 with `no_response` incrementing in
lockstep with `resyncs` in the daemon's mcu_comm counters. One
"request-bad-checksum" exchange ~9 s after a COLD boot is benign MCU
reset noise, not a fault.
