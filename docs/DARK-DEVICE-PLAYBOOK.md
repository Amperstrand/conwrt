# Dark Device Playbook — recovering unknown/unreachable bench devices

Generalized from the 2026-09-22 lan7/lan8 recovery (AP3915i units wrongly
verdict "network-dead" for 4 months) and grounded in device-fingerprinting
practice: Fingerbank/PacketFence DHCP profiling, LFP router fingerprinting
(iTTL/IPID tuples), p0f-style passive stack signals, and SecLists
default-credential methodology.

A **dark device** is anything that should be reachable but isn't: stuck on a
wrong subnet, broken L3 config, wedged daemon, or genuinely pre-boot dead.
This playbook is the ordered ladder for telling those apart WITHOUT serial,
and for getting a shell when any IP-level path exists.

## Prime directives

1. **No negative without a positive control.** Before trusting any probe's
   "no answer", prove the probe works against a known-good host through the
   same path/interface. (AGENTS.md rule 11 — born from this exact failure.)
2. **IPv4 silence is not death.** A device with a broken/wrong v4 config
   still has: ARP (kernel), IPv6 link-local (EUI-64, kernel), NDP/DAD/RA,
   and any L2-visible periodic signals. Probe v6 before declaring dead.
3. **Watch longer than the boot window.** Boot-window frames (~10s) are the
   LOUDEST signal, not the only one. RAs, MLD reports, and beacons repeat
   forever. A 2-5 minute passive listen beats a 90s race.
4. **The probe host's own subnets are sweep candidates.** The bench switch
   lived in 192.168.13.0/24 the whole time; nobody swept it. Inventory
   archaeology + probe-host interfaces + RFC1918 defaults = the sweep list.

## The ladder

Run `python3 scripts/bench_discover.py plan --mac <MAC> --iface <IFACE>
--control-ip <KNOWN-GOOD> [--probe-subnets ...]` for a generated, ordered
ladder (`run` executes layers 0-3 over SSH to the probe host).

| Layer | Hypothesis | Method | Notes |
|---|---|---|---|
| 0 | the probe works | ping known-good host via same path | abort if fails |
| 1-v6 | device is v6-alive at `fe80::<EUI-64(MAC)>` | `ping -c3 -I <iface> fe80::...` | MAC from ANY frame ever seen (tcpdump, FDB, ARP cache, switch portmap). Linux/network-gear link-locals are still EUI-64 by default |
| 1-v6 | something is on-segment | `ping ff02::1` (all-nodes) | compare responder MACs against target |
| 1-v6 | NDP history exists | `ip neigh show dev <iface>` | STALE ≠ dead; `router` flag = odhcpd running |
| 2-v4 | static address in a candidate subnet | ARP/ping sweep per subnet, read `ip neigh` | sweep order: inventory history for this MAC → probe host's own subnets → operator extras → RFC1918/common |
| 3 | services exist | banner-grab 22/80/443/2222/53 on every found address | `nc` with a hard timeout; record server strings |
| 3 | stack identity | SYN to closed port → RST iTTL/IPID/window (LFP) | iTTL table 32/64/128/255; distinguishes vendor/OS family |
| 4 | credentials | ladder below | printed by the tool, operator-executed only |

### Passive layer (during a PoE cycle)

tcpdump on the probe host's VLAN iface, NOT `-i any` (VLAN filters break on
Linux cooked capture). Watch for: ARP probes (claims), DHCP DISCOVERs, DHCP
option 55/60 (Fingerbank fingerprint), ICMPv6 DAD targets (reveals configured
ULA!), RS/RA (router role), mDNS/SSDP/LLMNR, UDP beacons, and the source MACs
of EVERYTHING (each one is a future EUI-64 address).

## Transport matrix (what reaches what)

| From | To v4 on access VLAN | To zone-scoped v6 (`fe80::...%if`) |
|---|---|---|
| Mac/Linux direct | needs route/L3 on that VLAN | `ssh user@fe80::...%en0` works ONLY if the interface is local |
| via `ssh -J probe-host` | works (pin `/32` route per target first) | **usually FAILS** — the jump's sshd can't dial zone-scoped targets |
| **from the probe host itself** | works | **works** — `dbclient -y -y root@fe80::...%switch.100X` |

The universal door: **run dbclient ON the on-link host** (bench switch), with
`DROPBEAR_PASSWORD=<pw> dbclient -y -y root@fe80::<EUI-64>%<iface> 'sh -s' <
script.sh`. Script-via-stdin beats inline quoting through multi-hop SSH.
Known trap: a stray `~/.ssh/id_ed25519.pub` containing an RSA key breaks
key auth from the Mac — verify with `ssh-keygen -lf` and use the matching
private key explicitly.

## Credential ladder (ordered priors)

1. Fleet history: every password/pattern in inventory notes, recipes, and
   past sessions (e.g. `conwrt`, `Conwrt2026!`, vendor `new2day`).
2. Defaults: root/empty (OpenWrt), admin/admin, admin/password,
   vendor-sticker words.
3. Fleet keys: try every trusted key holder on the bench (switch's, build
   server's) — key reuse across a fleet is common.
4. Generic lists only with explicit operator approval (SecLists
   `ssh-betterdefaultpasslist.txt` via `nmap --script ssh-brute` or hydra).
   Dropbear has no lockout, but rate-limit yourself and log every attempt.

Also: **try key auth before assuming passwords** — but remember dropbear
silently refuses ALL pubkey auth when `/etc/dropbear` is group-writable or
non-root-owned (image-build artifact; check `ls -ld /etc/dropbear` first when
password works but keys never do).

## DHCP: what it can and cannot do

- **Bait server** (dnsmasq offering leases per VLAN) catches only DHCP
  *clients*. Static-configured devices stay invisible — but that zero-
  DISCOVER result is itself evidence: someone configured this device, so
  prefer operator-chosen subnets in layer 2.
- **Fingerprinting**: option 55 ordering + option 60 identify the OS/device
  family (Fingerbank-style: `"1,3,6,15,..."`).
- **Option 66/67**: only useful for bootloaders that DHCP+TFTP boot
  (`boot_net`-style); flash-booting bootloaders never touch the network.

## Ruled-out classes (don't re-litigate without new evidence)

- Physical reset-button recovery: AP3915i DTS has no GPIO buttons; OpenWrt
  failsafe needs console input.
- TFTP bait for flash-booting units: proven negative (they boot from flash).
- Zero frames EVER including bootloader phase (fresh PoE cycle + tcpdump):
  genuinely pre-boot dead → serial is the only path (lan6 class).

## Tooling

- `scripts/bench_discover.py` — generates (and optionally executes) the
  ladder; includes EUI-64 derivation, inventory archaeology, subnet
  prioritization, credential-ladder generation, and the control gate.
- `scripts/gs1900-portmap.sh` — per-port identity/PoE map on the bench switch.
- `scripts/router-probe.py` — boot-state identification once an address exists.
- `prompts/bench-forensics-01-dark-device.md` — session template for a dark
  device; `prompts/bench-forensics-02-session-archaeology.md` — mining past
  agent transcripts for a device's historical IPs/credentials (the technique
  that cracked the 2026-09-22 case).
