# Provisioning: where to plug a fresh device in, and how it gets its identity

The two questions every new conwrt user hits, usually at the same moment:

1. **"The device came up at 192.168.1.1 and I can't reach it / it broke my
   network."** — a freshly flashed unit is *stock OpenWrt with defaults*:
   `br-lan` at 192.168.1.1/24 running a DHCP server and IPv6 RAs, on whatever
   segment you plugged it into.
2. **"How do I give it my settings — do I build an image per device?"** — no.
   One image per *model/profile*; identity lands on first boot. Three
   patterns below, all sharing the same uci-defaults machinery.

Everything here was exercised on 2026-11-25 against `zyxel_nr7101`
(ramips/mt7621, OpenWrt 25.12.6) unless marked hardware-gated. Species-level
NR7101 specifics: `docs/nr7101/NR7101-ZERO-TO-DATA.md` (the on-ramp).

---

## 1. Why 192.168.1.1 bites — read this before powering the unit

A fresh OpenWrt device (including the zycast stage-1 initramfs, which is
stock by construction — `docs/zycast.md` §1c) does three things on the
segment you plug it into:

- answers/serves **DHCP** on 192.168.1.0/24 and emits **IPv6 RAs**,
- sits at **192.168.1.1**,
- in stage 1, **re-arms that DHCP server on every reboot** (RAM-only image;
  nothing you change persists — `docs/gotchas.md` §"First flash runs from
  RAM").

Plug that into a port on your LAN switch and one of two things happens:

- **Your LAN is NOT 192.168.1.0/24:** your segment now has a *second* DHCP
  server and RA source. Clients that renew mid-window can get a
  192.168.1.x lease with the new device as gateway/DNS → broken WiFi and
  DNS for real users. This is the rogue-DHCP class; it has disabled real
  networks in the field (conwrt-bench incidents 2026-05-23 and 2026-09-28).
- **Your LAN IS 192.168.1.0/24** (very common — most home routers default
  there): the unit is *invisible in plain sight* (same subnet, no route to
  it) **and** it fights your router's DHCP on equal terms.

There is also a zycast-specific reason to keep the flash segment dedicated:
the bootloader's multicast listen window (NR7101: every boot, ~7 s) accepts
a reflash from **any** sender on the segment. A dedicated segment is the
unit-selection mechanism — see `docs/zycast.md` §1b (the write window) and
the receiver model notes.

**The fix is topology, not luck.** Pick one of the three below *before* you
power the unit.

## 2. Connection topologies

### T1 — Direct ethernet (one unit, zero infrastructure)

Cable your computer's ethernet port straight to the device. Nothing between.

- The device **is a DHCP server**: set your host port to DHCP and it will
  hand you a 192.168.1.x lease (or use static `192.168.1.2/24`).
- Disconnect that port from your LAN; do not put a switch in the middle.
- If the host's WiFi is on 192.168.1.0/24, same-subnet confusion follows:
  turn WiFi off on that host while flashing, or use a USB ethernet adapter.
- Do not use the machine whose *only internet* is that port — flashing
  sessions die mid-flight when their uplink vanishes. A cheap USB NIC gives
  you a dedicated port with no such risk.
- Power: the NR7101 is single-port PoE — power it with any 802.3at injector
  and "power cycle" means pulling the injector.

Good for: your first unit, rescue work, anything one-at-a-time.
Bad for: batches, and for anyone whose host networking you cannot disturb.

### T2 — A dedicated OpenWrt flash host ("the bench switch pattern, without the bench")

Any **spare** OpenWrt router or switch becomes the flashing machine — no
computer needed. The Go zycast sender is a ~3 MB static binary that runs on
OpenWrt itself (`docs/zycast.md` §3: `GOOS=linux GOARCH=mips GOMIPS=softfloat
go build ...`).

The key idea: a *spare* device's `br-lan` is a dead-end LAN — nothing
valuable shares it — so the rogue DHCP of your fresh unit lands somewhere
harmless by construction. To reach the unit at 192.168.1.1, give the flash
host a second runtime address (no config change, nothing persists):

```sh
# ON THE FLASH HOST (runtime only — clean after reboot)
ip addr add 192.168.1.2/24 dev br-lan
```

Then flash from the flash host itself (sender binds the interface with
`SO_BINDTODEVICE`, so no routing changes are needed):

```sh
/tmp/z send -i br-lan -t ras --loops 15 /tmp/fw.bin   # bounded loops; §1b discipline
```

Rules that keep this safe:

- **Do not use your only/home router as the flash host.** A dedicated
  $0-class spare (any old OpenWrt box) is the point: a mistake on it costs
  nothing; a mistake on your home router costs your internet. If the flash
  host must stay online, use its WAN port for that and keep the DUT on LAN.
- Two DHCP servers on the flash host's br-lan are harmless here — the only
  "client" class device on that segment is the DUT itself, which *serves*
  rather than requests. Nobody else is there to get a poisoned lease.
- Power control: if the flash host has managed PoE (GS1900-8HP class), the
  sender's `poe off/on` subcommand drives the cycle automatically
  (`docs/zycast.md` §5); otherwise power-cycle the DUT's injector by hand.
- If the flash host is also your bench switch with per-port VLANs, that is
  topology T3.

Good for: repeat flashing, small batches, keeping your real LAN untouched.
This is the "dedicated conwrt port" concept: one device whose whole job is
to own the 192.168.1.x segment during staging.

### T3 — Managed bench switch (per-DUT VLANs + PoE orchestration)

The lab pattern: an OpenWrt switch with PoE, one isolated VLAN per DUT bay,
the sender and the SVIs on the switch, MAC-gated power windows. Fully
documented with proven commands in `docs/zycast.md` §5-§6 (timings measured
on NR7101 + GS1900-8HP). This is what conwrt's own bench runs.

| Topology | What you need | Units per run | Your LAN is… |
|---|---|---|---|
| T1 direct | one cable, one host port | 1 | safe (point-to-point) |
| T2 flash host | one spare OpenWrt device | 1-3 (serially) | never touched |
| T3 bench switch | OpenWrt PoE switch | 1 per bay VLAN | never touched |

## 3. The three identity patterns

All three put your identity into the device through the same first-boot
mechanism (uci-defaults scripts: run on first boot, deleted on exit-0,
retried next boot on failure) and the same rogue-DHCP triple
(`dhcp.lan.ignore=1`, `ra=disabled`, `dhcpv6=disabled`). They differ in
*where the identity travels*.

### P1 — Bake-at-build: request an image with your defaults baked in (ASU)

For batches and for anyone who wants zero post-flash steps. ASU
(sysupgrade.openwrt.org) builds a per-model image on demand with your
packages and a defaults script baked in; conwrt renders that script from
your profile:

```sh
PYTHONPATH=scripts python3 scripts/firmware-manager.py \
    request --profile zyxel_nr7101 --ssh-key ~/.ssh/id_ed25519.pub
# → build enqueued → downloaded, sha256-verified, cached under images/
#   (verified 2026-11-25: 25.12.6, 7.3 MB, 47-line defaults script)
```

The default LAN-IP mode is **mac-hash**: the first-boot script derives
`10.x.y.1` from the unit's own MAC — every unit gets a unique, collision-free
address with *no per-unit images* (the pattern the whole industry converges
on). Set `lan_ip_mode = "static"` + `lan_ip` in your config for a fixed
address. `--dry-run` prints the exact payload and defaults script without
submitting.

### P2 — Boot-then-apply: stage-2 overlay at sysupgrade

For one-offs on stock images, and as stage 2 of every two-stage flash. The
overlay is a tiny tarball (`etc/config/dhcp`, a first-boot lan_ip script,
`etc/dropbear/authorized_keys`) applied atomically with the permanent image:

```sh
PYTHONPATH=scripts python3 -c "
from profile.overlay import build_overlay_tarball
print(build_overlay_tarball(disable_dhcp=True,
      authorized_keys=open('/root/.ssh/id_ed25519.pub').read().strip(),
      lan_ip='192.168.5.1'))"
scp -O /tmp/conwrt-overlay-*.tar.gz root@192.168.1.1:/tmp/
ssh root@192.168.1.1 "sysupgrade -n -f /tmp/conwrt-overlay-*.tar.gz /tmp/<sysupgrade.bin>"
```

First boot of the permanent image creates the overlay → persistence begins,
host keys stabilize, the unit answers on YOUR address with DHCP quiet.
(The `lan_ip` leg's hardware validation: issue #781; the mechanism is the
standard OpenWrt uci-defaults contract.)

### P3 — Recovery-then-apply: the two-stage flow for dark/stock/bootlooping units

When nothing can reach the box (stock firmware, unknown password, bootloop),
the flash path itself is a recovery vehicle: zycast writes a known-good
**initramfs** (boots from any flash state, RAM-only), and you finish with
P1/P2 from inside it. Full mechanics + why:
`docs/zycast.md` §1c-§1e. Until stage 2 completes, the unit is a live
grenade on any shared segment — keep it on T1/T2/T3.

Stage-1 identity (baked initramfs instead of stock) exists as
`conwrt initramfs-bake` — verified offline 2026-11-25:

```sh
PYTHONPATH=scripts python3 scripts/conwrt.py initramfs-bake \
    --model-id zyxel_nr7101 --lan-ip 192.168.7.1 \
    --hostname nr7101-demo --ssh-key ~/.ssh/id_ed25519.pub \
    --out initramfs-overlay
# → files/etc/uci-defaults/99-conwrt-identity + README-build.md (SDK recipe)
```

uci-defaults re-run on every ramdisk boot, so each stage-1 boot carries the
identity (persistence is irrelevant at that stage). The SDK build + Z-Loader
acceptance of the baked image are bench-gated (#784 cut 2 legs, #782
discipline); until proven, assume stage 1 is stock at 192.168.1.1.

### Which pattern?

| Situation | Pattern |
|---|---|
| Many units of a model, repeat flashing | P1 (ASU bake, mac-hash IPs) |
| One unit, stock image already at hand | P2 (overlay) |
| Unit already runs OpenWrt | P2 straight (no stage 1 at all) |
| Dark / stock / bootlooping / unknown password | P3 → then P1 or P2 |
| Fresh unit must not ever touch 192.168.1.0/24 | P1 with static/mac-hash + T2 |

Never: one baked image *per unit*. It buys nothing the first-boot script
can't derive, and it makes you track which image goes in which box.

## 4. Quick verification (read-only, any stage)

```sh
mount | grep -E 'overlay|ubi'      # empty = stage 1 (RAM-only) — finish the flow
cat /tmp/sysinfo/board_name        # confirm the model before trusting anything
uci get dhcp.lan.ignore            # '1' = DHCP silent (rogue-discipline landed)
ip addr show br-lan                # the LAN address you baked/overlaid
```

## Related

- `docs/zycast.md` — flash mechanics, write-window discipline, timings,
  the two-stage design rationale (§1c-§1e), switch workflow (§5)
- `docs/gotchas.md` §"First flash runs from RAM" — the stage-1 footgun
- `docs/nr7101/NR7101-ZERO-TO-DATA.md` — NR7101 end-to-end on-ramp
- `recipes/zyxel/nr7101/` — self-documenting flash recipe
- Issue #781 — hardware validation of the overlay `lan_ip` first-boot path
