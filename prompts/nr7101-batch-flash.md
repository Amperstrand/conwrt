# NR7101 Batch Flash + Inventory + Burn-In (5 units)

Session prompt for flashing a batch of ZyXEL NR7101 units with conwrt,
giving each a deterministic identity, running a ~2-minute hardware
burn-in, inventorying the modem, and installing FIPS mesh.

**⚠️ WARNING: zycast permanently overwrites BOTH firmware slots (Kernel +
Kernel2). Stock firmware is unrecoverable from the device afterwards.
mtd2 (Factory: MAC/serial/calibration) is NOT touched.**

## Hardware facts (verified from OpenWrt source 2026-10-27)

The NR7101 has a **2.4GHz MT7603 radio** — confirmed in the device tree
(`mt7621_zyxel_nr7101.dts`: `wifi@0,0` on pcie0, 0x400-byte EEPROM from
Factory@0x0) and in `mt7621.mk` (`DEVICE_PACKAGES := kmod-mt7603 …` — the
driver ships in every official/ASU image, so radio0 = 2g exists on every
flashed unit). Plus: Quectel RG502Q-EA 5G modem (USB), 1× GigE PoE port,
serial. PCIe0 = the WiFi card (NOT the modem — boot-time mt7621-pci hangs
are the radio enumerating).

What each original ask maps to:

| Original ask | Implementation |
|---|---|
| Advertise `nr7101_$mac` SSID | Management AP on radio0: SSID `nr7101_<mac12>`, PSK = MAC-derived wifi-domain password (`fleet_identity` preset) |
| Unique passwords per unit | Root + WiFi PSK both MAC-derived (fleet salt + domain separation, tollgate pattern); computable host-side from the label MAC before boot |
| 2.4GHz as LAN+WAN, join open APs | Single radio: AP (lan) + STA (wan) concurrently is channel-locked and **unreliable on mt76** — `net-roles` disables serving APs when a wifi uplink is active. Default: AP on, WAN = 5G modem/ethernet. If open-AP uplink is wanted for a unit: `travelmate` or a `wifi`-type uplink in `net-roles`, accepting the AP tradeoff on that unit |
| "FIPS so they mesh" | FIPS overlay (UDP over cellular/bench VLAN). Radio backhaul possible too: `fips-mesh-setup radio0` builds an 802.11s bare-L2 mesh between units (mesh + management AP share the radio/channel — evaluate per site) |

## Decisions (already made — do not re-derive)

- **Bench switch: the OpenWrt GS1900-8HP** (bench DUT bays lan2-8, per-port
  PoE control, per-VLAN dnsmasq authority on 100N, zycast sender platform —
  Go/MIPS binary proven 2026-05-26). The stock GS1900 is the lab island
  switch; it has no SSH, no PoE automation, no zycast.
- **Flash method: zycast from the bench switch** (recovery ladder rung 4,
  proven; macOS zycast is banned — 2026-06-28 lesson).
- **Identity: `fleet_identity` use case** — one image for all units; each
  derives root password + hostname from its own MAC at first boot
  (salt stays in config.toml / env, never in git).
- **FIPS package**: build `.apk --arch mipsel` (OpenWrt 25.x = apk) from
  the local fips checkout, install post-flash with `apk add
  --allow-untrusted`.

## Preflight (do ALL before touching a unit)

1. **Coordination gate (hard blocker):**
   - `cat data/active-sessions.jsonl` — check live lanes.
   - The **fleet lane** owns nr7101 units (incl. `nr7101-919c`), and
     **lpac-hwval holds exclusive modem windows**. Build the EXCLUDE list
     of fleet-unit MACs from `data/inventory.jsonl` + the conwrt-lab
     `lab.yaml` (`$CONWRT_LAB`). A unit on that list is NOT flashed,
     power-cycled, or PoE-touched by this session. If a target unit's MAC
     is unknown → STOP and resolve identity first (MAC/serial gate).
2. **Worktree hygiene:** run from a session worktree
   (`scripts/dev-session.sh start <name>`), base `origin/master`.
3. **Disk gate:** `df -h /` — under ~10G free, run
   `scripts/dev-session.sh sweep --pressure` before the fips apk build.
4. **Registry reconcile:** `python3 $CONWRT_BENCH/scripts/lab_registry.py
   reconcile` — detect dead devices/switch reboots/place drift.
5. **Mint the fleet salt (once for the whole fleet):**
   `openssl rand -hex 16` → `[use_cases.fleet_identity] salt` in
   `config.toml` (gitignored) AND export as `CONWRT_FLEET_SALT` for
   host-side lookups. Record the salt in the PRIVATE registry, never here.
6. **config.toml:**
   ```toml
   [use_cases]
   enabled = ["fleet_identity", "net-roles"]   # order matters: net-roles last
   [use_cases.fleet_identity]
   salt = "<minted>"
   hostname_prefix = "nr7101"
   [use_cases.net-roles]
   uplinks = [ { type = "sim" }, { type = "ethernet" } ]   # no wifi type — no radio
   ```
7. **Sanity-check derivations host-side:**
   `python3 scripts/fleet_secrets.py --mac <unit MAC> --check-shell`
   for each target unit (from labels). Print + privately store
   (passwords, LAN IPs) for the session.
8. **Image:** `python3 scripts/firmware-manager.py request --profile
   zyxel_nr7101 --dry-run` (note: ASU profile uses DASHES). Then build
   for real; verify sha256. Image includes fleet SSH key (CURRENT key —
   stale baked keys lock you out).
9. **FIPS apk:** in the fips checkout:
   `./packaging/openwrt-apk/build-apk.sh --arch mipsel` (needs
   cargo-zigbuild + apk-tools v3; see its README). Copy
   `dist/fips_*_mipsel_24kc.apk` to the session worktree.
10. **Burn-in runner ready:**
    `python3 scripts/nr7101_burnin.py --help` (payload is static-tested;
    first live run is part of unit #1 below).

## Per-unit loop (~12-15 min/unit; unit #1 includes manual verification)

Repeat for each unit, one at a time (zycast multicast reaches EVERY
device in the listen window — only the target may be cycling):

1. **Assign a bay:** `python3 $CONWRT_BENCH/scripts/bench_net.py …` —
   target unit into a free DUT bay VLAN (100N), PoE OFF.
   All OTHER target units: powered and fully booted (out of the ~7s
   Z-Loader window) or PoE-off. Never two units cycling at once.
2. **Start zycast on the switch** (from the bench switch or via it, per
   `recipes/zyxel/nr7101/nr7101-flash.sh`), sending the
   initramfs-recovery image to 225.0.0.0:5631 on the bay VLAN.
3. **MAC-VERIFY THE BAY OCCUPANT FIRST (2026-10-28 incident):** during
   the ~10s listen window (or any time the occupant ARPs), tcpdump the
   bay VLAN for 15s — the source IPs/MACs name the resident device. A
   wrong-attribution port-map is not hypothetical: bay2 was attributed
   to a6e4 but held ea7f (.12.113 ARPs); a cross-arch initramfs was
   multicast into the wrong bootloader window (unit survived — wrong-arch
   kernel cannot boot — but only by luck of architecture).
3b. **PoE ON the target port.** Z-Loader enters Multiboot Listening
   automatically within ~10s (no serial trigger needed). Flash ~3 min.
4. **Kill zycast the moment the unit boots** (kernel boot seen on
   timeline/serial, or after the documented flash time). Left running,
   any reboot into Z-Loader re-flashes.
5. **Boot + adopt:** device comes up at 192.168.1.1 (~60s to SSH; NR7101
   OpenWrt runs no DHCP server — reach it through the switch). Verify
   `board_name` matches `zyxel,nr7101`, install/verify fleet SSH key,
   then run the profile apply (fleet_identity runs at first boot from the
   baked image; if applying over SSH instead, it re-runs idempotently).
6. **UNIT #1 ONLY — manual verification (AGENTS test-before-automate):**
   - `uci get system.@system[0].hostname` → `nr7101-<mac12>` (value readback)
   - `uci get dhcp.lan.ignore` → `1`
   - `iw dev` shows radio0/phy; `uci get wireless.default_radio0.ssid` →
     `nr7101_<mac12>`; a WiFi client can see the SSID and join with the
     derived wifi password (`fleet_secrets.py` output). If the AP block
     skipped at first boot (wireless config not yet generated — known
     uci-defaults timing), the SSH-apply pass configures it: re-run apply,
     then re-verify.
   - SSH with the derived root password works
   - Reboot → all of the above survive (persistence)
   - Undo path known: passwd + uci revert + re-flash
   Only after this passes does the batch continue.
7. **Burn-in:** `python3 scripts/nr7101_burnin.py --ip <derived-or-1.1>
   --inventory`. PASS gates: modem present + ATI/GMR/GSN/QCCID answered,
   ram/flash checks ok, cpu non-degenerate, thermal <85C. On FAIL: stop,
   save the report, record the unit in inventory as FAILED with evidence
   path — do not stack changes on a sick unit.
8. **FIPS:** `scp -O` the apk to /tmp, `apk add --allow-untrusted
   /tmp/fips_*.apk`. FIPS starts; `fipsctl` → record the node npub in the
   inventory notes (that npub IS the mesh management identity). On the
   bench VLAN units find each other via mDNS; cellular/Nostr discovery is
   configured whenever SIMs go in. Verify fips did NOT auto-start any
   DHCP-serving service (Escape-Hatch rule 9).
9. **Records (per unit, before the next unit starts):**
   - `data/inventory.jsonl` via burnin `--inventory` (evidence log)
   - conwrt-lab `lab.yaml` + registry commit (system of record: MAC,
     bay, derived LAN IP, hostname, IMEI, modem fw, fips npub)
   - burnin JSON under `data/burnin/`

## Rogue-DHCP discipline

Every unit lands on a bench DUT VLAN with `dhcp.lan.ignore=1` +
ra/dhcpv6 disabled (fleet_identity bakes it). The bench switch's
per-VLAN dnsmasq is the ONLY DHCP authority on 100N. After unit #1, sniff
the VLAN once (`tcpdump -i <vlan-if> -n 'udp port 67'`) — every OFFER
must come from the switch.

## Abort conditions

- Unit fails MAC/identity gate or board_name mismatch → STOP that unit.
- lpac-hwval / fleet lane needs a unit this session touched → finish
  records, leave the unit booted and documented, coordinate.
- `Remote closed` auth-death after first boot → do NOT verdict dead:
  one PoE power cycle + retry window first (Reset Failsafe Discipline).
- Two units in a Z-Loader window simultaneously → kill zycast NOW, sort
  out power states, then continue one-at-a-time.

## Timing budget

Preflight ~30-40 min (incl. apk build) · unit #1 ~25 min (manual verify)
· units #2-5 ~12-15 min each · records included per unit. FIPS apk build
is the only step that can eat disk — respect the disk gate.
