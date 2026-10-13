# Network Segmentation — production house LAN vs lab bench

**Status: eth1 phase COMPLETE 2026-09-28 — execution record and evidence in
[conwrt-bench issue #28](https://github.com/Amperstrand/conwrt-bench/issues/28).
Island fully migrated with zero WiFi downtime: NR7101 self-migrated to
192.168.12.124, both rogue AP3915i disarmed, stock GS1900 re-homed to static
192.168.12.3 and flash-saved. Rogue containment was proven against the REAL
rogues (zero rogue packets ever reached VLAN 13). New since: the ER6P DUT rig
now occupies ERX eth4 (mgmt static 192.168.13.4 on tagged VLAN 13 — **migrated 2026-09-28 to tagged VLAN
12 at 192.168.12.4** (gateway+DNS via the ERX; first time with working
internet; eth4's tagged-13 removed — production L2 path closed). The
production AP itself was then audited and hardened (2026-09-28): it is the
Zyxel EX5700 "gangap" at 192.168.13.111 (closes open-confirmation #1) — v4
DHCP already clean, but a live rogue-RA server was caught (scapy RS probe)
and disarmed; the ERX is now the sole DHCP **and** RA authority on VLAN 13.
Firmware upgrade deliberately deferred by operator (no-WiFi-outage policy).
Remaining open: eth2 re-home (bench-mgmt leak), cold-boot verify window.
Sections below describe the design.**

The house WiFi is production: it must never go down or hand out bad leases,
because other residents notice. Everything on the bench (GS1900-8HP ×2,
GS1900-24E, AP3915i fleet, NR7101, EX5700 test units, and everything to come)
is lab: not production-critical, and frequently *deliberately misconfigured*
(that is the job). The EdgeRouter X (ERX, 192.168.13.1, OpenWrt 25.12.4,
ramips/mt7621, DSA) is quasi-production: it is the house gateway, but it also
physically interconnects the lab. This document maps the current state,
explains why rogue DHCP from lab ports poisons the WiFi, lays out the options
with tradeoffs, and proposes a target design where **the only thing the ERX
guarantees is: production keeps working and the ERX stays the only DHCP
server the WiFi clients can ever see.**

---

## 1. Ground truth — current topology (live-verified 2026-09-27)

Probed over SSH (`ubus call system board`, `bridge vlan`, `bridge fdb`,
`uci show network`, `/tmp/dhcp.leases`) and cross-referenced against
`data/inventory.jsonl`:

```
                    INTERNET
                       │
                 ERX eth0 (WAN, 85.166.119.110/22)
                       │
  ┌────────────────────┴───────────────────────────┐
  │ ERX br-lan (vlan_filtering=1)                  │
  │ VLAN 13 "house"  : eth1:u* eth2:u* eth3:u*     │
  │ VLAN 14 "guest"  : eth1:t  eth4:u*             │
  │ dnsmasq DHCP+RA server ONLY on br-lan.13       │
  └──┬──────────────┬──────────────┬───────────┬───┘
   eth1          eth2           eth3         eth4
   LAB (flat!)   LAB bench      PRODUCTION   LAB (down)
   │             │              │            │
 GS1900-8HP    GS1900-8HP      house AP     GS1900-24E
 (ZyXEL STOCK  (OpenWrt,       (EX5700 per  (unplugged/
  V2.90, mgmt   realtek-poe     operator;    off; mgmt
  = DHCP cli    fork, mgmt      family       192.168.1.1 on
  on flat VLAN  192.168.13.2    WiFi +       switch VLAN 1,
  1)            untagged)       servers      VLAN 14 untagged)
   │             │              behind it
 DUTs flat in   DUT bays lan2-8  (ai-legion,
 house LAN!     isolated VLANs   electrumx, Sonos,
 (NR7101 "Toll- 100N, routed     phones, tablets,
 Gate" lease    out via mgmt     Nest, vacuum…)
 .13.124 is     VLAN→ERX         ≈23 MACs, incl.
 LIVE proof)                    randomized WiFi MACs
```

Facts that matter:

- **eth3 is the only production LAN port** (all family WiFi clients + house
  servers learn behind it). eth0 is WAN. Everything else is lab.
- **eth1 is the worst rogue-DHCP path and it is live**: the stock ZyXel
  GS1900-8HP was kept factory-flat by operator decision (2026-09-24, fleet
  OEM-automation target). All its ports sit untagged in VLAN 13 — the house
  LAN. Proof: NR7101 DUT currently holds a house lease (`TollGate`,
  192.168.13.124, MAC `78:c5:7d:13:91:9c` learned on eth1). If that unit (or
  any future DUT there) boots OpenWrt defaults, its dnsmasq **is** a rogue
  DHCP server on the production segment, and the WiFi race is lost or won by
  milliseconds.
- **eth2 leaks the bench management plane into production**: the OpenWrt
  GS1900's mgmt is untagged VLAN 1 → ERX VLAN 13. Its DUT bays are properly
  isolated (per-port VLAN 100N), but the switch itself sits in the house L2 —
  the `apk add dnsmasq` incident class (AGENTS.md) poisons WiFi through
  exactly this path.
- **eth4** (VLAN 14 untagged, currently no carrier) was the GS1900-24E bench
  switch. VLAN 14 has no DHCP server (`no-dhcp-interface=br-lan.14`) and no
  active consumers right now (empty FDB).
- A DUT plugged into any free ERX port today lands in VLAN 13 or 14 — i.e.
  directly adjacent to (13) or one SSID away from (14) production clients.

### Who has DHCP responsibility today

| Segment | DHCP authority | Intended | Actual risk |
|---|---|---|---|
| VLAN 13 house LAN (WiFi clients, servers, eth1+eth2 mgmt, flat DUTs) | ERX dnsmasq (192.168.13.1) | yes | **contested daily** — every flat lab device can answer DHCPDISCOVER |
| VLAN 14 guest | none (`dhcp.lan_guest.ignore=1`) | yes | any lab device on 14 serves guest SSID clients if one exists |
| Bench VLANs 100N (switch L3 192.168.10N.1) | per-VLAN dnsmasq on the OpenWrt GS1900 (.50–.150) | yes, rogue-safe | isolated by design; only reachable via routing |

The invariant we want: **exactly one DHCP server per L2 broadcast domain,
and no lab device ever shares an L2 domain with a production client.**

---

## 2. Why the ERX cannot "just filter DHCP" (research)

Requirement investigated: "ERX blocks all DHCP from all ethernet ports from
propagating so it remains the only DHCP server even with rogues elsewhere."
Findings (zread on openwrt/openwrt + web, sources at the bottom):

1. **OpenWrt has no DHCP snooping.** No host feature, and the MT7530 DSA
   driver exposes no snooping. Forum consensus 2016→2024 is uniform: with a
   bridged AP/switch you cannot filter rogue DHCP in-band; put untrusted
   devices on their own subnet (forum.openwrt.org t/68491, t/217800, t/49811).
2. **fw4/iptables never see same-VLAN switch-port traffic.** The MT7530 ASIC
   forwards VLAN-13 frames port↔port in hardware; the CPU bridge only gets
   copies of flooded traffic. Dropping the CPU copy does not stop delivery to
   the AP port. (DSA mini-tutorial: bridge offload happens "whether you have
   VLAN filtering or not"; MikroTik docs for the same switch class: "when
   offloading is active the packets are processed within the switch, so are
   never seen by the CPU".)
3. **Bridge-family nftables rules only work for software-bridged frames.**
   Disabling DSA bridge offload per-port is an unmerged netdev RFC (Jan 2025);
   kernel 6.12 (this box: 6.12.87) does not have it. Forcing the whole house
   LAN through the 880 MHz MT7621 CPU would also throttle the network for
   nothing.
4. **What the ERX *can* do**: segment (VLAN membership per port), route+drop
   at L3 between segments, and *see* flooded DHCP copies for detection. That
   is the complete toolbox on this hardware.

Conclusion: the only robust control is **L2 segmentation per trust boundary**
— the same pattern already proven on the OpenWrt GS1900 bench switch
(docs/BENCH-SWITCH-PATTERN.md, "rogue-DHCP-safe: isolated VLANs").

---

## 3. Options and tradeoffs

| Opt | Approach | Rogue-DHCP protection | Production risk during change | Cost / caveats |
|---|---|---|---|---|
| 0 | Status quo (+ detection watchdog only) | none — alerts after WiFi is already poisoned | none | unacceptable; eth1 path is live today |
| A | Minimal: eth4 isolated VLAN + fw4 drops + watchdog | closes only the spare-port path; eth1/eth2 mgmt still flat | tiny | 30 min; leaves the *proven* incident paths open |
| **B** | **Full prod/lab VLAN split (recommended)** | complete: no lab L2 adjacency to production anywhere | small, one port at a time, rollback-armed | re-home both GS1900 mgmt planes (~1–2 careful sessions); bench tooling IPs move once |
| C | Flat LAN + bridge-nft DHCP filter | (theoretical) | n/a | **rejected by research**: impossible on mt7530/6.12 without disabling offload; offload-disable would bottleneck the house |
| D | Lab router behind one ERX port (lab gets NAT) | complete for WiFi | near-zero ERX config churn | extra box; double-NAT breaks direct SSH/ubus bench tooling from prod-side hosts (ai-legion) — port-forward gymnastics |
| E | DHCP-snooping switch as LAN core (e.g. Netgear S350 GS308T, ~$40, real trusted-port snooping + rate-limit + logging) | good for a flat LAN | medium: inserts a new SPOF into the WiFi path | still no lab isolation benefits; one more config surface; reboot of a $40 switch = WiFi outage |
| F | Variant of B: keep stock GS1900 flat, but its DUTs move to the OpenWrt GS1900 | partial (single flat mgmt remains) | small | only if stock-GS1900 OEM tests need flat L2 — B subsumes this anyway by giving eth1 its own VLAN |

Process/tooling layers that apply to **every** option (already in repo):
`scripts/flash/port_isolator.py` (isolate before power-on),
`scripts/profile/overlay.py` (`dhcp.lan.ignore=1` baked into sysupgrade
overlays), AGENTS.md escape-hatch rule 9 (check `/etc/init.d/<svc> enabled`
after every package install — the `apk add dnsmasq` lesson).

---

## 4. Recommended design (target state)

Principles, each mapped to established best practice (see sources):

- **Segment by trust level, not device type** — production, lab-mgmt, bench,
  wild. Few zones, each with one purpose. (homelab segmentation consensus)
- **Management plane off the user VLAN** — "the management VLAN is not
  configured on any user-facing interface" (Cisco CVD). Our equivalents: the
  two GS1900 mgmt IPs must leave VLAN 13.
- **No user/lab traffic in the default/untagged VLAN** (Cisco/Huawei: avoid
  VLAN 1 as a catch-all; unused ports → isolated parking VLAN).
- **Deny-by-default between zones**, add documented exceptions.
- **All paths controlled** — an unmanaged bypass (the flat stock GS1900)
  defeats everything; it must be re-homed too.
- **Escape hatches before VLAN changes** — console/failsafe verified before
  touching the quasi-production router (their own dark-device lessons).

### Target port map (ERX)

| ERX port | Role | VLAN(s) | Subnet / L3 | DHCP |
|---|---|---|---|---|
| eth0 | WAN prod | — | ISP | client |
| eth3 | **PRODUCTION — house AP + servers** | 13 untagged (+14 tagged *if* AP serves a guest SSID — confirm) | 192.168.13.1/24 | **ERX dnsmasq — the only DHCP server production can see** |
| eth1 | LAB — stock ZyXel GS1900-8HP | 12 untagged (re-home off 13; drop vestigial `eth1:t` VLAN 14) | 192.168.12.1/24 on ERX; switch DHCP-client or .2 | none on ERX (switch self-manages); fw4 drops sport 67 from this zone |
| eth2 | LAB — OpenWrt GS1900-8HP bench | 12 tagged (mgmt) — DUT VLANs 100N stay switch-local as today | switch.12 = 192.168.12.3 | per-VLAN dnsmasq on the switch (unchanged, isolated) |
| eth4 | LAB — wild DUT port / GS1900-24E | 19 untagged | proto 'none' (no L3, no DHCP) or lab VLAN if it needs routing | none — rogue hears only itself |

### Firewall (fw4) sketch

```
config zone; option name 'lab'; list network 'lab_mgmt' 'lab_wild'
  input REJECT; forward REJECT; output ACCEPT
config forwarding; option src 'lab'; option dest 'wan'      # DUT internet egress
# no lab→lan forwarding except documented exceptions (e.g. ai-legion SSH in)
config rule; option src 'lab'; option proto 'udp'; option src_port '67';  option target 'DROP'  # rogue v4 OFFER/ACK renews
config rule; option src 'lab'; option proto 'udp'; option src_port '547'; option target 'DROP'  # rogue DHCPv6
config rule; option src 'lab'; option proto 'icmpv6'; list icmp_type 'router-advertisement'; option target 'DROP'
```

Layer-2 guarantee chain: a rogue on any lab port is inside a VLAN whose only
other member is the ERX CPU port → broadcast OFFERs die in the VLAN (routers
do not forward 255.255.255.255, no relay configured); unicast renews cross
at L3 where fw4 drops them; DHCPv6/RA likewise. dnsmasq keeps serving only
br-lan.13 (already enforced by `no-dhcp-interface=` on eth0 and br-lan.14).

### Detection (cheap, all options)

The CPU *does* see flooded DHCP copies, so a watchdog on the ERX closes the
loop for anything that still reaches VLAN 13 via trusted ports:

```sh
# /etc/cron.d + script sketch: alert on any DHCP server that is not us
tcpdump -i br-lan.13 -ln -c 1 'udp src port 67 and not src host 192.168.13.1' \
  && logger -t rogue-dhcp ALERT "$(date) non-ERX DHCP server seen on VLAN 13"
```

(Fold into `gs1900-bench-arm.sh`-style re-arming; runtime-only pieces die on
reboot — say so in the notes, per repo rules.)

---

## 5. Change-safety protocol (the "WiFi must never go down" part)

The ERX is quasi-production: **runtime-apply → verify from a second host →
confirm; auto-rollback armed the whole time.** Never a bundled
commit+reload+restart (AGENTS.md network-gear discipline).

1. **Doors first**: keyed SSH to the ERX from at least two hosts on *eth3*
   (ai-legion `.208` is on the production segment — it survives any lab-port
   change), plus failsafe procedure rehearsed (hold reset through power-on,
   192.168.1.1). Optional ultimate hatch: ER-X serial header + adapter.
2. **Stage, never bundle**: `uci set` the one port's bridge-vlan membership,
   review `uci changes`, then apply via the rpcd rollback primitive
   (verified present on this box — `uci` ubus object + rpcd running,
   luci-base installed):
   ```sh
   ubus call uci apply '{"rollback": true, "timeout": 120}'   # auto-revert unless confirmed
   # ...verify reachability from second host, WiFi still up...
   ubus call uci confirm
   ```
   If the change kills management, rpcd reverts the config and reloads after
   the timeout — the LuCI "apply with rollback" mechanism, driven from CLI
   (openwrt/luci#1769, wiki UCI §ubus). Verify the methods first with
   `ubus list -v uci` on the target box.
3. **Belt-and-braces deadman** (in addition, per AGENTS.md BusyBox rules):
   `setsid sh -c 'sleep 300 && reboot' >/dev/null 2>&1 &` — cancel only after
   re-verification.
4. **Value readbacks gate commits**: `uci get` / `bridge vlan` after every
   apply; `uci revert network` to a clean baseline before staging (staging
   debris survives SSH sessions in `/tmp/.uci`).
5. **Never rely on runtime bridge edits**: netifd re-applies uci state and
   wipes runtime `bridge vlan` changes even without reboot (inventory note
   2026-09-24, learned live on the eth1 PVID merge). UCI is the only truth.
6. **One port per session**: eth1 first (worst offender, lowest blast radius
   — its consumers are lab), then eth2 (bench mgmt re-home + bench_switch.py
   pattern update), then eth4. **eth3 and eth0 are never touched.**
7. **Cold-cycle verify before done**: full PoE/power cycle, watch the box
   come back, re-run verification. Then update inventory + registries
   immediately (stale worst-case verdicts are themselves a hazard).

### Per-step verification gates (binary)

- After each port re-home: SSH to ERX still alive from ai-legion; WiFi client
  (phone) still has 192.168.13.x lease with gw 192.168.13.1; re-homed switch
  reachable on its new 192.168.12.x; `bridge vlan` output matches intent.
- Rogue-DHCP negative test with positive control: plug a deliberately rogue
  DHCP server (spare OpenWrt box, defaults) into the re-homed port; confirm a
  WiFi client's *new* DHCPDISCOVER still yields only the ERX lease
  (`ubus call dhcp ipv4leases` / lease file shows one server). Prove the test
  rig itself works first (AGENTS.md: no negative without a positive control).

---

## 6. Open confirmations needed from the operator

1. **eth3 AP identity**: operator believes the house AP is an OpenWrt EX5700.
   Confirm physically (the design only needs "the AP + family segment =
   eth3", which the FDB already proves).
2. **VLAN 14 consumer**: `eth1:t` guest tagging looks vestigial (empty FDB).
   Is there a guest SSID anywhere (then move `:t` to eth3 with the AP), or
   can VLAN 14 be retired/frozen?
3. **eth4 / GS1900-24E plans**: stays a lab wild port (VLAN 19, proto none)
   or gets the 24E back with a lab VLAN?

## 7. Sources

- OpenWrt forum: rogue DHCP on bridged ports — t/68491 (2016), t/49811,
  t/217800 (2024, "nothing you can do with a bridged AP/switch");
  ebtables/bridge-filter history t/2492.
- Kernel/netdev: DSA bridge HW offload & `offload_fwd_mark` semantics
  (docs.kernel.org DSA; netdev patch 2021 "don't set offload_fwd_mark…");
  per-port bridge-offload disable RFC (lists.openwall.net, 2025-01) — not in
  6.12.
- OpenWrt wiki: DSA mini-tutorial (bridge offload with/without vlan_filtering),
  bridge VLAN UCI (`config bridge-vlan`, netifd nbd commit 0e8cea0f).
- Apply/rollback: openwrt/luci PR #1769 (rpcd uci apply/confirm + rollback
  timer), wiki UCI §ubus interface ("apply … with automatic rollback if not
  confirmed").
- Segmentation best practice: Cisco CVD campus (management VLAN not on user
  interfaces; unused-port parking VLAN; avoid VLAN 1), Huawei campus guides
  (management VLAN design), SANS VLAN-hopping/native-VAN guidance; homelab
  consensus guides (management/trusted/IoT/guest zones; deny-by-default;
  "segmentation is only effective when all paths are controlled"; mDNS
  breakage across VLANs — why production devices stay put).
- DHCP-snooping hardware reality: Netgear S350 series (GS308T/GS310TP) and
  M-series support trusted-port snooping with rate limiting (kb.netgear.com
  21815/21814) — documented as Option E, not recommended here.
- Live evidence: ERX probes 2026-09-27 (board/uci/fdb/leases), inventory
  records for GS1900-8HP ×2 (stock on eth1, OpenWrt on eth2), GS1900-24E
  (eth4), NR7101 DUT lease on the house LAN via eth1.
