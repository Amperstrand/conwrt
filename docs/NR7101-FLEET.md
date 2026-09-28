# NR7101 Fleet — Census, Reachability, Modem Firmware, RF Survey (2026-09-27)

Live-verified 2026-09-27 by the session-review lane. Purpose: single reference for
the NR7101 fleet now, and the onboarding path for **more NR7101 units** later.

## TL;DR

- **Three distinct NR7101 units** exist in records (distinct IMEIs/MACs). Exactly
  **one is on the bench and reachable**: the ex-Telenor unit, now the house
  "TollGate" DUT at `192.168.12.124` (OpenWrt 25.12.5), cabled on **switch lan8**.
- The **Altibox unit is off-bench/dark** (no carrier on any DUT port, no ARP/FDB
  trace). A third **ice+ unit** was recorded 2026-05 with working ice.net service
  and is field-deployed, not benched.
- Modem = **Quectel RG502Q-EA**. Bench unit firmware: `RG502QEAAAR11A03M4G`.
  **Stay on R11A03**; if ever deployed with live service, walk to **R11A07M4G
  and stop**. Avoid R13A04. Never cross QEAAAR/AACR tracks.
- RF survey from the bench: **Telenor + ice both LTE/5G-NSA visible**, RSRP
  −92 dBm. The seated Telenor SIM is **inactive** (home PLMN quiet-fail; ice
  returns explicit registration-deny `+CEREG: 1,3`). No APN/ping possible until
  an active SIM exists. `AT+QPING` procedure is staged below.

## Unit census

| Unit | MAC | IMEI | Modem fw | State (2026-09-27) |
|---|---|---|---|---|
| ex-Telenor ("TollGate") | `78:c5:7d:13:91:9c` | 354351111598628 | `RG502QEAAAR11A03M4G` | **LIVE**: house LAN `192.168.12.124`, OpenWrt 25.12.5 r33051, hostname TollGate, WiFi APs + captive-portal role, switch **lan8** (VLAN 1008), PoE ~4.5 W |
| ex-Altibox (stock) | `78:c5:7d:23:de:fe` | unknown | unknown (unqueryable) | **DARK**: last seen in `zyxel_research/NR7101.md` on lan3 @ `192.168.2.1` ICMP-only; now no link on lan2–lan7, zero ARP/FDB trace. Physical recovery = owner action |
| ice+ unit | `4c:c5:3e:b6:1d:90` | 354351110824785 | `RG502QEAACR13A03M4G_ZYXEL` | Field-deployed (2026-05 record: ice.net LTE B3, data OK). Not bench-connected |

## Reachability map (ex-Telenor unit)

Two-hop path; **only ai-legion-small's SSH key** is authorized (4 keys in
dropbear; x280 and ai-legion keys rejected; root password set):

    x280 → ai-legion-small → ssh root@192.168.12.124

**Stale paths — do not trust older docs**: `192.168.1.1` (switch.1002) and
`192.168.2.1` are gone; the unit now DHCPs on the house LAN. Old port map
(lan2) is stale; current cable = **lan8**. This is also the unit carrying the
rogue-DHCP risk documented in `docs/NETWORK-SEGMENTATION.md` (house lease
`.13.124`).

## Bench switch snapshot (OpenWrt switch `192.168.13.2`)

- **lan1** = trunk/uplink (VLAN 1 untagged mgmt + tagged 1002/1003/…).
- **lan8** = NR7101 TollGate (carrier up, PoE ~4.5 W).
- **lan2–lan7** = no carrier (empty).
- PoE budget 65 W, consumption ~4.5 W. Control: `ubus call poe manage '{"port":"lanN","action":"enable|disable"}'`.
- Read port state: `/sys/class/net/lanN/carrier`; `ubus call poe info`.

## Modem firmware guidance (research 2026-09-27)

Sources: Zyxel EMEA downloads article, Zyxel Community threads (14838, 15326,
17802, 25834, 26363, 27809), OpenWrt forum 167633, Quectel RG502Q-EA R11A07
release notes. zread.z.ai and openwrt.org/wiki were unreachable from bench
network (disclosed).

- Official Zyxel doctrine: **avoid radio-module updates unless necessary**;
  modem fw is region/network-tailored and can degrade performance.
- **R11A07M4G** = community stability baseline (DFOTA/NETWORK/SIMCARD fixes;
  minor known issues only).
- **R13A02** mixed; **R13A04 (latest)** has repeated severe reports (total
  connectivity loss, 24 h lease-renewal failures, cell-lock/CA regressions;
  downgrade only via Zyxel support).
- Operator **AACR** builds can region-lock (reported on A1 AT); ours ran fine
  on ice.net. Never cross QEAAAR ↔ AACR tracks — "illegal image".
- Stock-device firmware: prefer **ABUV.10** (ABUV.8 "very stable" but older;
  ABUV.11 breaks LTE for some users).
- **Decision for this fleet**: bench unit stays on R11A03 (untestable gains
  without service; blind DFOTA = risk). Deploy-to-live path: sequential DFOTA
  R11A03 → R11A06 → R11A07M4G, stop. DFOTA chain must be walked in order.

## AT toolbox (RG502Q-EA on OpenWrt NR7101)

- AT port: **`/dev/ttyUSB2`** (QMI data on `cdc-wdm0`/`wwan0`).
- The AT port is **shared** — expect interleaved traffic/stray ERROR lines;
  drain the port before parsing.
- Busybox gotcha: `sleep` needs **integer** arguments; use the drain-then-send
  pattern (see `/tmp/nr7101-survey.sh` pattern on ai-legion-small, or
  re-create: `cat $P > /tmp/at.r & printf 'ATI\r' > $P; sleep 2; kill %1`).
- Cookbook: `ATI`/`AT+CGMR` (fw), `AT+QCCID` (SIM ICCID), `AT+CPIN?`,
  `AT+QCSQ` (signal), `AT+COPS=?` (**operator scan**, ~60 s),
  `AT+QENG="servingcell"` / `"neighbourcell"` (cell survey; needs camped
  state), `AT+CEREG?` (registration), `AT+QNWINFO` (serving network),
  `AT+QPING=<cid>,"8.8.8.8",10,3` (**ping through the modem**, requires active
  PDP context).

## 2026-09-27 RF survey + registration test (bench, no active service)

- `AT+COPS=?`: **Telenor 24201 (LTE AcT7 + NR-NSA AcT12), ice 24214 (LTE +
  NR-NSA), NetCom 24202 (LTE, forbidden for this SIM)**.
- `AT+QCSQ`: LTE, RSSI −65, **RSRP −92 dBm**, SINR 15.7, RSRQ −10.
- Registration: auto + manual `24201` → searches (`CEREG 0,2`) then idles
  (`0,0`), `QNWINFO: No Service`. Manual `24214` (ice) → **`+CEREG: 1,3`
  (DENIED)**.
- Verdict: RF healthy, multiple operators visible; **SIM inactive** (home PLMN
  quiet-fail + roaming deny). "Tower ping"/APN tests are impossible without
  registration; `AT+QPING` is the ready procedure once a live SIM is seated.
- Recommend for future live testing: any active Norwegian prepaid SIM
  (Telenor/ice/NetCom), then: `COPS=0` → verify `CEREG 0,1` → `CGDCONT=1,"IP","<apn>"`
  → `CGACT=1,1` → `QPING`.

## Onboarding more NR7101 units (playbook)

1. **Port/VLAN**: pick a free DUT port (lan2–lan7 currently empty), add
   `bridge-vlan` (see `network.vlan100N` pattern; DUT ports untagged, lan1
   tagged). Assign bench subnet `192.168.10N.51` static once verified.
2. **Power**: `ubus call poe manage '{"port":"lanN","action":"enable"}'`;
   verify draw via `ubus call poe info` (NR7101 idles ~4.5–5 W).
3. **Flash**: stock units via zycast — see `docs/zycast.md` and
   `~/src/zyxel_research/NR7101.md` (procedure proven 2026-05-26). OpenWrt
   images: `zyxel_research/firmware/nr7101/`. Warning from zyxel_research:
   23.05.0 release images soft-brick; use 23.05.5+ or snapshots.
4. **First SSH**: doctrine per AGENTS.md — inventory + install bench key
   immediately (`ssh-copy-id` equivalent into dropbear).
5. **Inventory**: append to `data/inventory.jsonl`
   (`python3 scripts/inventory.py --add` or hand-crafted line — records are
   loose-schema; include MAC, IMEI, modem fw via `ATI`, SIM ICCID via
   `AT+QCCID`).
6. **Modem fw policy**: leave as-found unless deploying live (see above).
7. **Labgrid**: enroll once bench addressing + keys verified (exporter stanza
   pattern in `labgrid/exporter.yaml` on ai-legion).

## Open items

- Altibox unit: physical location unknown — owner action if wanted back.
- Seated Telenor SIM is inactive; leave or pull (inert either way).
- ice+ field unit: consider a live inventory refresh next time on bench.

## Service activation paths (research 2026-09-27)

Radio-side activation does not exist: eNB/gNB is subscription-blind; attach is
AKA challenge-response against the HSS/UDM with the SIM pre-shared key; there
is no NAS "provision me" message. The pay-then-activate primitive exists one
layer up as commercial MVNO APIs:

- Dormant SIM + REST activation: Hologram (bulkclaim), Soracom
  (activateSim/setSimToStandby/suspendSim), emnify (SIM status API + prepaid
  quota API: "customer pays, service instantly restored").
- eSIM (GSMA SGP.22): pay -> profile download over any IP -> attach. No tower
  involvement.
- In-core precedent of TollGate semantics: 5G UPF "walled garden" (out-of-
  credit): SMF PFCP redirect -> UPF DNS-spoofs captive portal, whitelists
  payment processors, restores on payment (e.g. OmniUPF; LinkIT Zero Balance).

Bench build path ("TollGate for cellular"): Cashu storefront -> MVNO activate
API -> HLR flip -> NR7101 attaches. Best-fit Nordic provider: Onomondo (ICE +
Telenor Norway, API-first, PAYG ~EUR 0.003/MB, no inactive fees); Soracom
plan01s for lifecycle-API experimentation. One API SIM makes the NR7101 a
scriptable attach/detach test rig.

## See also

- docs/CELLULAR-ACCESS-WITHOUT-SUBSCRIPTION.md — no-SIM/dummy-SIM/test-SIM
  taxonomy, JIT activation architecture, provider rate comparison
  (silent.link vs Onomondo vs Soracom for Norway), Cashu bridge, own-core
  (srsRAN) path.

## IP Update (2026-09-28)

The bench network was resegmented. The NR7101 moved:
- **Old**: 192.168.13.124 (house LAN, VLAN 1) — rogue-DHCP risk, removed
- **New**: 192.168.12.124 (LAB VLAN on ERX) — isolated from house WiFi

All tooling updated:
- modemifd reader.conf: DEVICENAME now 192.168.12.124:7002
- modem-at-bridge (socat): restarted on new subnet
- pcscd: verified reader + ICCID + logical channel working

The NR7101 is also the lpac host: /usr/bin/lpac (v2.3.0, MIPS) deployed
with stdio drivers at /usr/lib/lpac/driver/.
