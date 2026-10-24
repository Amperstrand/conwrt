<!-- Unit-level values redacted 2026-10-23: full unredacted census archived in the private conwrt-bench registry. -->
# NR7101 — Species Guide: Modem Firmware, RF Survey, Flashing (2026-09-27)

Live-verified 2026-09-27 by the session-review lane. Purpose: species-level
reference for the NR7101 (firmware guidance, RF behavior, flash methods) and
the onboarding path for **any NR7101 unit** later. Fleet census and unit
coordinates live in the private lab project (see the census section).

## TL;DR

- Fleet census (unit count, provenance, per-unit state) is operator-private
  inventory — private census dossier (#290); multiple units exist across
  modem firmware families, exactly one bench-active.
- Modem = **Quectel RG502Q-EA**. Firmware families seen on the bench:
  `RG502QEAAAR11A03M4G`.
  **Stay on R11A03**; if ever deployed with live service, walk to **R11A07M4G
  and stop**. Avoid R13A04. Never cross QEAAAR/AACR tracks.
- RF survey from the bench: **Telenor + ice both LTE/5G-NSA visible**, RSRP
  −92 dBm. The seated Telenor SIM is **inactive** (home PLMN quiet-fail; ice
  returns explicit registration-deny `+CEREG: 1,3`). No APN/ping possible until
  an active SIM exists. `AT+QPING` procedure is staged below.

## Unit census

Everything about the operator's concrete units — census, provenance,
per-unit firmware, deployment/bench state, reachability, coordinates —
is fleet inventory and lives ONLY in the private lab project:
`conwrt-bench/docs/nr7101-fleet-census-private.md` (#290 — unit
inventory belongs in the private project, identifiers or not). Nothing
in this public doc describes the operator's units; addresses in older
revisions must not be trusted. Species-level guidance (modem firmware
families and what they mean for flashing) is in the modem-firmware
section below. The rogue-DHCP risk class for bench DUTs generally is
documented in `docs/NETWORK-SEGMENTATION.md`.

## Bench switch snapshot

(Bench switch specifics are topology — private census dossier, #290.)
Species-level facts: NR7101 draws ~4-5 W PoE (well inside any GS1900
PoE budget; budget math for a full bench lives with the bench docs).
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

- Per-unit open items (physical recovery, SIM state, field-refresh) are
  fleet inventory — tracked in the private census dossier (#290).

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

The bench network was resegmented (2026-09-28): the NR7101 moved OFF the
house LAN (rogue-DHCP risk removed) onto an isolated LAB VLAN on the ERX.
Concrete addresses and the tooling endpoints that follow them live in the
private census dossier (#290); all tooling (modemifd reader, modem-at-bridge)
was repointed at the resegmentation.
- modemifd reader (now [Amperstrand/ifd-modemifd](https://github.com/Amperstrand/ifd-modemifd), Rust): reader.conf DEVICENAME follows the unit's current address; the retired C implementation was removed from this repo
- pcscd: verified reader + ICCID + logical channel working

The NR7101 is also the lpac host: /usr/bin/lpac (v2.3.0, MIPS) deployed
with stdio drivers at /usr/lib/lpac/driver/.

## AT Port Instability (2026-09-28 finding)

The RG502Q-EA USB modems AT command port SHUFFLES across power cycles:

## AT Port Instability (2026-09-28 finding)

The RG502Q-EA USB modem's AT command port SHUFFLES across power cycles:
- Boot 1: ttyUSB2 (original)
- Boot 2 (after PoE cycle): ttyUSB1  
- Boot 3 (after another cycle): ttyUSB3

**Implication**: never hardcode the AT port. Auto-detect at boot by probing
each /dev/ttyUSB* with "AT" and checking for "OK" response.

## CSIM Pacing Requirements (confirmed on new boot)

- AT commands (ATI, CPIN, CFUN): respond immediately
- AT+CSIM: requires 8+ second gaps; rapid CSIM triggers thrash; recovery = 15+ s
- After power cycle: full 15s wait before first CSIM attempt

## Current AT Port: /dev/ttyUSB3 (as of 2026-09-28 ~12:10)
