# DRAFT — reply to obsy on ddimension/wwand PR #85 (comment 6718397441)

STATUS: POSTED 2026-11-09 — https://github.com/ddimension/wwand/pull/85#issuecomment-6735989033 (operator-approved).
Owner: mf286d-bringup session (w1:p5H). Updated: 2026-11-09.
Merge in fresh findings from ~/mf286d-work/evidence/b14/FINDINGS.md if present.

---

Short answer: **no — there is no known way to get QMI data working on the B14
modem firmware today.** B12 is the only known-good, and downgrade is the only
proven fix. But we spent this weekend reverse-engineering this platform,
unpacked the actual B14 update package — and found what we believe is the
exact mechanism: B14 ships a **modem-side multi-client data bridge** that
takes ownership of data calls away from external QMI. It's identified from
the shipped configuration, and it suggests a possible fix without any
firmware change. Details below.

## What "B14" actually is

The "Nordic_B14" package (Oct 2024) bundles three things:

1. Router firmware `TELIA_MF286DV1.0.1B02` (the security fix for
   CVE-2023-25649 — this part is good)
2. Modem firmware `BD_TELIAMF286DV1.0.0B14`
3. **A modem-side NV settings script** — the community extracted a 5-line
   fragment; we pulled the **full script** from the package (also in our
   repo, link at the end):
   ```
   nv set net_select="Only_LTE"
   nv set default_lte_band_lock="0x2008080045"     # B1/B3/B7/B20/B28/B38
   nv set default_gw_band_lock="0x2000000400000"
   nv set lte_band_lock="0x2008080045"
   nv set gw_band_lock="0x2000000400000"
   nv set fota_net_set="1"
   nv set cr_version="Nordic_MF286D_B14"
   nv set cr_inner_version="CR_TELIAMF286DV1.0.0B14"
   nv set integrate_version="TELIA_MF286DV1.0.1B02"
   nv set integrate_release_version="TELIA_MF286DV1.0.1B02"
   nv set zte_dst_datastall_monitor_switch="1"
   nv set DDNSProvider_default="no-ip.com;zoneedit.com;dyndns.org;freedns.afraid.org;"
   nv set zte_syslog_enable="1"
   nv set syslog_level="1"
   nv set syslog_path="/etc_rw/log"
   nv set key_local_id="0"
   nv set key_syslog_name="key.log"
   nv set key_syslog_size="512"
   nv set cutoff_detect_switch="1"
   nv set cutoff_net_link_detect_url_0="8.8.8.8"
   nv set cutoff_net_link_detect_ping_times="2"
   nv set cutoff_net_link_detect_timeout="5"
   nv set log_manage_switch="0"
   ... (plus https/tcm service URLs, empty by default)
   ```
   Notable: the LTE-only RAT lock, the data-stall watchdog
   (`zte_dst_datastall_monitor_switch`), the cutoff monitor pinging
   `8.8.8.8` — and the **version identity itself** (`cr_version`,
   `cr_inner_version`) stored as NV items, which mechanically explains a
   long-standing gotcha: after downgrading, the device keeps *reporting*
   B14 until factory defaults clear these.

Naming trap: the delta filename is
`TELIA_MF286DV1.0.0B12-TELIA_MF286DV1.0.1B02.up` — the router side goes
"V1.0.0B12 → V1.0.1B02" while the *modem* reports "B14". Same package,
two version schemes; this confused the wiki note discussion for a while.

## What breaks (aggregated from forum.openwrt.org/t/175362, eko.one.pl
thread id=21790, ispreview thread 42622)

| Still works on B14 (under OpenWrt) | Broken on B14 |
|---|---|
| AT ports (ttyUSB0-2) | QMI WDS `start-network` → hangs → "Unknown error" (PAP/CHAP, ipv4, ipv4v6 — all tried) |
| QMI UIM (SIM state ready) | `--stop-network 0xffffffff --autoconnect` → "No effect" |
| QMI NAS (registered, signal ok) | Voice calls |
| QMI DMS, WDA raw-ip | 3G (NV-disabled by the package) |

The single most telling datapoint (from "luca" on the OpenWrt forum,
2025-03-03): while uqmi reported `"Out of call"`, `AT+CGPADDR` showed
**three active PDP contexts with live IP addresses**. The modem's data
engine was running sessions that QMI WDS could not see, could not stop,
and could not start. Meanwhile the same modem works fine under the stock
firmware — so this is a host-control problem, not a radio or SIM problem.

## Why it breaks — what we found by unpacking the actual package

We pulled the official Nordic B14 update package
(`TELIA_MF286DV1.0.0B12-TELIA_MF286DV1.0.1B02.up` — the public ZTE DMS
server still serves it) and unpacked it. Findings, in order of relevance:

1. **B14 rewrites the modem's own software, not just the router.** The
   delta package carries 163 modem files: the full baseband (AMSS) image
   set *plus the modem-side Linux data-path stack* — the Qualcomm DSI
   data-call configuration (`dsi_config.xml`, apparently a *new* file in
   B14), the QMI libraries (`libqmi_cci/csi/sap`), the MCM RIL service,
   and ZTE's data adapters (`zte_adapter_ppp/cfg`, `libztecmdq`).
2. **119 carrier-policy (MCFG) files**, with the Telia/Telia Sweden
   profiles among the patched ones, plus direct writes to the modem's EFS
   configuration store.
3. The full **30-item NV script** (community previously had 5 lines):
   LTE-only RAT lock with the Nordic band set, a data-stall watchdog, and
   — notably — the modem version identity itself stored in NV. That last
   one mechanically explains a known gotcha: after downgrading modem
   partitions, the device keeps *reporting* B14 until factory defaults
   are restored.
4. **None of the NV items is a QMI/autoconnect switch.** The forum
   shorthand "the update sets NV items that break QMI" is incomplete.

Putting it together — **the mechanism, found**: among the decoded files is
the modem's `/etc/qmi_ip_cfg.xml` and an init script that starts
`/usr/bin/qmi_ip_multiclient` — Qualcomm's **multi-client QMI data
bridge**, a modem-side daemon that holds one data call per LAN client
(the architecture router-style modems use). The B14 config ships:

```xml
<mode>multi_client</mode>
<lan_clients_allowed>3</lan_clients_allowed>
```

Count them: **three** — exactly the number of live PDP contexts B14 users
see in `AT+CGPADDR` while QMI WDS insists it is "out of call". With the
modem's own bridge owning the data calls, external QMI WDS control fails
in precisely the observed ways: `start-network` → conflict → "Unknown
error"; `stop-network 0xffffffff` → "no effect" (it can't stop calls it
can't see). The stock firmware drives the modem through this bridge and
never notices; every third-party stack (uqmi, ModemManager, wwand) tries
to drive WDS directly and loses.

Honest scoping: this is identified from the shipped configuration + the
symptom fingerprint, decoded from the official package — we have NOT
live-verified it (we own no B14 unit and won't experiment on community
hardware). So instead of "we can walk you through it", here is the actual
guided experiment, as a **prompt you can paste into
[opencode](https://opencode.ai)** (or any coding agent) on a machine that
can reach your router. It is read-only by default; the one interventional
step is clearly marked, reversible, and requires your explicit go-ahead.

````text
I own a ZTE MF286D router whose internal modem runs firmware B14
(BD_TELIAMF286DV1.0.0B14) under OpenWrt. QMI data does not work
(uqmi/qmicli --start-network -> "Unknown error"; AT works).

Researchers suspect B14 ships a modem-side daemon, qmi_ip_multiclient
(config /etc/qmi_ip_cfg.xml, mode=multi_client, lan_clients_allowed=3),
that takes ownership of data calls away from external QMI. Help me verify,
safely, and produce a structured report they can use.

RULES:
- My device, my data: everything runs only against my router at
  <ROUTER_IP> (SSH root) and its modem (adb over the router).
- Phase 1 is READ-ONLY: no nv writes, no flashing, no service changes.
- Phase 2 changes ONE thing, only after showing me the plan and getting
  my explicit yes, and is reversible (daemon restart / reboot restores).
- Capture every command's full output to files under ./b14-probe/.

PHASE 1 — evidence (read-only):
1. Connect: ssh root@<ROUTER_IP>; confirm OpenWrt + modem version
   (ATI on the AT port; expect BD_TELIAMF286DV1.0.0B14).
2. ADB: adb devices (install android-tools on the router if needed:
   it has no internet? use its WiFi or offline-install adb). Then:
   adb shell cat /etc/qmi_ip_cfg.xml          # mode? lan_clients_allowed?
   adb shell "ps | grep -i multiclient"       # daemon running?
   adb shell ls -la /etc/init.d/ | grep -i qmi
3. Blind-spot reproducer (the key fingerprint):
   AT+CGPADDR   (expect: ~3 PDP contexts with IPs)
   uqmi -d /dev/cdc-wdm0 --get-current-settings   (expect: "Out of call")
   uqmi -d /dev/cdc-wdm0 --get-data-status
4. Dump for comparison: adb shell "cat /proc/mtd"; list /etc/init.d/;
   any cfg/nv listing tools present on the modem (read-only).

PHASE 2 — the H8 test (ONLY with my explicit approval, reversible):
5. uqmi baseline: --start-network <APN> (expect fail).
6. adb shell /etc/init.d/start_stop_qmi_ip_multiclient stop
   (if the script name differs, find it with: adb shell ls /etc/init.d/)
7. Re-run the exact same uqmi --start-network. Record the result
   verbatim — SUCCESS would confirm the mechanism.
8. RESTORE: ...start_stop_qmi_ip_multiclient start (or just reboot the
   router). Re-verify stock behavior.

REPORT — write ./b14-probe/B14-REPORT.md:
- modem fw, router fw, OpenWrt version; whether qmi_ip_cfg.xml exists
  and its full contents; daemon present/absent + its cmdline
- CGPADDR vs get-current-settings outputs (phase 1)
- phase 2: before/after start-network outputs, restore confirmation
- anything unexpected (crashes, watchdogs, LED/state changes)
Then show me the report and ask before doing anything else.
````

Post the report (or a link) either here or to our collection thread,
[conwrt issue #621](https://github.com/Amperstrand/conwrt/issues/621) —
that is where we track this platform, and structured reports there feed
directly into conwrt's device handling (the campaign tooling already
gates on modem version; a confirmed H8 means an automatic "disable the
bridge during setup" step instead of a scary warning).

## The downgrade path (proven, painful)

If you're on B14 and just want it working, the community-proven route:

1. Flash stock firmware for the router side (the ZTE update framework
   refuses to run against OpenWrt).
2. On a Windows machine, run the ZTE framework ("ZAS"-family tool) with the
   B12 delta packages — note these are **incremental**: you may need to hop
   through intermediate versions.
3. Re-flash OpenWrt afterward.
4. Restore factory defaults at least once — otherwise the router keeps
   reporting the old (NV-cached) modem version.

The eko.one.pl forum (thread id=21790, posts ~791, 803-823, in Polish)
has the step-by-step; the OpenWrt forum thread 175362 links the relevant
posts. The wiki now warns against upgrading to B14 at all.

## What we're contributing — and where this is all going

We maintain [conwrt](https://github.com/Amperstrand/conwrt), a
reverse-engineering and flashing toolkit for rescued routers. The goal
we're building toward: point conwrt at **any** old router in any state —
stock, bricked-halfway, unknown firmware, carrier-locked — and have it
**autodetect what the unit is and what state it's in, flash it to a
working OpenWrt install, and bring it up preconfigured to a chosen
profile**: network setup, the right modem datapath, eSIM profile
provisioning, and the other bells and whistles — automatically, with
safety gates at every step. The MF286D is one of the species we're
working the hardest, and the B14 question matters to us precisely
because "any old router" includes B14 units: a flow that can't reason
about B14 isn't done.

Status on this device family:

- **Done**: the ZTE download-mode transport is largely reverse-engineered
  and automated on Linux (no Windows): factory-mode web entry with the AD
  hash recipe, dload-mode client, bootloader blank-download flash path, and
  a verified full partition backup. We've used it to flash and recover
  MF286D units end-to-end, and the campaign runner now gates on the modem
  firmware version (a B14 unit gets flagged, not silently misconfigured).
- **In progress**: extending that flow to a fully automated, Linux-native
  B14→B12 modem downgrade; the eSIM provisioning piece (this modem's
  carrier policy blocks the management applet — that policy layer is our
  current research target, and this B14 dig was part of it); and the
  B14 payload decode (done — results above).
- **Honest limitation**: we don't own a B14 modem and won't risk bricking
  community hardware, so B14 validation beyond static analysis waits for
  a donor unit.

## Context pack for anyone who wants to dig (or has a B14 unit to test)

- Hardware note that confuses everyone (it confused us too): there are
  **two modem generations** in the MF286D family. B12/B14-era units (USB
  `19d2:1485`, the ID this PR pins ports for) carry a **Qualcomm MDM9650**
  modem — ADB-rooted one to confirm. The older B02-era kit hardware was
  Marvell-based (different USB composition family). Older teardowns
  floating around (including our own early notes) describe the Marvell
  one — don't cross-apply.

- B14 delta package URL pattern (the delta-finder gist by dream-svg
  automates getting a fresh link):
  `https://dleu.ztems.com/zxmdmp/download.do?doWhat=getUp&filename=firmwarepackages/DE/ZTE/MF286D/337964/TELIA_MF286DV1.0.0B12-TELIA_MF286DV1.0.1B02.up`
- Community firmware archive: `https://dl.eko.one.pl/orig/zte_mf286d/NORDIC/`
  (B12 and B14 images, including full mtd dumps)
- If you have a B14 unit + ADB: `adb shell` → dump the NV/config database
  (`cfg show` / `nv` tooling on the modem Linux), diff against the
  extracted package script above, and look for data-path / autoconnect /
  PDP policy items. `AT+CGPADDR` vs `uqmi --get-current-settings` is the
  cheapest blind-spot reproducer.
- Everything we extracted is published in our (public) conwrt repo, along
  with the tooling that produced it — the delta-container parsers and the
  payload decoder for ZTE's custom `.p` format:
  [recipes/zte/mf286d/b14/](https://github.com/Amperstrand/conwrt/tree/mf286d-b14/feat/recipes/zte/mf286d/b14)
  (branch `mf286d-b14/feat`, merging to master via PR #663; the running
  research log is [issue #621](https://github.com/Amperstrand/conwrt/issues/621)).
  The full NV script, the decoded `qmi_ip_cfg.xml`, and the 230-file
  decoded set are all there.

If you run the prompt above on your B14 unit, thank you — that is the
single most useful datapoint this platform is missing right now.
