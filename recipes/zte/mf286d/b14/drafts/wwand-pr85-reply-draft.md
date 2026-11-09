# DRAFT — reply to obsy on ddimension/wwand PR #85 (comment 6718397441)

STATUS: DRAFT — DO NOT POST. Requires human approval.
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
   fragment from the `.up`; we pulled the full 30-item script:
   ```
   nv set net_select="Only_LTE"
   nv set default_lte_band_lock="0x2008080045"   # B1/B3/B7/B20/B28/B38
   nv set default_gw_band_lock="0x2000000400000"
   nv set lte_band_lock="0x2008080045"
   nv set gw_band_lock="0x2000000400000"
   ... (25 more — full list in our repo, link below)
   ```
   Notable members: the LTE-only RAT lock above, a data-stall watchdog,
   and the modem version identity itself.

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
hardware). Two things would confirm: (a) checking whether a B12 modem
lacks the daemon or runs it in single-client mode (on our bench, next
session), and (b) any B14 owner running, over ADB (works on B14, see
forum): `cat /etc/qmi_ip_cfg.xml` and trying
`/etc/init.d/qmi_ip_multiclient stop` (or editing the config to
`single_client`) before bringing the interface up. If that restores QMI
control, the fix is a config change — no downgrade needed. We can walk
anyone through it.

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

## What we're contributing

Hardware note first, because it confuses everyone (it confused us too):
there are **two modem generations** in the MF286D family. The B12/B14-era
units (USB `19d2:1485`, the ID this PR pins ports for) carry a **Qualcomm
MDM9650** modem — ADB-rooted one this weekend to confirm. The older B02-era
kit hardware was a Marvell-based generation (different USB composition
family, `19d2:1489`-class). Older teardowns floating around (including our
own early notes) describe the Marvell one — don't cross-apply.

We maintain [conwrt](https://github.com/Amperstrand/conwrt) — a
reverse-engineering and flashing toolkit for this device family. Status:

- **Done**: the ZTE download-mode transport is largely reverse-engineered
  and automated on Linux (no Windows): factory-mode web entry with the AD
  hash recipe, dload-mode client, bootloader blank-download flash path, and
  a verified full 22-partition backup including the modem partitions. We've
  used it to flash and recover MF286D units end-to-end.
- **In progress**: extending that flow to a fully automated, Linux-native
  B14→B12 modem downgrade — the missing pieces are the modem-partition
  update path mapping and the `.up` package layout (we're unpacking the
  B14 package now).
- **Honest limitation**: we don't own a B14 modem and won't risk bricking
  community hardware, so our contributions are reverse engineering and
  simulation until we can validate on our own bench unit.

## Context pack for anyone who wants to dig (or has a B14 unit to test)

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
- We'll publish our firmware diff and the full NV script extraction on the
  conwrt repo (issue #621) as they land.

Happy to coordinate with anyone holding a B14 unit — the read-only probe
list is short and we can walk through it.
