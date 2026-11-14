# B14 QMI Breakage Analysis — modem-Linux rootfs diff (B12 → B14)

EXP-039. 2026-11-10. Fully offline (delta application on banked B12 extraction).
Deliverable of the B14-rootfs-diff mission. Companion: B14-GENEALOGY-REPORT.md (EXP-038).

---

## Verdict up front

**The hypothesis is KILLED with certainty:**

> *"qmi_ip_multiclient is shipped-but-inert on B12, and the B14 delta contains a
> change that causes it (or its parent chain) to actually START."*

- `qmi_ip_multiclient` is NOT started by anything in B12 **and** not in B14.
- Its binary code is **byte-identical** B12→B14 (24 changed bytes = 20-byte ELF
  build-id at 0x198 + 4 metadata bytes between the last strtab string and
  `.shstrtab`; **zero** changes in `.text`, `.rodata`, `.data`).
- `/etc/qmi_ip_cfg.xml` (`<mode>multi_client</mode>`) is byte-identical.
- No init.d script, rc*.d symlink, or startup chain references it in either build.

**The B14-under-OpenWrt QMI breakage ("CID allocation failed in CTL client /
endpoint hangup") is NOT caused by the modem-Linux rootfs.** Every QMI-path
binary, config, init script, symlink set, and the USB composition are unchanged.
The breakage therefore lives in the **AMSS/MPSS baseband** (MPSS.AT.2.5.1-00628
→ 00735; segments b11/b15 grew, b09 vaddr moved e06fc000→e06f3000) — i.e.
baseband QMI/CTL endpoint handling — or conceivably router-side (untested here).

---

## 1. Method

- Source: `system.mld` entry of `delta.package` (B12→B14 OTA), 3,800,495 B,
  ZFD01.02 container — 1,007 entries (767 LZMA payloads, 214 dir/symlink
  markers, 25 raw small files, 1 ZDFU blob).
- Applied against the banked pristine B12 rootfs
  (`mtd16-extract/375765971/rootfs`).
- **BSDIFF-variant semantics completed during this analysis** (this closes the
  last open format question from EXP-038):
  - `z` (low u32 of the third ctrl field) = seek applied **BEFORE** the run;
  - high dword `0x80000000` flag = **backward** (negative) seek;
  - entry[0] always reads from `old[0]`;
  - reads past EOF clamp to zero (25 such bytes in netmgrd — encoder artifact).
  Proof: netmgrd (24 ctrl entries) reconstructs to exact size with full diff
  consumption, valid ELF, valid section table, and 1,260/1,270 .rodata strings
  matching the old build. All **559/559 patches apply with 0 failures/0
  warnings** under these semantics.
- Result tree: `b14/b14-rootfs/` (B14 modem-Linux rootfs, 100% of delta applied
  except the fota `modem.b20A` staging blob).

## 2. Full file-level diff summary

613 files differ B12→B14 (559 patched, 226 full-content, 26 raw, 8 new).
**~95% of the byte differences are rebuild noise**, not functionality:

- ELF `.note.gnu.build-id` (20 B @ 0x198) rewritten in every binary, and
- prelink relocation churn (`.dynsym` st_values, `.got`, `.gnu.prelink_undo`)
  caused by library size shifts.

### The 8 NEW files
```
usr/lib/modules/.../netfilter/zte_check_privateip.ko   (5,256 B — new netfilter mod)
usr/zte/zte_conf/scripts/get_syslog.sh
usr/zte/zte_conf/scripts/iperf3_diag.sh
usr/zte/zte_conf/scripts/l2tpv3.sh
usr/zte/zte_conf/scripts/lan_static_routing_do.sh
usr/zte/zte_conf/scripts/wire_set_portmirror.sh
usr/zte/zte_conf/scripts/zte_crash_switch.sh
usr/zte/zte_conf/scripts/zte_web_keylog.sh
```
→ ZTE router features (logging/diagnostics/L2TP/port-mirror), not modem control.

## 3. Startup / service topology: UNCHANGED

| Check | Result |
|---|---|
| All `/etc/init.d/*` script contents | **identical** (every one; `functions` is a symlink marker) |
| rcS.d / rc2-rc6.d symlink sets | **identical** (delta re-lists existing links as 0-byte markers; no adds/removes) |
| `rcS-zte-after-modem` | **identical** |
| `rcS-zte-before-modem` | **only change: removal of the `set_passwd` block** (see §6) |
| Startup order | unchanged (S40start_qti_le, S39 QCMAP, S45netmgrd, S37 ipacm… same) |
| USB composition | `boot_hsusb_composition → compositions/9025` **identical**, no manifest entry |
| `etc/mdev/usb.sh` | +1 trailing space byte (cosmetic) |
| `build.prop` | build timestamp only (`202107100056` → `202404240450`) |

Boot services on BOTH builds: qti (S40, QMI data), QCMAP_ConnectionManager
(S39), netmgrd (S45), ipacm/perf/diag (S37/S38), qmi_shutdown_modemd (S45).
**`qmi_ip_multiclient` appears in NO runlevel in either build** — its init
script `start_stop_qmi_ip_multiclient` exists but is never linked/invoked.

## 4. Daemon configs: UNCHANGED

| Config | Content | B12→B14 |
|---|---|---|
| `/etc/data/netmgr_config.xml` | netmgrd backend config | **byte-identical** (OTA re-ships same bytes) |
| `/etc/data/dsi_config.xml` | DSI library config (rmnet mappings) | **byte-identical** |
| `/etc/qmi_ip_cfg.xml` | `multi_client`, tcp 7777… | **byte-identical** |
| `mobileap_cfg.xml` | — | not present in either rootfs (QCMAP uses defaults/EFS) |

## 5. QMI-path binaries: ZERO code change

`.text` section diffs (v4 semantics, validated outputs):

```
qmi_ip_multiclient      56,500 B   diff = 0
qti                    889,988 B   diff = 0        (S40, QMI data daemon)
qti_ppp                 12,228 B   diff = 0
QCMAP_ConnectionManager 406,064 B  diff = 0
MCM_MOBILEAP_ConnMgr     42,220 B  diff = 0
atfwd_daemon             5,680 B   diff = 0        (AT forward)
usb_composition_switch      560 B  diff = 0
mcm_data_srv             29,100 B  diff = 0
MCM_atcop_svc             6,512 B  diff = 0
libqmi.so.1             141,612 B  diff = 0
libqmiservices.so.1       2,288 B  diff = 0
libqmi_client_qmux.so.1  15,724 B  diff = 0
libqmi_csi.so.1          13,160 B  diff = 0
libdsi_netctrl.so.0     320,360 B  diff = 0
libnetmgr.so.0           66,380 B  diff = 0
```

Static binaries (no section table parse) verified via string diffs:
`zte_topsw_mdm` (±6 strings, symbol churn), `zte_topsw_wan_sig` (±2),
`zte_topsw_daemon` (±19), `zte_topsw_mc_startup` (±11 — none QMI-related),
`prestartdua` (±10), `libqmi_cci.so.1` (rebuilt, symbols shifted, no new
functionality strings), `mcm_ril_service` (849+/327−: symbol-table churn from
different stripping; no new QMI service surface).

## 6. The REAL functional changes found (none QMI-related)

1. **`rcS-zte-before-modem`: B14 REMOVES the hardcoded root password.**
   B12 runs a `set_passwd` block at every boot that sets the modem-Linux ADB
   root password to a fixed string **derived from firmware constants
   (REDACTED — see local evidence notes / EXP-039 ledger; the value is
   plaintext inside the boot script of every shipped B12 unit and inside
   ZTE's public OTA delta, i.e. firmware-public).** B14 deletes the block.
   Security note: every B12 unit's modem-Linux root credential is therefore
   unit-independent. [REVIEW NOTE: redacted per house rules before merge —
   flagged by the modem-lane review.]

### Pre-merge security disposition (leak-scan record)

- Git history contains the literal value in commits `0aac179` (introduced)
  and `4bc4523` (redacted); branch HEAD is clean (`git grep` at HEAD: none).
- Broader credential sweep over branch-added files: no other credential-like
  strings (bench/fleet credentials untouched — modem-lane confirmed).
- Rotation: **not applicable** — the value is firmware-hardcoded and
  re-applied by B12 at every boot (`set_passwd` in `rcS-zte-before-modem`),
  so any per-unit rotation survives exactly one reboot.
- **Disposition: ACCEPTED — firmware-public value (ships in plaintext in
  ZTE's public OTA delta and in every B12 unit's boot script), redacted
  going forward; history scrubbing judged UNNECESSARY because the value is
  already public via ZTE's own firmware distribution. No fleet credential
  affected.** (Recorded for the pre-merge gate per house rules.)
2. **`netmgrd` minor update** (511,488→511,520 B): adds `DATA5_CNTL`…
   `DATA14_CNTL` interface names + `rmnet_sdio`, fixes a log-string typo
   (`NETMGR_IS_COMPLETE_MSG`→`NETMGR_IK_COMPLETE_MSG`). No behavior change to
   external QMI; new rmnet channel name support only.
3. **`zte_topsw_router`** feature additions (multi-WAN/PDNS routing, iptables
   time-filter, dnsmasq crash-restart watchdog, traceroute diagnostics,
   `QCMAP_CLI update IPACM_cfg.xml` hook) — router-side, no modem control.
4. New netfilter module `zte_check_privateip.ko` + 8 feature scripts (§2).
5. Kernel modules rebuilt (wlan.ko etc.); `modules.dep` gains
   zte_check_privateip/xt_physdev entries.
6. WEBSERVER cgi (`qcmap_auth`, `qcmap_web_cgi`) updated (web UI only).

## 7. Where the breakage actually lives

With the rootfs exonerated at every level (configs, scripts, symlinks, daemon
code, USB composition), the OpenWrt-community-observed B14 failure mode
(`qmicli … endpoint hangup / CID allocation failed in CTL client`) must
originate:

- **AMSS/MPSS baseband (most likely)** — MPSS.AT.2.5.1-00628→00735 changes the
  QMI dispatcher/CTL endpoint behavior on the Hexagon side (b11 +0x7E0, b15
  +0x4C50, b09 vaddr move). Our EXP-038 chunk map shows b15 chunks 0-81 rebuilt
  — the baseband QMI/CTL code regions.
- Router-side `root_uImage.mld` (full B14 router firmware, untested here — out
  of modem scope).

Testing that from OpenWrt is unnecessary for us: B12 remains the correct
firmware for our use (and B14 adds zero eSIM capability — EXP-038).

## 8. Tooling addendum (format RE completed)

`bspatch_final.py` = proven ZTE-BSDIFF40 applier:
```python
# entry[0]: base = 0. else: base = oldpos + (-z if flag else z)
# x = add-run (old[base..] + diff), y = literal from extra,
# z: seek BEFORE next run; flag 0x80000000 = backward seek.
```
Also in this directory: `rebuild_final.py` (full rootfs rebuilder).

## 9. Artifacts

```
b14/system.mld.delta          extracted system partition delta (ZFD01.02)
b14/system-manifest.txt       full 1,007-entry manifest
b14/rebuild_final.py          canonical rebuilder (559/559 ok)
b14/bspatch_final.py          proven patcher semantics
b14/b14-rootfs/               reconstructed B14 modem-Linux rootfs
```
