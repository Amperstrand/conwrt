# ZTE MF286D — dload-mode bring-up notes (session 2026-11-03)

Species-level only (unit identifiers → private project). Sources: live bench
session on a Telia B09 unit (BD_TELIAMF286DV1.0.0B09, B10/Nordic matrix),
real ZAS tool in a WinPE/KVM oracle, full wire capture. Evidence bundle and
the oracle analysis live on the bench host (`mf286d-vm/ORACLE-ANALYSIS.md`).

## Environments (empirical state taxonomy)

| Env | How entered | Network | Services |
|---|---|---|---|
| E1 stock | normal boot | `192.168.0.1` (carrier config), DHCP **server**, answers ICMP | full goahead web |
| E2 factory-goform | stock-side `SwitchFactoryMode&Open` + `REBOOT_DEVICE` (fresh AD), or any power-cycle while the flag is armed — **flag is sticky across power cycles** | DHCP **client**, wants `192.168.32.1` | goform: Open/Query/Close only (all other verbs → `{"result":"failure"}`) |
| E3 download-env | **hardware factory-reset** (hold RESET ~10–15 s) | DHCP **server** + DNS + HTTP at `192.168.32.1` | goform cycles `FactoryResult: Closed`↔`Opened`; DNS resolves `cndms.ztems.com` → `192.168.82.3` |

Per-port source MACs: the switch presents a different adjacent MAC per physical
LAN port (observed two adjacent addresses in the OUI block, same last bytes).
The dload-family environments only brought up **LAN port 1** on our bench —
bench the unit from port 1.

## Proven entry mechanics (native, no Windows)

```
pw_hash = sha256hex(base64(web_password)).upper()          # LOGIN (goform_set_cmd_process)
AD      = md5hex_lower(md5hex_lower(wa_inner_version + cr_version) + RD)
# fetch wa_inner_version,cr_version,RD via goform_get_cmd_process (multi_data=1)
# stock side: SwitchFactoryMode&SwitchCMD=Open&AD=... -> FactoryResult:Success
# RD ROTATES after Open — re-fetch and recompute for REBOOT_DEVICE
# REBOOT_DEVICE with fresh AD -> reboots into E2
# E2 side: same AD recipe; Query -> FactoryResult:Opened; Close -> Success
```

Version matrix via `goformId=ONLINE_UPGRADE_TOOL&command=get_current_version`
(`$$PRODUCT;;wa;cr;Nordic_x;hw;IMEI` — GoAhead-Webs, HTTP/1.0).

## Transport (the open problem)

The real ZAS tool (BL_DL_LTE_QualComm_Net plugin), after its goform phase,
sends a **440-byte ISAKMP-framed proprietary opener** (vendor payload types
0x85/0x87, replayable hex captured) to **udp/500** at the device ~1/s with
backoff, and also probes udp/69 (E2 answers those with ICMP-unreachable).
Observed in E2 and E3: **nothing answers**. The responder and/or the final
device-side transition has not been identified. The tool's Start UI action
(right-click row → "Start Update.") was never conclusively engaged through
the oracle's input channel — that experiment is first in line next session.

Tool-side transport targeting rule (L3): the dload subnet must contain ONLY
the tool host and the device — the tool adopts any third address (including
a DHCP server-id) as a transport target. Do not run a DHCP server on `.32.x`
while the tool is active; the tool host leases from the device in E3.

## Oracle (WinPE/KVM) operational recipe

- OVMF boot, **3072 MB RAM minimum** (boot.wim = 1.9 GB loaded to RAM; 1.5 GB
  VMs die with "Windows failed to start")
- `systemd-run --property=MemoryMax=5G` to escape session memcg/earlyoom
- Hot-add absolute pointer via monitor: `device_add qemu-xhci` + `device_add
  usb-tablet` — vncdotool clicks only land after this
- Drive keys via QEMU monitor `sendkey`; **write .bat files into the FAT kit
  image instead of typing long commands** (keystroke injection is lossy)
- Kit: `APP_CONFIG_NAME=MF287+-DL-BackUpNV-N-01_DL.config` is the
  field-proven choice (matches the community kit's own ini); `root_uImage`
  sha256 per kit SHA256SUMS; SW PATH must match the drive letter PE assigns
  (C:, not D:)

## Post-flash planning notes

- OpenWrt default LAN = `192.168.1.1` — collides with other bench routers;
  first-boot re-IP the unit from its isolated bridge before merging onto any
  shared bench network.
- Field post-flash config (eko.one.pl thread 24403): WAN proto qmi
  (`/dev/cdc-wdm0`), carrier APN, **PAP auth for T-Mobile-class SIMs**;
  eko.one.pl serves ipq40xx zte_mf286d images; 4IceG/Modem-extras for band
  management.
