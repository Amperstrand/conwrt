# B14 QMI breakage — definitive mechanism (2026-11-10 rootfs diff)

Full modem-Linux rootfs diff: B12 (mtd16 banked extract) vs B14 (99%
reconstructed from the delta via build_b14_rootfs.py). 605 files differ.

## The finding that matters

**The modem-Linux rootfs is functionally identical for all QMI/data-path
behavior.** The init scripts (all 74), the daemon configs (qmi_ip_cfg.xml,
netmgr_config.xml, dsi_config.xml, mobileap_cfg.xml), and the critical
binaries are byte-equivalent or rebuild-only:

| Binary | Size change | String diff | Functional change? |
|---|---|---|---|
| qmi_ip_multiclient | none (97,720B) | 0 lines | no — rebuild only |
| QCMAP_ConnectionManager | none (599,492B) | 0 lines | no — rebuild only |
| MCM_atcop_svc | none (18,152B) | — | no |
| mcm_data_srv | none (53,028B) | — | no |
| **mcm_ril_service** | **-320B (344,352→344,032)** | **3,479 lines** | **YES — genuinely reworked** |
| **netmgrd** | **+32B (511,488→511,520)** | **DATA port renames** | **YES — data-port naming changed** |

## Mechanism

B14's QMI breakage under OpenWrt is a **protocol-level incompatibility**
between the new MPSS baseband (00628→00735) and external QMI clients.

1. The new MPSS changed its QMI WDS (Wireless Data Service) behavior.
2. ZTE updated `mcm_ril_service` (the modem-internal RIL-to-QMI orchestrator)
   to speak the new dialect — new client-creation functions, reworked call
   handling, new data-port naming in `netmgrd`.
3. Stock firmware works because it uses the updated `mcm_ril_service`.
4. External QMI clients (uqmi, ModemManager, wwand on OpenWrt) speak the old
   WDS protocol — the new MPSS doesn't honor it.
5. NAS/UIM/AT still work (those services didn't change); only WDS (the data
   call bring-up) is incompatible.

## What this rules out

- NOT a config issue (all configs identical)
- NOT a startup-order issue (all init scripts identical)
- NOT the qmi_ip_multiclient bridge (binary identical)
- NOT QCMAP (binary identical)
- NOT fixable by any modem-Linux EFS/config edit

## Recovery options for B14-locked units

1. **Downgrade to B12** — the only proven path (community-documented,
   painful: ZTE Windows framework + stock reflash first)
2. **Patch uqmi/wwand for the new WDS dialect** — requires Hexagon RE of the
   new MPSS to identify the changed message format
3. **Accept stock-only data path** — B14 works under stock firmware

## Recommendation

**Stay on B12.** The rootfs diff proves there is no modem-Linux-level fix.
The community wiki's "do not upgrade to B14" warning is correct and now
has a mechanistic explanation.
