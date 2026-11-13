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
| mcm_ril_service | -320B | rebuild churn* | no — zero .text changes |
| netmgrd | +32B | DATA port renames | minor — port naming only |

*String-diff analysis of mcm_ril_service initially suggested 3,479 lines of
changes; the completed ZTE-BSDIFF40 patch format (EXP-039: backward-seek
flag) proves ALL 559 patches apply to .text sections with zero code changes —
the string differences were prelink address churn from recompilation.

## Mechanism

B14's QMI breakage under OpenWrt is a **protocol-level incompatibility**
between the new MPSS baseband (00628→00735) and external QMI clients.

1. The new MPSS (00735) changed its QMI WDS behavior on the external/USB
   QMI bridge interface.
2. The modem-Linux userspace — including mcm_ril_service, qmi_ip_multiclient,
   QCMAP, and ALL init scripts — is functionally IDENTICAL between B12 and B14.
3. Stock firmware works because its data path uses the INTERNAL transport
   (SMD/glink channels), not the USB QMI bridge that external clients use.
4. External QMI clients (uqmi, ModemManager, wwand) speak to the USB QMI
   bridge — the interface where the new MPSS changed its WDS behavior.
5. NAS/UIM/AT still work (those services use the same bridge but didn't
   change in the new MPSS); only WDS broke.

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
