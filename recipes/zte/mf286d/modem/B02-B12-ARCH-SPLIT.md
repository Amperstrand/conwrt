# B02-kit ↔ live-B12 architecture split (modem-Linux side)

> [Contributed by the modem-lane cross-session analysis (w1:p5V), 2026-11-09.
> Cross-linked into FINAL-STATUS per its review note (b).]

# B02-kit ↔ live-B12 diff — modem-Linux (mtd16/system) side

2026-11-09, host-side, read-only on the EXP-034/035 evidence tree.
Compared: `evidence/modem-fw-re/extracted/sysj-root` (B02 kit rootfs) vs
`evidence/modem-fw-re/live-b12/dumps/mtd16-extract/375765971/rootfs`
(live BD_TELIAMF286DV1.0.0B12). Pulled binaries in `live-b12/` verified
byte-identical to the flash copies (zte_adapter_sim sha256 match).

## Findings

1. **atcmdsrv DOES NOT EXIST in B12** — no file, no string reference, in any
   mtd16 volume (rootfs/fwfs/ztedata). The B02 monolith was restructured:
   B12 runs `atfwd_daemon` (started by `etc/init.d/misc-daemon` →
   `start_atfwd_daemon`, start-stop-daemon lines present) plus the
   `zte_topsw_*` family (`rcS-other`: wlan, pbm, diag, mmi, devui…).
   ⇒ **The B02-kit address maps in ANALYSIS.md §3/§5 (atcmdsrv SIM_RestrictedAccess
   @0x46FCC, QMI registry @0x99A1D, ciRequest @0x5E23C, prim-0x2C wrapper
   @0x5FA44) do NOT transfer to the live unit.** The B12 equivalents must be
   re-located in `atfwd_daemon` / `zte_topsw_atfwd` / `zte_adapter_sim`.

2. **zte_adapter_sim grew 72% and gained a QMI IDL UIM client layer**
   (B02 25,014 B / 2019 → B12 43,144 B): new strings include
   `zte_mdm_qmi_idl_uim_register`, `uim_get_service_object_internal_v01`,
   `QMI_UIM_REFRESH_IND_V01 has been received`, `qmi_uim_ind: …`,
   `ZTE_ADAPTER_MDM_UIM_{REFRESH,STATUS_CHANGE}_EVENT` IPC notifications.
   The UIM plumbing changed materially between versions — B12's SIM adapter
   is a real QMI UIM client, not just a CI pipe.

3. **No LPA/eSIM machinery in the B12 modem-Linux AT layer**: zero hits for
   downloadprofile / euicc / lpa / esim / csim / ccho across
   `zte_adapter_sim`, `atfwd_daemon`, `zte_topsw_atfwd`; no `lpad` file or
   string anywhere in mtd16 (minidlna/jquery hits are substring false
   positives). **If the `-lpad` sighting is real, it lives CP-side — the
   pending mtd9 UBI extraction is the right place to look** (mtd9.img is a
   UBI image, 74,448,896 B; mtd9-blocks.pkl suggests extraction state).

## Implications for the campaign

- **Version-shopping deprioritized**: B02→B12 is not "older same-code" — the
  exact subsystem of interest was restructured. A B02 modem flash would
  behave differently (possibly better, possibly worse), but it is a
  cross-architecture downgrade experiment, not a clean A/B. Only worth it
  after live-B12-native RE (mtd9 + the three B12 binaries) is exhausted.
- **§7c live plan update**: CI-primitive direct test (`/dev/ccidatastub`)
  should be re-targeted at the B12 process set; the struct layouts in §7c
  were derived from B02 atcmdsrv and need re-validation against
  atfwd_daemon/zte_topsw_atfwd first.
- Zyxel prior-art cross-ref (PR #666 §3c): in production CPEs the LPA is an
  OEM-layer, on-demand-spawned helper — if ZTE follows the same shape, the
  `-lpad` caller would sit in the B12 data/goform layer (WEBSERVER/www exists
  in mtd16 rootfs), not the AT layer.

Artifacts: this file only (analysis was in-place, read-only; no writes to the
EXP-034/035 tree).
