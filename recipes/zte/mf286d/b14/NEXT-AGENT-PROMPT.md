# NEXT-AGENT-PROMPT — MF286D B14 continuation (ready to run)

Copy-paste this as the session prompt for the next B14 research session.
Predecessor: 2026-11-09 40-min spike; read `~/mf286d-work/evidence/b14/FINDINGS.md` FIRST (state, artifacts, hypotheses, roadmap).

---

MISSION: B14 follow-up dig, software-only, zero external interactions (downloads
for research fine; no posts/comments anywhere). Do not modify anything under
`~/mf286d-work/evidence/modem-fw-re/` (live RE session owns it — read only). Do
NOT git commit (overseer owns the conwrt lane). Artifacts:
`~/mf286d-work/evidence/b14/` (+ `/tmp/opencode/b14/` if still present).

BASELINE FACTS (do not re-derive, do not contradict):
1. The B14 package `TELIA_B12-V1.0.1B02.up` is acquired + hashed at
   `~/mf286d-work/evidence/b14/` (sha256 7df293bd…). Direct ZTE DMS URL works.
2. It unpacks (ZIP → delta.package container → 15 .mld blobs → ZFD01.02
   per-file deltas). Parsers exist: `parse_delta.py`, `scan_zfd.py`.
3. Full 30-item NV script extracted (`unpacked/cpe_postprocessing.sh`) — no
   autoconnect/QMI item in it; NV-cached version identity explains the
   "still shows B14 after B12 flash" effect.
4. B14 changes: modem AMSS (modem.b00–b28, big deltas b08/b10/b11/b15/b19),
   modem-Linux data-path stack (dsi_config.xml, libqmi_cci/csi/sap,
   mcm_ril_service, zte_adapter_ppp/cfg, libztecmdq), 119 MCFG carrier files
   incl EU/Telia/Telia_SWE, and modem EFS (efs.mld: fsdelta.bin/config_1.p,
   config_2.p). Manifests in `evidence/b14/manifests/`.
5. The `.up`-internal SYSJ/ARBI Marvell tree at modem-fw-re/extracted is B02-kit
   Marvell — NEVER baseline against it. Live B12 modem = Qualcomm MDM9650.
6. No B12 modem flash dump exists yet.

TASKS (priority order — NOTE: ZFD decode is SOLVED, see FINDINGS.md §S9 +
zfd_decode.py; decoded payloads in /tmp/opencode/b14/decoded2/, key files in
evidence/b14/decoded/):
0. **E9 — Telia MCFG, no baseline needed**: clone
   `github.com/sbaresearch/mbn-mcfg-tools`, run `mbn-tool -e` on
   `decoded2/raw__modem.mld_..._EU_Telia_MF297D_Telia_SWE_mcfg_sw.mbn.p.payload`
   (ships FULL-FILE in the B14 package). Read Data_Profiles + policyman
   carrier_policy.xml for Telia data-call policy. Update H3.
1. **E8 — qmi_ip_multiclient provenance (H8, top hypothesis)**: confirm
   whether B12 ran `/usr/bin/qmi_ip_multiclient` with `/etc/qmi_ip_cfg.xml`
   (`lan_clients_allowed=3` in B14; 3 == the PDP contexts users see). Check
   manifests/system-scan.txt, then the D4 dump when it exists.
2. **D4 support — B12 modem baseline**: if the RE session has produced the mtd9
   (modem) + mtd2 (efs2) dumps by now, use them as bsdiff bases; else check
   `~/mf286d-re/` for new arrivals. Then **E10**: LZMA-decode all 642 bsdiffs
   and `bspatch` them vs B12 → full B14 modem-Linux tree → wholesale diff.
3. **E11 (bench, if a B14 unit appears)**: `adb shell` — kill/reconfigure
   qmi_ip_multiclient (single_client mode), retest uqmi/wwand QMI WDS.
   Potential fix-without-firmware-change; highest community value.
4. **Update FINDINGS.md** hypothesis verdicts (H8 bridge > H2 stack > H3
   carrier; H1-NV strong form refuted) and re-rank.
5. Report to the overseer: `herdr agent prompt w1:p5H '<summary>'`.
6. Report to the overseer: `herdr agent prompt w1:p5H '<summary>'`.

CONSTRAINTS REMINDERS: species-level facts only in anything community-facing;
drafts land in files for human approval; time-box acquisition attempts
(≤10 min per path); if a decode rabbit-holes >45 min, bank partial state in
FINDINGS.md and move on.
