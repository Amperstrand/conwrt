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

TASKS (priority order):
1. **E1 — decode the ZFD .p stream** (the 17-byte prologue 5D 000002 0000 2114
   C48AF63F 042FF85A 93 then divergent bytes; LZMA props but not plain LZMA).
   Find the delta-apply engine inside kit images (`~/mf286d-work/kit/UPDATE/
   mdm9650-*.ubifs/ubi`, `mdm-image-mdm9650.ubifs`) or router dumps
   (`~/mf286d-re/fw/nordic-B14/mtd8.bin`) — mount/unsquash, locate the updater
   binary (strings: "ZFD01", "NORMDIFF", "fsdelta.bin"), reverse the hunk
   format, write a standalone applier. Verify on Ver_Info.txt.p (178 B target).
2. **D4 support — B12 modem baseline**: if the RE session has produced the mtd9
   (modem) + mtd2 (efs2) dumps by now, use them as delta bases; else check
   `~/mf286d-re/` for new arrivals. Kit MDM9650 images are a fallback base of
   unverified provenance — verify version strings before trusting.
3. **E2/E3 — diff the policy payloads**: dsi_config.xml old-vs-new; Telia_SWE
   mcfg_sw.mbn old-vs-new (MCFG tooling leads in /tmp/opencode/b14/research/
   REPORT.md if present, else research fresh: "mcfg_sw.mbn extract tool").
   Classify every diff item: data-path/PDP/autoconnect/QMI-relevant or not.
4. **Update FINDINGS.md** hypothesis verdicts (H2 firmware-stack vs H3
   carrier/EFS policy vs H1-NV — H1 strong form already refuted) and re-rank.
5. If a B14 bench unit becomes available: run the D1–D3 live probes listed in
   FINDINGS.md §4 (adb NV/EFS dump before/after factory reset; QMI WDS trace;
   selective revert of dsi_config/MCFG/EFS).
6. Report to the overseer: `herdr agent prompt w1:p5H '<summary>'`.

CONSTRAINTS REMINDERS: species-level facts only in anything community-facing;
drafts land in files for human approval; time-box acquisition attempts
(≤10 min per path); if a decode rabbit-holes >45 min, bank partial state in
FINDINGS.md and move on.
