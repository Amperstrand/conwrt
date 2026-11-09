# MF286D B14 — continuation research kit (for a future agent)

Queue prompt (token-burn lane). Written 2026-11-09 at the end of the
time-boxed B14 spike. This prompt is SELF-CONTAINED: everything the next
agent needs is here or in the artifact paths below.

**Campaign framing**: the main fleet work is device 1 + device 2 — both run
B12 modem firmware (the known-good) and are NOT to be updated. B14 is a
separate research thread answering the community question
(ddimension/wwand PR #85, obsy): *"can the modem work with B14 firmware?"*
No B14 unit exists on our bench and we will not risk community hardware:
this thread is reverse engineering + simulation until one arrives.

## State of knowledge (2026-11-09 spike, all verified on artifacts)

- The "Nordic_B14" `.up` package is ACQUIRED and unpacked:
  `~/mf286d-work/evidence/b14/TELIA_B12-V1.0.1B02.up`
  (sha256 `7df293bd…dc9dc9`, 23.9 MB zip) → `evidence/b14/unpacked/`.
  Contents: `root_uImage.mld` (router V1.0.1B02 image + signatures +
  `public_ver.pem`), `delta.package` (13.2 MB), `cpe_postprocessing.sh`
  (the FULL 30-item NV script — community had only 5 items).
- `delta.package` = 15 `.mld` blobs. `modem.mld` = ZFD01.02 per-file delta,
  **163 files**: full AMSS re-delta (modem.b00–b28 + mba), WLAN firmware,
  and **119 MCFG carrier files** including EU/Telia/Telia_SWE +
  `mcfg_sw.mbn.p` (the Telia carrier policy file is PATCHED in B14).
- `system.mld` touches the **data-path stack directly**: `dsi_config.xml`,
  `libqmi_cci/csi/sap`, `mcm_ril_service`, `zte_adapter_ppp/cfg`.
- Modem hardware (live-proven via ADB root on device 1, same day):
  **Qualcomm MDM9650**, msm baseband, kernel 3.18.31 (Jul-10-2021 =
  B12 build), UBIFS root; `/proc/mtd` on modem: modem = 71 MB (mtd9),
  efs2 = mtd2. Do NOT use `~/mf286d-work/evidence/modem-fw-re/extracted/`
  as a B12 baseline — that is the B02-kit **Marvell** generation artifact
  (different modem family; its conclusions do not transfer).
- Community symptom matrix + sources: see `recipes/zte/mf286d/notes.md`
  (B14 section). Key repro: `AT+CGPADDR` shows active PDP contexts while
  QMI WDS reports "Out of call" — the modem's data engine runs sessions
  external QMI cannot see/stop/start.

## Hypotheses (ranked; update with evidence, don't assume)

- **H2 — firmware data-path stack change** (NEW, strongest): B14 ships
  changed data-path components (`dsi_config.xml` = Qualcomm DSI data-call
  config; `libqmi_*` = the modem's own QMI framework; `mcm_ril_service`,
  `zte_adapter_ppp`). The external QMI WDS interface behavior changed in
  firmware. Test statically FIRST: extract old-vs-new `dsi_config.xml` and
  diff; check `libqmi` version strings; check `mcm_ril_service` strings
  for WDS/start-network handling changes.
- **H1 — modem-internal autoconnect via NV/MCFG**: the 30-item NV script +
  patched Telia MCFG flips data-call ownership to the modem (stock uses
  ZTE's internal bring-up; external hosts conflict). Explains the PDP/CGPADDR
  blind spot. Test: map all 30 NV items + the 119 MCFG files against
  Qualcomm's data-call policy taxonomy; look for autoconnect/always-on/PDP
  policy keys.
- **H3 — carrier-policy gating**: the patched Telia MCFG enables a policy
  that only the stock host satisfies (e.g. requires ZTE's connection
  manager handshake). Test: diff Telia mcfg payload vs the EU/generic one
  shipped in the same package — the delta between carrier variants
  localizes Telia-specific policy.

H1–H3 are not mutually exclusive; B14 likely combines them.

## Experiments (each: how, expected outcome per hypothesis, cost)

Static (no hardware):
1. **E1 dsi_config.xml diff** — extract from `system.mld` (B14) vs any B12
   source (see blockers); diff. Expect H2: changed call-config defaults.
   Cost: hours.
2. **E2 AMSS delta inventory** — enumerate the 163 files' deltas
   (sizes/change-ratio); identify which AMSS images actually differ vs
   re-packed. Expect: small true-change set → tractable RE target. Cost: 1h.
3. **E3 NV-30 meaning table** — map each `cpe_postprocessing.sh` NV item
   to Qualcomm NV taxonomy (public NV item lists / AOSP `nv_items`);
   classify: RAT-lock / band / data-path / SIM-policy / other. Cost: 2h.
4. **E4 MCFG carrier diff** — Telia vs EU vs Telia_SWE payloads in the
   package; localize carrier-specific policy. Cost: 2h.
5. **E5 signature chain** — `public_ver.pem` + `*.signature` files: what
   is signed and how (answers whether a community-fixed package is even
   installable — relevant to the downgrade prompt 02). Cost: 1h.

Dynamic (requires a B14 unit — NOT on bench):
6. **E6 ADB probes** — `adb shell` works on B14 (community-evidenced):
   `getprop`/`cfg show`/NV dump; compare against device 1's B12 dumps
   (capture the B12 side FIRST — see prerequisites).
7. **E7 QMI WDS differential trace** — qmicli/uqmi transcript on B14 vs
   device 1's B12 baseline (we hold B12 transcripts from EXP-029/030 era);
   localize the first divergent message.
8. **E8 targeted NV/MCFG flips** — on a B14 unit, flip candidate items
   (from E3/E4) one at a time, reboot, re-run E7. ONLY with operator
   approval + full modem backup first (brick-class caution).

## Prerequisites / blockers (do these FIRST when picked up)

1. **Dump device 1's modem flash over ADB** (`adb pull` or dd of mtd9 +
   efs2; ~71 MB). NO B12 modem flash image exists anywhere — the verified
   22-partition backup (`ai-legion:/home/ubuntu/mf286d-backup-20261107/`)
   is router-side only. Coordinate with the RE session that owns the modem
   interface (`herdr agent list`; the ISD-R/qmiuim lane).
2. **B14 unit acquisition** — flag to the operator if the community thread
   surfaces a donor; until then this thread stays static-only.
3. **B12 `dsi_config.xml`/`libqmi` source** — after prerequisite 1 (the
   modem dump contains the live B12 copies under /usr or /etc of the modem
   Linux; alternatively pull via adb from the RUNNING device 1 without a
   full flash dump).

## Definition of "fully working" (the ladder)

1. Static root-cause: a named component + named change that explains the
   WDS behavior (E1–E5 output).
2. A validated fix hypothesis: an NV item / MCFG file / config that, when
   flipped on B14, restores external QMI WDS (E8) — or proof it needs
   firmware (feeds prompt 02's downgrade automation instead).
3. Community deliverable: updated PR #85 reply (draft lives at
   `/tmp/opencode/b14/wwand-pr85-reply-draft.md` on the session host —
   may have been cleaned; the PR #663 notes + this prompt carry the
   durable copy) + conwrt notes update.

## Report/results

Findings → `~/mf286d-work/evidence/b14/` (FINDINGS.md is the running
handoff doc). Conwrt commits → your own worktree lane per AGENTS.md
(`scripts/dev-session.sh start <name>`), `Refs: #621` in messages.
Never interact outside Amperstrand repos; the PR #85 reply ships only
after human approval.
