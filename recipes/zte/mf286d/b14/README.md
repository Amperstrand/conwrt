# MF286D B14 spike artifacts (2026-11-09, time-boxed research)

Copied from the bench evidence dir `~/mf286d-work/evidence/b14/` (59 MB
with binaries — NOT committed; the `.up` is re-downloadable from the
public ZTE DMS URL, sha256 in ARTIFACT-SUMS.txt / sha256.txt).

- FINDINGS.md — the handoff document (state, artifacts, hypotheses with
  verdicts, experiments E1–E8, blockers, roadmap WS-A..D)
- NEXT-AGENT-PROMPT.md — ready-to-run continuation prompt
- cpe_postprocessing.sh — the FULL 30-item modem NV script (community had 5)
- parse_delta.py, scan_zfd.py — the delta-container parsers written by the
  spike session (ZFD01.02 per-file delta format)
- ARTIFACT-SUMS.txt — hashes of all 30 spike artifacts

Campaign context: `recipes/zte/mf286d/notes.md` (B14 section),
`prompts/mf286d-b14-0{1,2,3}-*.md`. Issue: #621.

## Extension window (same day, +15 min): ZFD codec cracked + H8

- zfd_decode.py — the ZFD `.p` codec: `[BE32 comp_len][BE32 uncomp_size]
  [LZMA1 props 5D/128K][raw LZMA1 no-EOS]`; 642 records = BSDIFF40 patches
  (need B12 base + bspatch), 230 = full files (readable now, no base)
- decoded/ — the 230 readable files incl. the H8 evidence:
  qmi_ip_cfg.xml.B14 (multi_client, lan_clients_allowed=3),
  start_stop_qmi_ip_multiclient.B14.sh, netmgr_config.xml.B14,
  dsi_config (exonerated — stock Qualcomm, no ZTE knobs)
- FINDINGS.md S9–S11 + hypothesis ranking H8 > H2 > H3 (H1 refuted)

## Persisted at shutdown (2026-11-09)

- `manifests/` — modem-manifest.txt (163 modem-image files) + system-scan.txt
- `research-REPORT.md` — subagent research: MCFG tooling (mbn-mcfg-tools),
  dsi_config schema, ZFD prior-art (none), community downgrade path
- `decoded-full/` — all 230 raw full-file decodes (4.4 MB; bsdiffs excluded,
  regenerable — pipeline in FINDINGS.md §2)
- `drafts/` — wwand PR#85 reply draft (DO NOT POST — human approval required)
  + session-input.md
- Regeneration pipeline for the un-committed binaries: FINDINGS.md §2.
