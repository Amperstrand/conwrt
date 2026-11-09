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
