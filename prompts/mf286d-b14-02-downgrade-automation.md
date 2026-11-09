# MF286D modem B14→B12 downgrade — conwrt automation (queue prompt)

Low-urgency research-queue prompt ("expiring tokens" lane). This is
follow-on work once the B14 dig (prompts/mf286d-b14-01-dig.md) has the
package unpacked and the failure mode characterized. Software-only:
simulator-first, NO bench hardware, NO community hardware. We do not own a
B14 modem and will not risk bricking anyone's unit — this prompt produces
tooling + a validated plan, not a live flash.

## Goal

Make `conwrt` able to downgrade an MF286D modem B14→B12 (or re-flash a
chosen modem firmware) fully automated on Linux, replacing the community's
current path: Windows VM + ZTE "update framework" (ZAS-style tool) + stock
firmware first (documented painful; see forum.openwrt.org/t/175362 posts by
"luca" 2025-03-03 and eko.one.pl thread id=21790).

## What conwrt already has (proven on device 1, B12 baseline)

- Full 22-partition verified backup incl. modem partitions
  (`~/mf286d-re/firehose_backup.py`, ACQ-2026-11-06 evidence).
- dload transport spec + client (`~/mf286d-re/dload_client.py`,
  EXP-015/017), bootloader blank-download flash path with fence
  (`scripts/zte-blankdl-flashd.py`, EXP-018), resolve_uboot.
- Factory-mode goform entry mechanics incl. AD hash recipe
  (recipes/zte/mf286d/notes.md) — the no-Windows door into the same
  environments the ZAS tool uses.
- Hardened flash campaign runner pattern (`scripts/mf286d_flash_campaign.py`)
  with gate/fence regression tests (`scripts/test_blankdl_fence.py`).

## Unknowns to close (in order)

1. **Modem flash path**: does the modem image update go through the router
   (dload mode writes modem partitions) or through the modem's own download
   mode over USB? Community says the Windows framework flashes it; our
   transport capture of ZAS (EXP-015/017, ORACLE-ANALYSIS.md) is the
   starting evidence. Map which transport and which partition set.
2. **The `.up` package layout**: delta manifest, per-partition images, the
   NV script application mechanism (who applies `nv set` — router or modem,
   at which stage). Depends on dig artifacts in
   `~/mf286d-work/evidence/b14/unpacked/`.
3. **Version-identity NV cache**: post-flash, factory defaults must be
   restored so the router re-reads identity from the modem (eko.one.pl
   posts 803/804). Any conwrt flow must bake this in or the unit reports a
   stale version forever.
4. **Brick-risk audit**: run the pre-flash audit (prompts/brick-risk-audit.md,
   23 items) against the plan. Modem partition writes are brick-class:
   enumerate escape hatches BEFORE the first simulated flash. No B14 unit
   exists on our bench — validation is simulator + community-evidence only
   until one arrives.

## Deliverables (repo-side)

1. `scripts/mf286d_modem_flash.py` (or extend the campaign runner) with a
   `--simulate` mode that replays the captured ZAS protocol against a fake
   endpoint; golden transcripts from our existing captures.
2. `recipes/zte/mf286d/modem-downgrade.md`: the validated, species-level
   downgrade procedure with the NV-cache gotcha, gate rules (MAC/serial
   specimen gate per AGENTS.md), and the "do not run on B12 units" warning.
3. Tests for the above (protocol framing, gate ordering, abort paths).
4. Issue on conwrt #621 thread with status + what a live B14 unit would let
   us validate.

## Constraints

- Never interact outside Amperstrand repos; drafts for the wwand PR #85
  reply live in /tmp and ship only after human approval.
- No modem firmware updates on OUR units (operator rule; device 1 stays
   B12 as the known-good reference).
- Simulation only until a B14 unit is physically on the bench with the
  operator's explicit go.
