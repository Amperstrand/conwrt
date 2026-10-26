# Run 2026-10-15 — venues S3.5 hardware-dry gate evidence

> Provenance: reconstructed 2026-10-25 from merged PR #190's body — the
> note this record replaces was written to the (gitignored)
> `test-results/notes/` path and never committed (conwrt #479). Content
> transcribes PR #190's gate-evidence statement; no new claims.

- **VM run green**: `integration-20261015-040452` — 68 passed / 0 failed /
  4 skipped (the venue-parametrized successor suite,
  `test_vpn_nordvpn_e2e_venues.py`).
- **Hardware venues swept DRY** — every live-DUT door was owner-gated at
  deletion time:
  - x1860-2: hung since 2026-10-09; owner-gated physical recovery.
  - x1860-1: no L2 path.
  - ws3915i: dark, nanny-escalated.
  - nr7101: no NetworkService by design.
- **Deletion** of the VM-only predecessor
  (`test_vpn_nordvpn_e2e_vm.py`) was on explicit reviewer instruction;
  this deviation record is the gate evidence for that deletion (PR #190).
