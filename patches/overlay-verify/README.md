# Overlay-Verify Fix: Test Plan and Evidence

## Summary

The tmpfs→jffs2 overlay switch at S95 can silently lose critical files
(shadow, network config, dropbear). This causes the device to boot but
be unmanageable (auth-dead). Our fix verifies files after the switch and
retries with a clean overlay if missing.

## Evidence collected (2026-09-23)

### Hardware test (Extreme WS-AP3915i, ipq40xx, jffs2 overlay)
- **30/30 firstboot → auth-dead** (deterministic on degraded overlay)
- **30/30 power-cycle → recovery** (factory state returns)
- Recovery is 100% reliable — the fix automates this power cycle

### QEMU test (x86-64, ext4 overlay)
- 36 power-cut cycles at 12 timings (5-60s)
- All managed — ext4 journal absorbs power cuts
- Failure is jffs2-specific (no journal, no fsck)

### Stock firmware analysis (ZyXEL V2.90 board_poe.ko)
- 16 retries × 50ms delay (matched in our realtek-poe fork: aabf65f)
- UART protocol identical to our fork
- PoE backend timeout fixed (35s in labgrid conwrt_poe.py)

## Test plan for this fix

- [ ] Flash a unit with the patched image (patches/overlay-verify/)
- [ ] Run 50+ firstboot cycles with the overlay-verify active
- [ ] Verify: auth-dead detected by overlay-verify (not by external probe)
- [ ] Verify: clean retry succeeds (unit boots managed after auto-retry)
- [ ] Verify: no false positives (healthy boots don't trigger retry)
- [ ] Verify: retry counter resets on healthy boot
- [ ] Compare against stock image on same hardware (A/B proof)

## Files

- Patch: `patches/overlay-verify/0001-verify-overlay-switch-integrity.patch`
- PoE fix: `realtek-poe` fork, commit `aabf65f` on `ai-experiments`
- QEMU harness: `scripts/overlay_roulette.py`
- Hardware sweep: `scripts/hardware_sweep.py`
- Recovery loop: `~/labgrid/recovery-loop.py` (on ai-legion)

## Related upstream

- PR #10037 (firstboot overlay race) — still open since 2022
- Our fix is complementary (catches what the race drops)
- We do NOT plan to PR upstream yet (own branch only)
