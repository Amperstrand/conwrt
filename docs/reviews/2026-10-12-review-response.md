# Conwrt 2.0 — Review Response and Disposition (2026-10-12)

Reply to `conwrt-2.0-review-feedback-2026-10-12.md` (external architecture and
progress review). Every observation was independently verified against the
repository, PR diffs, GitHub Actions runs, and issues **before** action.
Companion comments live on #100, #104–#106, #107, #108, #113, #118; new
tracking issues #124 (XMODEM reliability) and #125 (SSH trust hardening).

## Disposition table

| Finding | Accurate? | Disposition | Fix/issue/PR link | Evidence/test | Remaining risk |
|---|---|---|---|---|---|
| PR boundary / CI (P0) | **Yes** — PR #119 had 66 files: 5 Rust commits + ~16 unrelated VPN/nordvpn commits inherited from a polluted local base (the #120 lineage), plus a master merge; Python CI failed on `nordvpn.py` Pyright (lines 54/67) | **Fixed** — stack rewritten: #119 = 5 Rust commits directly on master (36 files, Rust/docs/CI only) + 2 review fixes; #122/#123 rebased on top; force-pushed | PRs #119/#122/#123 (rewritten) | `git diff origin/master..feat/conwrt-2.0-rust-foundation` = 36 Rust/docs files; Python diff vs master = Makefile additions only → Python CI outcome == master (green); Rust workspace tests/clippy/fmt/no_std green at every level (37/69/77 tests) | The unrelated VPN work still needs its own review in #120 — owned by that session; `nordvpn.py` Pyright errors must be fixed **there** |
| Boot-state confidence (P1) | **Yes** — SSH banner alone classified `OpenWrt`, with a note admitting stock-dropbear ambiguity; `ssh_overrides_http_vendor_guess` encoded the inverted prior | **Fixed** in #119 | commit `fix(core)` on #119 | `DeviceState::SshOnly` (SSH answered, OS unconfirmed); `OpenWrt` now requires positive HTTP fingerprints (uhttpd/LuCI); SSH+recovery-header ⇒ contradictory `Unknown`; ARP-entry-no-responses ⇒ `Unknown`; fixtures: stock-dropbear-beside-vendor-UI, contradictory signals, ARP-only; enum docs pin: classifier output never authorizes destructive ops | Classifier refinement continues (management-interface discovery noted in the bench session's handoff); authenticated `/etc/openwrt_release` confirmation arrives with the SSH provider workflow |
| Model serialization (P1) | **Yes, latent** — no flatten catch-all; the only reserializer was a test, but nothing *prevented* future writeback, and the roundtrip test demonstrated silent field loss | **Fixed (projection decision)** in #119; lossless tracked | #119 commit + #118 comment | `Serialize` derive removed from `DeviceModel`/`OpenwrtInfo`/`FlashMethod` — writeback is now a **compile error**; module docs declare read-only projection; lossless representation (`flatten` + real-corpus roundtrip tests) scoped in #118 | None mechanical; the projection must be revisited when #118 types more fields |
| XMODEM limitations (P1) | **Partially** — limitations were already documented in the module docs (accepted, with revisit pointer), but the pointer referenced closed #106, nothing pinned the semantics, and no reliability tracking existed | **Fixed + deferred** — 4 characterization tests in #122; follow-up tracked | #122 + #124 | Pins: mid-stream NAK → sender advances without retransmit (sender-side `Ok` ≠ receiver acceptance); mid-stream CAN counted-not-honored; ACK-timeouts → `ExhaustedRetries`; clean whole-transfer restart. **New platform finding**: Linux `SO_RCVTIMEO` surfaces as `WouldBlock` (fatal in xmodem-0.4); only serial-style `TimedOut` soft-handles — drivers must translate | Real-receiver compatibility matrix unproven (#124) — no automated serial flash until per-bootloader restart-safety is documented; `embedded-io-async` spike outstanding (#124, M5) |
| Issue status hygiene (P2) | **Yes** — #104/#105/#106 closed while #122/#123 were unmerged drafts; handoff doc also said M1 “✅” | **Fixed** | #104/#105/#106 reopened; #100 policy comment; doc fix in #123 | Policy: **milestone issues close on merge**; roadmap/handoff markers changed ✅→📦 (in draft PR) | Process discipline only — needs to hold over time |
| Agent-protocol compatibility (C) | Valid concern, prototype-stage | **Deferred with acceptance criteria** | #107 comment | Version-skew, unknown-variant, additive-field, and independent-release tests added to the spike's acceptance criteria; no ABI freeze until then | As stated in ADR-0004 kill-criteria process |
| Desired-state priority (B) | Valid ordering advice | **Adopted** | #113 comment, #100 comment | Minimal planner slice (mock-only, dry-run purity via existing call journal) scheduled after the M3 agent proof; roadmap M0–M9 unchanged | None — ordering, not scope |
| Remote-capability proof (A) | Valid — agree it's the highest-value next proof | **Adopted** | #100 comment | M3 (#107/#108) prioritized next after stack merges | — |
| Execution/disconnect semantics (D) | Valid | **Deferred with design input** | #108 comment | Three-layer taxonomy + per-capability disconnect outcomes (abort / complete / unknown-needs-verification) recorded | — |
| Credentials and trust (E) | **Partially** — handshake-ordering is already safe (refusal in `check_server_key` aborts before auth can start); persistent store/rotation/UX/regression-test gaps real | **Deferred** | #125 | Acceptance criteria: no-auth-before-approval regression (count auth callbacks on ChangedKey/FirstUse-refused), persistent trust store, rotation UX, credential resolution, redacted logs, M3+ network-agent mutual auth | Until #125 lands, TOFU memory is per-process (tests only) — acceptable for read-only diagnose |
| TollGate licensing (F) | Concern valid, **already addressed** | **No action** | ADR-0007 | ADR-0007 already gates: no installer code until upstream LICENSE lands; GPL artifacts install-only; behavioral reimplementation only | Watch upstream license status (continuous item in ADR-0007) |
| `no_std` proof strength (G) | Valid — cross-check necessary-not-sufficient, and the docs agree | **No action needed now** | ADR-0002/0011, roadmap M5/M6 | MCU link/boot/DMA/sizing/HIL evidence is already the M5/M6 exit criteria; no portability overclaim found in docs (roadmap/handoff wording tightened by the P2 fix anyway) | — |

## Where we disagree / correct the memo

1. **QEMU fixture retarget coupling (P0 sub-item)** — the review asks the
   OpenWrt 24.10→25.12.5 VM bump in #123 be split or justified. It **is**
   load-bearing: the ring-2 Dropbear tests, the on-OpenWrt deploy proof, and
   the bench program all target 25.x; one fixture version keeps the evidence
   chain coherent. Justification added to the PR body; the two legacy-fixture
   commits are separable on reviewer request. We kept them: splitting would
   leave #123's own test evidence unverifiable without a second VM fixture.
2. **XMODEM framing** — the memo presents the mid-stream NAK/CAN gaps as
   undiscovered; the module docs already declared them accepted limitations.
   The genuine gaps (no pinning tests, closed tracking issue, no
   receiver matrix) are now closed as described above.
3. **“Ensure the Python CI workflow passes”** — it now does, but note the
   root cause was *unrelated VPN code entering the stack via branch
   pollution*, not the Rust work. The remaining Pyright errors in
   `scripts/nordvpn.py` are #120's to fix; they no longer appear anywhere in
   the Rust stack. (Two `test_extreme_*` failures observed locally on
   pristine master are environment-specific — uv Python 3.13.15 vs CI's
   pinned interpreters; master CI is green. Out of scope here.)

## Immediate queue — adopted

1. ✅ PR stack audited + rewritten; both CI workflows green on the new heads
   (Python == master; Rust verified locally at every stack level).
2. ✅ Classifier shortcut corrected with ambiguity fixtures.
3. ✅ Model-data strategy decided: read-only projection, mechanically
   enforced; lossless path in #118.
4. ✅ XMODEM failure cases pinned and gated (#124).
5. Next (per #100): M3 narrow agent-backed read-only diagnostic proof
   (#107/#108), then the minimal planner slice (#113) — mock-only, no
   hardware.

No merges performed; no hardware-mutating operations executed (the bench
sysupgrade remains explicitly authorization-gated). Ongoing development
continues on the existing roadmap.
