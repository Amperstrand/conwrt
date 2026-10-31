# OpenWrt version truth — single-source layering (2026-10-31)

**Question this answers:** "which OpenWrt version are we testing on?" —
asked across Amperstrand repos (conwrt, prta-scenario-poc, conwrt-bench).
The answer has **layers**, each with exactly ONE authoritative home.
Anything else reading a version must derive from its layer, not re-pin.

| Layer | Question it answers | Single source | Consumers |
|---|---|---|---|
| **Species qualification** | "What release is this MODEL family qualified/flashed on by default?" | `conwrt/models/*.json` → `openwrt.version` | flash defaults, `conwrt source-image`, plan-time floors/warnings (#606) |
| **Specimen reality** | "What is ACTUALLY flashed on THIS physical unit right now?" | `conwrt-bench/registry/inventory.jsonl` (+ `registry/devices/*.yaml`) | bench sessions, labgrid places, hardware lanes |
| **Harness test image** | "What image does the QEMU/VM oracle boot?" | conwrt: `tests/integration/_pins.py` · prta: `configs/test-matrix.yaml` (one definition per repo — enforced, not duplicated) | integration suites, ring-2 apply tests |
| **Policy floors** | "What is refused / warned at plan time?" | `conwrt/crates/conwrt-core/src/plan.rs` (`min_openwrt`, kernel 6.12.113 check, 24.x warning) | `conwrt plan` / `conwrt apply` |

## Enforcement

`python3 scripts/check_version_pins.py` (conwrt; also `make check-pins`):

1. **Single-sourcing** — no `OPENWRT_VERSION = "…"` literal outside
   `_pins.py` in the integration suite (the flash-lifecycle duplicate
   that motivated this doc is gone).
2. **Model parse check** — every `models/*.json` version parses; the
   24.x species (17 today) are listed as carrying the deprecation
   warning (#607 stages their migration).
3. **Cross-repo visibility** (informational, skips if not checked out):
   prta's bench image family and the conwrt-bench specimen inventory.

## Audit findings (2026-10-31, first run)

- **Fixed here**: `test_flash_lifecycle.py` carried a second
  `OPENWRT_VERSION = "25.12.5"` — a silent-drift time bomb next to
  `conftest.py`'s.
- **Known entropy, accepted**: `conwrt-bench/registry/inventory.jsonl`
  `firmware_version` values are free-text ("OpenWrt 24.10.2 r28739",
  "24.10.2", "?"). That layer is *descriptive* (recorded observations);
  normalization belongs to conwrt-bench, tracked in its own backlog —
  the checker prints the census, it does not gate on the prose.
- **Agreement at audit time**: conwrt oracle 25.12.5 == prta bench
  image 25.12.5; bench has both 24.10.x and 25.12.x specimens live
  (specimen reality ≠ test target — that is correct, not drift).

## Rules going forward

- Bumping the oracle release = one commit in `_pins.py` (conwrt) or
  `configs/test-matrix.yaml` (prta). Never a sed across test files.
- A test needing the family branches on `_pins.PKG_MANAGER`, never on
  its own version literal.
- Cross-repo "they must agree" is a human/CI-review concern via the
  checker output, not a runtime dependency — no repo fetches another
  at test time.
