# conwrt Refactoring Plan

## Current State

- **30,000 lines** of Python across `scripts/`
- **271 lint errors fixed** (already committed)
- **No dead code** found in audit
- **6 files over 750 lines** — analyzed below

## Phase 1: Quick Wins (Low Risk)

### 1.1 Consolidate `internet_checksum` — 2 different implementations

**Problem**: Two files implement the same RFC 1071 algorithm differently:

| File | Implementation | Handles carry |
|---|---|---|
| `gs1920-repack-firmware.py:50` | Accumulate all words, fold at end | At end |
| `gs1920-validate-zynos-openwrt.py:20` | Fold carry inline each iteration | Inline |

Both produce correct results but the divergence is a maintenance risk.

**Plan**:
1. Create `scripts/checksum_utils.py` with canonical `internet_checksum()` 
2. Use the inline-carry version (more standard RFC 1071 pattern)
3. Update both gs1920 scripts to import from `checksum_utils`
4. Remove the local definitions

**Effort**: 30 min | **Risk**: Low | **Files**: 3

### 1.2 Remove `sha256_file` wrapper indirection

**Problem**: `firmware-manager.py` and `extreme_ap391x_analyze.py` each define a wrapper that just delegates to `flash.context.sha256_file`:

```python
# firmware-manager.py:82
def _sha256_file(path: Path) -> str:
    return _sha256_file_impl(str(path))  # just calls flash.context.sha256_file

# extreme_ap391x_analyze.py:75
def sha256_file(path: Path) -> str:
    return _sha256_file_impl(str(path))  # same thing
```

**Plan**:
1. Replace both wrappers with direct imports: `from flash.context import sha256_file`
2. Update call sites to pass `str(path)` instead of `Path` (or add `Path` support to canonical)

**Effort**: 15 min | **Risk**: Low | **Files**: 2

## Phase 2: Module Consolidation (Medium Risk)

### 2.1 Move extreme.py utilities to extreme_helpers.py

**Problem**: `extreme.py` (823 lines) mixes two concerns:
- **Utility functions** (lines 26-256, ~230 lines): SSH wrappers, SCP helpers, JSON file I/O, TFTP setup
- **State handlers** (lines 257-697, ~440 lines): The actual flash state machine handlers

`extreme_helpers.py` already exists with 5 utility functions. 12 more utilities from `extreme.py` belong there.

**Functions to move**:
```
extreme.py → extreme_helpers.py:
  _setup_interface_ips         (interface config — also in platform_utils)
  _extreme_tftp_server_ip      (profile config getter)
  _extreme_stock_ssh_options   (SSH option builder)
  _resolve_extreme_uboot_value (profile config getter)
  _ensure_extreme_backup_dir   (filesystem helper)
  _extreme_confirm_or_fail     (user interaction)
  _extreme_openwrt_ssh         (SSH wrapper)
  _extreme_openwrt_scp_from_remote (SCP wrapper)
  _extreme_openwrt_scp_to_remote   (SCP wrapper)
  _write_json_file             (JSON file I/O)
  _prepare_extreme_tftp_root   (TFTP filesystem setup)
  _cleanup_extreme_tftp_assets (TFTP cleanup)
```

**After move**: `extreme.py` shrinks from 823 → ~590 lines (state handlers only), `extreme_helpers.py` grows from ~50 → ~280 lines.

**Effort**: 1 hour | **Risk**: Medium (need to update imports in test_extreme_handlers.py, test_extreme_utils.py) | **Files**: 3+

## Phase 3: Analyzed — No Action Needed

### 3.1 flash_dispatcher.py (796 lines) — KEEP AS-IS

Cohesive state machine. Contains: FlashModeConfig, 3 cleanup functions, mode resolution, state runner, 7 state handlers. Splitting would scatter the state machine across files and make the flow harder to follow.

### 3.2 postflash.py (734 lines) — KEEP AS-IS

Sequential post-flash workflow. Each function is called in order during device setup. Contains: profile application, credentials, WireGuard, Tollgate, LAN IP, verification, SSH key, password, inventory. These are all steps in one workflow — splitting would add indirection.

### 3.3 auto_detect.py (765 lines) — KEEP AS-IS

Detection orchestrator. Contains: passive probes, active probes, router identification, display, main. The probes are already partially delegated to `probe_utils.py`. The identification logic is the core value and should stay with the orchestrator.

### 3.4 firmware-manager.py (772 lines) — KEEP AS-IS

ASU firmware client. Contains: HTTP API helpers, cache management, cache key computation, metadata, ASU request building. Tightly coupled — cache uses HTTP, CLI uses both. Natural separation exists (marked by comment separators) but splitting would create circular dependencies.

### 3.5 extreme_ap391x_analyze.py (790 lines) — KEEP AS-IS

Standalone firmware analysis tool. Each function builds on the previous in a pipeline: download → extract → analyze → classify. Splitting would break the pipeline readability.

## Phase 4: Style Cleanup (Optional)

### 4.1 Remaining 196 lint issues

| Type | Count | Fix |
|---|---|---|
| E501 line too long | 152 | Auto-format with ruff format (breaking change) |
| E402 import order | 36 | Add `# noqa: E402` to test files with sys.path |
| E741 ambiguous var | 8 | Rename `l` → `line`, `I` → `index` |

**Effort**: 1 hour | **Risk**: Low (but E501 is cosmetic)

## Execution Priority

| Priority | Task | Effort | Impact |
|---|---|---|---|
| P0 | 1.1 internet_checksum consolidation | 30 min | Eliminates algorithmic divergence |
| P0 | 1.2 sha256_file wrapper cleanup | 15 min | Removes unnecessary indirection |
| P1 | 2.1 extreme.py → extreme_helpers.py | 1 hour | 230 lines moved, cleaner separation |
| P2 | 4.1 E741 ambiguous variables | 15 min | 8 variable renames |
| P2 | 4.1 E402 noqa for tests | 15 min | 36 suppressions |
| P3 | 4.1 E501 line length (auto-format) | 1 hour | 152 lines reformatted |

**Not recommended**: flash_dispatcher, postflash, auto_detect, firmware-manager, extreme_ap391x decomposition — these files are large but cohesive.
