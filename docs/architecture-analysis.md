# conwrt Architecture Analysis

Assessment of the current codebase structure and arguments for/against
refactoring toward greater modularity. Written after building the field-lab
feature, which exposed both strengths and friction points in the existing
architecture.

## Current structure

```
scripts/
├── conwrt.py              # shim → conwrt/ package
├── fieldlab.py            # shim → fieldlab/ package
├── conwrt/                # main flashing CLI (28 files)
│   ├── cli.py             # argparse subparsers
│   ├── __init__.py        # dispatcher (_COMMAND_MAP)
│   ├── cmd_*.py           # one per subcommand
│   ├── flash/             # flash method handlers
│   ├── profile/           # profile/target/render
│   └── ...
├── fieldlab/              # field-lab CLI (11 files)
│   ├── cli.py
│   ├── __init__.py
│   ├── *_cmd.py           # one per subcommand
│   ├── transport.py       # SSH layer
│   ├── network.py         # platform abstraction
│   └── rundir.py
├── ssh_utils.py           # flat: SSH command builders
├── platform_utils.py      # flat: platform detection
├── tftp-server.py         # flat: hyphenated, not importable by name
├── router-fingerprint.py  # flat: hyphenated, not importable by name
├── router-probe.py        # flat: hyphenated, not importable by name
├── firmware-manager.py    # flat: hyphenated, not importable by name
├── model_loader.py        # flat: shared model registry
├── shell_safe.py          # flat: input validators
├── use_cases/             # auto-discovered plugin directory
├── lib/common.sh          # shell helpers (run IDs, logging)
└── ...
```

## What works well

1. **Package + shim pattern** — `conwrt.py` → `conwrt/` and `fieldlab.py` → `fieldlab/` gives clean entry points with lazy imports. Each subcommand lives in its own file. This is good.

2. **Auto-discovered plugins** — `use_cases/` presets are auto-discovered, not registered. Adding a use case = adding a file. This is the right pattern for extensions.

3. **Shell helpers** — `lib/common.sh` provides run-ID generation, logging, state tracking. The Python code follows the same conventions (timestamp-slug naming).

4. **Test infrastructure** — `pythonpath = ["scripts"]` in pyproject.toml makes everything importable from tests. 3154+ tests with consistent mocking patterns.

5. **Safety culture** — `shell_safe.py` validators, `AGENTS.md` rules, dry-run-first design. The codebase is disciplined about hardware safety.

## Pain points exposed by field-lab

### 1. Hyphenated module names (highest friction)

`tftp-server.py`, `router-fingerprint.py`, `firmware-manager.py` cannot be
imported with `import tftp_server`. They require `importlib.import_module()`
hacks or `importlib.util.spec_from_file_location()`.

**Impact**: field-lab can't reuse `tftp-server.py` as a library call. The
coordination log shows the other LLM offering to "expose tftp-server as a
library call" — this friction is real and ongoing.

### 2. Duplicated SSH transport

| File | What it does |
|------|---|
| `ssh_utils.py` | `ssh_cmd()`, `run_ssh()`, `scp_cmd()`, `check_ssh()` |
| `fieldlab/transport.py` | `Host`, `run_remote()`, `stream_remote()`, `check_tool()` |
| `conwrt/flash/detect.py` | `check_ssh()` (different sentinel, different timeout) |

Three separate SSH command builders. `fieldlab/transport.py` adds `jump`
(ProxyJump) support that `ssh_utils.py` lacks. `flash/detect.py`'s `check_ssh`
is intentionally different (per the cursor rules — F811 guards against
re-introducing the import).

**Impact**: Any new SSH feature (ProxyJump, FIPS, custom ports) must be added
in multiple places. Bug fixes don't propagate.

### 3. Duplicated IP-assignment logic

| File | macOS approach | Linux approach |
|------|---|---|
| `conwrt/cmd_probe.py` | `ifconfig en6 inet X netmask Y alias` | (not supported) |
| `fieldlab/network.py` | `ifconfig en6 inet X netmask Y alias` | `ip addr add X/Y dev eth0` |

Both implement the same platform-branching pattern independently.

### 4. Platform detection scattered

`platform_utils.py`, `fieldlab/network.py`, and `cmd_probe.py` all detect
platform independently using `platform.system()`. No shared helper.

### 5. Run directory management split across shell + Python

- Shell: `init-run.sh` creates `runs/<timestamp>-slug/` with `run-metadata.json`
- Python: `fieldlab/rundir.py` creates `runs/<timestamp>-fieldlab/` with `manifest.json`

Same convention, two implementations, no shared helper.

## Refactoring options

### Option A: Extract shared `network_ops.py` (recommended)

Create `scripts/network_ops.py` containing the genuinely shared primitives:
- Platform detection (`detect_platform()`)
- IP assignment (`assign_ip()`, `remove_ip()`) with platform branching
- Interface detection (`auto_detect_interface()`, `get_probe_interface()`)
- ARP helpers (`get_arp_table()`)

Both conwrt and fieldlab import from it. Existing modules re-export for
backward compatibility.

**For**:
- Eliminates the worst duplication (SSH, IP, platform)
- Low risk — extract, don't rewrite
- Enables field-lab to call `tftp_server.start()` once the module is renamed
- Other LLM agreed this is shared territory in the coordination log

**Against**:
- Touches files both LLMs use (coordination needed)
- Existing tests mock at specific module paths — extraction breaks mocks
- Adds one more import layer

### Option B: Rename hyphenated modules to underscore

Rename `tftp-server.py` → `tftp_server.py`, `router-fingerprint.py` →
`router_fingerprint.py`, etc. Add backward-compatible shims.

**For**:
- Makes modules importable by name (Python convention)
- Eliminates `importlib.import_module()` hacks
- One-time cost, permanent benefit

**Against**:
- Breaks `make` targets, docs, muscle memory
- Git rename history gets messy
- The cursor rules explicitly document the hyphenated-module workaround

### Option C: Full restructure into a `conwrt/` package

Move ALL flat scripts into `conwrt/` subpackages: `conwrt/network/`,
`conwrt/tools/`, `conwrt/models/`, etc.

**For**:
- Clean namespace
- Clear ownership boundaries
- Ansible-style modularity

**Against**:
- Massive git diff (every file moves)
- Breaks every test mock path
- Breaks the coordination agreement with the other LLM
- High regression risk on safety-critical code
- AGENTS.md says "prefer small, focused changes"

### Option D: Status quo (do nothing)

Leave the structure as-is. Accept the duplication.

**For**:
- Zero risk
- No coordination needed
- Working code stays working

**Against**:
- Duplication grows with each new feature
- field-lab can't cleanly reuse conwrt's TFTP server
- New contributors confused by the flat/package split

## Recommendation

**Option A (extract shared primitives) + selective Option B (rename only the
modules we actively import from).**

Concretely:
1. Create `scripts/network_ops.py` with platform/IP/interface primitives
2. Rename `tftp-server.py` → `tftp_server.py` (the only hyphenated module
   field-lab needs to import)
3. Leave everything else as-is
4. Both conwrt and fieldlab import from `network_ops.py`
5. Existing modules re-export for backward compatibility

This is the minimal viable refactor. It eliminates the friction that actually
blocked field-lab development, without disrupting the working codebase.

## What NOT to refactor

- The flash state machine (`conwrt/flash_dispatcher.py`, `monitors.py`) —
  it's complex, well-tested, and works. Don't touch it.
- The UCI/render pipeline (`profile/`, `use_cases/`) — it's the right
  abstraction for the flashing workflow.
- The shell-based Stage 1 run system (`init-run.sh`, `run-step.sh`) —
  it serves a different purpose (LLM-driven discovery) and the Python
  field-lab run system (`rundir.py`) is intentionally separate.
- The model JSON schema and validation — it's the single source of truth.

## Ansible comparison

Ansible's connection-plugin architecture (SSH, local, paramiko) is the
pattern conwrt's transport layer is evolving toward. The key lesson from
ansible's experience: platform-specific bugs are the long-tail pain point.
Investing in a clean transport interface early (like fieldlab/transport.py
with its `jump` parameter and swappable implementation) pays dividends later
when FIPS/WireGuard transports are added.

However, ansible's full plugin-loader architecture is overkill for conwrt.
conwrt has ~10 commands, not hundreds. The current lazy-import dispatcher
(`_COMMAND_MAP` in `conwrt/__init__.py`) is sufficient.
