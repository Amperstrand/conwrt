# PRTA Transition Plan — one test, every venue

Plan note (2026-10-14). Status: PROPOSAL, decision-complete. Moves conwrt's
device/VM test tiers onto the testing framework **pattern** that TollGate's
PRTA repo (`~/src/prta-scenario-poc`, "physical-router-test-automation")
uses, so the SAME test module — e.g. the one-token NordVPN e2e
(`tests/integration/test_vpn_nordvpn_e2e_vm.py`) — runs against a local
QEMU VM, an x1860, an NR7101, or any labgrid place, with per-device
performance rows.

This plan **builds on** `docs/DEVICE-TRANSITIONS.md` (state vocabulary,
resources-including-the-human, envelope preconditions) and does not
contradict it: that doc defines how *flashing transitions* map onto labgrid
resources; this doc defines how *test tiers* reach devices. The two meet at
the labgrid place.

Grounding convention: every claim below cites a file in `conwrt`
(this repo), `prta` (`~/src/prta-scenario-poc`), or `tlab`
(`~/src/tollgate-lab`). Operational claims made today are marked
*(verified 2026-10-14)*.

---

## 1. The PRTA pattern, precisely — what we adopt

PRTA's venue abstraction is **not a class hierarchy; it is an env-fed seam
plus a labgrid adapter**:

1. **Tests depend on one thing**: a `router` fixture that reads
   `TOLLGATE_SSH_HOST/KEY/PORT/JUMP_HOST` from the environment
   (prta `tests/conftest.py`, `router` fixture). The venue is *chosen by the
   runner*, never by the test body.
2. **Venue = environment + inventory + (optional) labgrid acquire.** With
   `TOLLGATE_VENUE=labgrid`, the same fixture instead calls
   `lib/labgrid_venue.py::bench_for_router()`: resolve a logical name in the
   gitignored inventory (`lib/lab_inventory.py`), **acquire** the place,
   then `apply_venue_env()` — which literally sets the same
   `TOLLGATE_SSH_HOST/KEY/JUMP_HOST` env vars (prta
   `lib/labgrid_venue.py:131-142`). The labgrid place is just another way
   to *feed the seam*. Nothing in the test changes.
3. **Venue-appropriateness is marker-gated at collection**: `physical_only`,
   `virtual_lab_only`, `gcloud_only` markers vs `TOLLGATE_LAB_TYPE` (prta
   `tests/conftest.py::pytest_runtest_setup`). A test that needs real WiFi
   skips in the VM venue instead of failing.
4. **Exclusivity is structural**: `--lock-phase` acquires a router lock
   before the session starts; the labgrid venue acquires the place for the
   session and releases it in a finalizer (prta `tests/conftest.py:292-319`).
5. **The adapter is unit-testable without labgrid**: `LabgridBench` takes an
   injectable `Runner` and drives `labgrid-client` as a subprocess (prta
   `lib/labgrid_venue.py:49-96`) — CI needs no coordinator.
6. **Perf rows are keyed by scenario, not by run**: prta
   `tests/test_conwrt_vpn_matrix.py` (env `CONWRT_ROUTER`) emits one row per
   NordVPN technology with board/release context — the same harness that
   produced the x1860 matrix in our README.

### What PRTA lacks that conwrt explicitly needs

Stated plainly, not assumed away:

| Gap | Evidence | Consequence for us |
|---|---|---|
| **One venue per pytest session.** Venue selection is env/session-wide; there is no parametrization that runs one test against VM *and* hardware in a single run | prta `tests/conftest.py` (env-driven `router`), README "Testing Venues" | We must ADD a pytest-parametrized `venue` fixture (§3). Neither repo has it today; the PoC (§8) builds it |
| **PRTA's `Router` class is TollGate-coupled** (backend config, portal, mints) | prta `lib/router.py`, imported by `tests/conftest.py` | We adopt the *seam*, not the class. conwrt's handle is `run(cmd) -> CompletedProcess` |
| **`labgrid-client` has no `whohas`** on this install | *(verified 2026-10-14)*: `invalid choice` — occupancy is `show`'s `acquired:` field or `reservations` | Venue fixtures probe `acquire` and skip-not-fail on refusal |
| **tlab `RouterDriver` file transfer violates our dropbear rules**: `put_file`/`get_file` use plain `scp` (no `-O`), and the driver binds only `address`+`username` — no port, no keyfile | tlab `tollgate_lab/drivers/labgrid_router.py:94-131` | Do not use `RouterDriver` for transfers until it grows `-O` + port/keyfile (AGENTS.md "Offline Device Package Installation"). Command execution is fine |
| **tlab fixtures hardcode an operator IP** (`ROUTER_SSH_HOST` default `192.168.13.112`) | tlab `tollgate_lab/fixtures/sessions.py` | Violates "never hardcode device IPs" (AGENTS.md Lab SSOT). We resolve from places, never from fixture defaults |
| **PRTA local runner kills by pattern** (`pkill -f cdk-mintd`, `kill_stale_vm` by pgrep) | prta `scripts/run-local-tests.sh:170-179` | Forbidden on this shared host (AGENTS.md multi-agent rule 2). We keep conwrt's pidfile teardown (`tests/integration/conftest.py:340-350`) |
| **PRTA's virtual lab is TollGate-shaped** (OpenWrt + Debian client + bridge + Cashu mints) | prta `scripts/virtual-lab.py` (POC_BRIDGE, DEBIAN_*, mint wiring) | Wrong shape for conwrt's single-OpenWrt-VM tier; conwrt's QEMU fixture stays (it already credits PRTA for the overlay pattern) |
| **`conwrt_poe` power driver lives only inside ai-legion's labgrid package** | conwrt `labgrid/README.md` ("install copy"); *(verified 2026-10-14)*: `power get` from ai-legion-small fails `ModuleNotFoundError: labgrid.driver.power.conwrt_poe` | Power-dependent venue features must run where the driver is installed (or install it locally); venue fixtures treat power as an *optional* capability |

### Adopt / adapt / reject summary

- **Adopt**: env-fed venue seam; subprocess `labgrid-client` adapter with
  injectable runner; logical-name inventory with `protected` flag and
  identifier-free errors; skip-not-fail venue gating; acquire-for-session
  exclusivity; scenario-keyed perf rows.
- **Adapt (new, ours)**: pytest parametrization over venues; minimal
  `VenueHandle` contract; registry = conwrt's existing `data/lab.yaml`
  (NOT a second inventory file — see §4).
- **Reject/defer**: PRTA `Router` class; `virtual-lab.py`; SHC/GCP cloud
  venues (no conwrt need); tlab `RouterDriver` transfers; tlab
  hardcoded-IP fixtures; pattern-based process cleanup.

---

## 2. Venue abstraction (deliverable 1)

### 2.1 The contract

A venue is anything that can execute a shell command on an OpenWrt system
and tell us who it is. Concretely — already proven by the PoC (§8):

```python
class VenueHandle:
    name: str                      # "virtual-x86-64@qemu(127.0.0.1:2522)", "labgrid:ap-lan2"
    def run(self, command: str, timeout: int = 30) -> subprocess.CompletedProcess: ...
```

Everything else (power, console, flashing) is an *optional* capability
declared per venue — the runtime equivalent of the resource classes in
`docs/DEVICE-TRANSITIONS.md` §2. A test declares what it needs; the venue
either has it or the test skips.

### 2.2 Fixture mapping — today's names keep working

| conwrt fixture today | Where | Venue-era equivalent | During migration |
|---|---|---|---|
| `openwrt_vm` (session QEMU; port from `CONWRT_VM_SESSION_PORT` via `scripts/vm_port.py`) | `tests/integration/conftest.py:228-350` | **engine** of the `qemu-session` venue — wrapped, not replaced | untouched |
| `flash_vm` (dedicated QEMU on `127.0.0.2`, `CONWRT_VM_FLASH_PORT`) | `tests/integration/test_flash_lifecycle.py:96-140` | flash venue for `virtual-x86-64`; on hardware becomes `flash_lease` (§4.3) | untouched until step S5 |
| `wireguard_installed` (opkg/apk-aware install) | `tests/integration/conftest.py:392-409` | capability fixture layered on `venue.run` — same logic, any venue | untouched |
| `ssh_cmd` | `tests/integration/conftest.py:374-378` | `venue.run(...).stdout` | untouched |
| `device` (`CONWRT_DEVICE_IP`) | `tests/e2e/conftest.py:27-52` | a *direct* venue — the env var stays as the single-direct-venue alias | untouched |
| `router` (`CONWRT_BENCH_ROUTER`) | `tests/bench/conftest.py:89-96` | direct/labgrid venue feeding the same `{ip, board, release, cores}` dict | untouched until S4 |
| prta `ssh_router` (env seam in PRTA's conwrt suite) | prta `conwrt/conftest.py:37-81` | superseded — conwrt grows its own venue module and the PRTA-side tests move home (post-step) | PRTA keeps its copy |

**Entry-point compatibility rule**: `make integration`, `make bench`,
`make bench-vpn`, `make e2e`, `make test`, `make test-live` (Makefile
lines 117-176) must stay green and semantically unchanged through every
step. New venue tests carry `pytest.mark.integration` (auto-applied by the
path-scoped hook in `tests/integration/conftest.py:38-57`), so the
`make test` selector `-m "not integration and not bench and not live"`
already excludes them. No Makefile edit is required until the optional
`make venues` convenience target at the very end.

### 2.3 Venue selection

```bash
# today's behavior — nothing changes:
make integration                                   # QEMU suite (incl. venue smoke)

# venue runs (opt-in, after S2):
CONWRT_VENUES="qemu-session,labgrid:ap-lan4" pytest tests/integration/test_vpn_nordvpn_e2e_venues.py
CONWRT_VENUES="labgrid:x1860-bench" CONWRT_LIVE_NORDVPN_TOKEN=... pytest ...   # hardware venue
```

Resolution order (mirrors prta's inventory-first design, but our SSOT is
`data/lab.yaml` — AGENTS.md "Lab Single Source of Truth"):
`labgrid:<place>` → place exists in the registry (generated exporter/places,
`scripts/lab_registry.py`); address/key come from the place's
`NetworkService` via `labgrid-client` on the exporter path — **never a
hardcoded IP in code**. `qemu-session` → the existing fixture.
Unresolvable/dark venue → **skip with reason**, never error (§7 finding).

---

## 3. Parametrized venue fixture (the piece PRTA doesn't have)

New module `tests/venues.py` (test-tier only; `scripts/` stays the
flashing-tooling namespace):

```python
@dataclass(frozen=True)
class Venue:
    key: str            # "qemu-session" | "labgrid:ap-lan4" | "direct:x1860-desk"
    kind: str           # qemu | labgrid | direct

def venues_from_env() -> list[Venue]: ...
```

- Unit-tested with a **fake labgrid runner** (injectable `Runner`
  callable — the pattern prta `lib/labgrid_venue.py:49` uses so CI needs no
  coordinator). Covers: env parsing, unknown place → actionable error,
  protected device → refusal (prta `bench_for_router` semantics).
- The pytest fixture (added to `tests/integration/conftest.py` in S2,
  additive only) parametrizes over `venues_from_env()`, defaulting to
  `["qemu-session"]` — i.e. **a bare `make integration` runs exactly what
  it runs today plus nothing hardware**. Labgrid venues appear only when
  `CONWRT_VENUES` names them.

Capability layer (S3+): `wireguard_installed(venue)`, `has(venue, "iperf3")`
etc. — the existing install logic from `tests/integration/conftest.py:392`
parameterized by venue. The opkg/apk era detection already written there
transfers verbatim.

---

## 4. Device matrix from data/lab.yaml (deliverable 2)

**One registry**: `data/lab.yaml` (gitignored; template
`labgrid/lab.yaml.example`). Places are GENERATED from it
(`scripts/lab_registry.py emit-exporter` / `deploy-exporter`); hand-edits
are forbidden outside append-only enrollment (AGENTS.md Lab SSOT rules).
PRTA's separate `configs/labgrid/inventory.local.yaml` is NOT adopted —
same idea, but we already own a registry and a generator.

| Venue | Species (`models/`) | Place | Mutating tests allowed? | Notes |
|---|---|---|---|---|
| `qemu-session` | `virtual-x86-64.json` | local fixture (today); optional `QEMUDriver` place later — template exists at `labgrid/qemu-x86-64.yaml.example` (snapshot=on pristine boots) | yes — `flash_vm` sysupgrade lifecycle | the only venue where flashing is cheap and reversible (overlay deleted at teardown) |
| `labgrid:ap-lan2..8` | AP3915i etc. | exist today (coordinator `ai-legion:20408`) | flash via conwrt-bench tooling only; venue tests read-mostly | `labgrid/README.md` resources table; SSH currently dark *(verified 2026-10-14)* — see §7 |
| x1860 bench unit | `dlink-covr-x1860-a1.json` | **to enroll**: device + `labgrid_place` in `data/lab.yaml`, NetworkService from bench statics | yes, behind `flash_lease` + AGENTS envelope rules | desk variant (manual power) modeled by `docs/DEVICE-TRANSITIONS.md` §4 YAML |
| NR7101 | `zyxel-nr7101.json` | **to enroll as `protected: true`** | **no flashing** — read-only/configure venues only | exactly one bench unit exists and it is the deployed house TollGate DUT (`docs/NR7101-FLEET.md` census). A second benched unit is a hardware project, prerequisite for NR7101 flash venues |

Protected places: the labgrid venue refuses them for mutating fixtures —
directly analogous to prta `bench_for_router()` refusing `protected` routers
before any coordinator call (prta `lib/labgrid_venue.py:104-128`).

### 4.1 Identity gates stay in force

Venue fixtures lower the *access* barrier, never the *safety* barriers:
before any mutating command, the AGENTS.md rules apply unchanged — read
`/tmp/sysinfo/board_name` AND the specimen MAC/serial against the registry
record; `sysupgrade -F` forbidden; envelope preconditions
(`docs/DEVICE-TRANSITIONS.md` §3) machine-checked where the plan's P1/P2
phases land them (`resources_required` in `models/*.json`).

### 4.2 Sibling-session safety (the 2026-10-13 class of collision)

- **VM side (already solved, keep)**: host ports claimable via
  `CONWRT_VM_SESSION_PORT` / `CONWRT_VM_FLASH_PORT`
  (`scripts/vm_port.py::require_free` names the holder and the env var);
  QEMU teardown by pidfile with `/proc/<pid>/cmdline` sanity check
  (`tests/integration/conftest.py:340-350`); `pkill` by pattern forbidden.
- **Gap found live *(verified 2026-10-14)***: only the *port* is
  session-scoped — the overlay, pidfile, serial log paths
  (`tests/integration/.openwrt-session.*`, `.serial.log`) and the
  `~/.ssh/config` `Host 127.0.0.1` block are shared per checkout. A sibling
  session booting the session VM from the same worktree collides on all of
  them (observed: pidfile-lock failure, and a live VM on 2322 while the
  diag VM held 2422). **Work item V3 (S2)**: derive the whole VM working
  set from a session id (env `CONWRT_VM_SESSION` → overlay/pidfile/serial
  under `test-results/` or `/tmp/opencode/<session>/`), and use a
  per-session ssh-config `Host` alias (e.g. `Host conwrt-vm-<session>`)
  instead of squatting on `127.0.0.1`. Until V3 lands, the AGENTS rule
  "one worktree per session" is the actual isolation — the PoC run followed
  it (executed from a scratch worktree, sibling's ssh-config entry
  snapshotted and restored).
- **Hardware side**: labgrid acquire IS the exclusion primitive; queue with
  `reserve --wait` rather than poll-acquiring (AGENTS.md bench rules —
  `docs/labgrid-coordination.md` is the org canon). Claim before you code:
  check `gh pr list` + `data/active-sessions.jsonl`.

### 4.3 Flash-lifecycle scheduling

Mutating tests (sysupgrade lifecycle, bench bake-per-scenario flashes) get a
dedicated fixture:

```
flash_lease(place): reserve(name=f"conwrt-<session>-<story>") --wait
                    → acquire → yield VenueHandle → release
```

- One mutating fixture instance per place per run; reservation name carries
  the session id, so a crashed run leaves a *named*, cancelable reservation
  (`labgrid-client cancel-reservation`) instead of a silent lockout.
- VM flash tests keep today's dedicated-VM shape (`flash_vm`) — a QEMU
  overlay is its own lease.
- Bench bake-per-scenario (`tests/bench/conftest.py::_apply` — the
  "fresh boots are the stable path" rationale is documented there) rides
  the same lease when the router is a labgrid venue.

---

## 5. Performance measurement (deliverable 3)

`tests/bench/` already has the right bones; the plan adds one axis:

- **Scenario engine unchanged**: `tests/bench/scenarios.py` (`Scenario`
  dataclass, keyed rows) stays the single source of truth. Rows today are
  keyed by scenario name with board/release/cores in meta
  (`tests/bench/conftest.py::results`). **Change**: rows become
  `(scenario, venue)`; `meta` gains the venue identity — logical place name
  + model id + board + release + cores. No IPs in any published artifact
  (results are gitignored under `test-results/`; species-level privacy rule,
  AGENTS.md).
- **Measurement primitives unchanged**: `CpuSampler` (1 Hz `/proc/stat`
  polling over the venue channel) and `iperf()` transfer as-is — they only
  need `run()`, which every venue provides. Same for PRTA's matrix harness
  (`prta/tests/test_conwrt_vpn_matrix.py`) — prior art for per-device rows
  via `CONWRT_ROUTER`; the venue module subsumes that env var.
- **Apply strategy is per venue**: `Scenario.needs_bake` (already a field)
  meets venue flash capability:
  - `qemu-session` → `conwrt configure` (fast; overlay disposable)
  - x1860 bench → bake-per-scenario flash behind `flash_lease` (existing
    `_apply` path)
  - NR7101 (protected) → configure-only scenarios; `needs_bake` scenarios
    skip
  - mismatch ⇒ **skip with reason**, never fail (a venue without a
    capability is a scheduling fact, not a bug).
- **Comparability is explicit, never accidental**: every row carries the
  venue. VM rows are regression baselines (QEMU has no EIP-93, host CPU
  crypto) — cross-venue comparison becomes a deliberate query
  (`summary.md` gains a venue column), which is exactly how the README's
  x1860 matrix should grow into a multi-device matrix.

---

## 6. Migration sequence (deliverable 4) — strangler fig

Each step is one PR, independently shippable, `make ci` green, and the
existing entrypoints (`make integration/bench/bench-vpn/e2e/test-live`)
behave identically unless the operator opts into `CONWRT_VENUES`.

| Step | Content | Ships green because |
|---|---|---|
| **S0** *(done, this task)* | Plan + PoC `tests/integration/test_venue_smoke.py` (§8) | additive file; marked `integration` (excluded from `make test`); ruff clean |
| **S1** | `tests/venues.py` + fake-runner unit tests in `tests/test_venues.py` | pure addition; `make test`/`make ci` untouched |
| **S2** | `venue` fixture (additive) in `tests/integration/conftest.py`; venue smoke becomes canonical; **V3 work item**: session-scoped VM working set (§4.2) | bare runs default to `qemu-session` only — `make integration` output unchanged in shape; V3 removes the observed sibling collision class |
| **S3** *(riskiest — see below)* | `tests/integration/test_vpn_nordvpn_e2e_venues.py`: the one-token e2e body on `venue` + `wireguard_installed(venue)`, parametrized `[qemu-session]` first; `conwrt configure` gains venue-fed `--ip/--port` (no ssh-config squatting) | VM venue runs inside `make integration` (real proof, no token needed for collection); hardware venue added only after a manual green run (AGENTS "Test Before You Commit") |
| **S3.5** | delete `test_vpn_nordvpn_e2e_vm.py` | only after S3 has one green VM run AND one green hardware run recorded in `test-results/`; deletion is its own PR |
| **S4** | bench venue axis: `router` fixture fed by `tests/venues.py`; `CONWRT_BENCH_*` stays as the single-direct-venue alias; results gain venue column | `CONWRT_VENUES` unset ⇒ today's behavior byte-for-byte |
| **S5** | hardware flash venues: enroll x1860 in `data/lab.yaml`; `flash_lease`; NR7101 enrolled `protected`; second NR7101 onboarding flagged as hardware project | all hardware venues opt-in; envelope gates §4.1 |
| **post** | optional `make venues` target; bring PRTA's `conwrt/` suite home (its env seam maps 1:1 onto ours) | convenience only |

**Why S3 is the riskiest step.** It ports the flagship e2e
(`tests/integration/test_vpn_nordvpn_e2e_vm.py`) whose value is a *live
NordVPN tunnel* — token-gated, so CI cannot prove it; only local runs can.
It also sits exactly where live sibling work is happening *(verified
2026-10-14: uncommitted edits to `tests/integration/conftest.py` and
`test_vpn_nordvpn_e2e_vm.py` exist in the `conwrt-coord` checkout from
another session — PR #172's one-token e2e + pidfile teardown lineage)*.
Mitigations: S3 branches **from `origin/master` only** (AGENTS branching
rule), opens as a draft PR before work starts, lands after the sibling's
changes merge and rebases on top; the old file is not deleted until the
replacement has produced recorded evidence on both a VM and a hardware
venue; the configure path's ssh assumptions (`~/.ssh/config` `Host
127.0.0.1` entry) are replaced by explicit venue-fed connection parameters
in S3 itself, because hardware venues have no such entry to lean on.

### Sibling-work accounting (checked 2026-10-14)

- `gh pr list --state open` on Amperstrand/conwrt: **empty** at planning
  time.
- Recently merged and stacked on: **#172** (one-token VPN e2e on VM +
  pidfile VM teardown — the very test S3 ports), **#153** (multi-agent
  coordination: claimable VM ports — the mechanism §4.2 extends), **#159**
  (labgrid canon: `docs/labgrid-coordination.md` as org-wide SoT).
- Live signal to re-check before each step lands: `gh pr list`, the
  `data/active-sessions.jsonl` ledger, and uncommitted diffs in shared
  checkouts. Master moves at machine speed — fetch and rebase, never
  resolve by hand from a stale merge result.

---

## 7. What stays conwrt-native (deliverable 5)

| Tier | Why it stays |
|---|---|
| `tests/live/` (provider API contract tests, `-m live`) | host-side by design — "no router involved" is the point (`tests/live/test_vpn_live_apis.py` header). A venue is meaningless there; moving them would only add a skip |
| hermetic unit tests (`tests/test_*.py`, `make test`) | no device, no venue concept; they are the CI backbone |
| QEMU fixture machinery (`openwrt_vm`, image prep, overlay lifecycle) | PRTA's `virtual-lab.py` is a two-VM TollGate lab (bridge, Debian client, Cashu mints) — wrong shape; our fixture is single-purpose and already borrows the one PRTA idea worth borrowing (pristine base + per-session overlay, credited in `tests/integration/conftest.py:256-258`) |
| flash engine + bench tools (`scripts/conwrt.py`, `bench_*`) | they become the strategy/driver layer of `docs/DEVICE-TRANSITIONS.md` P2 — consumed by venues, not replaced |
| results/evidence layout (`test-results/`, `scripts/local-tests.sh`) | local, gitignored, history.journaled — venues only add rows |

---

## 8. PoC — venue seam, proven (2026-10-14)

`tests/integration/test_venue_smoke.py` — one test body, two venues:

```
CONWRT_VM_SESSION_PORT=2522 CONWRT_VENUE_PLACE=ap-lan2 \
  pytest tests/integration/test_venue_smoke.py -v
→ test_ssh_reachable_and_board_identity[qemu-session] PASSED
    [venue] virtual-x86-64@qemu(127.0.0.1:2522):
            board=qemu-ubuntu-24-04-pc-v2-i440fx-piix-arch_caps-fix-1996 release=25.12.5
→ test_ssh_reachable_and_board_identity[labgrid:ap-lan2] SKIPPED
    (SSHDriver control-master timeout — device dark)
1 passed, 1 skipped, exit 0
```

What it proves and records:

- **The seam**: the same assertions ran against a QEMU VM (via the existing
  `openwrt_vm` fixture, port claimed through `CONWRT_VM_SESSION_PORT`) and
  against a labgrid place (acquire → exporter-proxied `labgrid-client ssh`
  → release). Port 2522 was chosen because a sibling session's diag VM held
  `127.0.0.2:2422` at the time — ports are claimed, not assumed.
- **Skip-not-fail is load-bearing**: bench DUTs `ap-lan2/3/4` were
  SSH-dark today while acquire/release worked
  *(verified 2026-10-14)*. Before blaming tests: `lab_registry.py
  reconcile`, then the Dark-Device ladder (`docs/DARK-DEVICE-PLAYBOOK.md`)
  — a dark DUT is an operational state, and the venue fixture correctly
  degraded to a skip with the stderr evidence in the reason.
- **Coordination discipline held**: executed from a scratch
  `git worktree` (one worktree per session), teardown verified (no leftover
  QEMU, overlay + pidfile removed by the fixture), the sibling's
  `~/.ssh/config` `Host 127.0.0.1` entry snapshotted and restored
  byte-identical, `ap-lan2` confirmed released (`acquired: None`). No
  `pkill` was used anywhere.
- **Classification rule worth keeping** (encoded in the PoC):
  `labgrid-client` reports infrastructure failures as rc=2 with a
  traceback on stderr, while a failing *remote command* propagates its own
  exit status — only the latter is a test failure.

---

## 9. Open decisions, each with a default

| Decision | Default |
|---|---|
| venue module location | `tests/venues.py` (test-tier only; not `scripts/`) |
| marker strategy | reuse `integration` (VM) and `hardware` (device) markers; no new marker until S2 shows a need |
| default venue set | `["qemu-session"]` — hardware venues are always explicit opt-in |
| results location for venue runs | `test-results/venues-<ts>/` following the `scripts/local-tests.sh` convention |
| PRTA-side conwrt suite | stays in PRTA until the post step; then moves home in one mechanical PR |
