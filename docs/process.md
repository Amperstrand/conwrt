# conwrt Process Workflow

This document describes the end-to-end workflow for the conwrt framework: how runs are created, how steps execute, how artifacts are redacted, and what safety boundaries are enforced at every stage.

---

## 1. Conceptual Model

A **run** is a working directory containing a sequence of **steps**. Each step is driven by an LLM prompt and produces three kinds of output:

1. **Raw artifacts** (local only, never committed) — verbose notes, screenshots, command output
2. **Validated structured findings** (`findings.json`) — machine-readable data matching a JSON schema
3. **Redacted narrative report** — a cleaned version of the raw notes, safe to commit

The operator drives the entire workflow via `make` targets. The LLM CLI is plugged in through the `OPENCODE_CMD` adapter, so any command-line tool that accepts a prompt file and produces structured output can be swapped in.

---

## 2. Run Directory Layout

```
runs/
└── 20260101-120000-192-168-1-1/         # run directory (YYYYMMDD-HHMMSS-slug)
    ├── run-metadata.json                  # written by init-run.sh, validated against schema
    ├── state.json                         # tracks which steps are complete
    ├── step-01-identify-device/
    │   ├── raw/                           # LLM-produced artifacts — LOCAL ONLY, never committed
    │   │   └── notes.md
    │   ├── redacted/                      # script-redacted artifacts — safe to commit
    │   │   └── notes.md
    │   ├── findings.json                  # structured validated output — committed
    │   └── .tmp/                          # scratch space — ignored by git
    │       └── composite-prompt.md
    ├── step-02-fingerprint-surface/
    │   └── (same layout)
    ├── step-03-plan-capture/
    │   └── (same layout)
    └── step-04-analyze-artifacts/
        └── (same layout)
```

The slug in the run directory name is derived from the target IP address, with dots replaced by hyphens (e.g., `192.168.1.1` becomes `192-168-1-1`). This makes run directories sortable by timestamp and identifiable by target at a glance.

The `raw/` directory is excluded from git by `.gitignore`. The `redacted/` directory and `findings.json` are committed. The `.tmp/` directory holds transient build artifacts like the composite prompt and is also gitignored.

---

## 3. Step Lifecycle

Each step follows the same lifecycle, driven by `make` targets:

1. **`make init TARGET=<ip>`** — Creates the run directory, writes `run-metadata.json` (validated against `schemas/run-metadata.schema.json`), and initializes `state.json` with an empty steps list. This target runs dependency checks for `bash`, `git`, `curl`, `jq`, `nmap`, and `npx`, printing actionable install hints for anything missing.

2. **`make run-step STEP=01`** — Assembles a composite prompt from the run metadata, previous step findings, and the step template in `prompts/`. Calls the adapter (see Section 6) to execute the LLM against that prompt. After the adapter returns, validates `findings.json` against the step-findings schema. Marks the step complete in `state.json`.

3. **`make redact`** — Runs deterministic redaction on every file in `raw/`, writing the cleaned output to `redacted/`. This is a fail-closed process: if the redactor encounters an error or detects a pattern it cannot handle, it aborts without promoting any files. See `docs/redaction.md` for the full pattern specification.

4. **`make validate`** — Validates all `findings.json` files (and the run metadata) against their respective JSON schemas using `ajv-cli`. Reports pass/fail for each artifact.

5. **`make commit`** — Safety-checks that redacted output exists and contains no leaked patterns, verifies that `raw/` is properly gitignored, then stages only the committed artifacts (`run-metadata.json`, `state.json`, `findings.json` files, and `redacted/` contents) and creates a git commit. It does not push to any remote.

Each step is idempotent: `run-step.sh` refuses to re-run a step that already appears in `state.json` unless the `--force` flag is provided.

---

## 4. The 4 Standard Steps

### step-01: identify-device

**Goal:** Passive and minimally invasive device identification.

The step follows a layered discovery approach, starting with the least invasive methods and escalating only as needed:

- `ip addr` to find the local network interface and subnet
- ARP/neighbor table scan for hosts on the segment
- Ping sweep to confirm live hosts
- `nmap -sT -sV` for TCP connect service version detection (no raw sockets, no root required)
- HTTP/TLS header capture via `curl -I` and `openssl s_client`
- Vendor-documented read-only API probe (e.g., JNAP `GetDeviceInfo` for Linksys devices)
- Web UI screenshot via read-only browser navigation

**Output:** `findings.json` with one or more device candidates, each carrying a confidence level (`low`, `medium`, `high`, or `confirmed`). A `next_step_input` field recommends step-02 when confidence is at least medium.

### step-02: fingerprint-surface

**Goal:** Deeper read-only fingerprinting of the confirmed target.

**Precondition:** step-01 findings exist with at least one candidate at confidence >= medium.

This step zooms in on the identified device:

- Deeper nmap version scan with higher intensity on the confirmed target only
- `curl` GET requests to inspect web UI structure and API endpoints
- Web UI analysis via read-only browser navigation (Playwright MCP)
- GPL source availability check on vendor websites
- Cross-reference with OpenWrt Table of Hardware

**Output:** Extended candidate profile in `findings.json` with more detailed hardware and software information. The `next_step_input` field recommends step-03 and may include specific artifact sources to investigate.

### step-03: plan-capture

**Goal:** Design a safe capture plan. This step does NOT execute anything.

Based on the fingerprinting results, step-03 determines which artifacts should be collected and how:

- Configuration exports via official vendor UI/API
- GPL source bundles from vendor websites
- FCC filing data (public partition layouts, internal photos)
- OpenWrt ToH entries and community forum threads

Every collection method must fall into one of three categories:

1. Read-only API call
2. Public download from a vendor or regulatory website
3. Operator-performed manual action (e.g., "log in to the web UI and export settings")

No automated credentialed flows are allowed.

**Output:** `findings.json` with `next_step_input.parameters.capture_plan` containing a list of artifacts, each with a source URL, collection method, risk level, and justification.

### step-04: analyze-artifacts

**Goal:** Post-hoc analysis of captured artifacts to assess OpenWrt feasibility.

**Precondition:** Artifacts from the step-03 capture plan are placed under `step-04/raw/artifacts/`.

The LLM examines the collected artifacts and produces an assessment:

- Partition layout compatibility with OpenWrt expectations
- Bootloader identification and serial access requirements
- Wireless chipset support status in mainline or snapshot builds
- Community reports from OpenWrt forums, GitHub PRs, and wiki pages

**Output:** `findings.json` with a `recommendation` field set to one of:
- `supported-direct` — documented installation method available
- `supported-via-serial` — requires serial console but otherwise supported
- `experimental` — community patches exist but not in mainline
- `unsupported` — hardware incompatibility or locked bootloader
- `insufficient-data` — need more artifacts to determine

The rationale and references (OpenWrt ToH URLs, forum threads, GitHub PRs) are included alongside the recommendation.

---

## 5. State Machine

Run progress is tracked by `state.json` at the root of each run directory.

- Created by `init-run.sh` with `{"steps_completed": []}`
- `run-step.sh` appends the step ID to `steps_completed` after successful validation of `findings.json`
- `run-step.sh` refuses to re-run a step that already appears in `steps_completed` unless `--force` is passed
- This allows resuming a partial run (e.g., after a crash or network interruption) without repeating expensive steps like nmap scans or LLM calls

The state file is committed alongside other run artifacts, so the history of a run is visible in git log.

---

## 6. Adapter Model

The LLM CLI is abstracted behind the `OPENCODE_CMD` environment variable, allowing any compatible tool to be used.

**Default:** `opencode run --prompt-file`

**Contract:** The adapter command receives the composite prompt file path as its last argument. It must:
- Read the prompt from that file
- Write any artifacts under `$STEP_DIR/raw/`
- Write `$STEP_DIR/findings.json` matching `schemas/step-findings.schema.json`
- Exit 0 on success, non-zero on failure

The adapter section in `run-step.sh` is clearly marked with `### ADAPTER START` and `### ADAPTER END` comments, with a TODO note for customization. To use a different LLM CLI, set the environment variable:

```bash
OPENCODE_CMD="my-llm-cli --prompt" make run-step STEP=01
```

Environment variables passed to the adapter include `STEP_DIR` and `RUN_DIR` so the adapter knows where to write its output.

---

## 7. When to Commit

Commits happen only after both redaction and validation succeed:

1. After `make redact` succeeds and `redacted/` directories are populated with cleaned artifacts
2. After `make validate` passes for all `findings.json` files

The commit step (`make commit`) enforces these preconditions by running both targets internally before staging anything. Additionally, `commit-run.sh` verifies that `git status` shows no files under `raw/` (proving `.gitignore` is configured correctly) and scans `redacted/` for any residual sensitive patterns.

Raw artifacts are never committed. The `.gitignore` rules enforce this at the git level, and `commit-run.sh` double-checks at the script level. Only `redacted/` contents, `findings.json` files, `run-metadata.json`, and `state.json` are staged.

Commits are local only. conwrt does not push to any remote repository.

---

## 8. Safety Boundary

conwrt operates under strict read-only constraints. The boundary is non-negotiable.

```
┌─────────────────────────────────────────────────────────────────┐
│                     WHAT conwrt DOES                         │
│                                                                 │
│  Reads local network interface configuration                    │
│  Sends passive ARP/ping discovery probes                        │
│  Runs nmap TCP connect scans (-sT, no raw sockets, no root)     │
│  Fetches HTTP/HTTPS headers and TLS certificates                │
│  Calls vendor-documented read-only API endpoints                │
│  Captures screenshots of web UIs (read-only navigation)         │
│  Structures, validates, and redacts all findings                │
│  Commits redacted artifacts to local git (no push)              │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                   WHAT conwrt DOES NOT DO                     │
│                                                                 │
│  Flash firmware or bootloaders                                  │
│  Modify any device settings via web UI or API                   │
│  Attempt credentials or brute force authentication              │
│  Send factory reset triggers                                    │
│  Execute arbitrary code received from the LLM                   │
│  Push to remote git repositories (commit only)                  │
│  Send POST/PUT/DELETE requests to admin endpoints               │
│  Perform subnet scans after target is confirmed (step-02+)      │
│  Run nmap OS detection (-O) or SYN scans (-sS)                  │
└─────────────────────────────────────────────────────────────────┘
```

The safety boundary is enforced at three levels:

1. **Prompt-level:** Each prompt template contains explicit tool allowlists and blocklists, plus a disclaimer banner
2. **Script-level:** `commit-run.sh` verifies redacted output contains no sensitive patterns before staging
3. **Git-level:** `.gitignore` prevents raw artifacts from being tracked, and `commit-run.sh` double-checks

---

## 9. Known Limitations

- Only 4 steps are implemented in the scaffold. The architecture supports adding more steps by creating new prompt templates and updating `state.json` ordering, but this is not yet documented as a workflow.
- Vendor-specific recipes under `recipes/` are not yet populated. The directory structure exists as a placeholder for per-device capture instructions and known-good API endpoints.
- The adapter is tested with `opencode run --prompt-file`. Other LLM CLIs may need `OPENCODE_CMD` customization to satisfy the adapter contract (last argument = prompt file path, artifacts written to `$STEP_DIR/raw/`, findings written to `$STEP_DIR/findings.json`).
- The framework is a research prototype. Any actual device migration requires independent human validation of all findings and recommendations before proceeding.

---

## 10. Operational Lessons for Future Router Sessions

The framework should treat link state, IP reachability, HTTP readiness, and full service readiness as separate phases. A device may answer ARP or ICMP long before its management UI or documented API is actually usable.

### Readiness layering

- **Link ready**: carrier is up on the interface.
- **Network ready**: the operator workstation receives DHCP or sees ARP from the target.
- **Management ready**: the expected stock HTTP page or read-only API responds successfully.
- **Migration ready**: credentials and upload endpoint both succeed.

Scripts and operator procedures should wait for the highest required readiness state, not the first one observed.

### Capture-first mindset

When a flash or first boot appears to fail, packet capture often gives the most reliable answer. DHCP replies, ARP responses, DNS behavior, and router advertisements can prove the target has already booted into a new state even when earlier polling logic has timed out.

Recommended practice for future recipes and automation:

- start capture before reset or flash
- keep captures in `data/captures/`
- inspect capture before declaring a failed boot
- use observed traffic to decide whether to retry, continue provisioning, or roll back

### Per-device boot windows

Do not assume a single reboot timeout fits all hardware. Flash media and first-boot behavior vary significantly:

- slower eMMC and NAND first boots may exceed a generic 120-second timeout
- stock firmware after factory reset may expose link and DHCP before web/API services are ready
- recipe metadata should record model-specific timing expectations when validated

### Framework guidance

Future device recipes should include, when known:

- which physical port was used successfully
- what “stock ready” looks like for that device
- what “post-flash alive” looks like on the wire
- expected first-boot timing range
- rollback trigger and recovery path
