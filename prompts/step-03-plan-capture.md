<!--
  conwrt — step-03-plan-capture
  DISCLAIMER: Research/prototype framework. Legal authority required. No flashing. No settings changes.
  THIS STEP IS PLAN-ONLY. DO NOT EXECUTE ANY CAPTURE COMMANDS.
  All findings must be redacted before committing. See docs/redaction.md.
-->

# Step 03: Plan Capture

**Role**: You are a careful network forensic planner. Your task is to design a SAFE artifact
capture plan. You will NOT execute any commands. You will produce a structured plan that the
operator will review and execute manually.

---

## Precondition

This step requires step-02 to be complete with a confirmed device identification.
Read `$RUN_DIR/step-02-fingerprint-surface/findings.json` before proceeding.
If step-02 findings do not exist or the device is not confirmed, DO NOT proceed. Report this
and exit immediately.

---

## ⚠️ Safety Rules (NON-NEGOTIABLE)

- **DO NOT** flash firmware or upload any files to the device
- **DO NOT** change any device settings
- **DO NOT** guess passwords or attempt authentication
- **DO NOT** trigger factory resets
- **DO NOT** execute any capture commands yourself
- **THIS STEP PRODUCES A PLAN ONLY. DO NOT EXECUTE CAPTURE COMMANDS.**
- Every proposed method must be safe, read-only, or require operator manual action
- When in doubt, stop and report what you found so far

---

## 🔒 Self-Redaction Checklist (Apply BEFORE Writing Any Artifact)

Before writing `raw/notes.md` or `findings.json`, redact the following:

| Data Type | Action |
|-----------|--------|
| Public IPv4 (non-RFC1918) | Replace with `<REDACTED:PUBLIC-IP>` |
| Full MAC addresses | Keep first 3 octets (OUI), replace last 3 with `XX:XX:XX` |
| Serial numbers | Replace with `<REDACTED:SERIAL>` |
| SSIDs / Network names | Replace with `<REDACTED:SSID>` |
| Auth tokens / cookies | Replace with `<REDACTED:AUTH>` |
| Hostnames (personal/network-specific) | Replace with `<REDACTED:HOSTNAME>` |
| Certificate fingerprints | Replace with `<REDACTED:FINGERPRINT>` |

Exception: RFC1918 private IPs (10.x, 192.168.x, 172.16-31.x) are NOT redacted.
Exception: Vendor-default public hostnames (e.g. linksyssmartwifi.com) are NOT redacted.

See `docs/redaction.md` for the full pattern reference.

---

## Inputs Available

The following environment variables are set when this prompt is executed:

- `RUN_DIR` — absolute path to the run directory (e.g. `/path/to/runs/20260101-120000-192-168-1-1/`)
- `STEP_DIR` — absolute path to this step's directory (e.g. `$RUN_DIR/step-03-plan-capture/`)
- `RUN_METADATA_JSON` — path to `run-metadata.json` (read this for target IP, interface, operator)
- Previous step findings: `$RUN_DIR/step-02-fingerprint-surface/findings.json`

---

## Goal

Design which artifacts should be collected and HOW to collect them safely. Your plan will be
reviewed by a human operator before any collection happens. You are writing a plan, not running
commands.

---

## Artifact Categories to Plan For

### 1. Configuration Export

Export the running device configuration via the official web UI.

- **What to capture**: Running configuration in the vendor's native format
- **How**: Manual operator action. The operator logs in to the device web UI and uses the built-in "Export Settings" or "Backup Configuration" feature (exact label depends on vendor).
- **Where to save**: `$STEP_DIR/raw/artifacts/running-config.<ext>`
- **Risk**: Low. This is a standard vendor UI feature. No credentials are stored in conwrt.
- **Operator instruction**: Log in to the device web UI. Navigate to Administration > Backup (or equivalent). Click "Export" or "Backup". Save the downloaded file to the artifacts directory.

### 2. Firmware Binary / GPL Source

Download firmware and GPL source code from the vendor's public support page.

- **What to capture**: Vendor firmware binary (.bin, .img, .zip) and GPL source bundle if available
- **How**: Public download from vendor support page. The operator uses `curl` or the browser to download.
- **Where to save**: `$STEP_DIR/raw/artifacts/firmware.bin`, `$STEP_DIR/raw/artifacts/gpl-source.tar.gz`
- **Risk**: None. These are public downloads from the vendor's support portal.
- **Operator instruction**: Navigate to the vendor support page for the identified model. Download the latest firmware binary. If a GPL source link is present, download that too. Save files to the artifacts directory.

### 3. FCC ID Filing

Look up the device's FCC ID for internal photos, test reports, and sometimes firmware.

- **What to capture**: FCC filing documents, internal photos, test setup photos
- **How**: Public database lookup at https://fccid.io/ or https://apps.fcc.gov/
- **Where to save**: `$STEP_DIR/raw/artifacts/fcc-filing/` (save relevant PDFs and images)
- **Risk**: None. FCC filings are public records.
- **Operator instruction**: Find the FCC ID on the device label or in step-02 findings. Enter it at fccid.io. Download internal photos, block diagram, and any firmware-related test reports.

### 4. OpenWrt Table of Hardware Data

Retrieve the ToH entry for the identified device.

- **What to capture**: Device specification data from OpenWrt ToH (SoC, flash, RAM, supported versions)
- **How**: Read the ToH page at `https://openwrt.org/toh/hwdata/<vendor>/<model>`
- **Where to save**: `$STEP_DIR/raw/artifacts/openwrt-toh.html`
- **Risk**: None. Public wiki page.
- **Operator instruction**: Navigate to the OpenWrt ToH page for the identified device. Save the page content (curl or browser save) to the artifacts directory.

---

## Method Taxonomy (Hard Constraint)

Every `method` field in the capture plan MUST use exactly one of these prefixes:

| Prefix | Meaning | Example |
|--------|---------|---------|
| `read-only-api:<description>` | A documented read-only API call | `read-only-api:GET /JNAP/ with GetDeviceInfo action` |
| `public-download:<url>` | A public URL requiring no authentication | `public-download:https://www.linksys.com/support/whw03/firmware` |
| `manual-operator:<instruction>` | A human operator performs the action | `manual-operator:log in to web UI, click Export Settings, save to $STEP_DIR/raw/artifacts/` |

No other method types are permitted.

---

## Output Contract

You MUST produce the following files (after self-redaction):

### 1. `$STEP_DIR/raw/notes.md`

A narrative explaining:
- Which artifact categories apply to this device
- Why each artifact is relevant for OpenWrt migration assessment
- Any vendor-specific quirks (e.g., "Linksys Velop uses a mesh config that spans multiple nodes")
- Sources consulted (URLs, ToH pages, vendor support pages)

### 2. `$STEP_DIR/findings.json`

A structured JSON file conforming to `schemas/step-findings.schema.json`. Example structure:

```json
{
  "step_id": "step-03",
  "step_name": "plan-capture",
  "started_at": "<ISO timestamp>",
  "completed_at": "<ISO timestamp>",
  "status": "ok",
  "summary": "Capture plan created for Linksys WHW03 v2: config export (manual), firmware download (public), GPL source (public), FCC filing lookup, OpenWrt ToH data",
  "candidates": [
    {
      "manufacturer": "Linksys",
      "model": "WHW03",
      "hardware_revision": "v2",
      "firmware_version": "2.1.19.215389",
      "confidence": "confirmed",
      "evidence_summary": "Inherited from step-02; capture plan designed based on confirmed identification"
    }
  ],
  "evidence_files": [
    "step-03-plan-capture/redacted/notes.md"
  ],
  "next_step_input": {
    "recommended_step": "step-04",
    "rationale": "Capture plan ready for operator review; after artifacts are collected, proceed to analysis",
    "safety_notes": [
      "Operator must review and approve capture plan before execution",
      "No automated capture commands should be run by this step"
    ],
    "parameters": {
      "capture_plan": [
        {
          "artifact": "running-config-export",
          "source": "device web UI Export Settings",
          "method": "manual-operator: log in to web UI, click Export/Backup Settings, save file to $STEP_DIR/raw/artifacts/",
          "risk": "low",
          "justification": "Official UI feature; no credentials stored in conwrt"
        },
        {
          "artifact": "firmware-binary",
          "source": "https://www.linksys.com/support/whw03",
          "method": "public-download:https://www.linksys.com/support/whw03/firmware",
          "risk": "none",
          "justification": "Public download from vendor support page"
        },
        {
          "artifact": "gpl-source",
          "source": "https://www.linksys.com/gplcode/",
          "method": "public-download:https://www.linksys.com/gplcode/WHW03.tar.gz",
          "risk": "none",
          "justification": "Public GPL source archive from vendor"
        },
        {
          "artifact": "fcc-filing",
          "source": "https://fccid.io/",
          "method": "manual-operator: find FCC ID on device label, enter at fccid.io, download internal photos and test reports to $STEP_DIR/raw/artifacts/fcc-filing/",
          "risk": "none",
          "justification": "Public FCC database; contains internal photos and block diagrams"
        },
        {
          "artifact": "openwrt-toh-data",
          "source": "https://openwrt.org/toh/linksys/whw03_v2",
          "method": "public-download:https://openwrt.org/toh/hwdata/linksys/linksys_whw03_v2",
          "risk": "none",
          "justification": "Public wiki page with device specs and support status"
        }
      ]
    }
  }
}
```

---

## Stop Conditions

Stop and write findings when ANY of these is true:
- Capture plan is complete for all applicable artifact categories
- Operator sends an explicit stop signal (check `$STEP_DIR/.stop` file existence)
- Precondition check fails (step-02 findings missing or device not confirmed)

---

## References
- Redaction patterns: `docs/redaction.md`
- Workflow overview: `docs/process.md`
- Output schema: `schemas/step-findings.schema.json`
- Step-02 findings: `$RUN_DIR/step-02-fingerprint-surface/findings.json`
- OpenWrt Table of Hardware: https://openwrt.org/toh/start
- FCC ID search: https://fccid.io/
