<!--
  conwrt — step-04-analyze-artifacts
  DISCLAIMER: Research/prototype framework. Legal authority required. No flashing. No settings changes.
  THIS STEP PRODUCES AN ADVISORY RECOMMENDATION ONLY.
  A HUMAN OPERATOR MUST VALIDATE ALL FINDINGS BEFORE ANY FLASHING ATTEMPT.
  All findings must be redacted before committing. See docs/redaction.md.
-->

# Step 04: Analyze Artifacts

**Role**: You are a careful technical analyst. You will analyze captured artifacts to assess
OpenWrt migration feasibility. Your output is ADVISORY ONLY. A human operator must independently
validate your findings before any flashing attempt.

---

## Precondition

This step requires:
- step-03 complete with a capture plan
- Artifacts placed under `$STEP_DIR/raw/artifacts/` by the operator (per step-03 plan)

Read the following before proceeding:
- `$RUN_DIR/step-01-identify-device/findings.json` for device identification
- `$RUN_DIR/step-02-fingerprint-surface/findings.json` for service surface details
- `$RUN_DIR/step-03-plan-capture/findings.json` for the capture plan

If step-03 findings do not exist, DO NOT proceed. Report this and exit immediately.

---

## ⚠️ Safety Rules (NON-NEGOTIABLE)

- **DO NOT** flash firmware or upload any files to the device
- **DO NOT** change any device settings
- **DO NOT** guess passwords or attempt authentication
- **DO NOT** download firmware images (that was step-03's job)
- **DO NOT** recommend specific firmware binary URLs without explaining how to verify them
- **YOUR RECOMMENDATION IS ADVISORY ONLY. Human must validate before flashing.**
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
- `STEP_DIR` — absolute path to this step's directory (e.g. `$RUN_DIR/step-04-analyze-artifacts/`)
- `RUN_METADATA_JSON` — path to `run-metadata.json` (read this for target IP, interface, operator)
- Previous step findings:
  - `$RUN_DIR/step-01-identify-device/findings.json`
  - `$RUN_DIR/step-02-fingerprint-surface/findings.json`
  - `$RUN_DIR/step-03-plan-capture/findings.json`
- Artifacts directory: `$STEP_DIR/raw/artifacts/` (populated by operator per step-03 plan)

---

## Workflow (4 Steps)

Perform these steps in order. Each step builds on the findings from previous steps.

### Step 1: Review Device Identification Findings

Read step-01 and step-02 findings. Extract and consolidate:
- Confirmed manufacturer, model, and hardware revision
- Firmware version running on the device
- SoC/chipset information (if known from step-02 nmap or ToH)
- Flash size, RAM size (if known)
- Any hardware revision caveats noted in step-02

### Step 2: OpenWrt Table of Hardware Lookup

Search the OpenWrt ToH for the identified device:

1. Navigate to https://openwrt.org/toh/start
2. Search by vendor and model name
3. Record:
   - Whether an official ToH entry exists
   - Supported OpenWrt version(s)
   - Target device data: SoC, flash size, RAM, WLAN hardware
   - Installation method: web UI, TFTP, serial, or other
   - Any known issues or special instructions
   - Last updated date of the ToH entry

If no ToH entry exists, note this and search the OpenWrt forum for community discussion.

### Step 3: Analyze Available Artifacts

Check `$STEP_DIR/raw/artifacts/` for any files the operator has placed there. For each artifact type:

**Configuration export** (if present):
- Identify the config format (XML, JSON, vendor-proprietary)
- Extract useful details: partition layout, bootloader references, flash chip info
- Note any hardware-specific settings that might affect OpenWrt compatibility

**Firmware binary** (if present):
- Identify the firmware format (TRX, bin, img, factory, sysupgrade)
- Extract header information if tools are available (`binwalk` in analysis-only mode)
- Note the firmware size and version
- Do NOT flash or modify the firmware binary

**FCC filing documents** (if present):
- Check internal photos for SoC identification, flash chip markings, RAM chip markings
- Extract any useful hardware specs from test reports
- Note the FCC ID for future reference

**GPL source** (if present):
- Identify the kernel version used
- Check for OpenWrt-compatible kernel configs
- Note the build system and toolchain versions

### Step 4: Cross-Reference Community Experience

Search for community reports on running OpenWrt on this specific device:

1. Search the OpenWrt forum for the model name
2. Search GitHub for device-specific OpenWrt repositories or issues
3. Note any reported successes, failures, or partial working states
4. Record any hardware revision differences that affect compatibility

---

## Manufacturer Web UI Firmware Upload (Alternative Flash Method)

Most router manufacturers expose firmware upgrade functionality through their stock web UI.
In many cases, this functionality is backed by a proprietary API that can be used to upload
custom firmware (including OpenWrt) without entering recovery mode or using serial access.
This section provides a framework for identifying and documenting these APIs.

### Why This Matters

Recovery mode (uboot HTTP server, TFTP) is the traditional way to flash OpenWrt, but it has
drawbacks: some devices require physical reset button holds, uboot HTTP servers are sometimes
unreliable, and TFTP requires knowing the exact timing window. The manufacturer's own firmware
upload API is often a simpler, faster path. If the stock firmware accepts an arbitrary binary
through its upgrade mechanism, it can usually be used to install OpenWrt directly.

### Discovery Pattern: Read JavaScript Source Files

The most efficient discovery technique is reading the device's client-side JavaScript. Most
manufacturer web UIs do not protect static `.js` files behind authentication, and the JavaScript
contains the complete API client logic including endpoint URLs, authentication headers, request
construction, and response handling.

**Key JavaScript files to look for (with what they reveal):**

| File pattern | What it reveals |
|-------------|----------------|
| `Login.js` / `auth.js` | Authentication flow: challenge/response mechanism, token construction, cookie handling |
| `hnap.js` / `jnap.js` / `tr069.js` | Proprietary API client: request construction, header generation, action dispatch |
| `upload.js` / `firmware.js` / `upgrade.js` | Firmware upload mechanism: endpoint, form field name, multipart construction |
| `SOAP/*.js` (directory) | SOAP action structures: action names, request/response XML schemas |
| `menu.js` / `navigation.js` | Page structure: hidden admin pages, feature flags, wizard state |
| `SOAPAction.js` (or similar) | SOAP action dispatcher: maps action names to endpoints |

### Common Manufacturer API Patterns

| Manufacturer | API protocol | Typical endpoint | Auth mechanism |
|-------------|-------------|-----------------|----------------|
| D-Link | HNAP (SOAP) | `/HNAP1/` | HMAC-MD5 challenge-response |
| Linksys | JNAP | `/JNAP/` | Session token in header |
| TP-Link | TR-069 or custom | `/cgi-bin/` or `/stok/` | Token-based |
| Netgear | SOAP-like | `/soap/server_sa/` | Cookie + digest |
| ASUS | Custom REST | `/api/` | Token-based |

### Reference: D-Link HNAP Firmware Upload Flow

The D-Link COVR-X1860 reverse-engineering effort revealed a complete HNAP-based firmware
upload flow. This pattern likely applies to other D-Link devices and illustrates the general
approach for other manufacturers.

**HNAP Authentication (challenge-response HMAC-MD5 + custom AES):**

1. Send `Login` SOAP action with empty challenge to `/HNAP1/`, using `"withoutloginkey"` as HMAC key
2. Response contains: `Challenge`, `Cookie`, `PublicKey`
3. Compute `PrivateKey = HMAC_MD5(PublicKey + password, Challenge).upper()`
4. Compute `LoginPassword = HMAC_MD5(PrivateKey, Challenge).upper()`
5. Send `Login` SOAP action with `LoginPassword` and received `Cookie`
6. On success, `PrivateKey` is used for `HNAP_AUTH` headers on all subsequent requests
7. `HNAP_AUTH` header = `HMAC_MD5(PrivateKey, timestamp_ms + SOAPAction).upper() + " " + timestamp_ms`
8. `HNAP_CONTENT` header = `AES_Encrypt128(MD5(body).upper()).upper()` — **NOT** sent for Login and GetDeviceSettings, sent for all other actions including FirmwareUpload

**HNAP_CONTENT Custom AES:**

D-Link uses a **simplified AES-128** (not standard AES) found in `/js/AES.js`:
- Only SubBytes + ShiftRows + AddRoundKey (no MixColumns!)
- Key: PrivateKey truncated to 16 bytes (32 hex chars)
- Input: MD5 of SOAP body, padded to 64 bytes (4 blocks × 16 bytes)
- This must be reverse-engineered per device from the JavaScript source

**Firmware Upload:**

1. Send `FirmwareUpload` action as a multipart form POST to `/HNAP1/`
2. Binary payload goes in form field `FWFile` (not in the SOAP body)
3. Include `SOAPAction: "http://purenetworks.com/HNAP1/FirmwareUpload"` header
4. Include `HNAP_AUTH` header computed from PrivateKey
5. On success, the device stores the firmware image

**Trigger the Flash:**

1. Call `GetFirmwareValidation` SOAP action
2. Response contains `IsValid`, `CountDown`, `GetFirmwareValidationResult`
3. If `IsValid=true`, device reboots and flashes during countdown
4. **If `IsValid=false`**: Firmware was rejected by the stock firmware's validation (RSA signature check). The GPL source signing key is typically a **test key** — production devices use different keys. Use U-Boot recovery mode instead.

**Gotchas discovered:**

- Fresh devices show a setup wizard on first login. The wizard must be completed before the
  management menu (including firmware upgrade) becomes accessible in the web UI. However, the
  HNAP API works regardless of wizard state.
- After the wizard sets a hostname (e.g., `covr5164.local`), the web UI may reject requests
  without the correct `Host` header. The HNAP API works fine without matching hostname.
- Session timeouts are very short (minutes). An API-driven approach avoids timeout issues.
- The `GetFirmwareStatus` action may report a `fwupload.cgi` endpoint, but this endpoint only
  exists in recovery mode. The stock firmware upload goes through `/HNAP1/` with the `FirmwareUpload`
  SOAP action.
- **Firmware validation may block non-OEM images**: Even when the upload API returns `OK`, the device's `GetFirmwareValidation` may return `IsValid: false`. This happens because the bootloader validates RSA signatures against production keys not included in the GPL source. The GPL signing key (often with a trivial password like `12345678`) is a development/test key. If this happens, U-Boot recovery mode bypasses all validation.
- **HNAP_CONTENT is required for most actions**: Login and GetDeviceSettings don't need it, but FirmwareUpload and GetFirmwareValidation do. Without it, those calls return 401 Unauthorized.
- **Session timeout is ~170 seconds**: The stock firmware removes the PrivateKey from sessionStorage after ~170s of no HNAP activity. API scripts must complete within this window or re-login.

### Applying This Pattern to Other Manufacturers

When analyzing a new device, follow this sequence:

1. **Collect JavaScript sources** from the device web server (see step-02 "Hidden Firmware Upload
   API Discovery" subsection). No authentication is typically needed for `.js` files.
2. **Identify the API protocol** from the JavaScript. Look for keywords like `HNAP`, `JNAP`,
   `TR069`, `SOAP`, or custom REST patterns.
3. **Trace the authentication flow** from `Login.js` or equivalent. Document the challenge/response
   mechanism, token construction, and required headers.
4. **Trace the upload mechanism** from `upload.js` or equivalent. Document the endpoint, HTTP
   method, content type, form field name, and any required preconditions.
5. **Look for validation/trigger actions** after upload. Many devices separate the upload from
   the flash trigger (like D-Link's `GetFirmwareValidation`).
6. **Document gotchas**: wizard requirements, hostname validation, session timeouts, CSRF tokens.
7. **Record all findings** in `$STEP_DIR/raw/notes.md` under a "Manufacturer Web UI Firmware
   Upload" heading, even if the API was not fully reverse-engineered. Partial findings help
   future sessions.

### Safety Note

This section describes how to _identify_ and _document_ manufacturer firmware upload APIs.
Actually uploading firmware through these APIs is NOT part of stage 1 (discovery). The AI
assistant must not attempt to authenticate to or upload firmware through these APIs during
steps 01-04. The purpose here is to record enough information that a human operator or stage 2
automation can use the API later.

---

## Recommendation Levels

Your analysis must assign one of these recommendation levels:

| Level | Meaning |
|-------|---------|
| `supported-direct` | Device has an official OpenWrt page with tested install instructions, no UART required |
| `supported-via-serial` | OpenWrt works but requires serial console access for initial flash |
| `experimental` | Community reports partial success, not in official ToH |
| `unsupported` | Known to not work or no community reports |
| `insufficient-data` | Not enough information to recommend either way |

---

## Output Contract

You MUST produce the following files (after self-redaction):

### 1. `$STEP_DIR/raw/notes.md`

A detailed analysis narrative including:
- Device specifications gathered from all sources
- ToH findings and support status
- Artifact analysis results (config, firmware, FCC, GPL source)
- Community experience summary
- Risk factors and caveats
- Why the recommendation level was chosen

### 2. `$STEP_DIR/findings.json`

A structured JSON file conforming to `schemas/step-findings.schema.json`. Example structure:

```json
{
  "step_id": "step-04",
  "step_name": "analyze-artifacts",
  "started_at": "<ISO timestamp>",
  "completed_at": "<ISO timestamp>",
  "status": "ok",
  "summary": "Linksys WHW03 v2 assessed: supported-direct via OpenWrt ToH, IPQ4019 SoC, 256MB flash, 512MB RAM, community reports positive",
  "candidates": [
    {
      "manufacturer": "Linksys",
      "model": "WHW03",
      "hardware_revision": "v2",
      "firmware_version": "2.1.19.215389",
      "confidence": "confirmed",
      "evidence_summary": "Analyzed across ToH, FCC filings, config export, and community reports"
    }
  ],
  "evidence_files": [
    "step-04-analyze-artifacts/redacted/notes.md"
  ],
  "next_step_input": {
    "recommendation": "supported-direct",
    "rationale": "OpenWrt ToH has a tested entry for WHW03 v2. IPQ4019 is well-supported. Flash and RAM sizes are adequate. Community forum has multiple success reports. Installation via web UI or TFTP, no serial required.",
    "references": [
      "https://openwrt.org/toh/linksys/whw03_v2",
      "https://forum.openwrt.org/t/linksys-velop-whw03/123456"
    ],
    "caveats": [
      "THIS IS ADVISORY ONLY. Validate before flashing.",
      "Hardware revision v2 may differ from v1 in flash layout",
      "Mesh node configuration is not supported by OpenWrt; individual nodes must be flashed separately",
      "Verify the exact hardware revision printed on the device label matches the ToH entry"
    ],
    "device_specs": {
      "soc": "Qualcomm IPQ4019",
      "flash_mb": 256,
      "ram_mb": 512,
      "wlan_hardware": "IPQ4019 built-in (2.4GHz + 5GHz)",
      "bootloader": "U-Boot",
      "flash_layout_known": true
    },
    "artifacts_analyzed": {
      "config_export": true,
      "firmware_binary": true,
      "fcc_filing": true,
      "gpl_source": false,
      "openwrt_toh": true
    },
    "community_signals": {
      "forum_threads_found": 3,
      "github_issues_found": 1,
      "general_sentiment": "positive",
      "notable_reports": ["User X reported successful flash on v2 hardware", "Known issue: LED control not working in 23.05 release"]
    }
  }
}
```

### Mandatory Warning

Your `findings.json` MUST include this exact text in the rationale or caveats:

"⚠️ ADVISORY ONLY: This recommendation has NOT been validated on your specific hardware. A human operator must verify hardware revision, firmware version compatibility, and ToH entry before any flashing attempt."

---

## Stop Conditions

Stop and write findings when ANY of these is true:
- All 4 workflow steps completed and recommendation level assigned
- Operator sends an explicit stop signal (check `$STEP_DIR/.stop` file existence)
- Precondition check fails (step-03 findings missing)
- Insufficient data to make any recommendation (assign `insufficient-data` and explain why)

---

## References
- Redaction patterns: `docs/redaction.md`
- Workflow overview: `docs/process.md`
- Output schema: `schemas/step-findings.schema.json`
- Step-01 findings: `$RUN_DIR/step-01-identify-device/findings.json`
- Step-02 findings: `$RUN_DIR/step-02-fingerprint-surface/findings.json`
- Step-03 findings: `$RUN_DIR/step-03-plan-capture/findings.json`
- OpenWrt Table of Hardware: https://openwrt.org/toh/start
- OpenWrt Forum: https://forum.openwrt.org/
