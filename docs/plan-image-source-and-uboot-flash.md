# Plan — Vanilla image sourcing, U-Boot MD5 verification, and `make flash`

Status: in progress (see checklist at the bottom)

## Problem

Two gaps surfaced while flashing a GL.iNet GL-MT3000 (Beryl AX) with the
vanilla OpenWrt image:

1. **No image sourcing.** `cmd_flash` hard-errors with
   `One of --image or --request-image is required.` There is no path that
   resolves the *vanilla* OpenWrt `squashfs-sysupgrade.bin` from the detected
   model and downloads it. Operators must fetch the file by hand and pass
   `--image`.
2. **U-Boot MD5 is shown but never checked.** The GL.iNet U-Boot web failsafe
   returns `<size> <md5>` from `POST /upload` (see
   `gl-inet/mt798x-boot` → `failsafe/failsafe.c`). `flash/upload.py` parses
   that response but only logs `uboot_md5`; it never compares it to the local
   file. A truncated/corrupted upload would only surface as a failed boot.

Both matter most on the recovery path, where the device is not running OpenWrt
and cannot be asked to identify itself over SSH.

## Scope

In scope:

- Resolve + download + verify (SHA-256) the vanilla OpenWrt sysupgrade image
  for a model, with an optional per-model release pin.
- Wire sourcing into `conwrt flash` (default on; opt out with
  `--no-source-image`) and expose a `conwrt image` subcommand.
- Compare the MD5 returned by the U-Boot `/upload` response against the local
  file before triggering `/result`.
- Make targets: `detect`, `flash`, `flash-uboot`, `source-image`.
- Host-route hardening for the U-Boot recovery subnet so a colliding host
  subnet (e.g. another router's `192.168.1.0/24`) does not steal recovery
  traffic; optional `--suspend-wifi`.

Out of scope (tracked separately, not in this change):

- Using npm/`ajv-cli` in CI (unchanged).
- Reworking the ASU (`--request-image`) path.
- Zycast / serial image sourcing.

## Design

### 1. Image sourcing — `scripts/conwrt/image_source.py`

Release precedence (first match wins):

1. explicit `--release` / `OWRT_RELEASE` argument,
2. `openwrt.release` in the model JSON,
3. module `DEFAULT_RELEASE`.

Only full versions (`24.10.2`) are valid for a download URL; the model's
existing `openwrt.version` (`"24"`, used for ASU) is left untouched.

URL shape (standard OpenWrt target layout):

```
https://downloads.openwrt.org/releases/<release>/targets/<target>/<subtarget>/
  openwrt-<release>-<target>-<subtarget>-<profile>-squashfs-sysupgrade.bin
```

`<target>` is split from `openwrt.target` (`mediatek/filogic`); `<profile>` is
`openwrt.profile` (`glinet_gl-mt3000`).

Integrity: OpenWrt publishes a per-directory `sha256sums` file (there is **no**
per-image `.sha256`). Sourcing fetches `sha256sums`, finds the line for the
image basename, downloads the image into `images/` (gitignored), and verifies
the SHA-256. Cached files that already match are reused.

### 2. `conwrt flash` wiring

When neither `--image` nor `--request-image` is given and sourcing is enabled,
resolve + download the image for the resolved `--model-id` and continue. The
`parser.error` fallback remains for `--no-source-image` or unsupported models.

### 3. U-Boot MD5 verification

Add `parse_uboot_response(response)` (in `flash/upload.py`) that parses the
`<size> <md5>` GL.iNet format and `md5_file(path)` (in `flash/context.py`).
`_handle_uboot_uploading` compares the U-Boot MD5 against the local file MD5
and aborts before `/result` on mismatch (override with `--yes`). SHA-256 of the
local file before/after upload is retained.

> Note on hashing: OpenWrt/BusyBox only ships `sha256sum`, so conwrt's
> on-device checks use SHA-256. U-Boot's failsafe uses **MD5** internally; the
> MD5 here mirrors the value the *bootloader* reports, not a BusyBox command.

### 4. Host-route / WiFi collision

`_setup_interface_ips` additionally installs a `/32` host route for the
recovery IP via the wired interface (`ip route replace <ip>/32 dev <iface>` on
Linux, `route add -host` on macOS). This makes recovery traffic prefer the wire
when a different interface shares the subnet. `--suspend-wifi` (opt-in)
temporarily disables host WiFi radios and restores them in a `finally` block.

### 5. Make targets

```
detect        Auto-detect the connected router (non-interactive)
flash         Source the right image for the connected router and flash it
flash-uboot   Force U-Boot recovery flash of the connected router
source-image  Download + verify the image only
```

### 6. Tests

Hardware-safe, mocked only (per CONTRIBUTING.md): URL construction and release
precedence, `sha256sums` parsing + verification, U-Boot response parsing, MD5
compare pass/fail, host-route command construction, and `cmd_flash` wiring for
the sourcing branch.

## Usage note (two phases)

U-Boot mode cannot auto-detect the model (no SSH), so:

1. While the router runs OpenWrt: `make flash` (detects + sources + flashes), or
   `make source-image MODEL=glinet-mt3000` to cache only.
2. Enter U-Boot (hold reset, power on), then:
   `make flash-uboot MODEL=glinet-mt3000`.

## Checklist

- [x] Repo cloned; feature branch `feat/image-source-and-make-flash`
- [x] Baseline `pytest tests -m "not integration"` green (3859 passed)
- [x] `scripts/conwrt/image_source.py`
- [x] schema `openwrt.release` + `models/glinet-mt3000.json`
- [x] `flash_dispatcher` sourcing wiring + CLI flags (`--source-image`, `--release`, `--suspend-wifi`)
- [x] `cmd_image.py` + `conwrt image` subcommand
- [x] U-Boot MD5 parse + verify (`upload.py`, `context.py`, `handlers_uboot.py`)
- [x] Host route + `--suspend-wifi` (`platform_utils.py`, `extreme.py`, `flash_dispatcher.py`)
- [x] Makefile targets (`detect`, `flash`, `flash-uboot`, `source-image`)
- [x] README updates (targets table, CLI options, `conwrt image` usage)
- [x] Tests (image_source, upload parse, handlers_uboot MD5, cmd_flash sourcing, platform_utils, extreme host route, cmd_image)
- [x] `make ci` green (ruff + pyright + schemas + models + 3914 tests + smoke)
- [x] Live sanity: `fetch_image` downloaded + SHA-256-verified the real MT3000 24.10.2 image; cache reuse confirmed
- [x] Branch `feat/image-source-and-make-flash` pushed to `c03rad0r/conwrt`; PR #99 opened against `Amperstrand/conwrt`

## Verification log

- `pytest tests -m "not integration"`: 3914 passed, 12 skipped (baseline 3859 → +55).
- `ruff check scripts tests`: clean. `pyright scripts tests`: 0 errors.
- `validate_models.py`: all 24 models OK. `make validate-schemas`: OK.
- `make ci`: exit 0.
- Live: `resolve_image_url("glinet-mt3000")` → HTTP 200 (9,032,056 bytes);
  `sha256sums` parse matched; `fetch_image` download + verify + cache reuse all OK.
- Not verified on hardware (per CONTRIBUTING, tests are mock-only): the actual
  U-Boot `/upload` + `/result` flash and `--suspend-wifi` host behavior.

