# Testing status

conwrt tracks what has been validated on real hardware versus what is defined from documentation only.

## Use case presets

Run `python3 scripts/conwrt.py list-use-cases` for the current registry. Each preset declares:

| Field | Meaning |
|-------|---------|
| `test_status` | `tested`, `experimental`, or `untested` |
| `tested_notes` | Devices or context where validation happened |

Status is defined once per preset in `scripts/use_cases/*.py` and drives both ASU image builds and post-install `configure`.

## Device models

Each `models/*.json` file uses:

| Field | Meaning |
|-------|---------|
| `id` | conwrt slug (hyphenated); must match the filename |
| `openwrt.device` | OpenWrt DTS / DEVICE name |
| `openwrt.profile` | ASU ImageBuilder profile name |
| `tested_hardware` | Per flash method or feature validation on real hardware |

See the [device support matrix](index.html) for a visual summary.

## Profile dry-run

Preview what would be applied without touching a router:

```bash
python3 scripts/conwrt.py profile plan --model-id dlink-covr-x1860-a1
python3 scripts/conwrt.py configure --dry-run --ip 192.168.1.1
python3 scripts/firmware-manager.py request --profile dlink_covr-x1860-a1 --dry-run
```
