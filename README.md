# conwrt

A framework for flashing routers with OpenWrt, with a 2-stage workflow:

1. **AI-assisted discovery** (`prompts/`): Encounter an unknown router, identify it, fingerprint its attack surface, plan a capture strategy, and analyze pcap artifacts to determine flash methods and boot signatures. This is how new router models get onboarded into conwrt.
2. **Automated flashing** (`scripts/` + `models/`): Once a model is defined with its flash method and boot signatures, subsequent flashes of that model are fully automated -- detect recovery mode, upload firmware, verify, and collect inventory.

> **DISCLAIMER**: conwrt flashes firmware onto real hardware. You must have legal authority to modify any device you use it on. Verify model definitions and firmware images before every flash. The authors accept no liability for bricked devices or data loss.

## Requirements

- macOS (uses `say` for voice guidance, `ifconfig` for interface detection)
- `tcpdump` and `sudo` for pcap capture and network monitoring
- Python 3.10+
- An ethernet cable and a router to flash

## Supported Devices

| Device | Method | Status |
|--------|--------|--------|
| D-Link COVR-X1860 A1 | recovery-http | Tested on hardware |
| GL.iNet MT3000 | uboot-http | Tested on hardware |
| GL.iNet AR150 | sysupgrade | Model defined, not tested |
| GL.iNet AR300M (lite/nand/nor) | sysupgrade | Model defined, not tested |
| Linksys WHW03 V1/V2 | sysupgrade | Model defined, signatures needed |

## Layout

```
conwrt/
├── models/              # Device model definitions (species-level, static, in git)
│   ├── dlink-covr-x1860-a1.json
│   ├── glinet-gl-ar150.json
│   ├── glinet-gl-ar300m-lite.json
│   ├── glinet-gl-ar300m-nand.json
│   ├── glinet-gl-ar300m-nor.json
│   ├── glinet-mt3000.json
│   ├── linksys-whw03-v1.json
│   └── linksys-whw03-v2.json
├── scripts/             # Automated flashing and management scripts
│   ├── conwrt.py               # Main flasher (auto-detect, sysupgrade, U-Boot recovery)
│   ├── router-fingerprint.py  # SSH-based device fingerprinting and inventory
│   ├── firmware-manager.py    # ASU firmware build/download/cache management
│   ├── model_loader.py        # Shared model registry reader
│   ├── router-probe.py        # Device boot state detection (off/uboot/openwrt)
│   └── inventory.py           # Inventory utilities
├── data/                # Runtime data (gitignored)
│   ├── inventory.jsonl         # Append-only device inventory (specimen-level)
│   └── *.bin                   # Cached firmware images
├── captures/            # Pcap captures (gitignored)
├── images/              # ASU firmware cache (gitignored)
├── recipes/             # Device-specific procedures and notes
├── prompts/             # AI-assisted discovery step templates
│   ├── step-01-identify-device.md
│   ├── step-02-fingerprint-surface.md
│   ├── step-03-plan-capture.md
│   └── step-04-analyze-artifacts.md
├── docs/                # Process and documentation
├── examples/            # Example artifacts (redacted)
└── README.md
```

## Workflow

conwrt has two stages. Stage 1 is for new devices not yet in `models/`. Stage 2 is for known devices.

### Stage 1: AI-Assisted Discovery

When you encounter a router that isn't in the models directory, walk through the prompt templates in `prompts/` with an LLM:

1. **Identify device** (`step-01-identify-device.md`) -- determine make, model, hardware revision
2. **Fingerprint surface** (`step-02-fingerprint-surface.md`) -- map exposed services, boot behavior, recovery interfaces
3. **Plan capture** (`step-03-plan-capture.md`) -- design a pcap capture strategy to observe the boot sequence
4. **Analyze artifacts** (`step-04-analyze-artifacts.md`) -- extract boot signatures, recovery mode patterns, and flash method from captures

The output of this process is a model JSON for `models/` and recipe notes for `recipes/`. Once committed, that device model moves to Stage 2.

### Stage 2: Automated Flashing

For any device already defined in `models/`, the scripts handle everything end-to-end:

```bash
# Auto-detect device and flash with custom ASU image
python3 scripts/conwrt.py --request-image --wan-ssh
```

### Flash with an existing firmware image

```bash
python3 scripts/conwrt.py --model-id dlink-covr-x1860-a1 --image firmware.bin
```

### Request a custom ASU image with your SSH key, then flash

```bash
python3 scripts/conwrt.py --model-id dlink-covr-x1860-a1 \
  --request-image --ssh-key ~/.ssh/id_ed25519.pub --no-password
```

### Custom image with WAN SSH access (key-only auth)

```bash
python3 scripts/conwrt.py --model-id dlink-covr-x1860-a1 \
  --request-image --no-password --wan-ssh
```

### Dry run (detect recovery mode, skip upload)

```bash
python3 scripts/conwrt.py --model-id dlink-covr-x1860-a1 \
  --image fw.bin --no-upload
```

### List available device models

```bash
python3 scripts/conwrt.py list
```

### Manage cached firmware

```bash
# List all cached builds
python3 scripts/conwrt.py cache list

# Remove old builds, keep latest per model
python3 scripts/conwrt.py cache clean --keep-latest

# Remove all builds for a specific model
python3 scripts/conwrt.py cache clean --model-id dlink_covr-x1860-a1
```

### Fingerprint a connected router

```bash
# Auto-detect router at default gateway
python3 scripts/router-fingerprint.py

# Target a specific IP
python3 scripts/router-fingerprint.py --ip 192.168.1.1

# Save to file
python3 scripts/router-fingerprint.py --ip 192.168.1.1 --output fingerprint.json
```

## Key CLI Options (conwrt.py flash)

| Option | Description |
|--------|-------------|
| `--model-id ID` | Model ID from models/ (auto-detected if device is running OpenWrt) |
| `--image PATH` | Path to firmware image |
| `--request-image` | Request custom image from ASU with baked-in settings |
| `--ssh-key PATH` | SSH public key to embed (auto-detected: id_ed25519.pub or id_rsa.pub) |
| `--password PASS` | Set root password (default: random, printed once) |
| `--no-password` | Skip password, key-only auth |
| `--wan-ssh` | Open SSH on WAN interface (disables password login on WAN) |
| `--force-uboot` | Force U-Boot recovery even if OpenWrt is running |
| `--no-voice` | Disable voice guidance |
| `--no-upload` | Dry run, detect only |
| `--interface IFACE` | Ethernet interface (auto-detected) |
| `--capture PATH` | Save pcap capture |

## Data Model

`models/` holds **species-level** data: what a COVR-X1860 is, how to flash it, what its boot signatures look like. Static, checked into git.

`data/inventory.jsonl` holds **specimen-level** data: this specific unit's MAC address, serial number, SSH key fingerprint, and full flash timeline. Gitignored, append-only, stays local.

Each model JSON contains vendor info, OpenWrt target/device/arch, hardware specs (SoC, flash, RAM, ports, Wi-Fi), MAC OUI prefixes for device identification, flash method definitions, and boot milestone patterns from pcap analysis.

## Features

- Event-driven state machine with real-time pcap monitoring
- Auto-detects device state (OpenWrt, U-Boot, offline) and picks sysupgrade or U-Boot recovery
- Optional model ID — auto-detected from SSH fingerprint when device is running
- Voice guidance via macOS `say` (user actions and milestones only)
- Full timeline tracking: power off through SSH verification
- SHA-256 firmware verification
- SSH verification and inventory collection after flash
- ASU integration for custom firmware builds with baked-in SSH keys, passwords, WAN SSH
- Firmware cache management (`conwrt cache list/clean`)
- Automatic ethernet interface detection
- Link monitoring survives pcap writer death during reboot

## Privacy

All captures, images, and data directories are gitignored. SSH key user@host comments are stripped before embedding in firmware. Inventory stays local. No personal data in model definitions.

## Contributing

Standard PR-based workflow. Device contributions should include:

1. Model JSON in `models/`
2. Recipe notes in `recipes/`
3. Boot signatures from pcap analysis
4. Tested on real hardware

## License

MIT. See [LICENSE](LICENSE).
