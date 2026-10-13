# conwrt

**[→ Device Support Matrix](https://amperstrand.github.io/conwrt/)** — supported devices, flash methods, and tested hardware.
**[→ Use Case Test Results](https://tests.tollgate.me/)** — live test evidence from Nostr/Blossom (select "conwrt" tab).

A framework for flashing routers with OpenWrt, with a 2-stage workflow:

1. **AI-assisted discovery** (`prompts/`): Encounter an unknown router, identify it, fingerprint its attack surface, plan a capture strategy, and analyze pcap artifacts to determine flash methods and boot signatures. This is how new router models get onboarded into conwrt.
2. **Automated flashing** (`scripts/` + `models/`): Once a model is defined with its flash method and boot signatures, subsequent flashes of that model are fully automated -- detect recovery mode, upload firmware, verify, and collect inventory.

> **DISCLAIMER**: conwrt flashes firmware onto real hardware. You must have legal authority to modify any device you use it on. Verify model definitions and firmware images before every flash. The authors accept no liability for bricked devices or data loss.

## Quick Start

Plug the router into this machine's ethernet port and run:

```bash
python3 scripts/conwrt.py watch
```

conwrt scans for routers in recovery mode (and running OpenWrt), identifies the model by probe evidence, and asks before it flashes. Confirm, and it builds a fresh image with your SSH keys and config baked in (from `config.toml`), flashes, and verifies over SSH:

```
$ conwrt watch
Watching enp5s0 — probing 4 addresses every 5.0s (Ctrl-C to stop)
  · 192.168.0.1 — uboot
=======================================================
  Device found: 192.168.0.1  (uboot)
  MAC:      AA:BB:CC:12:34:56
  Model:    COVR-X1860 A1 mesh WiFi
  Model ID: dlink-covr-x1860-a1
=======================================================
  → flash this device with a fresh ASU image (latest OpenWrt, your keys baked in)? [y/N]: y
```

A router already running OpenWrt is detected via SSH board fingerprint and offered an in-place upgrade instead.

Other entry points:

| Command | What it does |
|---------|--------------|
| `conwrt watch` | Scan loop: detect → prompt → flash (the just-works path) |
| `conwrt probe` | One-shot table of what's on the wire (IP, state, model candidates) |
| `conwrt auto` | Deep 5-phase detection (passive listen, LLDP, DHCP, ARP, probing) with menu |
| `python3 scripts/conwrt_tui.py` | Interactive discovery TUI (preview/dry-run by design) |
| `conwrt flash --model-id ID --request-image` | Direct flash of a known model |

Device in a weird state (wrong IP, no recovery mode)? Put it in recovery first — for most models hold reset while powering on. `conwrt watch` will find it once the U-Boot recovery server answers.

## Requirements

- Linux or macOS (Ubuntu 22.04+/Debian and macOS tested; passwordless `sudo -n` is used for interface aliases and packet capture — without it, scanning and flashing still work, with fewer live events)
- `curl` and `ssh` on PATH
- Python 3.10+
- An ethernet cable and a router to flash

## Development setup

Hardware-safe development and CI do not require a router:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
make ci
```

Useful targets:

| Target | What it does | Hardware safe |
|--------|--------------|---------------|
| `make lint` | Ruff plus shell syntax checks | Yes |
| `make typecheck` | Pyright static checks | Yes |
| `make validate-models` | Validate every `models/*.json` against `schemas/model.schema.json` | Yes |
| `make test` | Python unit tests plus the existing smoke test | Yes |
| `make ci` | lint + typecheck + schemas + models + tests | Yes |
| `make rust-ci` | Rust workspace: fmt + clippy + tests + `no_std` cross-check (`crates/`, `apps/`) | Yes |
| `make ipk` | Build conwrt as an arch-independent OpenWrt ipk package | Yes |
| `make integration` | Full QEMU OpenWrt VM suite incl. a real `conwrt flash` sysupgrade lifecycle | Yes (local VM) |
| `make bench` | Bufferbloat benchmark: latency under load before/after SQM | Yes (local VM) |
| `make e2e` | Tests against a physical router (needs `CONWRT_DEVICE_IP`) | No — real device |

Device flashing targets (these mutate real hardware):

| Target | What it does |
|--------|--------------|
| `make detect` | Auto-detect the connected router (non-interactive) |
| `make flash` | Source the right vanilla OpenWrt image for the connected router and flash it |
| `make flash-uboot` | Force U-Boot recovery flash (enter U-Boot, then run; pass `MODEL=` for non-SSH recovery) |
| `make source-image` | Download + verify the vanilla OpenWrt image only (`MODEL=`, optional `RELEASE=`, `ARGS=--image-suffix ...`) |
| `make recovery` | Generic recovery flash for any model: probe the recovery web server, then `conwrt flash` (`MODEL=`, optional `IFACE=`) |

```bash
make source-image MODEL=glinet-mt3000 RELEASE=24.10.2   # cache + verify only
make recovery MODEL=glinet-mt3000 IFACE=enp0s31f6       # any model, recovery mode
```

The recovery helper (`scripts/flash-recovery.sh`) is model-agnostic: it reads
the model's recovery IP from `models/`, briefly configures the wired NIC to
probe the bootloader web server (**aborting if it isn't there**), then runs
`conwrt flash`. Models without an HTTP recovery address skip the probe.

Device configuration targets (these mutate real hardware):

| Target | What it does |
|--------|--------------|
| `make sta` | Connect the router to an upstream WiFi AP as a client (`SSID=`, `KEY=`, optional `BAND=`, `ENCRYPTION=`, `IP=`) |

```bash
make sta SSID=StarGate KEY=passphrase BAND=2.4ghz       # WiFi WAN backhaul
```

### Local test layers (nothing leaves your machine)

`make integration` / `make bench` / `make e2e` wrap `scripts/local-tests.sh`
and run the layers GitHub CI cannot (they need KVM or real hardware). They run
on demand — no scheduling, no publishing. All results land in the gitignored
`test-results/` folder: junit reports, per-run `index.md`, captured evidence
(serial log, `uci show`, firmware release), a `notes/` journal per run, and
`history.md` across runs.

Requirements for the VM layers: Linux with KVM (`/dev/kvm`),
`qemu-system-x86_64` + `qemu-img`, and (first run only) sudo for image
preparation. The VM fixture boots a per-session qcow2 overlay over a pristine
base, so every run starts from clean state. A full integration run including
the flash lifecycle takes ~7 minutes.

### Conwrt 2.0 (Rust foundation)

A portable Rust implementation is growing beside the Python code
(strangler-fig migration — no 1.x disruption). The M1 slice lives in
`crates/` + `apps/`: shared domain types that parse and validate the same
`models/*.json`, capability traits with a mock provider, a read-only
boot-state diagnostic workflow, and a `conwrt` CLI (`models`, `identify`,
`probe --scenario`). Design: [docs/architecture/conwrt-2.0-overview.md](docs/architecture/conwrt-2.0-overview.md),
decisions in [docs/adr/](docs/adr/), plan in [docs/roadmap/roadmap.md](docs/roadmap/roadmap.md).
Run `make rust-ci` (hardware-safe).

Related knobs:

- `CONWRT_CONFIG=/path/to/config.toml` — override the repo-root config for any
  conwrt invocation (the tests use this to avoid touching your config).
- `lan_ip_mode = "keep"` (in `[network]` or `[device]`) — leave the LAN IP
  untouched; useful when the address is managed externally.
- `conwrt flash --keep-config` — sysupgrade without `-n`: settings and SSH
  keys survive the upgrade. `conwrt flash --ip <addr>` targets a device at a
  non-default address (e.g. after a LAN move). Without `--keep-config` the
  override applies to the pre-flash connection only: `sysupgrade -n` resets
  the device to the model's default address, which is where conwrt polls,
  verifies, and records inventory after the flash.
  non-default address (e.g. after a LAN move).
- `CONWRT_BENCH=direct|labgrid` — one-shot bench-backend override for the
  `scripts/bench_*.py` tools (direct is the default; see
  [Optional labgrid integration](#optional-labgrid-integration)).

Do not run real flashing, sysupgrade, SSH, SCP, TFTP, tcpdump, serial, ASU, or other network-mutating commands from tests. Use mocks/stubs only. Commands such as `python3 scripts/conwrt.py ...`, `scripts/tftp-server.py`, and router SSH/SCP helpers can mutate real devices and should only be run intentionally against hardware you control.

## Supported Devices

### Flash Methods

| Method | How it works | Requires | Speed |
|--------|-------------|----------|-------|
| sysupgrade | SSH + SCP, runs sysupgrade -n | Running OpenWrt + SSH | ~3 min |
| recovery-http | Reset button, uboot HTTP server | Physical access + reset pin | ~2 min |
| dlink-hnap | HNAP SOAP API upload via stock firmware web UI | Stock D-Link firmware, network access | ❌ validation blocks flash |
| tftp | TFTP server for uboot network boot | Serial or uboot access | varies |
| extreme-rdwr-tftp | SSH to stock → rdwr_boot_cfg → TFTP boot initramfs → sysupgrade | Stock Extreme firmware, SSH access | ~5 min |
| zycast | Multicast to many devices simultaneously | Network broadcast domain | varies |
| serial-base64 | Transfer firmware over serial via base64 encoding | Serial console + `scripts/serial-flash.py` | ~22 min |
| serial-xmodem | XMODEM transfer from bootloader prompt | Serial console + bootloader XMODEM support | ~22 min |

### Device Support Matrix

See **[device support matrix](https://amperstrand.github.io/conwrt/)** — auto-generated from `models/*.json` (the authoritative single source of truth).

Tested devices are tracked in each model's `tested_hardware` field. To mark a device as tested, add a `tested_hardware` entry to its JSON:

```json
"tested_hardware": {
  "recovery-http": { "tested": true, "date": "2026-05-16", "notes": "..." },
  "wifi_sta_ap": { "tested": true, "date": "2026-05-16", "notes": "..." }
}
```

## Layout

```
conwrt/
├── models/              # Device model definitions (species-level, static, in git)
│   └── *.json           # See device matrix for full list
├── scripts/             # Automated flashing and management scripts
│   ├── conwrt.py               # Main flasher (auto-detect, sysupgrade, U-Boot recovery)
│   ├── router-fingerprint.py  # SSH-based device fingerprinting and inventory
│   ├── firmware-manager.py    # ASU firmware build/download/cache management
│   ├── model_loader.py        # Shared model registry reader
│   ├── router-probe.py        # Device boot state detection (off/uboot/openwrt)
│   ├── inventory.py           # Inventory utilities
│   ├── serial-boot-capture.py # Serial boot capture with UART break recovery
│   ├── serial-configure.py    # Configure devices via serial (IP, SSH key, auth)
│   ├── serial-flash.py        # Transfer firmware over serial via base64
│   ├── serial-backup.py       # Dump partitions via serial when SSH unavailable
│   ├── serial-console.py      # Interactive serial monitor with command FIFO
│   ├── extreme_ap391x_analyze.py  # Extreme AP391x firmware image analysis
│   ├── bench_discover.py     # Hypothesis-driven dark-device discovery ladder (EUI-64 v6, subnet archaeology, cred ladder)
│   ├── bench_inventory.py    # Read-only port scan + registry reconciliation (moved routers, exporter.yaml regen)
│   ├── bench_switch.py       # Bench/PoE switch lifecycle: backup/deploy/install-poe/verify/reset (see docs/BENCH-SWITCH-PATTERN.md)
│   ├── bench_session.py      # BenchSession: one bench, two backends (direct SSH/ubus default, optional labgrid) — powers the bench_* tools
│   ├── bench_doctor.py       # Read-only health check of the optional labgrid bench stack (offline mode: make labgrid-check)
│   ├── gs1900-bench-arm.sh   # Re-arm bench failsafes on the switch (TFTP lifelines, fw4 accept, watchers; deployed as /etc/bench-arm.sh)
│   ├── conwrt_serial_bridge.py  # Serve a listener router's UART as tcp://HOST:PORT (labgrid NetworkSerialPort / flash --serial)
│   ├── serial_transport.py   # Serial console driver: linted line-chunked delivery, FT232R break recovery
│   └── use_cases/             # Use case presets (auto-discovered plugins)
├── labgrid/               # Bench rig: PoE power backend (conwrt_poe), exporter config, tests
├── data/                # Runtime data (gitignored)
│   ├── inventory.jsonl         # Append-only device inventory (specimen-level)
│   └── *.bin                   # Cached firmware images
├── captures/            # Pcap captures (gitignored)
├── images/              # ASU firmware cache (gitignored)
├── recipes/             # Device-specific procedures and notes
├── prompts/             # AI-assisted discovery and serial troubleshooting templates
│   ├── step-01-identify-device.md
│   ├── step-02-fingerprint-surface.md
│   ├── step-03-plan-capture.md
│   ├── step-04-analyze-artifacts.md
│   ├── serial-01-connect-and-identify.md
│   ├── serial-02-bootloader-explore.md
│   ├── serial-03-backup.md
│   ├── serial-04-flash.md
│   ├── serial-05-configure.md
│   ├── serial-06-flash.md
│   ├── bench-forensics-01-dark-device.md
│   └── bench-forensics-02-session-archaeology.md
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

### Stage 1.5: Serial Console Recovery

When a device is inaccessible via network (broken firmware, wrong IP, no SSH), the serial console is the primary recovery path. Serial prompts (`prompts/serial-*.md`) guide the full workflow:

1. **Connect & identify** (`serial-01`) — capture boot sequence, identify bootloader/hardware/firmware
2. **Explore bootloader** (`serial-02`) — enter bootloader via ESC, enumerate commands, inspect env
3. **Backup** (`serial-03`) — dump Factory/calibration partitions (IRREPLACEABLE — always do this first)
4. **Flash via bootloader** (`serial-04`) — flash via zycast, TFTP, or XMODEM from the bootloader
5. **Configure** (`serial-05`) — change IP, install SSH key, enable auth via serial when network is down
6. **Flash via serial** (`serial-06`) — transfer firmware over the serial line itself (no network needed)

**Serial tools:**

```bash
# Capture boot sequence (auto-recovers from UART break during power cycle)
python3 scripts/serial-boot-capture.py /dev/cu.usbserial-XXXX 57600 --session <model>

# Configure device via serial (change IP, SSH key, auth)
python3 scripts/serial-configure.py /dev/cu.usbserial-XXXX 57600 --set-ip 192.168.5.1

# Backup partitions via serial (when SSH unavailable)
python3 scripts/serial-backup.py /dev/cu.usbserial-XXXX 57600 --partition Factory

# Transfer firmware over serial (no network needed, ~22 min for 7.3MB)
python3 scripts/serial-flash.py /dev/cu.usbserial-XXXX 57600 --base64 firmware.bin --verify --sysupgrade
```

**Serial is the MOST RELIABLE recovery method.** Try it FIRST, not last. See `docs/process.md` section 12 (Recovery Decision Tree) for guidance.

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

### Profile plan and configure (dry-run)

Preview operator profile from `config.toml` without changing a router:

```bash
python3 scripts/conwrt.py profile plan --model-id dlink-covr-x1860-a1
python3 scripts/conwrt.py configure --dry-run --ip 192.168.1.1
python3 scripts/firmware-manager.py request --profile dlink_covr-x1860-a1 --dry-run
```

Use cases and packages are defined once in `scripts/use_cases/` and applied via both ASU builds and post-install SSH.

### List available device models

```bash
python3 scripts/conwrt.py list
```

### Source the vanilla OpenWrt image for a model

Download + SHA-256 verify the stock OpenWrt image (into the gitignored
`images/` cache) without flashing. This is what `conwrt flash` uses
automatically when neither `--image` nor `--request-image` is given.

```bash
python3 scripts/conwrt.py image --model-id glinet-mt3000
python3 scripts/conwrt.py image --model-id glinet-mt3000 --release 25.12.5
python3 scripts/conwrt.py image --model-id dlink-covr-x1860-a1          # model's image_suffix (factory)
python3 scripts/conwrt.py image --model-id glinet-mt3000 --image-suffix squashfs-factory.bin
```

The **release** comes from `openwrt.release` in the model (falling back to the
repo default); override with `--release` / `CONWRT_OPENWRT_RELEASE`.

The **image flavour** comes from `openwrt.image_suffix` in the model (e.g.
`squashfs-factory.bin` for OEM web recovery, `initramfs-kernel.bin`,
`squashfs-sysupgrade.bin`), defaulting to `squashfs-sysupgrade.bin`; override
with `--image-suffix` / `CONWRT_IMAGE_SUFFIX`. This is what lets one code path
source the correct artefact for GL.iNet, D-Link, and other devices alike.

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
| `--source-image` / `--no-source-image` | Download the vanilla OpenWrt image for the model when neither `--image` nor `--request-image` is given (default: on) |
| `--release VERSION` | OpenWrt release for `--source-image` (e.g. `24.10.2`); defaults to `openwrt.release` in the model |
| `--image-suffix SUFFIX` | Vanilla image flavour for `--source-image` (e.g. `squashfs-factory.bin`); defaults to `openwrt.image_suffix`, then `squashfs-sysupgrade.bin` |
| `--suspend-wifi` | Temporarily disable host WiFi during U-Boot recovery to avoid subnet collisions (restored afterwards) |
| `--ssh-key PATH` | SSH public key to embed (auto-detected: id_ed25519.pub or id_rsa.pub) |
| `--password PASS` | Set root password (default: random, printed once, saved in inventory) |
| `--no-password` | Skip password, key-only auth |
| `--wan-ssh` | Open SSH on WAN interface (disables password login on WAN) |
| `--force-uboot` | Force U-Boot recovery even if OpenWrt is running |
| `--no-voice` | Disable voice guidance |
| `--no-upload` | Dry run, detect only |
| `--interface IFACE` | Ethernet interface (auto-detected) |
| `--capture PATH` | Save pcap capture |
| `--serial SPEC` | Optional serial boot-milestone monitor: `tcp://HOST:PORT[,baud]` (serial bridge, baud ignored) or `/dev/path[,baud]` — milestones detected from the serial stream alongside pcap; serial wins conflicts |
| `--transport ssh\|ubus` | Transport for `configure` command: SSH shell or ubus HTTP |
| `--version` | Print version and exit |

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
- Use case presets — flash OpenWrt pre-configured for tethering, SQM, VPN, guest WiFi, etc.
- Transport-agnostic ops pipeline — each use case generates typed operations that render to shell or ubus HTTP
- Firmware cache management (`conwrt cache list/clean`)
- Automatic ethernet interface detection
- Link monitoring survives pcap writer death during reboot
- conwrt ipk package — install on OpenWrt routers for router-to-router flashing

## Use Case Presets

conwrt doesn't just install OpenWrt — it installs OpenWrt **pre-configured for a specific use case**. Instead of flashing a stock image and then reading wiki docs to manually configure your router, you declare what you want in `config.toml` and the firmware arrives ready to go.

**Status: 14/15 use cases tested on OpenWrt 24.10.2** (QEMU/SHC). See [test results](https://tests.tollgate.me/) (conwrt tab). Use cases requiring WiFi (guest-wifi, travelmate, ap-nostr-id) need physical hardware. MPTCP bonding requires OpenWrt 25.12+ or SNAPSHOT.

### How It Works

Each preset is a single Python file in `scripts/use_cases/` that declares:
- Packages to include in the ASU firmware build
- A shell script of uci commands that runs on first boot
- Required hardware capabilities (auto-skipped if your device lacks USB, WiFi, etc.)

Enable them in `config.toml`:

```toml
[use_cases]
enabled = ["tether-android", "sqm"]

[use_cases.sqm]
download_kbps = 340000
upload_kbps = 19000
```

Or discover what's available:
```bash
python3 scripts/conwrt.py list-use-cases
python3 scripts/conwrt.py list-use-cases --model-id glinet-mt3000
```

### Priority Presets (near-zero configuration)

These use cases are the most immediately useful because they require almost no user configuration:

| Preset | What it does | User provides |
|--------|-------------|---------------|
| **tether** | USB WAN from Android or iPhone (auto-detects) | Plug in USB cable |
| **sqm** | Smart Queue Management with CAKE — eliminates bufferbloat | Download/upload speeds in Kbit/s |
| **travelmate** | Auto-connect to hotel/airport WiFi with captive portal detection | Nothing (auto-scans) |

These are the "flash and forget" cases — no wiki reading, no manual uci editing. Flash the image, plug in your phone or connect to upstream WiFi, and it works.

### All Available Presets

| Preset | Description | Post-flash? |
|--------|-------------|-------------|
| `tether` | Auto-detect Android or iPhone USB WAN. Android gets ADB auto-enable. | No |
| `tether-android` | USB WAN from Android. Enable tethering manually on the phone. | No |
| `tether-android-adb` | USB WAN from Android + ADB auto-enable. Confirm on phone, auto-activates. | No |
| `tether-ios` | USB WAN from iPhone. Enable Personal Hotspot manually on the phone. | No |
| `sqm` | Bufferbloat fix via CAKE/fq_codel (manual speeds) | No |
| `auto-sqm` | Auto-measure WAN speed + configure SQM (experimental) | No |
| `guest-wifi` | Isolated guest WiFi with separate subnet, DHCP, and firewall zone | No |
| `doh` | DNS-over-HTTPS via https-dns-proxy for encrypted DNS | No |
| `mwan3` | Multi-WAN failover or load balancing | No |
| `travelmate` | Auto-connect to captive portal WiFi | No |
| `tollgate` | Bitcoin/Lightning payment gateway (ipk from GitHub CI) | Yes (ipk deploy) |
| `wireguard-client` | VPN tunnel (auto-generates keys per device) | Auto (registration) |
| `wireguard-server` | VPN server for remote access | Yes (QR codes, peers) |
| `adguard` | Network-wide ad blocking | Yes (web setup wizard) |
| `openclash` | Transparent proxy for censorship bypass | Yes (subscription import) |
| `nodns` | Local DNS cache of nodns records via dnsmasq | No (auto-starts) |

Presets requiring post-flash setup need SSH access after first boot to complete configuration (importing VPN configs, running setup wizards, etc.).

### WireGuard VPN

**Status: Tested on hardware** (D-Link COVR-X1860 A1). WireGuard client, key generation, and post-flash registration all verified.

conwrt handles WireGuard in two stages: **firmware build** (use case preset) and **post-flash registration** (automatic). Each device auto-generates its own Curve25519 keypair on first boot — **no private keys ever exist in the firmware image**.

#### Stage 1: WireGuard client in firmware

Enable the `wireguard-client` use case in `config.toml`. This bakes `wireguard-tools` and a first-boot `uci` script into the firmware image. On first boot, OpenWrt generates a unique private key and configures the `wg0` interface with your server's endpoint.

The firmware includes:
- `wg0` WireGuard interface with `private_key='generate'` (unique per device)
- Peer config (server public key, endpoint, allowed IPs)
- Firewall `vpn` zone + LAN→VPN forwarding
- Optional kill switch (block all traffic if VPN drops)

#### Stage 2: Post-flash registration

After the router boots, conwrt automatically registers the device with your VPN server. This requires a `[wireguard]` section in `config.toml` with an SSH alias to your VPN server:

```toml
[wireguard]
registration_server = "my-vpn-server"  # SSH alias from ~/.ssh/config
wg_interface = "wg0"                   # WireGuard interface on the server
```

The registration flow:
1. SSH to router → read the auto-generated public key via `wg show wg0 public-key`
2. SSH to VPN server → run `wg set wg0 peer <pubkey> allowed-ips <address>` (live registration)
3. Append `[Peer]` block to `/etc/wireguard/wg0.conf` on the server (persistence)
4. Save public key to device inventory

The router's SSH key must be in the VPN server's `authorized_keys`. conwrt uses `BatchMode=yes` (key-only auth) for the server connection.

#### Full config example: Management VPN (split tunnel)

```toml
[use_cases]
enabled = ["wireguard-client"]

[use_cases.wireguard-client]
peer_public_key = "SERVER_PUBLIC_KEY"
endpoint_host = "vpn.example.com"
endpoint_port = 51820
address = "10.0.0.2/32"
allowed_ips = "10.0.0.0/24"    # only management subnet through tunnel
kill_switch = false

[wireguard]
registration_server = "my-vpn-server"
wg_interface = "wg0"
```

#### Full config example: Full tunnel VPN

```toml
[use_cases]
enabled = ["wireguard-client"]

[use_cases.wireguard-client]
peer_public_key = "SERVER_PUBLIC_KEY"
endpoint_host = "vpn.example.com"
address = "10.0.0.2/32"
kill_switch = true              # block all traffic if VPN drops

[wireguard]
registration_server = "my-vpn-server"
wg_interface = "wg0"
```

#### Key properties

- Same firmware image works for all devices — each generates unique keys on first boot
- Private key never leaves the router (generated on-device, stored in UCI overlay)
- Keys survive `sysupgrade` (UCI overlay preserved by default)
- Public key recorded in inventory for auditing and re-registration
- No secrets committed to git — `config.toml` is gitignored

#### Manual post-flash setup

`wg-setup.py` can apply WireGuard config post-flash from pre-generated server peer configs, without going through the full conwrt flash flow:

```bash
python3 scripts/wg-setup.py --peer 3 --server my-vpn-host
```

### NordVPN (vpn-nordvpn)

**Status: Tested on hardware** (D-Link COVR-X1860 A1, OpenWrt 25.12.5, 2026-10-08): unattended ASU flash → first boot brings up the tunnel, the `nord` 2.4GHz VPN-exit AP, DHCP/DNS for its clients, and management access from the VPN zone. Verified end-to-end: wired client and WiFi client exit via NordVPN DE, kill switch blocks all traffic when the tunnel dies, exit IP ≠ upstream IP. E2E user stories live in `tests/e2e/test_nordvpn_e2e.py`.

**Recommended: access token mode.** Everything resolves at BUILD time on the host (NordLynx key via `/v1/users/services/credentials` with HTTP Basic `token:<token>`, server via `/v1/servers/recommendations` with the `wireguard_udp` filter) and is baked as a static first-boot script — no curl, no jq, no API dependency on the device:

```toml
[use_cases]
enabled = ["vpn-nordvpn"]

[use_cases.vpn-nordvpn]
access_token = "nord-account-access-token"   # Nord Account → NordVPN → Manual setup
server = "DE"                                # country code/name/id, hostname, or IP (default: DE)
ap_ssid = "nord"                             # optional: 2.4GHz AP whose clients exit via the VPN
ap_key = "nordnord"                          # AP password
kill_switch = true                           # reject LAN→WAN if the tunnel drops
upstream_iface = "wwan"                      # wwan for WiFi STA uplink, wan for ethernet
```

**Server selection.** `server` accepts `DE`/`germany`/`81`, a concrete hostname (`de1507.nordvpn.com`), or an IP. Pick one with the companion CLI:

```bash
python3 scripts/nordvpn.py servers --country DE --limit 5      # hostname / station / load / pubkey
python3 scripts/nordvpn.py config --token TOKEN --server de1507.nordvpn.com --out de1507.conf
```

The legacy service-username/password token exchange was removed by NordVPN in April 2023 and is not supported. Tunnel address is static `10.5.0.2/32`; per-server WireGuard public keys come from the API metadata (they differ per server — never hardcode).

**Alternative: static config file.** A dashboard-exported WireGuard `.conf` (`config_file = "/path/to/nordvpn.conf"`) is parsed at build time and overrides the token. Useful for pre-generated keys.

**VPN-exit AP (`ap_ssid`).** A second SSID on the 2.4GHz radio whose clients get a DHCP lease on `172.16.31.0/24` and exit exclusively through the tunnel — no path to LAN. Hardware-verified details baked into the generated config: the AP is bridged (`br-vpnlan` — standalone AP interfaces never delivered DHCP), lives in a dedicated `vpnap` firewall zone with `vpnap→vpn` forwarding (joining the vpn zone directly drops DHCP/DNS and client forwarding), raises the shared radio to 20 dBm (txpower is radio-wide), and re-arms dnsmasq once the bridge is up.

**Management over the VPN (`allow_management`, default true).** TCP 22/80/443 from the vpn zone to the router are accepted, so you can reconfigure the router through the tunnel (or from the AP) instead of locking yourself out. Set `allow_management = false` only if you have another access path. DNS from the AP is scoped to `172.16.31.0/24` so the router is not an open resolver at its VPN exit IP.

Routing: the LAN is forwarded into the `vpn` firewall zone; netifd's wireguard proto installs the endpoint /32 route via the upstream gateway when the uplink comes up (a short fallback discovery covers paths where it doesn't). Optional `upstream_gateway` pins it statically.

### NordVPN OpenVPN technology (vpn-nordvpn-openvpn)

**Status: Tested on hardware** (COVR-X1860 A1, OpenWrt 25.12.5, 2026-10-08): token-driven service credentials + server resolution at build time, template-faithful config, exit verified (NordVPN UK). Perf: 134–168 Mbps with 65–78% CPU on the MT7621 (see the matrix below).

The same access token drives it — one token, every technology:

```toml
[use_cases]
enabled = ["vpn-nordvpn-openvpn"]

[use_cases.vpn-nordvpn-openvpn]
access_token = "nord-account-access-token"
technology = "openvpn-udp"          # or openvpn-tcp
server = "DE"                       # country/hostname/IP, same semantics as nordlynx
openvpn_cipher = "AES-256-CBC"      # template default; AES-256-GCM also negotiable
ap_ssid = "nord"                    # the VPN-exit AP works identically over OpenVPN
kill_switch = true
```

The generated config mirrors NordVPN's official per-server `.ovpn` templates: multi-port remotes (1231–1234), the NordVPN-wide CA and tls-auth key (embedded as constants, verified identical across all servers), `verify-x509-name` CN pinning, `remote-cert-tls server`, AES-256-CBC/SHA512 with GCM in `data-ciphers` for NCP. Service username/password are fetched from the token at build time and land in `/etc/openvpn/nordvpn.auth` (chmod 600) — nothing sensitive is committed, and the device makes no API calls.

### NordVPN IKEv2/IPsec on MT7621 — status and hardware acceleration (2026-10-08)

Findings from a hardware bring-up session, recorded so the next attempt starts informed:

- **IKEv2 to NordVPN works**: strongSwan 6.0.3 with EAP-MSCHAPv2 using the token-derived service credentials, IKE suite AES-CBC-256/HMAC-SHA2-256/MODP-2048, virtual IP 10.6.0.22. The server certificate chains to the same NordVPN Root CA used for OpenVPN.
- **OpenWrt 25.12 mt7621 ships without kernel XFRM** — `kmod-ipsec4 kmod-xfrm-interface kmod-nft-xfrm` must be installed (image packages, not runtime downloads, for a baked build).
- strongSwan needs these packages beyond the base: `strongswan-charon strongswan-swanctl strongswan-mod-{aes,sha1,sha2,gmp,hmac,pubkey,x509,pem,random,nonce,eap-identity,eap-mschapv2,md4,kernel-netlink,updown,attr,openssl}` and **`strongswan-mod-socket-default`** — with only `socket-dynamic`, charon logs "sending packet" while nothing ever leaves the interface (it never binds :500).
- **ESP CHILD_SA install fails with EINVAL (`unable to add SAD entry`) while the EIP-93 crypto driver is loaded** — IKE succeeds, TS narrows to 0/0 ↔ vip/32, then the kernel rejects the SAD entry. Unloading `crypto_hw_eip93` was attempted to confirm the driver interaction and **wedged the kernel** (network stack dead, wifi still beaconing; power cycle required). Treat the eip93 driver on kernel 6.12.94 as untested with xfrm — blacklist it before attempting IPsec, and never rmmod it with live crypto references.
- **Hardware acceleration reality on the MT7621 (EIP-93)**: accelerates `authenc(hmac(sha1/sha256),cbc(aes))` and `rfc3686(ctr(aes))` — classic IPsec ciphers, exactly what IKEv2 negotiated. It does **not** cover AES-GCM or ChaCha20-Poly1305: WireGuard and AES-GCM run on the MIPS cores (see `/proc/crypto`: `chacha20-mips`, `poly1305-mips`, generic GCM).
- Userspace OpenSSL on this SoC: ChaCha20-Poly1305 ≈ 23 MB/s, AES-256-CBC ≈ 11 MB/s, AES-256-GCM ≈ 6 MB/s — OpenVPN is CPU-bound well below the WireGuard ceiling.

### VPN performance matrix (x1860, OpenWrt 25.12.5, 2026-10-08)

iperf3 download (10s, best of 2) from a controlled server, router CPU sampled at 1 Hz. Server path caps the absolute numbers (~170 Mbps); CPU% at that load still separates the protocols. Harness: `prta-scenario-poc/tests/test_conwrt_vpn_matrix.py` (results in its gitignored `results/`).

| Technology | Throughput | Router CPU | Note |
|---|---|---|---|
| NordLynx (WireGuard, ChaCha20) | **172 Mbit/s** | 77% | fastest, kernel path |
| OpenVPN UDP AES-256-GCM | 156 Mbit/s | 75% | userspace OpenSSL |
| OpenVPN TCP | 168 Mbit/s | 78% | ≈ GCM (path-capped) |
| OpenVPN UDP AES-256-CBC | 134 Mbit/s | 65% | CBC+HMAC slower per byte |
| IKEv2/IPsec | not measured | — | blocked by the SAD/eip93 issue above |

### Future Direction

`conwrt watch` is the first interactive layer: detect what's plugged in, ask, flash. The long-term vision builds on that — interview the user before flashing ("Do you want USB tethering? SQM? A VPN?") and build the image with everything pre-configured. The `config.toml` use-case system is the declarative foundation for that interview.

## WiFi STA/AP Configuration

conwrt automatically configures WiFi after flashing based on `[network.sta]` and `[network.ap]` in `config.toml`. No manual uci editing needed.

**Status: Tested on hardware** (D-Link COVR-X1860 A1). Radio auto-detection verified: radio0=2.4GHz, radio1=5GHz.

### How It Works

1. **Post-flash SSH** (default): After flashing and SSH verification, conwrt detects the correct radio for each band via `uci get wireless.radioN.band` and applies STA/AP uci commands over SSH.
2. **ASU first-boot** (via `--request-image`): The same uci commands are baked into the firmware's first-boot script, so WiFi is configured before first SSH.

Both flows use the same radio detection logic — iterate `radio0..radio3`, check `band` option, match to the configured band.

### Quick STA connect (no config.toml edit)

Point a running router at an upstream AP directly from the CLI or make:

```bash
make sta SSID=StarGate KEY=passphrase BAND=2.4ghz IP=192.168.1.1
# equivalently:
python3 scripts/conwrt.py configure --ip 192.168.1.1 \
  --sta-ssid StarGate --sta-key passphrase --sta-band 2.4ghz
```

This creates the `wwan` interface (DHCP, added to the `wan` firewall zone),
switches the chosen band's radio to client mode, and connects. `--sta-band`
defaults to `[network.sta].band` or `2.4ghz`; `--sta-encryption` defaults to
`psk2` (use `sae` for WPA3, `none` for open). The other radio keeps serving the
local AP.

### Example: WiFi WAN backhaul

```toml
[network.sta]
band = "5ghz"
ssid = "UpstreamNetwork"
encryption = "psk2"
key = "passphrase"
```

The router connects to the upstream network on the 5GHz radio (auto-detected) and uses it as WAN. Firewall zone is `wan`.

### Example: Custom AP + STA simultaneously

```toml
[network.sta]
band = "5ghz"
ssid = "UpstreamNetwork"
encryption = "psk2"
key = "passphrase"

[network.ap]
band = "2.4ghz"
ssid = "MyNetwork"
encryption = "psk2"
key = "network-password"
```

STA on 5GHz for upstream WAN, AP on 2.4GHz for local clients. Both radios configured independently.

### Supported bands

| Config value | OpenWrt band | Notes |
|-------------|-------------|-------|
| `2.4ghz` | `2g` | 802.11b/g/n/ax |
| `5ghz` | `5g` | 802.11a/n/ac/ax |
| `5ghz-low` | `5g` | Lower 5GHz channels (UNII-1) |
| `5ghz-high` | `5g` | Upper 5GHz channels (UNII-3) |
| `6ghz` | `6g` | WiFi 6E (if hardware supports) |

## D-Link HNAP Flash Method

conwrt can flash D-Link routers running stock firmware without entering recovery mode, directly through the manufacturer's web UI API.

**How it works**: The HNAP (Home Network Administration Protocol) SOAP API accepts firmware uploads when properly authenticated. conwrt performs a challenge-response login (HMAC-MD5 + custom AES), uploads the OpenWrt factory image via multipart POST, and triggers the flash via `GetFirmwareValidation`.

**⚠️ DOES NOT WORK (COVR-X1860 stock v1.02):** The stock firmware's `GetFirmwareValidation` returns `IsValid: false` for OpenWrt images. The firmware upload API accepts the binary (returns `OK`), and the device reboots, but the bootloader-level validation rejects non-D-Link firmware and boots back to stock. The GPL RSA signing key (password: `12345678`) is a test key — production devices use different keys. **No router has ever been successfully flashed via HNAP. Use `recovery-http` (U-Boot) for reliable flashing.**

**Advantages over recovery-http** (when it works):
- No physical reset button press needed
- Works remotely over the network
- Faster setup (no recovery mode dance)

**Requirements**:
- Router running D-Link stock firmware with known admin password
- Network access to the router's web UI (HTTP)
- OpenWrt factory image (not sysupgrade)

**Usage**:
```bash
python3 scripts/conwrt.py --model-id dlink-covr-x1860-a1 \
  --image firmware.bin --flash-method dlink-hnap
```

The default password ("password") and API endpoints are defined in the model JSON.

## Running on OpenWrt (Router-to-Router Flashing)

conwrt can run FROM an OpenWrt router to flash another router, or from macOS/Linux, with multiple flash methods. Router-to-router provisioning and stock-firmware flashing are both supported.

**Status: Tested.** x1860 to x1860 recovery-http verified, WiFi STA/AP post-flash config verified. HNAP auth + upload API verified working but does NOT produce a successful flash — stock firmware validation blocks OpenWrt images.

### Setup

1. Flash the host router with OpenWrt (via conwrt from macOS/Linux).
   Configure `[network.sta]` in config.toml so it gets WiFi WAN after flashing.

2. Install dependencies on the host OpenWrt router:
   ```bash
   opkg update
   opkg install python3-base python3-light python3-urllib python3-json \
     python3-codecs python3-ctypes python3-email python3-logging \
     python3-openssl python3-struct python3-fcntl curl
   ```
   See `scripts/openwrt-requirements.txt` for the full list.

3. Copy conwrt to the router:
   ```bash
   scp -O -r scripts/ root@<host-ip>:/tmp/conwrt/
   scp -O models/<model>.json root@<host-ip>:/tmp/conwrt/models/
   scp -O firmware.bin root@<host-ip>:/tmp/conwrt/
   ```

4. Run conwrt from the router:
   ```bash
   ssh root@<host-ip>
   cd /tmp/conwrt/scripts
   python3 conwrt.py --model-id dlink-covr-x1860-a1 \
     --image /tmp/conwrt/firmware.bin --no-pcap --no-voice
   ```

   The interface is auto-detected as `br-lan` on OpenWrt.

### How It Works

The host router's LAN interface gets a temporary IP alias on the recovery subnet (e.g. `192.168.0.10/24`). The target router's uboot recovery HTTP server is detected via curl, firmware is uploaded via HTTP POST, and boot completion is verified via SSH polling.

**Important:** The SSH session to the host router will drop when the interface is reconfigured. Run in background:
```bash
python3 conwrt.py --model-id dlink-covr-x1860-a1 \
  --image /tmp/conwrt/firmware.bin --no-pcap --no-voice \
  > /tmp/conwrt/flash.log 2>&1 &
disown %1
```

### Supported Flash Methods

| Method | Status | Notes |
|--------|--------|-------|
| sysupgrade | Supported | SSH/SCP via Dropbear, works with any sysupgrade-capable model |
| recovery-http | Tested | Tested x1860 to x1860, polling-only mode |
| dlink-hnap | ❌ upload OK, flash fails | HNAP auth + upload works, but GetFirmwareValidation rejects OpenWrt images — no successful flash ever recorded |
| tftp | Untested | Uses bundled `scripts/tftp-server.py` (no dnsmasq dependency) |
| extreme-rdwr-tftp | Untested | SSH to stock → rdwr_boot_cfg writes U-Boot vars → TFTP boot initramfs → backup → sysupgrade |
| zycast (multicast) | Untested | Pure Python fallback when C binary unavailable (OpenWrt/MIPS) |
| serial | Tested (base64) | `scripts/serial-flash.py` + serial console |

### Monitoring Modes

| Mode | Requires | Events Detected |
|------|----------|-----------------|
| scapy (full) | python3-scapy | All: ARP, HTTP, ICMPv6, UDP |
| tcpdump (events) | tcpdump only | All: parsed from tcpdump output |
| polling-only | curl + ssh | Limited: link state + SSH availability |

On OpenWrt, tcpdump event monitoring is recommended — install via `opkg install tcpdump`.
Use `--no-pcap` for polling-only mode (no tcpdump needed).

## Optional labgrid integration

conwrt is fully standalone by default — flashing, serial recovery, and the bench scripts need nothing but SSH and a cable. For racked benches there is an **optional** [labgrid](https://labgrid.readthedocs.io/) integration; nothing changes unless you enable it:

- **Power, console, and SSH via labgrid places** — bench DUTs on a PoE switch become labgrid places: `NetworkPowerPort` (PoE), `NetworkSerialPort` (console over a serial bridge), `NetworkService` (SSH).
- **Serial-watched flashing** — `conwrt flash --serial tcp://HOST:PORT` streams boot milestones (U-Boot banner, kernel start, procd init, login prompt) from a serial bridge into the flash timeline; when serial and the pcap monitor disagree, serial wins (ground truth).
- **Boot tripwires** — a watched boot shows the dirty-overlay signature (`jffs2 ... unchecked/orphan`), wedged overlay replays, and failsafe prompts in-band instead of inferring them from network silence.

Enable it per run or persistently — the direct backend (plain SSH + ubus PoE) stays the default:

```bash
CONWRT_BENCH=labgrid python3 scripts/bench_inventory.py scan --host <switch>   # one-shot override
```

```toml
[labgrid]                    # config.toml — see config.example.toml
enabled = true               # false/absent = direct backend (default)
coordinator = "host:port"    # labgrid coordinator address
```

Health checks — both read-only, never a power action:

```bash
python3 scripts/conwrt.py bench-doctor    # L1 coordinator / L2 exporter / L3 serial bridges / L4 registry
make labgrid-check                        # offline exporter-vs-registry cross-check (CI-safe)
```

**Everything stays standalone**: without the env var and without a `[labgrid]` section, behavior is identical to a labgrid-free install — labgrid is never required, and `bench-doctor` reporting `ABSENT` levels is a healthy standalone checkout. Bench wiring, serial-bridge instances, and the place registry live in [`labgrid/README.md`](labgrid/README.md); the AP3915i-to-AP3915i serial bridge that feeds `NetworkSerialPort` and `--serial tcp://` is documented in [`recipes/extreme-networks/ws-ap3915i/SERIAL-VIA-AP3915I.md`](recipes/extreme-networks/ws-ap3915i/SERIAL-VIA-AP3915I.md).

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
