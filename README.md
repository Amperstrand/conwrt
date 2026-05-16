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

### Flash Methods

| Method | How it works | Requires | Speed |
|--------|-------------|----------|-------|
| sysupgrade | SSH + SCP, runs sysupgrade -n | Running OpenWrt + SSH | ~3 min |
| recovery-http | Reset button, uboot HTTP server | Physical access + reset pin | ~2 min |
| dlink-hnap | HNAP SOAP API upload via stock firmware web UI | Stock D-Link firmware, network access | ❌ validation blocks flash |
| tftp | TFTP server for uboot network boot | Serial or uboot access | varies |
| zycast | Multicast to many devices simultaneously | Network broadcast domain | varies |

### Device Support Matrix

| Device | sysupgrade | recovery-http | dlink-hnap | tftp | zycast | WiFi STA/AP |
|--------|:----------:|:------------:|:----------:|:----:|:------:|:-----------:|
| D-Link COVR-X1860 A1 | o | tested | ❌ validation blocks | -- | -- | tested |
| GL.iNet MT3000 | o | tested | -- | -- | -- | -- |
| GL.iNet AR150 | o | -- | -- | -- | -- | -- |
| GL.iNet AR300M (lite/nand/nor) | o | -- | -- | -- | -- | -- |
| Linksys WHW03 V1/V2 | o | -- | -- | -- | -- | -- |

Legend: tested = Tested on hardware | o = Model defined, not tested | -- = Not applicable

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
│   ├── inventory.py           # Inventory utilities
│   └── use_cases/             # Use case presets (auto-discovered plugins)
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
| `--password PASS` | Set root password (default: random, printed once, saved in inventory) |
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
- Use case presets — flash OpenWrt pre-configured for tethering, SQM, VPN, etc.
- Firmware cache management (`conwrt cache list/clean`)
- Automatic ethernet interface detection
- Link monitoring survives pcap writer death during reboot

## Use Case Presets

conwrt doesn't just install OpenWrt — it installs OpenWrt **pre-configured for a specific use case**. Instead of flashing a stock image and then reading wiki docs to manually configure your router, you declare what you want in `config.toml` and the firmware arrives ready to go.

**Status: All presets are untested on hardware.** The uci commands and package lists are based on OpenWrt wiki documentation and community guides. They need real-device validation before being considered production-ready.

### How It Works

Each preset is a single Python file in `scripts/use_cases/` that declares:
- Packages to include in the ASU firmware build
- A shell script of uci commands that runs on first boot
- Required hardware capabilities (auto-skipped if your device lacks USB, WiFi, etc.)

Enable them in `config.toml`:

```toml
[use_cases]
enabled = ["android-tether", "sqm"]

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

These three use cases are the most immediately useful because they require almost no user configuration:

| Preset | What it does | User provides |
|--------|-------------|---------------|
| **android-tether** | USB WAN from Android phone via RNDIS/CDC-ether | Nothing (plug in USB) |
| **iphone-tether** | USB WAN from iPhone via ipheth + usbmuxd | Nothing (plug in USB) |
| **sqm** | Smart Queue Management with CAKE — eliminates bufferbloat | Download/upload speeds in Kbit/s |
| **travelmate** | Auto-connect to hotel/airport WiFi with captive portal detection | Nothing (auto-scans) |

These are the "flash and forget" cases — no wiki reading, no manual uci editing, no VPN keys to generate. Flash the image, plug in your phone (tethering) or connect to upstream WiFi (travelmate), or set your bandwidth (SQM), and it works.

### All Available Presets

| Preset | Description | Post-flash? |
|--------|-------------|-------------|
| `android-tether` | USB WAN from Android phone | No |
| `iphone-tether` | USB WAN from iPhone | No |
| `sqm` | Bufferbloat fix via CAKE/fq_codel | No |
| `mwan3` | Multi-WAN failover or load balancing | No |
| `travelmate` | Auto-connect to captive portal WiFi | No |
| `tollgate` | Bitcoin/Lightning payment gateway | Yes (binary deploy) |
| `wireguard-client` | VPN tunnel (auto-generates keys per device) | No |
| `wireguard-server` | VPN server for remote access | Yes (QR codes, peers) |
| `adguard` | Network-wide ad blocking | Yes (web setup wizard) |
| `openclash` | Transparent proxy for censorship bypass | Yes (subscription import) |

Presets requiring post-flash setup need SSH access after first boot to complete configuration (importing VPN configs, running setup wizards, etc.).

### WireGuard VPN

conwrt builds WireGuard into the firmware image via the `wireguard-client` use case. Each device auto-generates its own Curve25519 keypair on first boot — **no private keys ever exist in the firmware image**.

**How it works:**

1. Set `private_key = "generate"` (the default) in config.toml — OpenWrt's wireguard-tools generates a unique key on first interface bringup and saves it to UCI
2. Keys survive sysupgrade automatically (stored in UCI overlay)
3. Post-flash: read the generated public key via SSH and register it with the VPN server
4. Public key is saved to device inventory (`data/inventory.jsonl`)

**Example: Management VPN (split tunnel)**

```toml
[use_cases]
enabled = ["wireguard-client"]

[use_cases.wireguard-client]
peer_public_key = "SERVER_PUBLIC_KEY"
endpoint_host = "vpn.example.com"
endpoint_port = 51820
address = "10.0.0.2/32"
allowed_ips = "10.0.0.0/24"
kill_switch = false
```

**Example: Full tunnel VPN**

```toml
[use_cases]
enabled = ["wireguard-client"]

[use_cases.wireguard-client]
peer_public_key = "SERVER_PUBLIC_KEY"
endpoint_host = "vpn.example.com"
address = "10.0.0.2/32"
kill_switch = true
```

`wg-setup.py` can apply WireGuard config post-flash from pre-generated server peer configs:

```bash
python3 scripts/wg-setup.py --peer 3 --server my-vpn-host
```

### Future Direction

The long-term vision is an interactive menu system that interviews the user before flashing: "Do you want USB tethering? SQM? A VPN?" — then builds a firmware image with everything pre-configured. The current `config.toml` approach is the declarative foundation for that interactive layer.

## WiFi STA/AP Configuration

conwrt automatically configures WiFi after flashing based on `[network.sta]` and `[network.ap]` in `config.toml`. No manual uci editing needed.

**Status: Tested on hardware** (D-Link COVR-X1860 A1). Radio auto-detection verified: radio0=2.4GHz, radio1=5GHz.

### How It Works

1. **Post-flash SSH** (default): After flashing and SSH verification, conwrt detects the correct radio for each band via `uci get wireless.radioN.band` and applies STA/AP uci commands over SSH.
2. **ASU first-boot** (via `--request-image`): The same uci commands are baked into the firmware's first-boot script, so WiFi is configured before first SSH.

Both flows use the same radio detection logic — iterate `radio0..radio3`, check `band` option, match to the configured band.

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
| zycast (multicast) | Untested | Pure Python fallback when C binary unavailable (OpenWrt/MIPS) |
| serial | Not yet | Requires USB-serial adapter |

### Monitoring Modes

| Mode | Requires | Events Detected |
|------|----------|-----------------|
| scapy (full) | python3-scapy | All: ARP, HTTP, ICMPv6, UDP |
| tcpdump (events) | tcpdump only | All: parsed from tcpdump output |
| polling-only | curl + ssh | Limited: link state + SSH availability |

On OpenWrt, tcpdump event monitoring is recommended — install via `opkg install tcpdump`.
Use `--no-pcap` for polling-only mode (no tcpdump needed).

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
