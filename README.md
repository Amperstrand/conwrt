# conwrt

**[→ Device Support Matrix](https://amperstrand.github.io/conwrt/)** — supported devices, flash methods, and tested hardware.

A framework for flashing routers with OpenWrt, with a 2-stage workflow:

1. **AI-assisted discovery** (`prompts/`): Encounter an unknown router, identify it, fingerprint its attack surface, plan a capture strategy, and analyze pcap artifacts to determine flash methods and boot signatures. This is how new router models get onboarded into conwrt.
2. **Automated flashing** (`scripts/` + `models/`): Once a model is defined with its flash method and boot signatures, subsequent flashes of that model are fully automated -- detect recovery mode, upload firmware, verify, and collect inventory.

> **DISCLAIMER**: conwrt flashes firmware onto real hardware. You must have legal authority to modify any device you use it on. Verify model definitions and firmware images before every flash. The authors accept no liability for bricked devices or data loss.

## Requirements

- macOS (uses `say` for voice guidance, `ifconfig` for interface detection)
- `tcpdump` and `sudo` for pcap capture and network monitoring
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
| `make ipk` | Build conwrt as an arch-independent OpenWrt ipk package | Yes |

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
│   └── use_cases/             # Use case presets (auto-discovered plugins)
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
│   └── serial-06-flash.md
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

**Status: `tether` tested on hardware** (GL.iNet MT3000, Android RNDIS). All other presets are untested — the uci commands and package lists are based on OpenWrt wiki documentation and community guides. They need real-device validation before being considered production-ready.

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
