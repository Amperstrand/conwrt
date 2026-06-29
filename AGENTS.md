# conwrt Agent Rules

Safety-critical rules for AI agents operating on real hardware.

## NEVER Force Sysupgrade

**`sysupgrade -F` is FORBIDDEN.** No exceptions.

The `-F` flag bypasses hardware validation and can brick devices by writing firmware for the wrong hardware. If sysupgrade rejects an image with "Device X not supported by this image", the image is wrong for the hardware. STOP.

Do NOT:
- Use `sysupgrade -F` or `--force`
- Override hardware validation checks
- Assume board.json is accurate (it reflects firmware, not hardware)

Instead:
- Investigate why the identity doesn't match
- Use `cat /tmp/sysinfo/board_name` to check device identity
- Download the correct firmware for the actual hardware
- If hardware identity is ambiguous, ask the operator before proceeding

## Always Identify Before Flashing

1. SSH to the device and read board.json AND `/tmp/sysinfo/board_name`
2. Cross-reference with the operator's claimed device model
3. If there's a mismatch, STOP and report it to the operator
4. Never assume the operator's claim is correct if the device says otherwise

## Trust Hardware Checks Over Firmware State

- `board.json` = what firmware was flashed (can be wrong)
- `/tmp/sysinfo/board_name` = firmware's device identity (can be wrong)
- `sysupgrade` validation = authoritative hardware check (trust this)
- Physical labels / MAC OUI = ground truth

When in doubt, trust sysupgrade's hardware validation. It is the last line of defense against bricking.

## Test Before You Commit (Post-Flash Configuration Safety)

**New features MUST be manually verified on a live device before being automated.**

Any shell script that modifies device state (uci set, network config, IP changes) must be tested end-to-end via SSH **before** being committed to automated flows (conwrt configure, ASU first-boot scripts, builder.py).

**Mandatory verification sequence for new configuration steps:**

1. **SSH manually first**: Run the exact shell commands on the device and verify the result
2. **Read back the value**: After `uci set`, run `uci get` to confirm the value was set correctly — not the literal variable name
3. **Test persistence**: Reboot and verify the change survives
4. **Verify recovery**: Confirm you know how to undo the change (firstboot, uci revert, failsafe)
5. **Then automate**: Only after steps 1-4 pass, commit the commands to the automation

**Why this matters**: A single-quote bug in `uci set network.lan.ipaddr='$_host'` wrote a literal string as the IP address, making the device unreachable. If this had been an ASU first-boot script baked into firmware, there would be NO recovery without serial. Always ensure changes are reversible before automating them.

**Specific rules:**
- Never `uci commit` a network IP change without verifying `uci get` returns the expected value first
- Shell variables in uci commands MUST use double quotes (not single quotes) for expansion
- On-device shell scripts use BusyBox tools only (`md5sum`, not `sha256sum`; no `chpasswd`, no `hostname`)
- Python-side hash algorithms MUST match what BusyBox provides (md5, not sha256)
- For UBIFS overlay devices: `uci commit` is permanent after reboot — there is no "undo" after reboot

## Inventory and Access Hardening After First Access

**The first time you get SSH access to a device, immediately inventory it and install an SSH key.** The COMFAST CF-WR632AX was explored and a model JSON was created, but no specimen-level inventory was recorded and no SSH key was installed. A factory reset wiped the overlay (including the `95-random-lan-ip.done` marker), the device randomized its LAN IP, and the device became permanently inaccessible. The empty-password dropbear config was useless because we couldn't find the device on the network.

**Mandatory post-first-access checklist:**

1. **Record inventory** — Append to `data/inventory.jsonl` via `python3 scripts/inventory.py --add` with MAC address, model, serial, firmware version, and current LAN IP
2. **Install SSH key** — `ssh-copy-id` or manually append your public key to `/etc/dropbear/authorized_keys`. This survives factory resets on some firmwares and survives normal reboots on all firmwares
3. **Check for random-IP behavior** — Look for `/etc/config/95-random-lan-ip.done` or similar markers. If the firmware randomizes LAN IP after factory reset, document this in the model JSON and recipe notes
4. **Record current LAN IP and recovery procedure** — Note the current IP, how to find the device if IP changes (WiFi SSID, MAC OUI scan, ARP sweep), and how to recover access

**Why both inventory AND SSH key matter:**
- Inventory = you know the device exists and what it is (specimen-level)
- SSH key = you can actually reach it even if the password changes or IP shifts
- Model JSON = you know what species of device it is, but not where THIS specific unit is

**The discovery prompts (steps 01-04) are read-only by design.** Inventory and SSH key installation happen AFTER discovery, when you have access and are preparing for flashing. This is the gap between "I found and identified a device" and "I can flash and manage this device."

## Related Projects

- **realtek-poe fork**: [Amperstrand/realtek-poe](https://github.com/Amperstrand/realtek-poe) — AI experimentation workspace for PoE research on OpenWrt switches. All AI work happens on the `ai-experiments` branch. `main` is a pristine upstream mirror. **Never interact with the upstream `Hurricos/realtek-poe` repo** — only humans may create issues or submit PRs there.
- **Test hardware**: Two GS1900-8HP A1 devices — one running OpenWrt (SSH), one running ZyXEL stock V2.90 (HTTP). Both accessible via USB ethernet.

## Offline Device Package Installation

When a router has no internet access (no WAN uplink yet), `opkg install` fails because it can't reach the package repository. Use `scp -O` (legacy SCP protocol — OpenWrt's dropbear lacks SFTP) to transfer `.ipk` files from the host machine:

```bash
# 1. Download packages on the host (with dependencies)
#    Use the router's OpenWrt release + arch to find the right repo
#    e.g. OpenWrt 24.10.2, aarch64_cortex-a53, mediatek/filogic
REPO_BASE="https://downloads.openwrt.org/releases/24.10.2/targets/mediatek/filogic"
PACKAGES_BASE="https://downloads.openwrt.org/releases/24.10.2/packages/aarch64_cortex-a53"

# 2. Download the .ipk files (host has internet)
curl -O "${PACKAGES_BASE}/packages/kmod-usb-net-rndis_*.ipk"
# ... repeat for each package + its dependencies

# 3. Transfer to router (note: -O flag required — dropbear has no sftp-server)
scp -O -i ~/.ssh/id_ed25519 *.ipk root@<router-ip>:/tmp/

# 4. Install on router (order matters: dependencies first)
ssh root@<router-ip> "opkg install /tmp/*.ipk"
```

**Key points:**
- Always use `scp -O` — OpenWrt dropbear lacks `/usr/libexec/sftp-server`, so default `scp` (which tries SFTP) fails with "Connection closed"
- Download packages matching the exact OpenWrt version, target, and architecture from the device
- Install dependencies before the packages that need them, or use `opkg install /tmp/*.ipk` which handles ordering
- Kernel modules (`kmod-*`) must match the exact kernel version on the device (`uname -r`)
- If the device already has the packages installed (e.g. from a previous firmware), skip this step — check with `opkg list-installed | grep <package>`

## External Repository Etiquette

**Never contribute to, comment on, or file issues against repositories outside the Amperstrand organization.** This includes starring, fork-sync PRs, issue comments, and discussion posts. We reference external repos for research only — we don't want to spam maintainers.

## Verify Serial Baud Rate From Source

**Never assume baud rate. Always confirm from the OpenWrt device tree or patch.**

The NR7101 model JSON said 115200. The actual baud rate is **57600** (from Bjørn Mork's OpenWrt patch). We wasted hours testing at the wrong baud rate.

Before connecting serial to any device:
1. Check the OpenWrt git commit/patch that added device support — it documents the UART baud rate
2. Cross-reference with the device's `chosen` node in the device tree (`stdout-path = "serial0:57600n8"`)
3. Update the model JSON if wrong
4. Use `serial-console.py --auto-baud` to auto-detect if unsure

## Zycast: Bootloader Listens Automatically (Serial Verified)

**Z-Loader enters Multiboot Listening mode on EVERY boot — serial trigger is NOT required.**

Verified via serial console on NR7101 (2026-06-27). The boot sequence is:

```
Z-LOADER V1.30 | 06/03/2020 08:39:30
Hit ESC key to stop autoboot:  1          ← 1-second ESC window
 NetLoop,call eth_init !
 ETH_STATE_ACTIVE!!
Multiboot Listening...                      ← Multicast listen starts
 6 5 4 3 2 1                                ← 6-second countdown
Starting application at 0x8402A800 ...      ← Boots firmware if no zycast received
```

**Total multicast listen window: ~7 seconds** (1s ESC prompt + 6s Multiboot countdown).

This means:
- Start zycast BEFORE power cycle — the bootloader will pick it up during the listen window
- Serial is NOT required to trigger Z-Loader — it enters multicast listen automatically
- Serial IS useful for: watching the flash happen, timing zycast precisely, verifying boot
- If nobody sends zycast during the ~7s window, the bootloader proceeds to firmware boot

**Timing for zycast flash:**
1. Start zycast sender (continuous loop)
2. Power cycle the device
3. Bootloader enters Multiboot Listening within ~10s of power-on
4. Flash happens automatically during the listen window
5. Device boots into new firmware (~20s after flash completes)

## Kill Zycast Immediately After Flash

**The bootloader listens for multicast on every Z-Loader entry.** If zycast is still running after a successful flash:
- Any reboot that enters Z-Loader will reflash the device
- This can cause a boot loop (flash → boot → power glitch → Z-Loader → reflash)

Kill zycast the moment you see kernel boot messages on serial:
```bash
pkill -f zycast
```

## Serial Wiring: Verify Before Connecting

**Always do a loopback test before connecting to a device.** We spent significant time debugging zero serial output when the issue was simply RX/TX swapped.

Mandatory sequence:
1. `serial-console.py --diagnose` — verify adapter detected, check signal lines
2. `serial-console.py /dev/cu.XXXX --loopback` — bridge TX→RX, verify echo (4 test patterns)
3. Then connect to device: adapter TX → device RX, adapter RX → device TX, GND → GND
4. **Do NOT connect VCC** — the device is powered by PoE/DC, not the serial adapter

Common mistakes:
- RX→RX and TX→TX (both listening, nobody talking) → zero output
- Missing GND → no signal reference → garbage or nothing
- 5V adapter on 3.3V UART → can damage the device

## PoE Injector Link State Is Unreliable

**PoE injectors maintain ethernet link to the host regardless of device power state.** The `enX: active 1000baseT` status only confirms Mac↔PoE injector link, NOT that the device is powered.

To verify device is actually powered:
- Check for LEDs on the device
- Check for ANY traffic on the interface (not just host-generated)
- Check ARP table for device MAC
- Use `tcpdump -i enX -c 5 'not src host <your-ip>'` to see if anything comes from the device

## macOS Serial Port Aliasing

**A single FTDI adapter may create multiple `/dev/cu.*` device nodes.** Opening one locks the others with "Resource busy".

For example, FT232R serial BG02QAPG creates both:
- `/dev/cu.usbserial-BG02QAPG` (by serial number)
- `/dev/cu.usbserial-8` (shortened)

These share one physical port. Use `serial-console.py --diagnose` to detect aliases. Never try to open both simultaneously.

## UART Break Recovery (FT232R Power-Cycle Glitch)

**The FT232R serial adapter gets stuck after a UART break condition during device power cycles.** When PoE power drops, the device's UART TX pin goes from 3.3V (idle-high) to 0V. The FT232R sees this as a break condition (sustained low = infinite 0x00 bytes with framing errors) and enters an error state. After power returns and the TX pin goes back to idle-high, the FT232R does NOT cleanly recover — the serial port stays "open" but delivers zero data.

**Symptoms**: Serial reader gets a single 0x00 byte (the break), then nothing — even though the device is booting and producing serial output. The port opens and reads fine, but always returns 0 bytes.

**Fix**: Close the serial port after detecting the break byte, wait for the device to start booting (2-3 seconds), then REOPEN the port fresh. This resets the FT232R's internal state:

```python
# Phase 1: Wait for break byte
chunk = s.read(1)
if chunk == b'\x00':
    s.close()                    # Close port — resets FT232R
    time.sleep(3)                # Wait for power return + early boot
    s = serial.Serial(PORT, BAUD, timeout=0.5)  # Reopen fresh
    s.reset_input_buffer()       # Clear any stale data
    # Now capture boot data normally
```

The `serial-boot-capture.py` tool implements this automatically with `--recovery-wait` option.

**Hardware fix**: A 10kΩ pull-up resistor between adapter RX and 3.3V keeps the line at idle-high during power-off, preventing the break condition entirely.

## Serial Console as Configuration Interface

**When network access is unavailable (wrong IP, IP conflict, no SSH), the serial console provides full root shell access to configure the device.** OpenWrt's serial console shows `root@OpenWrt:~#` after boot — you can run any command.

**What you can do via serial:**
- Change LAN IP: `uci set network.lan.ipaddr='192.168.5.1' && uci commit network`
- Install SSH key: `echo 'ssh-...' > /etc/dropbear/authorized_keys`
- Enable/disable password auth: `uci set dropbear.@dropbear[0].PasswordAuth='on'`
- Check firmware: `cat /etc/openwrt_release`
- Read partitions: `cat /proc/mtd`

Use `scripts/serial-configure.py` for structured configuration. See `prompts/serial-05-configure.md` for the full workflow.

**Pitfall**: Long SSH keys sent via serial may wrap across lines, causing the shell to enter continuation mode (`>`). Send Ctrl-C (`\x03`) to break out, then retry or use a shorter method.

## Serial-First Recovery Principle

**When a device has serial console access, try serial-based methods BEFORE network-based methods.** We wasted hours trying zycast from macOS when the serial cable was working perfectly the entire time.

**Recovery method priority (most reliable first):**
1. **Serial configure** (instant) — change IP, enable SSH, install key via serial
2. **Serial flash** (~22 min) — transfer firmware over serial (XMODEM/base64)
3. **SSH sysupgrade** (~3 min) — once network is up
4. **Zycast from switch** (~5 min) — from OpenWrt switch, NOT macOS
5. **Zycast from macOS** (unreliable) — last resort only

**Lesson (2026-06-28)**: We spent an entire session fighting zycast from macOS (IP removal, link flapping, process crashes). The serial cable worked the whole time. We should have tried serial flash FIRST.

## macOS USB Ethernet Instability

**macOS removes USB ethernet adapter IPs during device power cycles.** When PoE power drops, the ethernet link goes down, and macOS immediately removes the configured IP — even if set as "manual." This crashes any process using that interface (zycast, SSH, SCP).

**Workarounds (in order of preference):**
1. **Use serial instead** — no IP dependency, always works
2. **Use an OpenWrt switch** (GS1900-8HP) — stable networking, software PoE control
3. **Put a switch between Mac and device** — switch keeps Mac's link stable during device power cycle
4. **IP-keeper daemon** — re-adds IP every 0.1s (fragile, races with macOS)

**Never rely on macOS USB ethernet for time-critical operations during power cycles.** The IP WILL be removed.

## PoE Injector Data Passthrough

**Some PoE injectors pass power but NOT data.** Verify the data path before assuming ethernet connectivity:

1. Check device packet counters: `cat /sys/class/net/eth0/statistics/rx_packets` — should be >0
2. `tcpdump` on Mac's ethernet interface — any traffic from the device?
3. Bypass PoE injector with direct cable (use separate PoE brick for power)
4. Check cable pairs: PoE power uses pairs 4-5, 7-8; data uses pairs 1-2, 3-6. A cable with damaged data pairs can pass power but not data.

**Symptom (2026-06-28)**: Both Mac en9 and NR7101 eth0 showed "active 1000baseT" but 0 packets received on either side. The link was up to the PoE injector/switch, but data wasn't passing through to the device.

## Initramfs DSA Port Workaround

**OpenWrt initramfs-recovery images may NOT create DSA switch ports (`lan`, `wan`).** Only raw `eth0` exists. The `br-lan` bridge never comes up. Network interfaces referencing `lan` or `wan` devices fail silently.

**Symptom**: Device boots OpenWrt but is unreachable on any IP. `ip link show` shows only `eth0`, `lo`, `wwan0`. No `br-lan`, no `lan`, no `wan`.

**Fix via serial**:
```bash
ip link set eth0 up
ip addr add 192.168.X.1/24 dev eth0
# Now accessible on 192.168.X.1 via eth0
```

**Note**: The permanent OpenWrt image (sysupgrade) should create DSA ports correctly. This is primarily an initramfs issue.

## Serial Console as Configuration Interface

**When network access is unavailable (wrong IP, IP conflict, no SSH), the serial console provides full root shell access to configure the device.** OpenWrt's serial console shows `root@OpenWrt:~#` after boot — you can run any command.

**What you can do via serial:**
- Change LAN IP: `uci set network.lan.ipaddr='192.168.5.1' && uci commit network`
- Install SSH key: `echo 'ssh-...' > /etc/dropbear/authorized_keys`
- Enable/disable password auth: `uci set dropbear.@dropbear[0].PasswordAuth='on'`
- Check firmware: `cat /etc/openwrt_release`
- Read partitions: `cat /proc/mtd`

Use `scripts/serial-configure.py` for structured configuration. See `prompts/serial-05-configure.md` for the full workflow.

**Pitfall**: Long SSH keys sent via serial may wrap across lines, causing the shell to enter continuation mode (`>`). Send Ctrl-C (`\x03`) to break out, then retry or use a shorter method.
