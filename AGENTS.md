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

## Zycast Requires Z-Loader (Serial Trigger)

**Zycast multicast does NOT work on every boot.** The bootloader only listens for multicast when Z-Loader mode is active.

Z-Loader is entered via:
1. Serial interrupt (press Escape during boot delay), OR
2. Failed boot (firmware corrupt, bootloader falls back)

If the device is running healthy firmware, zycast multicast is useless — the bootloader boots straight through without listening. **Serial console access is required to trigger Z-Loader.**

Do NOT:
- Blindly run zycast for extended periods hoping the device picks it up
- Assume "the bootloader accepts multicast on every boot" (this was wrong in our docs — now corrected)
- Skip serial when planning a zycast flash

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
