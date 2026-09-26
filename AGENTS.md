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
- Uncommitted uci changes live in `/tmp/.uci` (RAM): they SURVIVE separate SSH sessions (shared /tmp), are shown merged by `uci get`/`uci show`, and aborted runs leave staging debris that poisons later diffs and can merge into later commits. Always `uci revert <config>` to a clean baseline before staging; gate commits on value readbacks, never on textual `uci changes` shapes (factory config shapes differ across OpenWrt release families)
- Shell variables in uci commands MUST use double quotes (not single quotes) for expansion
- On-device shell scripts use BusyBox tools only (`sha256sum`, not `md5sum`; no `chpasswd`, no `hostname`). SHA-256 is universally available on OpenWrt (base-files depends on it since 2018)
- Python-side hash algorithms MUST match what BusyBox provides (sha256, matching on-device `sha256sum`)
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

## U-Boot Env Writes: Fallback Bootcmd, Cold-Boot Verify, Record Before Shelving

**Any bootloader environment change must leave the device able to boot itself out of a bad flash — and must be proven with a cold power cycle before the device is left unattended.**

Motivating incident (AP3915i bench, found 2026-09-21): three Extreme AP3915i units were shelved after OpenWrt setup with a `bootcmd` that ran the STOCK boot script (`run boot_flash` / `bootx`). The stock script's watchdog/nboot/failover logic is incompatible with OpenWrt FIT images: `bootm` fails and the unit either boot-loops (Unit 1, documented in the model JSON) or drops to a silent U-Boot prompt and sits there indefinitely. Found months later on GS1900 ports lan6-8: powered, PHY linked, network stack never initializes, flat PoE draw — no remote control path left except serial. The model JSON's CRITICAL warnings were written after the first incident, but process gaps still let three more units go dark.

**Rules:**

1. **bootcmd MUST include a network fallback**: `run boot_openwrt; run boot_net` (semicolon, NOT `||` — semicolon doesn't depend on U-Boot operator support). If flash boot fails, the device still TFTP-tries. A bootcmd without a fallback is a dead end waiting to happen.
2. **Cold power-cycle verification before walking away**: after ANY U-Boot env write, cut power entirely (not just `reboot` — some env/boot errors only manifest from a cold start), watch the device come up fully (serial banner or network reachable), and only then call it done. "The write succeeded" ≠ "the device boots".
3. **Read back the env after writing**: `rdwr_boot_cfg` was broken (exit 255) on AP3915i variant 1 and returned empty on variant 2. An unreliable write path means the device may be running bootcmd defaults you never intended. Verify with `printenv` / read_all / fw_printenv and diff against what you meant to set.
4. **Hardware variants are different devices**: the two AP3915i variants ship different U-Boot builds with different default bootcmds (`run boot_flash` vs `bootx`) and different tool reliability. Never assume variant N's defaults from variant M's. Check per-unit before writing.
5. **Write env from stock firmware, not OpenWrt initramfs**: the OpenWrt DTS marks CFG partitions read-only; stock firmware's flashcp path is writable. If you must write from initramfs, install kmod-mtd-rw deliberately and know you're in brick-risk territory.
6. **No unit gets shelved without an inventory record**: if a device ends a session in ANY non-default state (env changed, half-flashed, bootloader-only, bricked), append it to `data/inventory.jsonl` immediately with the exact state and recovery path (e.g. "parked at U-Boot, 115200, fix bootcmd per model JSON"). Three AP3915i units had ZERO inventory entries — we only reconstructed what happened from the model JSON's warnings. A unit that goes silent with no record is indistinguishable from air.
7. **Strip known-bad args during env review**: e.g. `ubi.mtd=0` left in bootargs causes kernel UBI attach failure on OpenWrt. Review the full bootargs, not just bootcmd.
8. **Testbed ports must reflect reality**: a unit parked on a port with PoE disabled and no VLAN membership (lan8 was in both states) is invisible to every remote check. When shelving hardware on bench switches, verify the port would let you SEE the device if it spoke (PoE on, VLAN with L3, port map recorded).

## Escape-Hatch Discipline (before ANY destructive operation)

Motivating incident (2026-09-22, ap-lan2 / UNIT2): we ran `firstboot` on a
unit with exactly ONE working management door (blank-password SSH over v6).
The overlay was already marginal — dmesg showed `jffs2 ... 24 unchecked,
15 orphan` xattrs (captured, not acted on). The post-wipe jffs2 reformat plus
a bench power loss seconds after a config commit left the unit permanently
unmanageable: it boots, sends RAs, presents an SSH banner — and closes every
session at auth (zero working auth methods; keys and shadow state lost to
overlay replay). The escape hatches we might have reached for do not exist
on this species: NO reset button (no GPIO buttons in the DTS — OpenWrt
failsafe is unreachable), NO LuCI in stock images (:80 dead), TFTP fallback
never runs when flash-boot succeeds (0 RRQs against a verified server), and
the 2012-era U-Boot has no boot-counter/recovery logic. Seven bounded power
cycles: still dark. Serial console was the only remaining door — and it was
not attached. The same class already cost us lan3. Industry guidance (Cisco
OOB best practices, network change-rigor) says the same thing we learned the
hard way: verify EVERY access path before the change, and carry a
pre-checked rollback with no ambiguity.

**Rules:**

1. **Count the doors before you knock anything down.** Before `firstboot`,
   `sysupgrade`, env/bootloader writes, or any `uci commit` touching
   network/auth config: enumerate the INDEPENDENT ingress paths that will
   still work AFTER the change (key SSH, password SSH, LuCI, failsafe,
   TFTP fallback, serial). Fewer than two verified doors — or a change that
   destroys the only one — means STOP: attach the console first.
2. **Inventory the hatches per species, in the model JSON, before relying
   on them.** AP3915i: no reset button, no failsafe trigger, no LuCI in
   stock images, TFTP fallback only when flash-boot fails → serial is the
   only hatch. "Factory reset is lower-risk than reflashing" is a
   PER-DEVICE claim, never a universal one.
3. **Check overlay health before choosing the reset method.** `dmesg |
   grep -i jffs2` showing unchecked/orphan xattrs = marginal overlay. On a
   marginal overlay, `firstboot` (wipe + reformat-on-next-boot via the racy
   tmpfs→jffs2 switch) is the RISKIER option; `sysupgrade -n` (fresh image
   + deterministic fresh-overlay format) is the safer one. Never firstboot
   a dirty overlay, and never stack destructive operations on a sick unit.
4. **Unclean power during — or minutes after — overlay writes is a known
   corruption class** (documented OpenWrt regressions on ipq40xx and
   others: post-first-boot power cuts corrupt overlay files). Treat any
   such event as presumed-dirty: verify overlay health on the next boot
   before making further changes.
5. **Lottery cycling is not recovery.** Every dirty power-off deepens jffs2
   debris. Bound diagnostic cycles (≤2), then stop and use the
   deterministic hatch (console). If a "lucky boot" window opens, use it to
   FIX (flash/adopt immediately), not to poke.
6. **Fail fast in the tooling.** Assert pre-state before mutating: ROM auth
   audit (blank root + PasswordAuth on), overlay health, clean uci baseline
   (`uci revert` first). Gate commits on `uci get` VALUE readbacks, not
   textual `uci changes` diffs (staging debris from aborted runs survives
   SSH sessions in /tmp/.uci and poisons textual diffs; shapes differ
   across release families). Classify auth-death ("Remote closed" with the
   box alive) and STOP with a diagnosis instead of blind retries. Every
   stage owns its own preconditions and waits for its own readiness.
7. **Exercise hatches before you need them.** Periodically verify every
   door: console port map + serial reachability, failsafe procedure, TFTP
   lifeline with a positive-control fetch. An untested hatch is a rumor.
8. **Keep revert material local and verified.** Known-good image (sha
   verified at download time) + `sysupgrade -b` backup BEFORE any change.
   The internet is not guaranteed when you need the rollback image most.
9. **Package installs auto-start services.** `apk add dnsmasq` on the bench
   switch enabled a default-config DHCP service on the mgmt VLAN at next
   boot (rogue DHCP next to the real server). After ANY package install on
   network gear: check `/etc/init.d/<svc> enabled` and disable unless the
   service is intended. Keep the package; kill the service.

## Dark-Device Discovery Discipline (before verdicting "network-dead")

Motivating incident (2026-09-22): two AP3915i units sat FOUR MONTHS as
"stuck, serial-gated" while fully alive at operator-chosen static IPv4s and
EUI-64 IPv6 link-locals. The earlier session had every datum needed (source
MACs on the wire) and lacked only the methodology.

Rules:

1. **No negative without a positive control** (extends rule 11 above): prove
   the probe against a known-good host through the same path/interface in the
   same session before believing any "no answer".
2. **IPv6 before death**: derive `fe80::<EUI-64>` from ANY observed source
   MAC (split MAC, insert FFFE, XOR first byte 0x02) and ping6 it on the
   access VLAN. Linux/OpenWrt/network gear default to EUI-64 link-locals; a
   broken IPv4 config does not take these down. NDP `STALE` ≠ dead; the
   `router` flag means odhcpd is alive.
3. **v4 sweep order**: inventory archaeology for this MAC → the probe host's
   OWN interface subnets (the switch knew about 192.168.13.0/24 all along) →
   operator extras → RFC1918/common defaults.
4. **Passive patience**: listen 2-5 minutes on the VLAN interface (never
   `-i any` with VLAN filters). RAs/MLD/beacons repeat forever; the ~10s
   boot window is the loudest signal, not the only one.
5. **The only genuine serial-gated class**: zero frames EVER including the
   bootloader phase across a fresh PoE cycle. Anything that has emitted one
   frame has an IP-level attack surface.
6. **Zone-scoped v6 transport**: must be dialed FROM the on-link host —
   `DROPBEAR_PASSWORD=<pw> dbclient -y -y root@fe80::...%switch.100X`, with
   scripts piped via `sh -s` stdin (beats quoting through multi-hop SSH;
   `ssh -J` cannot dial zone-scoped targets; probe hosts may have broken
   openssh clients — dbclient is the reliable one).
7. **Password works but pubkey never does** → check `ls -ld /etc/dropbear`:
   non-root-owned or group-writable makes dropbear silently refuse ALL keys
   (image-build artifact, seen in the wild).

Tooling: `scripts/bench_discover.py` (ladder generator + control gate),
methodology: `docs/DARK-DEVICE-PLAYBOOK.md`,
session prompt: `prompts/bench-forensics-01-dark-device.md`,
history mining: `prompts/bench-forensics-02-session-archaeology.md`.

## Network-Gear Config Discipline (deadman switch before any commit+reload)

Motivating incident (2026-09-22, the GS1900 bench switch): a VLAN re-rig was
applied as one bundled command — `uci batch` writing `ports` as a single
space-joined STRING (the original config used uci LISTS), including a
rewrite of the MANAGEMENT VLAN (vlan1), followed by `uci commit network` +
`ubus call network reload` + `/etc/init.d/poe restart` — with no
verification between steps, no rollback path, and no out-of-band access.
The session died at the reload and the switch went dark (carrier up, no
L2/L3 response) with the suspect config COMMITTED. Recovery required
physical power-cycle, potentially failsafe mode.

**Rules:**

1. **Deadman switch first**: before any `uci commit network` + reload on a
   switch/router you only reach over the network, schedule a self-reboot —
   `nohup sh -c 'sleep 300 && reboot' >/dev/null 2>&1 &` — and cancel it
   (`kill` the sleep) only after re-verifying reachability. A wedged box
   then heals itself within 5 minutes instead of requiring physical access.
2. **One change, one verify, one step**: never bundle config write + commit
   + reload + service restart in a single command. When the session dies
   mid-bundle you cannot tell which stage killed it — and neither can the
   post-mortem.
3. **Diff `uci show <section>` against the known-good state BEFORE
   committing** — especially `ports`/list syntax. `set x.ports="a b c"`
   (string) and `add_list` entries (list) both look plausible and can behave
   differently in netifd. The management VLAN is the one config you never
   write blind.
4. **Prefer runtime-apply, verify, THEN commit**: apply the change via
   runtime commands (or commit + reload behind the deadman), prove
   reachability survived, and only then let the config persist. Committing
   before proving is how a transient wedge becomes a boot-time condition.
5. **Know the failsafe door BEFORE you need it** — button location, the
   ~2s LED window, the failsafe IP (192.168.1.1), and what the overlay
   carries that `firstboot` would destroy (e.g. the realtek-poe fork
   binaries on the GS1900). Failsafe + `mount_root` + surgical edit beats
   firstboot whenever the overlay holds irreplaceable bits.
6. **Detach long/mid-flight device commands** from your SSH session
   (`nohup ... &` with output to a file) so a client timeout cannot
   SIGKILL a half-applied sequence.

## AP3915i No-Serial Flash: The Proven Recipe and Its Traps

**The proven tuple (validated end-to-end 2026-09-21, lan4 unit, zero serial)**: OpenWrt **24.10.2** + `bootcmd=run boot_openwrt; run boot_net` + `WATCHDOG_COUNT=0`/`WATCHDOG_LIMIT=0` + `ubi.mtd=0` stripped from bootargs/static_bootargs + CFG1-only writes (CFG2 stays pristine stock as the last resort) + a per-port TFTP server on the switch for the fallback tail.

**Rules:**

1. **The semicolon fallback tail only catches commands that RETURN.** A sourced script that ends in `reset` (the stock `boot_kernel` script behind `run boot_flash`/`bootx`) never falls through — the unit wedges in the stock watchdog loop regardless of what follows the semicolon. This is the May 2026 "Critical Error" from SESSION-WRITEUP.md, and it happened AGAIN in September 2026 despite the lesson being on disk. The tail is a safety net for failing *commands*, not for *scripts that reboot*.
2. **Flash-boot capability is PER-UNIT, kernel-version-correlated — never assume it from the version alone**: 6.12 images (OpenWrt 25.12.x) failed `sf read`+`bootm` on some units while booting fine via `tftpboot`+`bootm`; 6.6 images (24.10.x) flash-booted reliably across the early fleet — but lan5 later flash-booted 25.12.5 self-sufficiently (TFTP-down verified, 105s to HTTP; models/extreme-networks-ws-ap3915i.json) and rule 10 proves capability tracks env identity, not bootloader bytes. Defaults: treat 24.10.x as the flash-boot-proven line for UNVERIFIED units; do not flash-boot 25.12.x on a unit until THAT unit has passed a TFTP-down flash-boot test; after any CFG/env change, re-verify before relying on flash boot. FIT forensics (gzip, same load/entry, same structure) do NOT explain the per-unit split — diagnosing the real cause needs serial.
3. **Never gate on `$?` behind a pipe**: `cmd | tail -2; echo $?` reports *tail's* exit code. This faked two success gates (apk and opkg installs that had actually failed) and cost hours of blind debugging. Use unpiped exit codes or content/hash gates.
4. **Package manager era map**: kmods live at `downloads.openwrt.org/releases/<v>/targets/<target>/generic/kmods/<kernel-hash>/` (NOT the arch feed). 24.10 = opkg: `opkg install --force-depends` on initramfs (kernel pkg absent from the status db). 25.x = apk: `apk add --allow-untrusted --force-non-repository` for local packages on tmpfs roots.
5. **Initramfs session hygiene**: staged `/tmp` files die with every reboot (re-stage after each cycle); every initramfs boot regenerates dropbear host keys (`ssh-keygen -R <alias>` between sessions); flash-rooted boots stabilize keys via the persistent overlay.
6. **Runtime VLAN interfaces sit in no firewall zone** → fw4 silently drops unsolicited inbound UDP: TFTP/DHCP servers on those VLANs never receive requests. Fix: `nft insert rule inet fw4 input iifname "switch.10*" accept` (runtime; vanishes on switch reboot).
7. **Stock service-shell transfers** (admin/new2day + legacy SSH algos): `tftp -g -r file 192.168.1.2` works once rule 6 is applied; the fallback is printf-octal-push over expect — remember **Tcl interprets `\OOO` escapes in double-quoted sends** (double the backslashes or your nulls vanish into the tty).
8. **CFG block format** (reverse-engineered, trusted): CRC32-LE over bytes[5:], byte4=0x01 active, bytes[5:]=null-separated KEY=VALUE, 0xFF pad to 65536. Partial-file writes are legal: unwritten tail of the erased block stays 0xFF — push only the env payload (~1.5KB), verify with a full-64K readback md5.
9. **The stock boot script arms a 34-second hardware watchdog** before `nboot` (QCA WDT @ 0xb017000, bite from `dis_wdt0_bite_time=0x0fffffff`). Stock firmware services it; OpenWrt's early boot races it — that race, not the script itself, is the reset loop. `WATCHDOG_DISABLE` (nonzero) skips arming. The script lives in BootPRI's EMBEDDED DEFAULT ENV (readable: `dd if=/dev/mtd4 | strings`), ends at an interactive shell ("watchdog might trigger"), and only runs `saveenv`×2 (mirroring CFG2) when `WATCHDOG_LIMIT≠0`.
10. **Flash-boot capability is ENV-IDENTITY-DEPENDENT — not fixed hardware (#61 PROVEN 2026-09-23)**: a "run boot_net-dependent" unit (could not sf-read-flash-boot ANY image) became flash-boot-capable after ONLY its CFG1 `ver`/`CURR_VER` strings were changed to the 2022-primary build identity (2-key edit, full-64K readback gate, TFTP-down power-cycle test: flash boot ~83s, zero RRQs). Mechanism refined from BootPRI env+script extraction: the boot script itself does NOT branch on these keys (CURR_VER is write-only, set when DEFAULT_SETTING=1) — leading theory is bootloader env-ACCEPTANCE gating: a CFG1 `ver` mismatching the running bootloader's identity falls back to the embedded default env (`bootcmd=bootx` → stock script → the documented watchdog wedges), a matching identity honors CFG1 (custom bootcmd runs). Full analysis: data/ap3915i-session-artifacts/bootpri-analysis/selector-mechanism-research.md (local). Either way the FIELD REPAIR is proven: 2-key CFG edit; keep CFG2 pristine as last resort. Write path trap: under OpenWrt the MTD numbering SHIFTS vs stock (CFG1 = mtd0 under OpenWrt, mtd1 under stock) — always resolve by `/proc/mtd` NAME, never by number; `mtd-rw.ko` needs `mtdcopy=1 i_want_a_brick=1` and then plain `mtd write ... CFG1` works.
11. **Positive-control every probe before trusting its negatives**: validate ping6/nc/grep patterns/binutils against a known-good target first. Tonight's casualties of skipped controls: an unvalidated ping6 methodology (150-attempt race interpreted as device silence), grep patterns that matched nothing real, and three "confirmed boot @5s" readings that were lingering pre-reboot sessions. A probe's negative result is only evidence if the probe provably works.

## Reset Failsafe Discipline (the ap-lan2 auth-dead incident, 2026-09-22)

Motivating incident: a bench adoption ran `firstboot` on ap-lan2 (AP3915i UNIT2 — healthy, SSH-able, both auth paths verified). The reset left the jffs2 overlay dirty (dmesg on recovery: `jffs2_build_xattr_subsystem ... 24 unchecked, 15 orphan` — a known artifact of interrupted/partial overlay writes; the kernel repairs these lazily at mount). The next boots raced the mount-time jffs2 replay: on some boots replay completed (unit healthy), on others it hung before `/etc` became writable — dropbear was listening, TCP:22 accepted, but with no writable `/etc` it had no host keys and closed every session at auth (`Remote closed the connection`). The unit sat ~45 min "auth-dead", was recorded UNMANAGEABLE ("needs console"), and was revived by a single PoE power cycle (replay completed, self-healed). Verified same evening: adopted (keys + known password + static IP), then survived BOTH a graceful reboot and a cold PoE cycle. Evidence: `data/bench/ap-lan2/20260922-recovery/`.

**Rules:**

1. **`firstboot` is a brick-class operation — treat it exactly like flashing.** Before ANY remote firstboot, arm the full recovery envelope: (a) rom-audit passed (blank root + PasswordAuth in ROM), (b) a KNOWN root password set and verified, (c) SSH keys pushed and BOTH auth paths verified, (d) per-VLAN TFTP lifeline armed, (e) a detached aliveness recorder running. The envelope must exist BEFORE the reset, not after. A reset you cannot recover from is a reset you do not run.
2. **Never firstboot onto a possibly-dirty overlay.** If a prior adopt/reset aborted mid-flow, check `dmesg | grep -i 'xattr\|jffs2'` for `unchecked/orphan` counts and let a full boot complete the replay before resetting again. Double-firstboot = dirty overlay = nondeterministic auth-dead boots.
3. **`Remote closed the connection` with TCP:22 open + RAs alive is a dropbear boot-state failure** (host keys / unwritable `/etc`) — NOT locked root, NOT a network fault, NOT necessarily permanent. It is often boot-nondeterministic: one deliberate PoE power cycle frequently cures it (jffs2 replay retries). NEVER verdict a unit "unmanageable / needs console" without at least one recorded power cycle + retry window.
4. **The `run boot_openwrt; run boot_net` TFTP tail only fires when FLASH boot fails.** A unit that flash-boots fine never enters `boot_net` — proven live during this incident (server armed and listening, zero RRQs). TFTP lifelines protect against flash/bootloader failures, NOT userspace auth failures. For userspace-dead units the recovery ladder is: v6 link-local dbclient → wrong-IP check (`ip neigh` on the switch — the unit may have moved off the address you're probing) → LuCI/uhttpd on :80 if the image has it → PoE cycle → serial.
5. **A stale worst-case verdict in a registry is itself a hazard.** places.json said UNMANAGEABLE for hours after the unit had been revived and adopted — the next agent would have skipped cheap recovery. Update registries the moment state changes; recovery notes must carry timestamps and evidence paths.
6. **Know which auth channels are config-independent**: v6 link-local + dbclient from the switch works no matter what `network.lan` says; `ip neigh` on the VLAN reveals the unit's actual v4; uhttpd/LuCI (:80) is a third door on images that include it. Verify at least two channels before declaring access lost.
7. **uci staging debris**: uncommitted changes live in `/tmp/.uci` (RAM: survives SSH sessions, dies at reboot) and `uci show` displays the MERGED (staged+committed) view. After any aborted uci flow, check `uci changes` and revert debris before staging again — or exact-diff guards will refuse legitimate commits.
8. **Detached daemons on BusyBox**: `nohup cmd &` over ssh DIES when the session closes — use `setsid cmd &`. There is no `timeout` applet; guard hangs from the Mac side. Anything staged in `/tmp` (recorders, TFTP roots, nft rules) is runtime-only and dies on switch reboot — re-arm and say so in the notes.
