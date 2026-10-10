# Pi EEPROM: boot policy, the arm/disarm switch, and the security outlook

## BOOT_ORDER semantics

Nibbles are tried RIGHT to LEFT; `f` = restart loop. Authoritative modes
(`scripts/pi_eeprom.py decode --order <hex>`):

| Nibble | Mode |
|---|---|
| 0x1 | SD card |
| 0x2 | Network (TFTP) |
| 0x3 | RPIBOOT |
| 0x4 | USB mass storage |
| 0x5 | BCM USB-MSD (CM4) |
| 0x6 | NVMe (BCM2712) |
| 0xe | stop |
| 0xf | restart |

Conwrt policy values:

| Value | Order | Use |
|---|---|---|
| `0xf241` | SD → USB → network | Disk-first, network as last-ditch rescue |
| `0xf142` | Network → USB → SD | **LAN-first management** (the lab default) |

## The arm/disarm switch (recommended pattern)

With `BOOT_ORDER=0xf142`, the netboot stage runs first on every boot:

- **Rescue server ARMED** (`pi_netboot.py arm`): the Pi boots the RAM-only
  rescue shell. Full disk access, re-flash, EEPROM changes.
- **DISARMED** (`pi_netboot.py disarm --purge`): the netboot pass finds no
  server and falls through to the disk. Normal boot, a few seconds slower.

This is the "network boot on/off" control requested for home use — no EEPROM
rewrite is needed to toggle it. Keep it DISARMED when not managing the device.

## BOOT_ORDER pitfall on flaky boards: netboot-first can wedge cold USB boots

Verified on hardware (2026-10-10): with `BOOT_ORDER=0xf142` (network first) and
a DISARMED rescue server, every cold boot went netboot → DHCP offers with no
bootfile → fall-through → USB → **hang** (3/3, across different media). With
`0xf241` (SD → USB → network), the same media boot fine cold. The fall-through
path after a failed netboot stage appears to wedge USB re-init on some boards.
Practical rule: **netboot-last is the reliable order for USB-booted Pis**;
netboot rescue remains reachable as the final fallback (arm the server, remove
the USB media, or let it cycle through). LAN-first policies should be validated
per-board before adoption.

## Delivering EEPROM updates

Three flows, all with different reliability:

1. **Boot medium** (recommended): the same three files in the boot FAT
   partition (e.g. `/boot/firmware` on a disk-booted Ubuntu), applied by the
   bootloader on the next boot. Works regardless of boot order and needs no
   server.
2. **On-device**: `apt install rpi-eeprom`, then
   `sudo rpi-eeprom-config --apply boot.conf` — schedules the update into the
   boot mount. Same result as (1).
3. **Netboot tree** (caveat!): staging the files in the TFTP root makes the
   bootloader *download* them, but without `ENABLE_SELF_UPDATE=1` in the
   CURRENT EEPROM it will not *apply* them — verified on hardware
   (2026-10-08: pieeprom.upd fetched, never flashed). Enable self-update
   first via flow 1 or 2 if you want flow 3.

Evidence of a successful update: subsequent boots fetch `pieeprom.sig` but do
NOT re-download `pieeprom.upd` (version match → skip). Visible in
`logread | grep tftp` on the router.

Build packages with `scripts/pi_eeprom.py build --boot-order 0xf142 --boot-uart`.

## Network boot security (outlook)

Plain TFTP netboot has **no authentication**: whoever controls DHCP/TFTP on
the L2 controls the OS a netboot-first Pi runs. In order of increasing rigor:

1. **Switch-based (implemented)**: boot options only go to known MACs
   (`dhcp-host` tags), the server is disarmed when idle, and rescue sessions
   can run on an isolated port/VLAN (conwrt `port_isolator` pattern).
2. **Signed network boot (Pi 4/5 supported, irreversible)**: program an RSA
   public-key hash into EEPROM OTP (`FLASH_LOCK` — one-way), set
   `SIGNED_BOOT=1`; the bootloader then only accepts `boot.img` + `boot.sig`
   whose signature chains to that key, on TFTP or any medium. Enable via the
   `raspberrypi/secure-boot-recovery` flow from a host. After OTP lock, a
   wrong-key device boots nothing — treat as a fleet decision, not a lab
   toggle.
3. **Immutable OS layer (alternative)**: Ubuntu Core on Pi trades Debian
   flexibility for transactional signed updates and confinement — real-world
   reports cite first-boot friction and hardware-driver gaps (Bluetooth, slow
   boot) on Pi. Evaluate per use case; keep Ubuntu Server + unattended
   upgrades for lab boxes.

## Secure boot options — documented, NOT enabled

None of the below is turned on in the lab today. They are the roadmap for
"authenticate the whole boot chain" when a deployment actually needs it.
Recorded so the decision is a known, costed choice rather than an accident.

### Option A — Signed network boot without OTP lock (recommended phase 1)

- What: `SIGNED_BOOT=1` in the EEPROM config. The bootloader requires
  `boot.img` + `boot.sig` (a signed FAT image wrapping config.txt, kernel,
  dtbs, firmware files) instead of loose files, from TFTP or any boot medium.
- Key handling: RSA-2048 key pair generated on the signing host; the private
  key never touches the Pi. Signature files are produced by the
  `secure-boot-recovery` tooling.
- Protects against: rogue DHCP/TFTP servers booting a malicious OS over the
  LAN (the realistic home/lab threat), swapped-SD attacks.
- Does NOT protect against: an attacker with physical access who reflashes
  the EEPROM via SD-card recovery (no OTP hash programmed yet) and flips
  `SIGNED_BOOT=0`.
- Cost: every kernel/config/firmware change requires rebuilding and
  re-signing `boot.img` (CI job); boot debugging gets harder (signature
  failures are silent without UART).
- Reversibility: fully reversible while OTP is unlocked — flip
  `SIGNED_BOOT=0` via any EEPROM update flow.

### Option B — Full secure boot with OTP lock (production phase 2)

- What: Option A plus programming the public-key hash into OTP and setting
  `FLASH_LOCK`. The bootloader refuses any unsigned/wrong-signed EEPROM and
  boot image, permanently.
- Protects against: everything A does, plus physical boot-medium/EEPROM
  tampering. This is the "cryptographically solid before booting" state
  production fleets (e.g. digital signage) run.
- Costs and risks (all real, all irreversible):
  - `FLASH_LOCK` cannot be undone. Lose the private key and the board is an
    e-waste paperweight (no recovery, no RMA path).
  - Every EEPROM update must now be signed with the enrolled key; unsigned
    recovery flows stop working.
  - rpiboot/USB provisioning is restricted under secure boot (signed gadget
    images only).
  - Key custody becomes an operational requirement (HSM or at minimum an
    offline, backed-up key with documented escrow).
- Prerequisites before even considering: a stable OS build pipeline, a
  tested key-ceremony process, and a fleet big enough that the threat model
  justifies bricking risk.

### Option C — Immutable/signed OS layer (Ubuntu Core)

- What: Ubuntu Core instead of Ubuntu Server — read-only rootfs, snaps,
  transactional signed OTA updates with automatic rollback; optional secure
  boot and full-disk-encryption integration on supported hardware.
- Protects against: runtime tampering and broken updates; complements (does
  not replace) A/B for the boot chain.
- Costs: first-boot setup expects monitor/Ubuntu SSO (headless path exists
  but is clunkier), snap packaging learning curve, Pi hardware-driver gaps
  reported in the field (Bluetooth), slower boots. Public field reports are a
  mixed bag on Pi specifically — pilot before committing a fleet.

### Option D — Full disk encryption (data at rest only)

- LUKS rootfs with a dropbear-in-initramfs unlock over SSH (classic headless
  pattern) on Ubuntu Server, or Ubuntu Core FDE where supported.
- Protects data at rest on the 1TB disk; does NOT authenticate boot.
  Relevant only once the disk holds data worth encrypting.

### Recommended path

| Phase | Action | When |
|---|---|---|
| 0 (now) | Arm/disarm switch, per-MAC tags, disarm-by-default, tmpfs-only tree | done |
| 1 | Option A: signed `boot.img`, no OTP lock | when a Pi runs something exposed beyond the home VLAN |
| 2 | Option B: OTP lock | only for a real fleet with key ceremony + escrow |
| parallel | Option C/D per workload | when a workload demands it |

### labgrid outlook

The Pi fits labgrid as: a Place with a power port (smartplug/USB-Switch),
a console via `ser2net` (BOOT_UART=1 is already set, 115200 on GPIO14/15),
and a custom strategy that (a) arms `pi_netboot.py`, (b) power-cycles, (c)
drives the rescue shell over telnet. No upstream labgrid driver needed —
the `external`/shell exporters plus conwrt tooling cover it. Under Option B,
labgrid's boot strategy would additionally push a freshly signed `boot.img`
per test job.

## Operational notes

- `BOOT_UART=1` is set on managed Pis: a 3.3V USB-serial adapter on GPIO
  UART (115200) shows bootloader + kernel logs with no screen.
- EEPROM updates are version-gated by the bootloader: after a successful
  flash, re-offering the same `pieeprom.upd` is skipped automatically.
- On OpenWrt the TFTP tree lives in tmpfs — it disappears on router reboot.
  `pi_netboot.py arm` re-uploads it; nothing persists on the router.
