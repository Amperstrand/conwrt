<!--
  conwrt — serial-03-backup
  DISCLAIMER: Read-only backup of device data via serial console. This step dumps
  flash contents for forensics and recovery. DO NOT modify any device state.
  You MUST have legal authority to access the target device.
-->

# Serial 03: Backup & Dump

**Role**: You are a serial console operator performing a forensic backup of a router.
Your goal is to dump all critical device data — bootloader environment, partition
contents, factory calibration — so that the device can be recovered if flashing fails.

---

## ⚠️ Safety Rules (NON-NEGOTIABLE)

- **DO NOT** flash firmware
- **DO NOT** erase or write to any flash partition
- **DO NOT** modify bootloader environment
- **DO NOT** reset or reboot the device
- **ONLY USE** read commands: `md.b`, `nand read`, `printenv`
- All dumps go to the host machine via serial capture — nothing is written to the device
- The Factory/calibration partition is IRREPLACEABLE — always back it up first

---

## Prerequisites

- serial-02 completed: bootloader command access, partition layout known
- Bootloader prompt active (you are IN the bootloader, not in firmware)
- Sufficient disk space on host: flash dumps can be 128MB+

---

## Why Backup Before Flash

**If you flash without a backup and something goes wrong:**
- Factory partition (MAC, serial, calibration, certificates) is lost forever
- No way to restore original firmware
- Device may be permanently bricked
- No recovery image available

**A complete backup enables:**
- Full device recovery to pre-flash state
- Forensic analysis of original firmware
- Partition-level comparison before/after flash
- Factory data preservation (MAC, serial, certs)

---

## Procedure

### Step 1: Dump Bootloader Environment

Save the complete environment variable set:

```bash
printf 'printenv\r' > /tmp/conwrt-serial-cmd
```

Capture the full output to `$STEP_DIR/raw/bootloader-env.txt`. This is small (a few KB)
and contains boot configuration, MAC address, partition layout, and boot flags.

### Step 2: Dump Partition Table

Record the exact partition layout for recovery reference:

**From U-Boot:**
```bash
printf 'printenv mtdparts\r' > /tmp/conwrt-serial-cmd
printf 'nand info\r' > /tmp/conwrt-serial-cmd
```

**From RedBoot:**
```bash
printf 'fis list\r' > /tmp/conwrt-serial-cmd
```

Save to `$STEP_DIR/raw/partition-table.txt`.

### Step 3: Dump Critical Partitions (PRIORITY)

Dump partitions in priority order. **Factory/calibration is ALWAYS first** — it contains
irreplaceable device-specific data.

The dump method depends on the bootloader:

**Method A — U-Boot `md.b` (memory dump byte):**

```bash
# Read flash at base+offset for partition size
# Format: md.b <address> <length_in_hex>
printf 'md.b 0x1e000000 0x40000\r' > /tmp/conwrt-serial-cmd
```

The output format is:
```
001e00000: 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff    ..."3DUfw.........
```

**Parsing md.b output to binary:**
The host-side capture script must parse hex bytes and write them to a .bin file.
Use `scripts/serial-dump-parse.py` (if available) or parse manually.

**Method B — U-Boot `nand read` to RAM then `md.b`:**

```bash
# Read NAND partition to RAM, then dump from RAM
printf 'nand read 0x80000000 0x0 0x40000\r' > /tmp/conwrt-serial-cmd
# Wait for completion, then:
printf 'md.b 0x80000000 0x40000\r' > /tmp/conwrt-serial-cmd
```

**Method C — Z-Loader / ZyXEL-specific:**

Z-Loader may not have a direct memory dump command. Options:
1. Use `md.b` if available (same as U-Boot)
2. Use the bootloader's built-in backup command if one exists
3. Fall back to firmware-level backup (SSH + dd) if firmware is accessible

### Step 4: Dump Order (Priority)

Dump partitions in this order — most critical first:

| Priority | Partition | Why | Typical Size |
|---|---|---|---|
| 1 | **Factory / Calibration** | MAC, serial, WiFi calibration, certificates — IRREPLACEABLE | 256KB |
| 2 | **Bootloader** | Bootloader binary — needed for unbrick | 256KB-512KB |
| 3 | **Config / Environment** | Bootloader env — boot flags, network config | 256KB-512KB |
| 4 | **Kernel / Firmware** | Active firmware for restore | 8-32MB |
| 5 | **Kernel2 / Recovery** | Backup firmware partition | 8-32MB |
| 6 | **Data / NVRAM** | User configuration, certs | varies |

**Large partitions (Kernel, Kernel2) may take a very long time via serial.**
A 32MB partition at 57600 baud takes ~70 minutes. Consider:
- Only dump Kernel (active firmware) if time is limited
- Use network-based backup (SSH + dd) if firmware is running
- Use TFTP to push backup from bootloader if supported

### Step 5: Verify Dumps

After each dump, verify integrity:

```bash
# On host: calculate SHA-256
sha256sum $STEP_DIR/raw/dumps/factory.bin
sha256sum $STEP_DIR/raw/dumps/bootloader.bin
```

**Quick validation:**
- Check file size matches expected partition size
- Check first bytes for known magic values:
  - U-Boot: starts with jump instruction (`ea0000xx` on ARM, `3c1xxx` on MIPS)
  - Factory/calibration: varies, but should NOT be all 0x00 or all 0xFF
  - SquashFS: magic `hsqs` (0x73717368) or `sqsh` (0x68737173)
  - UBI: magic `UBI#` (0x55424923)

### Step 6: Capture Device Identity

Record device-identifying information for inventory:

```bash
printf 'printenv ethaddr\r' > /tmp/conwrt-serial-cmd
printf 'printenv serial#\r' > /tmp/conwrt-serial-cmd
printf 'printenv model_id\r' > /tmp/conwrt-serial-cmd
```

Or read from Factory partition at known offsets (device-specific).

---

## Output Contract

Write `$STEP_DIR/findings.json`:

```json
{
  "step": "serial-03-backup",
  "dumps": [
    {
      "partition": "Factory",
      "filename": "raw/dumps/factory.bin",
      "size_bytes": 262144,
      "sha256": "<hash>",
      "verified": true,
      "irreplaceable": true
    },
    {
      "partition": "Bootloader",
      "filename": "raw/dumps/bootloader.bin",
      "size_bytes": 524288,
      "sha256": "<hash>",
      "verified": true
    }
  ],
  "device_identity": {
    "mac_address": "<REDACTED:MAC>",
    "serial_number": "<REDACTED:SERIAL>",
    "model_id": "0x07010001"
  },
  "partition_table_snapshot": "raw/partition-table.txt",
  "bootloader_env_snapshot": "raw/bootloader-env.txt",
  "notes": "Factory and Bootloader partitions dumped via md.b. Kernel partition (31MB) skipped — too large for serial dump at 57600 baud (~70min). Will use SSH+dd after firmware is accessible.",
  "next_step_input": {
    "recommendation": "serial-04-flash",
    "parameters": {
      "backup_complete": true,
      "factory_backed_up": true
    }
  }
}
```
