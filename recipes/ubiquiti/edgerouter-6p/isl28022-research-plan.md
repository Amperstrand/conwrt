# ISL28022 Power Monitoring Research Plan

**Created**: 2026-05-22
**Status**: In Progress
**Goal**: Determine definitively what I2C devices exist at 0x3F/0x40 on the ER-6P, and get them working under OpenWrt.

---

## Problem Statement

Two I2C devices respond at addresses 0x3F and 0x40 on I2C bus 1 (twsi1). Initial investigation suggested they might not be ISL28022 due to repeating register patterns and manufacturer ID = 0x0000.

**RESOLVED 2026-05-22**: Systematic hypothesis testing confirmed:
1. **0x3F and 0x40 are THE SAME chip** — writes to one address are visible from the other
2. **The chip IS an ISL28022** — registers respond correctly to word-mode reads, bus voltage decodes to ~24.46V (matches 24V PSU)
3. **The "repeating pattern" was a red herring** — caused by byte-mode i2cdump accessing word-addressed registers
4. **The chip works on power-on defaults** — no initialization needed (matches EdgeOS behavior)
5. **Next step**: Bind the kernel ISL28022 driver via DT to get hwmon sysfs interface

---

## Evidence Summary

### What We Know
| Fact | Source | Confidence |
|------|--------|------------|
| Two devices at 0x3F/0x40 on bus 1 | `i2cdetect -y -r 1` on live hardware | HIGH |
| Devices respond to SMBus reads/writes | `i2cget/i2cset` tested | HIGH |
| `twsi1` is enabled (`status = "okay"`) | Live DT dump via `dtc -I fs` | HIGH |
| No DT child nodes for 0x3F/0x40 | Live DT dump — empty bus | HIGH |
| Manufacturer ID = 0x0000 | `i2cget -y 1 0x3f 0xfe w` | HIGH |
| Repeating 16-byte pattern across all registers | `i2cdump -y 1 0x3f b` | HIGH |
| `ubnt_platform.ko` has `i2c_isl28022` symbol (BSS at 0xF0) | Module symbol table | HIGH |
| `ubnt_platform.ko` uses raw SMBus calls, not I2C driver framework | nm shows only `i2c_get_adapter`, `i2c_smbus_read/write` | HIGH |
| c-spiess (PR #13160) found ISL28022 in EdgeOS DT at 0x40 | PR conversation | MEDIUM |
| c-spiess's `i2cget` readings differ from ours (0x79 0x9f vs 0x79 0x1f) | PR conversation vs our reads | MEDIUM |
| Wave 0 (May 20) found devices on bus 1 with `-r` flag | w0-5-i2c-aggressive evidence | HIGH |
| Config write changes data readings (0xee00 → 0xeb00) | Session testing today | HIGH |

### What We Don't Know
| Question | How to Resolve |
|----------|----------------|
| What chip is actually at 0x3F and 0x40? | Extract EdgeOS DTB and check `compatible` strings |
| Why manufacturer ID returns 0x0000? | May be normal for uninitialized ISL28022; check datasheet |
| What shunt resistor value is used? | EdgeOS DTB or ubnt_platform.ko data section |
| Are there hardware revision differences between our ER-6P and c-spiess's? | Compare board info from `cat /tmp/sysinfo/board_name` |
| Does the ISL28022 kernel driver successfully bind? | Apply DT patch + rebuild kernel, check dmesg |

---

## Research Phases

### Phase 1: EdgeOS Reverse Engineering (Zero Risk)

#### 1A: Extract EdgeOS Device Tree ✅ COMPLETE — 2026-05-22
- [x] Extracted DTB from `vmlinux.64.edgeos.bak` on router's boot partition (`/dev/mmcblk0p1`)
- [x] DTB found at offset 0x65cd80 in EdgeOS kernel, 11,601 bytes
- [x] Decompiled with `dtc -I dtb -O dts` → `edgeos-dts-extracted.dts` (565 lines)
- [x] **CRITICAL FINDING**: `twsi1` (i2c@1180000001200) has **NO child nodes** in EdgeOS DT either!
- [x] EdgeOS does NOT declare ISL28022 in DT — `ubnt_platform.ko` probes via raw SMBus
- [x] `twsi0` (i2c@1180000001000) has: ds1337 RTC at 0x68, tmp421 at 0x4c
- [x] `twsi1` (i2c@1180000001200) — completely empty bus in DT

**Finding**: Ubiquiti hardcoded ISL28022 support in `ubnt_platform.ko`, not DT. The chip identity and addresses are in the module binary, not the device tree. This means c-spiess's PR #13160 DT approach (adding DT nodes for ISL28022) may work IF the kernel's ISL28022 driver can probe the chips — but EdgeOS never used DT for this.

#### 1B: Deep Reverse Engineer ubnt_platform.ko I2C Code ✅ COMPLETE — 2026-05-22
- [x] Full MIPS64 disassembly with capstone + relocation resolution
- [x] **ISL28022 address = 0x40** (hardcoded: `addiu $a3, $zero, 0x40` at .init.text+0x1C4)
- [x] **ISL28022 bus = 1** (`i2c_get_adapter(1)` at .init.text+0x16C, stored in `sys_i2c_adapt1`)
- [x] **No ISL28022 register writes!** Module never calls `i2c_smbus_write_byte_data` for ISL28022. Chip runs on power-on defaults. No calibration register set.
- [x] ISL28022 read function at .text+0x1250: reads regs 0 (config, discarded), 1 (shunt voltage), 2 (bus voltage)
- [x] `power_mon_sh` at .text+0x1C90: outputs three values (voltage/10, current/10, power/10000)
- [x] Shunt voltage processing: sign-extend 15-bit → multiply by 10/8 = 1.25
- [x] Bus voltage: mask with 0xFFFC (clear status bits)
- [x] "3Faied" string: "3" is KERN_ERR log level prefix, "Faied" is typo for "Failed"
- [x] All I2C addresses are hardcoded immediates, NOT from data tables

**Complete I2C Device Map from ubnt_platform.ko:**
| Device | Bus | Address | Access |
|--------|-----|---------|--------|
| ISL28022 (power mon) | 1 | 0x40 | read_word_data |
| SFP data (primary) | 0 | ? | read_byte_data |
| SFP data (secondary) | 0 | ? | read_byte_data |
| TMP421 (temp) | 1 | ? | read_byte_data |
| ADT7475 (fan ctrl) | 1 | ? | read_byte_data |
| POE controller | 0 | 0x22 | read/write_byte_data |

**EdgeOS ISL28022 pseudocode:**
```c
// Init (no register writes — power-on defaults only):
memset(&i2c_isl28022, 0, 456);
strlcpy(i2c_isl28022.name, "i2c_isl28022", 20);
i2c_isl28022.addr = 0x40;
i2c_isl28022.adapter = i2c_get_adapter(1);

// Read (called from polling thread every ~1 second):
regs[0] = i2c_smbus_read_word_data(&i2c_isl28022, 0); // config (discarded)
regs[1] = i2c_smbus_read_word_data(&i2c_isl28022, 1); // shunt voltage
regs[2] = i2c_smbus_read_word_data(&i2c_isl28022, 2); // bus voltage
shunt_signed = sign_extend_15bit(byte_swap(regs[1]));
current = (shunt_signed * 10 + 4) / 8;  // positive rounding
bus_voltage = byte_swap(regs[2]) & 0xFFFC;
power = current * bus_voltage;
// Store for sysfs display

// Sysfs display:
sprintf(buf, "%s %s %s\n", voltage/10, current/10, power/10000);
```

#### 1C: Cross-Reference with c-spiess PR #13160
- [x] PR uses compatible "isl,isl28022" (mainline binding is "renesas,isl28022")
- [x] PR uses shunt-resistor-micro-ohms = <8000> (8mΩ)
- [x] PR only declares device at 0x40 (not 0x3F) — matches our RE finding (EdgeOS uses only 0x40)
- [ ] Our config reg reads 0x791f vs c-spiess's 0x799f — need to investigate
- [ ] Check if c-spiess tested under OpenWrt or EdgeOS
- [ ] Our mfg ID = 0x0000 — ISL28022 may not have mfg ID registers, or chip revision differs

### Phase 2: Kernel Rebuild and Hardware Test

#### 2A: Set Up Full OpenWrt Build Tree on Build Host
- [ ] Clone OpenWrt v25.12.4 source on 192.168.X.X
- [ ] `make menuconfig` for octeon/generic target
- [ ] Verify kernel config matches running firmware

#### 2B: Apply Patches
- [ ] Add ISL28022 DT node to `cn7130_ubnt_edgerouter-6p.dts`
  - Add `pmon@40` (NOT 0x3F — EdgeOS only uses 0x40) with `compatible = "renesas,isl28022"`
  - Include `shunt-resistor-micro-ohms = <8000>` (matching PR #13160)
  - twsi1 already enabled in DT (no change needed)
- [ ] Enable `CONFIG_SENSORS_ISL28022=y` in kernel config
- [ ] Build full firmware image

#### 2C: Flash and Verify
- [ ] Backup current overlay (`tar czf /tmp/backup.tar.gz /etc/config /root/`)
- [ ] Flash via `sysupgrade` (board validation — safe)
- [ ] Re-deploy kernel module and userspace tools
- [ ] Check `dmesg | grep isl28022` for driver probe result
- [ ] If probe succeeds: verify hwmon sysfs readings
- [ ] If probe fails: check driver error, compare with datasheet

### Phase 3: Integration (After ISL28022 Confirmed Working)
- [ ] Update `poe-ubus info` to read from hwmon sysfs
- [ ] Update `poe-monitor` to use hwmon instead of raw i2cget
- [ ] Re-enable `poe-watchdog` with real current data
- [ ] Test power budget enforcement with real measurements

---

## Build Host Inventory (192.168.X.X)

| Resource | Path | Size | Status |
|----------|------|------|--------|
| OpenWrt SDK | `/home/ubuntu/openwrt-sdk-25.12.4-octeon-generic_gcc-14.3.0_musl.Linux-x86_64` | 974MB | Installed |
| Kernel source (in SDK) | `.../build_dir/.../linux-6.12.87/` | ~500MB | Available |
| EdgeOS module | `/tmp/edgeos-root/lib/modules/4.9.79-UBNT/extra/ubnt_platform.ko` | ~1.3MB | Available |
| EdgeOS chroot | `/tmp/edgeos-chroot/` | ~50MB | Available |
| Our module | `/home/ubuntu/er6p-poe-build/er6p-poe.ko` | 27KB | Available |
| Free disk space | `/` | 117GB | Sufficient |
| Python3 + Capstone | System | — | Available |
| sudo | — | — | Works (no password) |

**Missing**: Full OpenWrt source tree (needed for DT patches and kernel rebuild)

---

## Router State (192.168.X.X)

| Component | Status |
|-----------|--------|
| OpenWrt | 25.12.4, kernel 6.12.87 |
| er6p-poe module | v0.5.0 loaded from `/root/er6p-poe.ko` |
| PoE control | Working (eth1 verified with load) |
| UCI config | realtek-poe standard format |
| ubus interface | poe-ubus with info/manage/reload |
| I2C bus 1 | Active (twsi1 enabled in DT) |
| Devices at 0x3F/0x40 | Respond but return repeating pattern |
| Serial cable | NOT available |

---

## Key Files

| File | Purpose |
|------|---------|
| `recipes/ubiquiti/edgerouter-6p/isl28022-research-plan.md` | THIS FILE — tracking document |
| `recipes/ubiquiti/edgerouter-6p/poe-reverse-engineering.md` | Full EdgeOS RE report |
| `recipes/ubiquiti/edgerouter-6p/poe-diagnosis.md` | Wave 0 diagnostic findings |
| `recipes/ubiquiti/edgerouter-6p/disasm/poe_st-fully-documented.md` | Full poe_st disassembly |
| `recipes/ubiquiti/edgerouter-6p/disasm/edgeos-userspace-protocol.md` | HAL analysis |
| `recipes/ubiquiti/edgerouter-6p/disasm/helpers-documented.md` | Helper function analysis |
| `recipes/ubiquiti/edgerouter-6p/test-evidence/wave-0/w0-5-i2c-aggressive/` | I2C bus scan evidence |
