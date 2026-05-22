# B3+B4+B5: GPIO Register Access + I2C Stub + PoE Engine

## Date: 2026-05-20

## Files Created/Modified

### B3: GPIO Register Access Layer
- `src/er6p-poe-gpio.h`: GPIO layer header (init/exit/set/all_off)
- `src/er6p-poe-gpio.c`: Implementation
  - `er6p_poe_gpio_init()`: ioremap(GPIO_BASE_PHYS, 0x200)
  - `er6p_poe_gpio_set()`: allowlist check → POE_GPIO_MAP lookup → writeq TX_SET/TX_CLEAR
  - `er6p_poe_gpio_all_off()`: iterate all allowed ports, clear both roles

### B4: I2C/ISL28022 Access Layer (STUB)
- `src/er6p-poe-i2c.h`: I2C layer header (init/exit stubs)
- `src/er6p-poe-i2c.c`: Stub returning 0 — monitoring deferred to userspace CLI (C1)

### B5: PoE Sequence Engine
- `src/er6p-poe-engine.h`: Engine header (enable/disable/disable_all)
- `src/er6p-poe-engine.c`: Implementation
  - Enable: 48v off → 24v off → 24v on (verified A7 poe_st replay)
  - Disable: 24v off → 48v off

### Integration
- `src/er6p-poe.c`: Updated to v0.2.0, includes all layers
- `Kbuild`: Updated for composite module (4 .o files)

## Build

Cross-compiled on 192.168.X.X (ubuntu/ubuntu):
```
SDK=/tmp/openwrt-sdk-25.12.4-octeon-generic_gcc-14.3.0_musl.Linux-x86_64
KDIR=$SDK/build_dir/target-mips64_octeonplus_64_musl/linux-octeon_generic/linux-6.12.87
TOOLCHAIN=$SDK/staging_dir/toolchain-mips64_octeonplus_64_gcc-14.3.0_musl/bin
PATH=$TOOLCHAIN:$PATH STAGING_DIR=$SDK/staging_dir ARCH=mips CROSS_COMPILE=mips64-openwrt-linux-musl- \
  make -C $KDIR M=/tmp/er6p-poe modules
```

All 4 source files compiled with zero warnings:
- src/er6p-poe.o
- src/er6p-poe-gpio.o
- src/er6p-poe-i2c.o
- src/er6p-poe-engine.o

## Router Test (192.168.X.X)

### insmod
```
[27068.355453] er6p-poe: loading driver (ports: 3 allowed)
[27068.360703] er6p-poe: GPIO base mapped at 00000000b9894c2d (phys 0x1070000000800)
[27068.368226] er6p-poe: driver loaded successfully
```

### rmmod (disable_all fires)
```
[27058.223057] er6p-poe: port=1 role=0 gpio=4 OFF
[27058.227526] er6p-poe: port=1 role=1 gpio=3 OFF
[27058.236543] er6p-poe: port=3 role=0 gpio=10 OFF
[27058.240990] er6p-poe: port=3 role=1 gpio=7 OFF
[27058.245546] er6p-poe: port=4 role=0 gpio=16 OFF
[27058.249993] er6p-poe: port=4 role=1 gpio=9 OFF
[27058.249993] er6p-poe: unloading driver
```

### Module Metadata
- Size: 12288 bytes
- Taint: O (OOT only — pre-existing gpio_reg, NOT from er6p-poe)
- Kernel taint: 4096 (bit 12, same as before)
- GPIO region confirmed: 1070000000800-10700000008ff (256 bytes)

## GPIO Numbers Verified

| Port | ethX | 24V GPIO | 48V GPIO | Verified in dmesg |
|------|------|----------|----------|-------------------|
| 1    | eth1 | 4        | 3        | YES               |
| 3    | eth3 | 10       | 7        | YES               |
| 4    | eth4 | 16       | 9        | YES               |

## Notes
- B6 (sysfs interface) is needed to trigger enable/disable from userspace
- Currently module only exercises GPIO on init/exit path
- No sysfs attribute to trigger er6p_poe_enable() yet
