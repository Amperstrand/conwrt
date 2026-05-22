# ER-6P PoE Driver: Build and Install Guide

**Target**: EdgeRouter 6P (ER-e300), Cavium Octeon III (CN7030), MIPS64 big-endian
**OpenWrt**: 25.12.4, kernel 6.12.87, target octeon/generic
**Date**: 2026-05-20

---

## SDK Setup

### Download the OpenWrt SDK

Download the SDK for the `octeon/generic` target from the OpenWrt 25.12.4 release:

```bash
wget https://downloads.openwrt.org/releases/25.12.4/targets/octeon/generic/openwrt-sdk-25.12.4-octeon-generic_gcc-14.3.0_musl.Linux-x86_64.tar.xz
tar xf openwrt-sdk-25.12.4-octeon-generic_gcc-14.3.0_musl.Linux-x86_64.tar.xz
mv openwrt-sdk-25.12.4-octeon-generic_gcc-14.3.0_musl.Linux-x86_64 sdk-octeon
```

### Verify SDK

```bash
ls sdk-octeon/staging_dir/toolchain-mips64_octeon+64_gcc-14.3.0_musl/bin/
```

You should see `mips64-openwrt-linux-musl-gcc` and related tools.

### Version Pinning

The exact versions matter. The module must be compiled against the same kernel the router runs:

| Component | Version |
|-----------|---------|
| OpenWrt | 25.12.4 |
| Kernel | 6.12.87 |
| GCC | 14.3.0 |
| Target | octeon/generic |
| C library | musl |

If the router runs a different kernel version, the module will fail to load with "disagrees about version of symbol" errors. Always match the SDK to the running firmware.

---

## Build the Kernel Module

### Makefile

The module uses a standard out-of-tree kernel module build:

```makefile
# er6p-poe/Makefile
KDIR ?= $(HOME)/sdk-octeon/build_dir/target-mips64_octeon+64_musl/linux-octeon_generic/linux-6.12.87

ARCH = mips
CROSS_COMPILE = mips64-openwrt-linux-musl-
export ARCH CROSS_COMPILE

obj-m := er6p-poe.o
er6p-poe-y := er6p-poe-gpio.o er6p-poe-engine.o er6p-poe-sysfs.o er6p-poe-debugfs.o er6p-poe-i2c.o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
```

### Build Command

```bash
make KDIR=/path/to/sdk-octeon/build_dir/target-mips64_octeon+64_musl/linux-octeon_generic/linux-6.12.87
```

Set `STAGING_DIR` to suppress warnings:

```bash
STAGING_DIR=/path/to/sdk-octeon/staging_dir \
  make KDIR=/path/to/sdk-octeon/build_dir/target-mips64_octeon+64_musl/linux-octeon_generic/linux-6.12.87
```

### Build Output

The build produces `er6p-poe.ko` in the current directory. Verify it:

```bash
file er6p-poe.ko
```

Expected: `ELF 64-bit MSB relocatable, MIPS64, version 1 (SYSV), not stripped`

Check module metadata:

```bash
modinfo er6p-poe.ko
```

Should show `vermagic: 6.12.7 SMP mod_unload MIPS64` matching the running kernel.

---

## Install on the Router

### Copy Files

```bash
# Kernel module
scp -O er6p-poe.ko root@router:/tmp/er6p-poe.ko

# Userspace tools
scp -O userspace/poe root@router:/usr/sbin/poe
scp -O userspace/poe.init root@router:/etc/init.d/poe
scp -O userspace/poe.config root@router:/etc/config/poe
scp -O userspace/poe-watchdog root@router:/usr/sbin/poe-watchdog
scp -O userspace/poe-watchdog.init root@router:/etc/init.d/poe-watchdog
scp -O userspace/poe-monitor root@router:/usr/sbin/poe-monitor
scp -O userspace/poe-monitor.init root@router:/etc/init.d/poe-monitor

# Make executables
ssh root@router 'chmod +x /usr/sbin/poe /usr/sbin/poe-watchdog /usr/sbin/poe-monitor /etc/init.d/poe /etc/init.d/poe-watchdog /etc/init.d/poe-monitor'
```

### Load the Module

```bash
ssh root@router 'insmod /tmp/er6p-poe.ko'
```

Verify:

```bash
ssh root@router 'lsmod | grep er6p_poe'
ssh root@router 'dmesg | tail -20 | grep er6p-poe'
```

You should see log messages about GPIO mapping, BIT_CFG configuration, and sysfs entries created.

### Start the Service

```bash
ssh root@router '/etc/init.d/poe enable'   # Enable boot start
ssh root@router '/etc/init.d/poe start'    # Start now
```

### Enable Watchdog and Monitor (Optional)

```bash
ssh root@router '/etc/init.d/poe-watchdog enable'
ssh root@router '/etc/init.d/poe-watchdog start'
ssh root@router '/etc/init.d/poe-monitor enable'
ssh root@router '/etc/init.d/poe-monitor start'
```

### Verify

```bash
ssh root@router 'poe list'
```

Expected output:
```
Port     Status     Mode
----     ------     ----
eth1     disabled   off
eth3     disabled   off
eth4     disabled   off
```

---

## Module Parameters

The kernel module accepts one parameter:

### power_budget_w

- **Type**: int
- **Default**: 50
- **Permissions**: 0644 (readable and writable at runtime)
- **Description**: Total PoE power budget in watts. The driver rejects enable requests that would exceed this budget.

Set at load time:

```bash
insmod /tmp/er6p-poe.ko power_budget_w=75
```

Read at runtime:

```bash
cat /sys/module/er6p_poe/parameters/power_budget_w
```

Modify at runtime:

```bash
echo 75 > /sys/module/er6p_poe/parameters/power_budget_w
```

Note that changing the budget at runtime does not retroactively disable ports that are already enabled. It only affects future enable requests.

---

## Build Troubleshooting

### "STAGING_DIR" warnings

The SDK prints warnings about `STAGING_DIR` not being set. Suppress them:

```bash
export STAGING_DIR=/path/to/sdk-octeon/staging_dir
```

Add this to your shell profile or wrap it in the make invocation.

### "compiler differs from the one used to build the kernel"

This means the GCC version in your SDK doesn't match the kernel's vermagic. Ensure you're using the exact SDK version pinned above. If you have multiple SDKs installed, check `KDIR` points to the right one.

### "No rule to make target 'modules'"

The `KDIR` path doesn't point to a kernel source tree. Verify the path:

```bash
ls $KDIR/Makefile
ls $KDIR/.config
```

Both must exist. If not, the SDK is incomplete or the path is wrong.

### Unknown symbol errors at load time

```bash
insmod: ERROR: could not insert module er6p-poe.ko: Unknown symbol in module
```

Check which symbols are missing:

```bash
dmesg | grep "Unknown symbol"
```

Common causes:

- Built against wrong kernel version. Rebuild with matching SDK.
- Missing kernel config options (CONFIG_GPIO_OCTEON, CONFIG_I2C, CONFIG_DEBUG_FS).

### "disagrees about version of symbol"

The module was built for a different kernel. Check vermagic:

```bash
modinfo er6p-poe.ko | grep vermagic
uname -r
```

The vermagic must match the running kernel exactly.

---

## Userspace Deployment Summary

| File | Destination | Purpose |
|------|-------------|---------|
| `er6p-poe.ko` | `/tmp/er6p-poe.ko` | Kernel module |
| `poe` | `/usr/sbin/poe` | CLI tool |
| `poe.init` | `/etc/init.d/poe` | Init script |
| `poe.config` | `/etc/config/poe` | UCI configuration |
| `poe-watchdog` | `/usr/sbin/poe-watchdog` | Overcurrent daemon |
| `poe-watchdog.init` | `/etc/init.d/poe-watchdog` | Watchdog init |
| `poe-monitor` | `/usr/sbin/poe-monitor` | Monitoring daemon |
| `poe-monitor.init` | `/etc/init.d/poe-monitor` | Monitor init |

The kernel module goes to `/tmp/` because the router's root filesystem is read-only (squashfs overlay). On reboot, `/tmp/` is cleared. The init script handles re-loading the module, or you can place the module in the overlay if persistence is needed.

### Dependencies

The userspace tools require:

- `i2c-tools` (for `i2cget`, used by watchdog and monitor)
- `procd` (standard on OpenWrt, for init scripts)
- `uci` (standard on OpenWrt, for configuration)

Install if missing:

```bash
opkg update
opkg install i2c-tools
```

---

## Updating the Module

After rebuilding:

```bash
# On the router: disable PoE first
/etc/init.d/poe stop

# Copy new module
scp -O er6p-poe.ko root@router:/tmp/er6p-poe.ko

# Restart service
/etc/init.d/poe start
```

The stop/start cycle ensures all GPIO pins are properly cleaned up before the old module is unloaded and the new one is loaded.
