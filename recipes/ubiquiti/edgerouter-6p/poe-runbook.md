# ER-6P PoE Operator Runbook

**Device**: EdgeRouter 6P (ER-e300) running OpenWrt 25.12.4
**Date**: 2026-05-20

This runbook covers day-to-day PoE operations on the ER-6P under OpenWrt. You don't need to read the reverse engineering document to use these commands.

---

## Quick Reference

```
poe enable eth1 24v-2pair      # Turn on 24V PoE on eth1
poe disable eth1               # Turn off PoE on eth1
poe status eth1                # Check port status
poe list                       # Show all ports
poe debug                      # Raw register dump
```

**Allowed ports**: eth1, eth3, eth4 only. eth0 and eth2 are permanently blocked.

---

## Enable PoE

Turn on 24V passive PoE on a port. The connected device receives power over the Ethernet cable.

```bash
poe enable eth1 24v-2pair
```

Expected output:
```
PoE enabled on eth1 (mode=24v-2pair)
```

The `24v-2pair` mode delivers 24V over 2 pairs (pins 1/2 and 3/6). This is standard passive PoE compatible with Ubiquiti devices, MikroTik devices, and any 24V passive PoE equipment.

The `24v-4pair` mode is accepted but currently maps to the same 24V output. It is reserved for future 4-pair support.

The port takes about 1-2 seconds for power to stabilize. The PoE LED (left LED on the RJ45 port) illuminates green when a powered device is connected and drawing current. The LED does not light on an empty port, even when PoE is enabled.

---

## Disable PoE

```bash
poe disable eth1
```

Expected output:
```
PoE disabled on eth1
```

Power is removed immediately. Any connected PoE device will lose power. The PoE LED turns off.

---

## Check Status

### All Ports

```bash
poe list
```

Expected output:
```
Port     Status     Mode
----     ------     ----
eth1     enabled    24v
eth3     disabled   off
eth4     disabled   off
```

### Single Port Detail

```bash
poe status eth1
```

Expected output when enabled:
```
Port:       eth1
Status:     enabled
Mode:       24v
Voltage:    29600 mV
Current:    49 mA
Link:       up
```

When disabled, voltage and current show `N/A`.

The voltage reading comes from the ISL28022 power monitor chip on the I2C bus. If the `i2cget` command fails (no `i2c-tools` installed, or I2C bus not available), voltage and current show `N/A`.

Note: The ISL28022 measures the entire 24V bus, not individual ports. Voltage and current readings shown by `poe status` are bus-wide totals. If multiple ports are enabled, the current reading is the combined draw of all ports.

---

## UCI Configuration

PoE state persists across reboots via UCI configuration at `/etc/config/poe`:

```
config poe 'global'
	option power_budget_w '50'

config port 'eth1'
	option enabled '0'
	option mode '24v-2pair'

config port 'eth3'
	option enabled '0'
	option mode '24v-2pair'

config port 'eth4'
	option enabled '0'
	option mode '24v-2pair'
```

### Enable a port persistently

Edit `/etc/config/poe` and set `enabled` to `1`:

```
config port 'eth1'
	option enabled '1'
	option mode '24v-2pair'
```

Then reload the service:

```bash
/etc/init.d/poe reload
```

Or apply via UCI commands:

```bash
uci set poe.eth1.enabled='1'
uci commit poe
/etc/init.d/poe reload
```

### Change power budget

```bash
uci set poe.global.power_budget_w='75'
uci commit poe
/etc/init.d/poe reload
```

The power budget limits total PoE wattage across all enabled ports. Default is 50W. Each 24V 2-pair port counts as 12W. If enabling a port would exceed the budget, the enable command fails with a power budget error.

---

## Boot Persistence

The init script `/etc/init.d/poe` runs at boot (START=95) and:

1. Loads the `er6p-poe.ko` kernel module from `/tmp/er6p-poe.ko`
2. Waits for sysfs entries to appear under `/sys/kernel/er6p_poe/`
3. Reads `/etc/config/poe`
4. Validates all port configurations
5. Applies the desired state to each port

The module configures GPIO pins during load (sets output enable bits) and disables all PoE ports as a safe starting state before applying the UCI config.

On service stop, all ports are disabled first, then the module is unloaded.

### Reload without reboot

```bash
/etc/init.d/poe reload
```

This re-reads UCI config and applies only the changes (delta apply). Ports that haven't changed are not touched. There is no power interruption to unchanged ports.

---

## Safety

### Power Budget

The driver tracks total power consumption and rejects enable requests that would exceed the configured budget. Check current usage:

```bash
cat /sys/kernel/er6p_poe/power_budget
```

Output: `budget=50W used=12W`

### Overcurrent Protection

The `poe-watchdog` daemon polls the ISL28022 bus-wide current sensor every 2 seconds. Since the ISL28022 measures total bus current (not per-port), overcurrent detection will disable all enabled ports when the bus threshold is exceeded. Events are logged to syslog:

```bash
logread | grep poe-watchdog
```

The watchdog threshold is configurable:

```bash
uci set poe.global.watchdog_overcurrent_ma='500'
uci commit poe
```

### Monitoring

The `poe-monitor` daemon writes real-time voltage and current to files under `/run/poe/`:

```bash
cat /run/poe/eth1/voltage_mv
cat /run/poe/eth1/current_ma
```

These files are suitable for collectd, Prometheus node exporter, or custom monitoring scripts.

---

## Troubleshooting

### "sysfs entry not found (module loaded?)"

The kernel module is not loaded. Check:

```bash
lsmod | grep er6p_poe
```

If not loaded:

```bash
insmod /tmp/er6p-poe.ko
```

Verify sysfs appeared:

```bash
ls /sys/kernel/er6p_poe/
```

You should see `eth1`, `eth3`, `eth4`, and `power_budget`.

### "is not a PoE-capable port (not in allowlist)"

You tried to control a port that is not in the allowlist. Only eth1, eth3, and eth4 support PoE. eth0 (WAN) and eth2 (management) are permanently blocked at both the kernel and userspace level. There is no override.

### Module fails to load

Check dmesg for errors:

```bash
dmesg | grep er6p-poe
```

Common causes:

- **"failed to ioremap GPIO base"**: The GPIO controller address is wrong or already mapped by another driver. Check for conflicts with `ubnt_platform.ko` (should not be loaded under OpenWrt).
- **"disagrees about version of symbol"**: The module was compiled for a different kernel version. Rebuild against the running kernel's headers.
- **"Unknown symbol"**: Missing kernel config option. Ensure `CONFIG_GPIO_OCTEON` and `CONFIG_I2C` are enabled.

### PoE enabled but no power on device

1. Check the PoE LED. If the LED is off, the GPIO is set but no current flows. The device may not be drawing power, or the cable may be faulty.
2. Check the link state:
   ```bash
   cat /sys/class/net/lan1/carrier
   ```
   If `0`, the device is not connected or the cable is bad.
3. Check voltage and current:
   ```bash
   i2cget -y 1 0x3F 0x02 w
   ```
   Should return a non-zero value (~0x765F = ~29.6V).
4. Verify the GPIO state:
   ```bash
   cat /sys/kernel/debug/er6p_poe/registers
   ```
   The TX_SET register should show the bit for the enabled port set.

### Power budget exceeded

```bash
poe enable eth4 24v-2pair
```
Output: `Error: failed to enable PoE on eth4`

Check the budget:
```bash
cat /sys/kernel/er6p_poe/power_budget
```

If `used` is close to `budget`, disable another port first, or increase the budget in UCI.

### No carrier after enabling PoE

PoE and Ethernet link are electrically independent. Enabling PoE does not affect the PHY or the Ethernet link. If the device does not get a link:

1. The cable may not be wired correctly for both data and power. Passive PoE uses pins 1/2 and 3/6 for power delivery (same as 10/100 Mbps data). A 4-pair cable (all 8 wires connected) is recommended.
2. The device may need a moment to boot. Wait 30 seconds and check again.
3. The PoE device may have its own link negotiation delay.

---

## Allowlist: Why eth0 and eth2 Are Never Touched

The ER-6P has 5 Ethernet ports (eth0-eth4). All 5 have GPIO pins for PoE control in the hardware. However, the system operator has imposed strict constraints:

- **eth0**: WAN uplink. Toggling PoE on this port risks disrupting the upstream connection. Even a momentary glitch during GPIO writes could cause the WAN link to flap. Never enable PoE on eth0.
- **eth2**: Management port. This port is used for out-of-band access to the router. Toggling PoE on this port risks losing management connectivity. Never enable PoE on eth2.

These constraints are enforced at three levels:

1. **Compile-time**: The kernel module has `static_assert` directives that cause a build failure if port 0 or port 2 appears in the allowlist.
2. **Runtime (kernel)**: `is_port_allowed()` rejects any port not in `{1, 3, 4}`. Sysfs writes return `-EPERM`.
3. **Runtime (userspace)**: The `poe` CLI has its own allowlist check and rejects commands for eth0 or eth2.

There is no configuration option or override to change this.

---

## Warning: Never Force Sysupgrade

**`sysupgrade -F` is forbidden.** The `-F` flag bypasses hardware validation and can brick the device by writing firmware for the wrong hardware. If `sysupgrade` rejects an image with "Device X not supported by this image", the image is wrong for the hardware. Stop and investigate.

Before flashing:

1. Check the device identity: `cat /tmp/sysinfo/board_name`
2. Verify it matches the firmware image target
3. If there is a mismatch, stop. Do not override.

See `AGENTS.md` in the repository root for the complete safety protocol.

---

## Files on the Router

| File | Purpose |
|------|---------|
| `/tmp/er6p-poe.ko` | Kernel module (loaded at boot) |
| `/usr/sbin/poe` | CLI tool |
| `/etc/init.d/poe` | Init script (procd-managed) |
| `/etc/config/poe` | UCI configuration |
| `/usr/sbin/poe-watchdog` | Overcurrent protection daemon |
| `/etc/init.d/poe-watchdog` | Watchdog init script |
| `/usr/sbin/poe-monitor` | Monitoring data export |
| `/etc/init.d/poe-monitor` | Monitor init script |
| `/sys/kernel/er6p_poe/` | Sysfs interface (created by module) |
| `/sys/kernel/debug/er6p_poe/registers` | Debug register dump |
| `/run/poe/` | Monitor output files |

---

## Common Workflows

### Power a MikroTik device on eth1

```bash
poe enable eth1 24v-2pair
```

Wait 30 seconds for the device to boot. Verify link:

```bash
poe status eth1
```

### Power cycle a device

```bash
poe disable eth3
sleep 5
poe enable eth3 24v-2pair
```

### Emergency: kill all PoE

```bash
/etc/init.d/poe stop
```

This disables all ports and unloads the module. To re-enable:

```bash
/etc/init.d/poe start
```

### Check overcurrent events

```bash
logread | grep poe-watchdog
```

If a port was auto-disabled, re-enable it after addressing the cause:

```bash
poe enable eth1 24v-2pair
```
