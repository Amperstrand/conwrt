# W0-6 Regression Test Report

**Date:** 2026-05-20
**Router:** 192.168.X.X (Edgerouter-6P)
**SSH Key:** ~/.ssh/REDACTED_KEY
**Test:** Wave 0 Task W0-6 - Regression check for gpio-reg.ko and GPIO17 toggle

## Test Objective

Verify that:
1. gpio-reg.ko module is still loaded
2. GPIO17 toggle (blue:power LED) still works
3. Final state equals initial state
4. No kernel oops

## Test Evidence Files

- `lsmod.txt` - Module loading status
- `initial-state.txt` - Initial GPIO state before testing
- `final-brightness.txt` - Final LED brightness after toggle
- `dmesg-tail.txt` - Kernel messages
- `sysfs-gpio-17.txt` - GPIO 17 sysfs interface state

## Test Results

### 1. Module Loading Status

**Command:** `lsmod | grep gpio`
**Result:** ✓ PASS

```
gpio_button_hotplug    16384  0
gpio_reg               12288  0
leds_gpio              12288  0
```

**Conclusion:** gpio-reg.ko module is loaded.

### 2. GPIO17 Initial State

**Command:** `cat /sys/class/leds/blue:power/brightness`
**Result:** 1 (ON)

**Observation:** GPIO 17 is mapped to the blue:power LED and is currently ON.

**File:** `initial-state.txt`

### 3. GPIO17 Toggle Operations

**Command:** `echo 0 > /sys/class/leds/blue:power/brightness` (OFF)
**Result:** ✓ PASS (brightness = 0)

**Command:** `echo 1 > /sys/class/leds/blue:power/brightness` (ON)
**Result:** ✓ PASS (brightness = 1)

**Observation:** LED successfully toggled off and back on. LED is a controlled by the LED subsystem (not directly by gpio-reg.ko), but gpio-reg.ko is responsible for exposing the underlying GPIO 17.

### 4. Final State Verification

**Initial State:** brightness = 1 (ON)
**Final State:** brightness = 1 (ON)

**Result:** ✓ PASS - Final state matches initial state.

**File:** `final-brightness.txt`

### 5. Kernel Error Check

**Command:** `dmesg | tail -50`
**Result:** ✓ PASS - No kernel oops

**Key gpio-reg messages:**
```
[14777.154975] gpio-reg: WRITE offset=0x188 value=0x0
[14822.278685] gpio-reg: WRITE offset=0x88 value=0x0
[14880.433645] gpio-reg: WRITE offset=0x90 value=0x1
```

**Observation:** All write operations succeeded without errors.

**File:** `dmesg-tail.txt`

## Notes

- gpio-reg.ko provides two interfaces:
  1. `/proc/gpio-reg/summary` - Read-only overview of GPIO registers and BIT_CFG
  2. `/proc/gpio-reg/bit_cfg/N` - Per-pin BIT_CFG register (N=0..19), read-only
  3. Write interface on `/proc/gpio-reg/summary` - Write register values at specific offsets

- The actual LED control is done through the LED subsystem at `/sys/class/leds/blue:power/brightness`, not through gpio-reg.ko directly.

- GPIO 17 (blue:power) is exposed via the gpio-reg.ko BIT_CFG interface and the LEDs GPIO subsystem.

## Summary

| Test Item | Result | Details |
|-----------|--------|---------|
| gpio-reg.ko loaded | ✓ PASS | All required modules present |
| GPIO17 toggle works | ✓ PASS | LED successfully toggled off/on |
| Final = Initial state | ✓ PASS | brightness restored to 1 |
| No kernel oops | ✓ PASS | dmesg shows no errors |

## Conclusion

**STATUS: ✓ PASS**

All regression checks passed. The gpio-reg.ko module is loaded, GPIO17 toggle functionality works correctly, and the final state matches the initial state with no kernel errors.

## Files Generated

- `recipes/ubiquiti/edgerouter-6p/test-evidence/wave-0/w0-6-regression/lsmod.txt`
- `recipes/ubiquiti/edgerouter-6p/test-evidence/wave-0/w0-6-regression/initial-state.txt`
- `recipes/ubiquiti/edgerouter-6p/test-evidence/wave-0/w0-6-regression/final-brightness.txt`
- `recipes/ubiquiti/edgerouter-6p/test-evidence/wave-0/w0-6-regression/dmesg-tail.txt`
- `recipes/ubiquiti/edgerouter-6p/test-evidence/wave-0/w0-6-regression/sysfs-gpio-17.txt`
- `recipes/ubiquiti/edgerouter-6p/test-evidence/wave-0/w0-6-regression/regression-report.md` (this file)
