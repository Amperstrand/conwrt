# lpac-openwrt: Updates Based on Session Learnings

## New Target: ramips/mt7621 (NR7101)

The NR7101 uses MediaTek MT7621 (MIPS32, mipsel_24kc). Add this target
alongside the existing aarch64 mediatek/filogic.

### SDK
```
https://downloads.openwrt.org/releases/24.10.1/targets/ramips/mt7621/openwrt-sdk-24.10.1-ramips-mt7621_gcc-13.3.0_musl.Linux-x86_64.tar.zst
```

### Build differences from aarch64
1. Toolchain: `mipsel-openwrt-linux-musl-gcc` (not aarch64)
2. CMake needs: `-DCMAKE_DISABLE_FIND_PACKAGE_Criterion=TRUE` (no test framework for MIPS)
3. **RPATH must be patched**: CMake sets build-dir RPATH; use patchelf to
   set `/usr/lib/lpac` for runtime driver discovery
4. **Driver .so files must be deployed**: lpac uses dlopen-based driver
   loading; the driver .so files go in `/usr/lib/lpac/driver/`
5. PC/SC and curl drivers DON'T cross-compile (host headers leak); use stdio
   drivers and pipe APDUs via the modem's AT port

### Deployed package structure
```
usr/bin/lpac                    # main binary (133KB after patchelf)
usr/lib/libeuicc.so.2          # eUICC library
usr/lib/libeuicc-driver-loader.so.2  # driver loader
usr/lib/libeuicc-drivers.so.2  # drivers library  
usr/lib/liblpac-utils.so       # utilities
usr/lib/lpac/driver/driver_apdu_stdio.so   # stdio APDU driver
usr/lib/lpac/driver/driver_http_stdio.so   # stdio HTTP driver
```

### AT Port Instability (CRITICAL)
The NR7101's modem AT port SHUFFLES across power cycles (ttyUSB2→1→3).
Never hardcode — auto-detect at boot. See conwrt-bench NR7101-FLEET.md.

### CSIM Pacing
RG502Q-EA requires 8+ seconds between AT+CSIM commands. Rapid commands
trigger a thrash state (flood of +CPIN URCs, dropped responses). Recovery
is 15+ seconds idle. This is documented in conwrt-bench #22.

## Recommended build script update
```bash
# Add to build script:
TARGETS="${LPAC_TARGETS:-mediatek/filogic ramips/mt7621}"

for target in $TARGETS; do
    arch=$(echo $target | cut -d/ -f1)
    sub=$(echo $target | cut -d/ -f2)
    # ... download SDK, configure, build
done
```
