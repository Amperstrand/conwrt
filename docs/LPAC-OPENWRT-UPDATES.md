# lpac-openwrt: Updates Based on Session Learnings

## New Target: ramips/mt7621 (NR7101)

The NR7101 uses MediaTek MT7621 (MIPS32, mipsel_24kc). Add this target
alongside the existing aarch64 mediatek/filogic.

### SDK
```
https://downloads.openwrt.org/releases/25.12.4/targets/ramips/mt7621/openwrt-sdk-25.12.4-ramips-mt7621_gcc-14.3.0_musl.Linux-x86_64.tar.zst
```
Verify against `…/targets/ramips/mt7621/sha256sums` before extracting.
(24.10.1 / gcc-13.3.0 still works — pick the SDK that matches the image you
deploy to.)

### Build differences from aarch64

1. Toolchain: `mipsel-openwrt-linux-musl-gcc` (not aarch64).
2. CMake needs `-DCMAKE_DISABLE_FIND_PACKAGE_Criterion=TRUE` (no test
   framework for MIPS).
3. **Suppress the RPATH, don't patch it.** Upstream's top-level
   `CMakeLists.txt` sets `CMAKE_INSTALL_RPATH` *after* the toolchain file has
   had its say, so a toolchain-level `CMAKE_SKIP_RPATH` is silently overridden
   and the binary ends up with `/usr/lib/lpac`. Pass all three on the **cmake
   command line**:
   `-DCMAKE_SKIP_RPATH=ON -DCMAKE_SKIP_BUILD_RPATH=ON -DCMAKE_SKIP_INSTALL_RPATH=ON`
4. **Add `-static-libgcc`.** The first link otherwise records
   `NEEDED libgcc_s.so.1`, which the target image does not ship.
5. **Prefer a single static ELF over the driver-`.so` layout.** With
   `-DLPAC_WITH_APDU_AT=ON -DLPAC_DYNAMIC_LIBEUICC=OFF
   -DLPAC_DYNAMIC_DRIVERS=OFF` (and the PCSC/MBIM/QMI/curl backends OFF) the
   output is one binary whose only `NEEDED` entry is `libc.so` — no
   `libeuicc*.so`, no `/usr/lib/lpac/driver/`, no patchelf step. This is the
   right shape for `/overlay`-constrained species (see the verified result
   below). The older patchelf + driver-`.so` recipe in this file was written
   for the dynamic build; use it only if you specifically need dlopen'd
   drivers.
6. PC/SC, MBIM, QMI and curl backends are switched off explicitly: they do not
   cross-compile cleanly and are not needed for the modem AT path.

### Verified result (2026-11-26, 25.12.4 / gcc-14.3.0)

| file | bytes | sha256 |
|---|---|---|
| `lpac` (unstripped) | 126240 | `e09cb3dc93a2f17b792d53ea686e722f55f9fdf2ec7820c10ffc273cd14f1e44` |
| `lpac` (stripped, **deploy this**) | 77288 | `2eb6673a12ddf1272ff700c060677b62e6c2bd79662e9e603efa223ef1b5fe11` |

`readelf -d`: `NEEDED` = `libc.so` only. No RPATH/RUNPATH, no TEXTREL.
Interpreter `/lib/ld-musl-mipsel-sf.so.1` (present in the image).
`nm`: `driver_apdu_at` and `at_expect` present; zero `pcsc|mbim|qmi|curl`
symbols. Runs natively on the router: `lpac version` → `code:0`,
`lpac driver list` → `{"LPAC_APDU":["at","stdio"],"LPAC_HTTP":["stdio"]}`.

Source hashes used: SDK `03f4766fcfbae86a814cbbf194226fa7e9ec66be2d4273bc1a0927a72a43a333`,
lpac `v2.3.0` codeload tarball `661dffbd1e9e5732dab4a0bb0a9837d4906c8c66bd748bda262fe3e8d3e420f6`
(identical to the `PKG_HASH` in `openwrt/packages` `openwrt-25.12 utils/lpac`).

The upstream feed package (`lpac 2.3.0-r1`, in the **generic
`packages/mipsel_24kc`** feed — *not* the target feed) also works, but its
metadata depends on `libcurl4`, `libpcsclite`, `pcscd` and `libmbim` because
the feed build enables every backend. On an image without those, either
side-load all four dependencies or use the AT-only build above.

### Deployment

`scp -O` (dropbear has no sftp-server) the binary to `/tmp`, `chmod 755`,
verify the remote `sha256sum`, then run it. `/tmp` is tmpfs — it survives
nothing, so re-stage after a reboot. Overlay headroom on this species is a few
MB, so install to `/usr/bin` only when you intend to keep it.

## AT Port Instability and How to Identify the Port

The NR7101's modem AT port SHUFFLES across power cycles
(observed 2 → 1 → 3 → 2). Never hardcode — detect.

`/sys/class/tty/ttyUSB*/device/interface` (the friendly name) is **absent** on
25.12.x, so the usable discriminator is the interface protocol of the parent
USB interface:

```sh
for t in 0 1 2 3; do
  d=/sys/class/tty/ttyUSB$t/device
  printf 'ttyUSB%s num=%s proto=%s\n' "$t" \
    "$(cat $d/../bInterfaceNumber 2>/dev/null)" \
    "$(cat $d/../bInterfaceProtocol 2>/dev/null)"
done
```

RG502Q-EA layout on a healthy unit: `proto=30` (diag), `proto=40` (NMEA/GPS),
and the AT port is one of the `proto=00` interfaces. Do **not** conclude from
protocol alone — confirm with a real `AT` round trip, and treat "no reply" as
"wrong port", not "dead modem".

Liveness/port probe (also a full Gate-0 read):

```sh
LPAC_APDU=at LPAC_APDU_AT_DEVICE=/dev/ttyUSBx /tmp/lpac chip info
```

## Card State, Not Card Fault: the Placeholder ICCID

An eUICC with **no enabled profile** answers the ICCID query with a placeholder
and shows an empty `profile list`. That is a **wiped/empty profile store, not a
dead card** — the ISD-R is usually healthy. Gate 0 distinguishes the two and
needs no writes:

```sh
LPAC_APDU=at LPAC_APDU_AT_DEVICE=/dev/ttyUSBx /tmp/lpac chip info     # EID, EUICCInfo2, free NVM
LPAC_APDU=at LPAC_APDU_AT_DEVICE=/dev/ttyUSBx /tmp/lpac profile list  # data: [] == empty store
```

Read both **before and after** any session and compare. A healthy 9eSIM with an
empty store reports `rspCapability` including `testProfileSupport`, a
`rulesAuthorisationTable`, and — on an evaluation card — a **test** root DS
address. Check which DS you are pointed at before downloading anything.

## Missing Busybox Applets on 25.12.x (operational traps)

Verified absent on a stock 25.12.4 ramips/mt7621 image: **`stty`**, **`timeout`**,
**`socat`**, **`microcom`**. `opkg` is gone — the package manager is **`apk`**.
Fractional `read -t 0.5` is rejected (`ash: read: line 0: invalid timeout`).

Consequences:

- The `ssh://` exec transport in `docs/NR7101-ESIM-PLAYBOOK.md` runs
  `stty -F <tty> raw -echo` on the router. **That cannot work here** — see
  issue #856.
- There is **no `timeout(1)`**, so anything that can block must be wrapped in a
  hand-rolled watchdog:

```sh
( CMD >/tmp/o 2>&1 & p=$!; i=0
  while kill -0 $p 2>/dev/null && [ $i -lt 30 ]; do sleep 1; i=$((i+1)); done
  kill $p 2>/dev/null; sleep 1; kill -9 $p 2>/dev/null
  echo "elapsed=${i}s" ) ; cat /tmp/o
```

- Kill only processes you started, by PID from your own pidfile — `pkill -f` on
  a shared host also matches your own shell's command line.
- Before blaming the card or the tool, check for a leftover holder of the AT
  tty (`fuser /dev/ttyUSB2`, `ps w | grep lpac`). An orphaned `cat /dev/ttyUSBx`
  from an earlier session is enough to make every later attempt fail.

## CSIM Pacing

RG502Q-EA requires 8+ seconds between `AT+CSIM` commands. Rapid commands
trigger a thrash state (flood of `+CPIN` URCs, dropped responses, and
`+CME ERROR: 0` on perfectly valid APDUs). Recovery is 15+ seconds idle.
This is documented in conwrt-bench #22.

**Do not diagnose the card from an error seen during thrash.** Drain the port,
wait 15 s, retry once. `ERROR` / `+CME ERROR: 0` immediately after a burst is a
spacing symptom; an ISD-R that does not answer with correct spacing is a real
finding.

Also: more than one AT command written down a single open fd produces
echo-driven `ERROR` storms on this firmware. One command per fd, or a relay that
genuinely disables echo.

## `lpac` Help Is Not Inert

`lpac <subcommand> --help` performs a full eUICC init (open the APDU device,
select ISD-R) *before* printing usage, so it **can hang forever** on a
contended or wrong AT port. On a target with no `timeout`, that strands the
modem lane and leaves a process holding the tty. Get the backend env var from
`lpac driver list` instead, and always wrap sub-command invocations in the
watchdog above. See issue #857.

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
