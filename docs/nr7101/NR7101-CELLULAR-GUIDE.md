# NR7101 Cellular Guide — the conwrt way (species-level, bench-proven 2026-11)

Port target: `conwrt/models/zyxel-nr7101.json` hints + `conwrt/docs/`.
Everything below was proven live on bench units (conwrt-bench evidence
links inline). Apply on a clean branch cut from origin/master.

## 0.1 The complete wwand deployment recipe (all pieces, 2026-11-04)
1. Fork: Amperstrand/wwand@feat/nr7101-rg502q (one patch: CTL
   GET_VERSION_INFO timeout treated as best-effort — this firmware
   never answers it; quectel-CM never asks, which is why it worked).
2. Build: conwrt-bench NR7101-WWAND-SDK-BUILD.md (SDK needs ucode
   host+target + json-c staged by hand; dep-check failure is benign —
   take the staged tree).
3. Deploy ALL of: the wwand tree, the **datapath_rmnet_nss.uc add-on
   into /usr/share/ucode/wwand/** (REQUIRED — without it wwand picks
   raw_ip on the vendor parent and traffic silently dies; it adopts
   the driver's pre-made QMAP child instead), libucode.so.0 (image
   ucode is static), struct.so, the vendor kmod+CM fallback trees,
   and the /etc/hotplug.d/usb/30-vendor-qmi rebind script.
4. Configure: nothing — autosetup detects modem+SIM; add per-card
   `config wwand_sim` sections (iccid → apn/name; pdp_type ipv4 for
   v6-disallowing roaming profiles). PLMN pin: wwand_modem mcc/mnc;
   RAT pin: modes lte (NR5G roaming registration can stall).
5. Verify: wwandctl status (state CONNECTED, SIM named) + ping -I
   wwand0. Reference numbers: 45.7 Mbit/s, 63 ms flat, cold-boot
   zero-touch, both cards (silent.link/Telenor roaming + ICE home
   dual-stack).

## 0. THE RECOMMENDED STACK (decided 2026-11-04, bench-proven)
**wwand from our fork** (Amperstrand/wwand@feat/nr7101-rg502q): the
GET_VERSION_INFO quirk patch makes it fully drive this modem. Cold
boot → zero-touch data on both test cards; 23 Mbit/s burst measured;
survived reboots/reflashes/SIM flips. Build: conwrt-bench
NR7101-WWAND-SDK-BUILD.md. Config: wwand_modem + per-ICCID wwand_sim.
quectel-CM+vendor-kmod remains the proven FALLBACK (one command);
ECM remains the simplest data path. The stacks below are the menu;
wwand is the default.

## 1. Connection stacks (four, pick by firmware behavior)

| Stack | Config (the OpenWrt way) | When | Status on RG502Q/25.12.6 |
|---|---|---|---|
| ECM | `proto dhcp` on `usb0` (modem auto-dials; set APN once via AT+CGDCONT) | Simplest data path; self-healing | PROVEN (57.1 Mbit/s, 24h+) |
| Stock QMI | `proto qmi`, `device /dev/cdc-wdm0`, `apn`, `auth`, `pdptype` (luci-proto-qmi; uqmi) | Default OpenWrt path | CTL DEAD on this firmware (uqmi client cannot handshake) |
| Vendor QMI | `proto quectelcm` (luci-proto-quectelcm + kmod-qmi_wwan_q + quectel-CM) | Performance/control: QMAP, routed IP, full QMI services | PROVEN (routed /27, 19-36 ms flat) |

Vendor-stack gotchas (all bench-proven):
- **Bind race**: stock qmi_wwan claims the device; ship a hotplug
  script that rmmods it and binds qmi_wwan_q on USB add (boot
  persistence — proven across cold boot).
- uqmi stays dead even under the vendor driver; use quectel-CM.

## 2. SIM slot selection (dual-card benches)

- Vendor AT (proven): `AT+QUIMSLOT=1|2` then `AT+CFUN=1,1`, wait ~3
  min, verify with `AT+QCCID`. Single-active radio: both cards may be
  seated; one is active. 2 ops per flip — timelock them.
- Stock-QMI alternative: `uqmi --uim-slot` (dead on this firmware).
- ModemManager alternative: mmcli SIM slots.

## 3. eSIM / eUICC profiles

- Tool: lpac (feed package exists; official 25.12 stdio backend is
  broken per community — use patched builds or build from source).
- **APDU transport choice is the whole game** (wwand pattern:
  QMI UIM → MBIM UICC → AT fallback). On this firmware: QMI/uqmi
  transports dead; **AT driver works** (`LPAC_APDU=at
  LPAC_APDU_AT_DEVICE=/dev/ttyUSB2`). Loader requires the
  `/usr/local/lib/lpac/driver/` layout with RPATH baked — flat
  copies into /usr/lib break driver discovery.
- Proven ops: profile list, nickname read/write. Card-as-state
  pattern: store provider credentials in the profile nickname
  (`sl|T=<token>`) — the card then self-identifies.
- LuCI options (community): luci-app-esim (rpcd + esim-ctrl CLI),
  luci-app-5gmodem (dual-SIM + eSIM, patched lpac builds), wwand
  (connection manager with native ES10c).

## 4. Band selection (no uci-native option; three ways)

- Vendor AT (proven on this modem): `AT+QNWPREFCFG="lte_band",<mask>`
  where mask = 1<<(band-1): B3=4, B7=64, B8=128, B20=524288. Some
  builds need CFUN re-init after the write (verify with AT+QNWINFO;
  landing must be VERIFIED before spending data). Band lock disables
  CA — lock only single-band tests or providers with one capacity
  band (e.g. ICE: B3-only is free; Telenor: leave auto for B3+B7 CA).
- Stock-QMI: uqmi NAS band-preference flags (client dead here).
- ModemManager: `mmcli --set-current-bands`.
- Per-provider preferred bands belong in data (providers.json), not
  prose — tooling applies them idempotently.

## 5. Provider knowledge as data (providers.json)

Per provider: APN, ICCID prefix, quota-check method (API/USSD/app +
plan semantics — e.g. ICE: 128 kbit/s overage throttle, datapakke
24h-from-first-use), preferred band, heartbeat. Verify the bucket
BEFORE speedtesting.

## 6. Verification taxonomy (verify.sh classes)

ECM no-data / QMI no-data / POLICED BEARER (plain ping passes, sized
ping + TCP die — cap/throttle enforcement; do not debug the network)
/ detach-loop (CEER) / route-missing. Speed tests: `curl -4` only
(busybox fetcher v6-selection false-fails; by-IP breaks vhosts).

## 7. Standing hazards (all bench-proven)

- NEVER set MTU explicitly (Quectel QMI fragmentation bug; MBIM MTU
  lock). Leave 1500/untouched.
- Retry loops are the outage class — timelock all modem ops
  (modem-budget.sh pattern: N/day, min-gap, failure cooldown).
- Mode switches (usbnet) are PoE-class events.
- Don't scatter tarball libs into apk-managed dirs (breaks apk
  self-repair; apk-v3 packages are not tar.gz).
- sysupgrade resets the router, NEVER the modem (separate computer).
