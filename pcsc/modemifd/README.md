# modemifd — pcscd IFD driver for modem SIM slots (spike, 2026-09-27)

Implements Amperstrand/conwrt-bench #21: exposes the NR7101 (Quectel
RG502Q-EA) SIM slot as a PC/SC reader via a TCP bridge to the modem AT port.

## Pieces (all live on the bench as of the spike)

- Router side (OpenWrt unit, ephemeral — recreate after reboot):
  - `apk add socat`
  - `socat TCP-LISTEN:7002,reuseaddr,fork FILE:/dev/ttyUSB2,raw,echo=0,b115200 &`
  - firewall rule `modemifd-bridge-in` (src=wan, tcp/7002, ACCEPT) — added
- Host side (ai-legion):
  - `/usr/local/lib/libifd-modemifd.so` (built from modemifd.c)
  - `/etc/reader.conf.d/modemifd.conf` (FRIENDLYNAME NR7101_SIM_bench,
    DEVICENAME 192.168.13.124:7002)
  - `/etc/polkit-1/rules.d/49-modemifd-pcsc.rules` (allow group ubuntu:
    access_pcsc + access_card — SSH sessions are not polkit-active seats)
  - pcscd.socket enabled (socket activation)

## Gotchas found (see issue #21 comment for details)

- pcscd requires IFDHSetCapabilities; its header passes the length param
  BY VALUE (DWORD), not by pointer — signature mismatch = build error.
- Static readers are named "FRIENDLYNAME 00 00" — clients must use the
  full name including the channel suffix.
- Keep pcscd under systemd socket activation; manual foreground runs
  trip polkit authorization for non-root clients.

## Proven in the spike (2026-09-27)

- pcsc_scan: reader listed, card present (AT+CPIN? probe), valid T=0 ATR.
- scriptor full APDU round-trip: SELECT MF / SELECT EF.ICCID / READ BINARY
  returned the seated SIM ICCID byte-perfect.
- Raw SELECT of the GSMA ISD-R AID returned 6F00: the operator USIM has no
  eUICC applet; lpac euicc_init failure is card-side, not stack-side.
- lpac (upstream, pcsc+curl backends) builds and enumerates the reader.

## Not yet implemented (see #21)

- Logical channels via AT+CCHO / AT+CGLA / AT+CCHC (currently basic channel
  only via AT+CSIM) — required for eUICC operations against a real eUICC
  card (sysmoEUICC + silent.link download, issue #18).
- Modem idle handling (CFUN/COPS) for long sessions.

## v2 (2026-09-27, same day): reconnect/resync hardening + full test round

Driver v2 adds retry-with-reconnect on empty/failed AT responses (URC
interleave resilience) and presence-probe resync. Router bridge is now a
procd service: /etc/init.d/modem-at-bridge (enabled at boot, respawn).

### Test results (all via the PC/SC path, ai-legion)

- Stability: 25/25 ICCID sessions, 241-720 ms (avg 330 ms) per 3-APDU
  session, zero failures including cold start after daemon restart.
- Basic channel: ICCID byte-perfect; EF.DIR READ RECORD exercised T=0
  61xx GET RESPONSE chaining.
- Logical channels (raw MANAGE CHANNEL passes through AT+CSIM — no
  CCHO/CGLA interception needed): full lifecycle on ch1 proven
  (open -> AID select -> EF select -> read -> clean close). ch2 works.
  ch3 shows a 6F00 quirk on this card/modem — use channels 1-2
  (lpac opens next-available, unaffected).
- Extracted through a logical channel: EF.DIR AID + label "Telenor USIM";
  EF.IMSI decodes to 242013086271211 (Telenor NO).
- Write path: UPDATE BINARY transported correctly; card answered 6982
  (security status) — write transport is stack-proven, permission is
  card-side. CHV1 on this operator card is invalidated (6984 on any
  VERIFY), so write testing completes when a sysmoISIM (known ADM/PIN)
  arrives.
- lpac (upstream, pcsc backend): enumerates the reader; euicc_init fails
  card-side (no ISD-R AID on an operator USIM) — ready for a sysmoEUICC.

### Operational notes

- Card session state PERSISTS across PC/SC sessions (channels/files stay
  selected after SCardDisconnect) — always close channels and re-select
  MF at session start.
- AT-port URC interleave (+CPIN: READY etc.) handled by v2 retry logic.
- Never stack socat listeners; use the procd service only.
