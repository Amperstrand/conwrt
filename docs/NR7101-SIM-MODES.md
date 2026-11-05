# NR7101 SIM modes — local eSIM, physical ICE, Android phone SAP

Status: hardware-proven on the Zyxel NR7101 / Quectel RG502Q-EA (2026-11-05).
This is the **deployment guide** for the three supported SIM sources. The
deep eSIM provisioning mechanics live in
[NR7101-ESIM-PLAYBOOK.md](NR7101-ESIM-PLAYBOOK.md) and
[MODEM-AS-READER-PLAYBOOK.md](MODEM-AS-READER-PLAYBOOK.md); the per-run
bench evidence and private identifiers stay in the operator's private
inventory, never here.

The model is the source of truth: `models/zyxel-nr7101.json`, section
`cellular.sim_modes` (three modes) and `cellular.carrier_profiles` (the
carrier/APN/PDP triplets). `conwrt sim` renders and validates those records;
it never writes to a device.

## At a glance

| Mode ID | Card location | Carrier profile | APN / PDP | Use when |
|---|---|---|---|---|
| `local_esim_silentlink` | 9eSIM (ECP3 eUICC) in the modem slot | Telia NO 242/02 (roaming) | `internet` / `ipv4` | silent.link / nadanada profile |
| `local_physical_ice` | physical ice+ card in the modem slot | ice+ NO 242/14 (home) | `ice.net` / `ipv4` | a plain physical SIM, no eSIM tooling |
| `remote_android_sap` | phone SIM, lent over Bluetooth SAP | carrier of the phone SIM (bench: Telia NO 242/02) | `telia` / `ipv4v6` (override as needed) | keep the SIM in the phone; remote access only via SAP |

All three run through the same wwand stack and the same modem. The local
modes put the card in the modem's own slot. The remote mode keeps the card
in the phone and lends it to the modem over Bluetooth; the phone's SAP server
is the card reader.

## Common facts (read before changing a mode)

- **Two SIM slots, one active.** `AT+QUIMSLOT=n` selects the slot. Apply it
  with a **full router power cycle**; a modem-only reset (`CFUN`) is not a
  host power cycle and can strand the wwand bring-up. The model's
  `cellular.sim.select` records this.
- **Local slot vs remote SAP is not the same view.** With wwand's UIM Remote
  active, QMI UIM stays bound to the modem's local slot. Its `pin1_state`,
  ICCID and IMSI describe the **local** card, not the phone's. The AT layer
  is the only view of the remote card. Do not use QMI identity to debug the
  phone SIM's PIN or ICCID.
- **One registration per SIM.** SAP lends the phone's card; while lent the
  phone has no network of its own (wwand-rsim's SAP server handles this).
  Do not add a second data path for the same subscriber while the NR7101 is
  using it.
- **PIN handling.** The local modes delete any stale remote `pincode`. If a
  local card is PIN-protected, provide the PIN through an environment
  variable, never on the command line or in git. The phone SIM's PIN, if
  enabled, is entered by wwand's remote-SIM watchdog after the SAP card
  arrives; it is not transferred by the phone's own unlock.
- **5G is position-dependent.** `modes=lte,nr5g` and `mode_preference 80`
  keep NSA available, but the modem may report LTE at READY and move to NR
  under load. Record the RAT at measurement time, not just the config.
  Band hints use colon-separated LTE band numbers (`QNWPREFCFG`), not
  bitmasks. A band lock disables carrier aggregation.
- **No `sysupgrade` touch.** Flashing OpenWrt does not reset the modem.
  SIM-mode changes are UCI + wwand restart, not reflash events.

## `conwrt sim` — render, validate, do not write

```sh
conwrt sim modes
conwrt sim validate
conwrt sim render local_esim_silentlink
conwrt sim render local_physical_ice --pin-env MY_CARD_PIN
conwrt sim render remote_android_sap
conwrt sim render remote_android_sap --reader 'ssh:rsim@<helper-host>:bt:<phone-bt-address>'
conwrt sim render remote_android_sap --json
```

- `render` prints the UCI plan (`uci -q delete` / `uci set`), the commit,
  `/etc/init.d/wwand restart`, and the verification steps. It does not run
  anything.
- `--pin-env NAME` **names** the environment variable that holds the PIN;
  export `NAME` first. The PIN itself never appears on the command line.
- The **reader spec and SIM PIN are redacted by default**. The plan
  references `$CONWRT_RSIM_READER` and `$CONWRT_SIM_PIN`; export them, or
  pass `--reader` and `--pin-env VAR`. `--show-secrets` prints the real
  values for a private terminal; never redirect that output to a log, an
  issue, or git.
- A remote plan without a reader prints the rest of the commands but exits
  `2` (`missing_secrets: ["rsim_reader"]`). The local plans are ready without
  secrets.
- `--apn` and `--pdp-type` override the carrier profile for a different
  phone carrier or a deliberate IPv4/IPv6 choice.

### Apply safely

1. Render with `--show-secrets` in a private terminal (or export the two
   env vars and use the default plan).
2. On the router, start from a clean baseline: the plan's first command is
   `uci revert network`. This discards uncommitted network staging (aborted
   runs leave debris in `/tmp/.uci` that would otherwise be committed with
   the SIM settings). Do not skip it because the SIM values look correct.
3. Run the `uci` lines on the router. **Read back every value with
   `uci get` before committing** — a quoting mistake turns an APN into a
   literal string. This is the same rule the bench uses for any network
   change.
4. `uci commit network`, then `/etc/init.d/wwand restart`. `wwandctl` may be
   absent for ~5 s after the restart; poll for it rather than declaring
   failure. Before the commit, make sure the independent path from step 5
   is actually usable.
5. **Verify an independent management path before committing.** Use a
   wired-LAN SSH session or the serial console. A SIM-mode commit that
   strands the cellular link survives a PoE power cycle — the router boots
   back into the same committed UCI — so power cycling is not a rollback.
   If neither wired SSH nor serial is available, do not change the mode
   over the cellular link alone. A power cycle is still useful for
   re-initialising the modem after a correct commit.
6. For a local mode, verify `wwandctl status` shows the local SIM and no
   remote-SAP line. For the remote mode, verify the SAP helper is alive and
   the status shows the remote card in use.

## Mode A — local 9eSIM (silent.link / nadanada)

### What you need

- A 9eSIM (ECP3 eUICC) in the modem's active SIM slot.
- The profile installed and enabled. Use
  [NR7101-ESIM-PLAYBOOK.md](NR7101-ESIM-PLAYBOOK.md): the proven APDU
  transport on this modem is **AT** (`LPAC_APDU=at
  LPAC_APDU_AT_DEVICE=/dev/ttyUSB2`), not MBIM.
- The wwand stack installed; `network.wwan0` present.

### Plan

```sh
conwrt sim render local_esim_silentlink
```

The plan deletes `network.wwmodem_auto.rsim_reader` and the stale
`pincode`, sets `network.wwan0.apn=internet` and
`network.wwan0.pdp_type=ipv4`, commits, and restarts wwand. If the 9eSIM has
a PIN, export it and name the variable with `--pin-env NAME`; the plan sets
it (delete it again when the card is removed).

### Verify and pitfalls

- `AT+CPIN?` → `READY`; `AT+QCCID` and `lpac profile list` show the intended
  profile.
- `AT+COPS?` should show Telia 242/02. If it lands on Telenor, this bench
  location is an RX blackhole for that profile; select Telia with
  `AT+COPS=1,0,"Telia",7` and re-check. The model records this in
  `carrier_profiles.silentlink_roaming_no`.
- A 5G-capable profile can still land on LTE. Do not report "LTE-only"
  without a second position/run; the bench cold boot ended on 5G NSA.

## Mode B — physical ice+ card

```sh
conwrt sim render local_physical_ice
```

Insert the ice+ card, run the plan (`apn=ice.net`, `pdp_type=ipv4`), and
verify `AT+COPS?` → ice+ 242/14 (home). The card is the QMI-visible
identity, like the 9eSIM. If the card has a PIN, export it and name the
variable with `--pin-env NAME`; the plan sets
`network.wwmodem_auto.pincode`; the bench card does not.

This mode is the same local-slot path as the 9eSIM; only the carrier profile
differs. The 2026-05-19 ice+ test recorded LTE B3 at 56 Mbit/s; the 5G /
throughput expectations are the same as Mode A on the same modem and
position.

## Mode C — Android phone over Bluetooth SAP

This keeps the SIM in the phone. The NR7101's modem sees it through
wwand-rsim's Bluetooth SAP helper, which may run on the router or on
another machine over SSH.

### Phone state and pairing

1. SIM in the phone; **airplane mode OFF**, **Bluetooth ON**, **Wi-Fi OFF**.
   The phone needs its cellular radio for the SAP server; while the card is
   lent the phone has no network of its own.
2. The phone must expose the **SIM Access Profile (SAP) server**. Stock
   Android has it, but most vendors ship it switched off
   (`profile_supported_sap`); Samsung and some car-oriented phones ship it
   on. The Pixel 10 / Android 17 bench needed a one-time hidden-API grant;
   see the workaround below.
3. Pair the phone with the helper host and trust it:
   ```sh
   bluetoothctl
   [bluetooth]# power on
   [bluetooth]# agent on
   [bluetooth]# default-agent
   [bluetooth]# scan on
   # ... wait for the phone's address to appear ...
   [bluetooth]# pair <phone-bt-address>
   [bluetooth]# trust <phone-bt-address>
   [bluetooth]# quit
   ```
   The phone asks once whether the host may use its SIM; allow it
   permanently. The first connection gives up after 60 s, so answer the
   prompt. The helper host needs BlueZ/RFCOMM; `rsim-card` itself uses kernel
   Bluetooth sockets, not a BlueZ library.

#### Pixel 10 / Android 17: hidden-API grant (bench workaround)

The tested Pixel 10 / Android 17 build enabled the SAP server
(`bluetooth.profile.sap.server.enabled=true`, advertised over SDP) but never
showed the Settings SIM-access prompt. A phone-initiated pairing produced a
clean Secure Connections bond; the SIM-access authorization is a separate
step. The tested shell UID (2000) holds `BLUETOOTH_CONNECT` **and**
`BLUETOOTH_PRIVILEGED`, so a small `app_process` helper can set the same
`IBluetooth` authorization the Settings dialog would grant:

```sh
# SapGrant.java is a ~30-line private-bench helper; it sets the SAP
# permission, it does not touch pairing.
AJ=$ANDROID_HOME/platforms/android-36/android.jar
javac -source 8 -target 8 -classpath "$AJ" -d classes SapGrant.java
$ANDROID_HOME/build-tools/36.0.0/d8 --lib "$AJ" --output dex classes/SapGrant.class
adb push dex/classes.dex /data/local/tmp/sapgrant.dex
adb shell app_process -Djava.class.path=/data/local/tmp/sapgrant.dex \
  /system/bin SapGrant <phone-bt-address> 1
```

Then toggle Bluetooth off/on so the waiting SAP service re-reads the
authorization:

```sh
adb shell cmd bluetooth_manager disable
adb shell cmd bluetooth_manager enable
```

A new RFCOMM connect should log `sap< CONNECT_RESP` and
`SIM access over channel …`; the channel is resolved over SDP and changes
across service restarts — never hardcode it. This is a **workaround for a
platform authorization bug**, not a general fix. Two traps cost time on the
bench: the "contacts and call history" checkbox is **PBAP, not SAP**, and a
stale bond can look like an SAP permission failure (`Authentication Failure
0x05`); replace it with a phone-initiated pairing. The full protocol log and
the helper source stay in the private bench dossier.

4. Keep the Bluetooth address, the reader spec and the SIM PIN in the
   private registry, never in git or an issue.

### Helper host and reader

The wwand-rsim README is the reference for installing `rsim-card`,
`wwandctl rsim` and the restricted SSH key. The short version:

- On the helper host, `rsim-card` must be in `PATH` and the phone paired and
  trusted. A dropped SAP link ends the helper; the modem gets its local SIM
  back and wwand retries.
- On the donor, the reader spec is
  `ssh:<user>@<helper-host>:bt:<phone-bt-address>`. Create the donor's key
  and print the restricted `authorized_keys` line with
  `wwandctl rsim ssh-key <user>@<helper-host>`; append that line to the
  helper user's `authorized_keys`. It runs `rsim-card --serve` for the
  listed reader (and its own `--list`) and nothing else.
- Verify the SAP path independently first (`rsim-card --list`,
  `wwandctl rsim scan <user>@<helper-host>`), then wire the donor.

### Plan

```sh
export CONWRT_RSIM_READER='ssh:rsim@<helper-host>:bt:<phone-bt-address>'
conwrt sim render remote_android_sap
# or, for a private one-off:
conwrt sim render remote_android_sap \
  --reader 'ssh:rsim@<helper-host>:bt:<phone-bt-address>' --show-secrets
```

The plan sets `network.wwmodem_auto.rsim_reader`, sets the PIN only if you
provide it (`--pin-env`/`CONWRT_SIM_PIN`), sets `network.wwan0.apn=telia`
and `pdp_type=ipv4v6`, commits, and restarts wwand. Override the APN for a
different phone carrier: `--apn <carrier-apn>`.

### Verify

- `wwandctl status` shows the remote SIM in use; the phone's Bluetooth
  settings show the SAP connection active.
- `AT+CPIN?` shows the remote card's state; QMI UIM still reports the local
  slot. If the phone SIM has a PIN, the wwand watchdog enters the configured
  PIN after the card arrives; the phone's own unlock does not carry over.
- `AT+COPS?` shows the phone carrier; `ping -I wwan0 -c 3 1.1.1.1` passes.

### Cold boot and throughput (2026-11-05 bench)

Power off, carrier down, power on, measure to first useful data:

| Phase | Local 9eSIM | Phone SAP |
|---|---:|---:|
| PoE on → Ethernet link | 8.402 s | 8.250 s |
| → donor SSH | 46.494 s | 48.782 s |
| → SIM/helper ready | 60.671 s | 60.275 s |
| → first ping | **63.681 s** | **113.895 s** |

Both runs ended on **Telia 242/02 5G NSA**. The SAP chain adds roughly 50 s
of boot latency (helper + SAP + APDU + PIN), not a throughput penalty:
Cloudflare 50 MB measured **92.3/12.2 Mbit/s v4** on the local 9eSIM and
**86.8/12.2 Mbit/s v4**, **77.4 Mbit/s v6** on the phone SAP. The phone path
reported LTE at READY and moved to NR under load; record the RAT.

### Stale-helper recovery

A helper started by a donor over SSH can outlive the donor's power-off: its
stdin channel is still open, it keeps the phone's RFCOMM channel, and the
next wwand start fails with `Device or resource busy`. The 2026-11-05 run
reproduced this; the helper ignored `SIGTERM` and needed `SIGKILL`.

On the helper host, find the stale helper and verify its parent before
killing **only** that PID:

```sh
ps -eo pid,ppid,etime,args | grep '[r]sim-card'
# confirm the parent is the expected sshd and the age matches the old session
kill <pid>
kill -9 <pid>          # only if it does not exit
```

Do not use `pkill -f`/`killall` on a shared host: other sessions' helpers are
indistinguishable in `ps`. Then restart wwand on the donor
(`/etc/init.d/wwand restart`) and wait for the new helper. If the phone
still holds the old RFCOMM channel, toggle the phone's Bluetooth or reboot
it; the stale helper must be gone first. A helper-side fix (exit on
stdin EOF / bounded heartbeat) is the durable fix; the lifecycle is tracked
in the private bench issue, not in this public doc.

## Troubleshooting

| Symptom | Check | Action |
|---|---|---|
| `wwandctl` missing just after restart | it can take ~20 s to appear | poll; do not reflash |
| Modem READY but no data | `wwandctl status`, `AT+COPS?`, APN readback | fix APN/PDP; restart wwand; power-cycle |
| Phone SAP busy | stale `rsim-card` on helper host | verify parent sshd, kill only that PID, retry |
| Phone not offering SAP | vendor `profile_supported_sap` off; permission | enable the SAP profile / grant permission (device-specific) |
| silent.link on Telenor, no RX | carrier selection | `AT+COPS=1,0,"Telia",7` |
| 5G advertised but LTE only | position / RAT at measurement | retest after moving; do not assume LTE-only |
| PIN rejects | wrong PIN or retry counter | stop; verify with the operator; do not burn retries |
| Local card PIN set | stale `pincode` from an old remote setup | local plan deletes it; or set via `--pin-env` |

## Legacy `conwrt esim` — deprecated

`scripts/conwrt/esim.py` is the legacy MBIM provisioning path. It is
deprecated and will be removed:

- The proven APDU transport on this modem is AT, not MBIM. The playbooks
  above document the AT path.
- `AT+CFUN=1,1` has been removed from the module. A modem-only reset is not
  a host power cycle and can strand wwand; the legacy flow now sets the USB
  mode/APN and asks for an explicit router power cycle.
- `conwrt esim status` still works as an AT-only read. `profiles`,
  `provision` and `switch` are the legacy MBIM one-shot flow; prefer the
  playbook + `conwrt sim` for the three supported modes.

## Model, validation and tests

```sh
conwrt sim validate          # 3 modes, 3 carrier profiles, no identifiers
conwrt sim modes             # the table above
conwrt sim render <mode>     # the plan; no device access
```

The validator rejects: a missing required mode, an unknown carrier profile,
a local mode that sets `rsim_reader`, a remote mode without a placeholder
reader, a CFUN reset in a UCI value, a PDP type outside
`ipv4|ipv6|ipv4v6`, a 19–20 digit identifier, and a real-looking MAC. The
unit tests are in `tests/test_sim_modes.py`.

## Related

- [NR7101-ESIM-PLAYBOOK.md](NR7101-ESIM-PLAYBOOK.md) — eSIM download/enable
  through the modem's own reader (9eSIM, silent.link, nadanada).
- [MODEM-AS-READER-PLAYBOOK.md](MODEM-AS-READER-PLAYBOOK.md) — the
  species-agnostic reader/provisioning mechanics.
- [wwand](https://github.com/ddimension/wwand) and
  [wwand-rsim](https://github.com/ddimension/wwand-rsim) — the QMI/wwand
  stack and the reader plugin, including the SAP phone details.
