# ZTE MF286D — No-Serial Exploitation & Tool Research Log

Working log for getting root / OpenWrt onto MF286D **without serial**. Companion to
`notes.md` (hardware/partition baseline). Provenance per section: **[DUMP]** = verified
against Telia-unit rootfs in `data/zte-mf286d/rootfs`; **[COMM]** = community, unverified;
**[TOOL]** = to verify on bench.

## 1. Attack surface from our own dump [DUMP]

Web server: **GoAhead** (`/usr/bin/goahead`) serving the ZTE goform API.

### telnetd is already running
- `etc/init.d/zte_init.sh:175` starts `telnetd &` **unconditionally** at boot
- Listens on **tcp/4719** (`sbin/telnet_log.sh`: "telnetd listening port is 4719")
- Gated by firewall, not by the daemon: `sbin/firewall_sys_fw.sh` inserts a DROP for
  4719 on LAN when `nv get telnet_lan_enable == 0`; WAN side has a whitelist mechanism
  (`wan_telnet_port_white` default 4719, `src_ip_start/end` ACCEPT rules — ZTE remote
  support path)
- ⇒ any command-injection or firewall-opening primitive immediately yields a root shell
  on 4719 (telnetd has no real auth: `/bin/login.sh`)

### CHANGE_MODE goform handler = backdoor machinery [DUMP]
Strings in goahead confirm the asiantuntijakaveri (2017, MF286) factory backdoor exists
in this build:
- `zte_goform_mgmt_change_mode_process`, `change_mode=1` → `start telnetd=0`, literal
  `telnetd &`
- Literal firewall bypass inside goahead: `iptables -t filter -I INPUT -p tcp --dport
  4719 -j ACCEPT` (+ udp variant)
- `SwitchFactoryMode`, `FactoryResult:Opened/Closed/Success/Failed`, `deviceImei`, `imei`
- Suspicious hardcoded values: **`login_9527`**, **`onceuponatimeinparadise`** (likely
  engineer/backdoor magic — 9527 is a recurring ZTE service value). Blog says the
  CHANGE_MODE password is RSA-encrypted IMEI; these strings suggest alternates. [TOOL]
- Build path leak: `../MF286DH3G_SE/...` (shared Three UK codebase)

### Other goform handlers of interest [DUMP]
`ONLINE_UPGRADE_TOOL`, `AUTO_UPGRADE`, `FOTA_SETTINGS`, `RESTORE_FACTORY_SETTINGS(_FORPST)`,
`PSTDownLoadFlagSet`, `URL_FILTER_ADD/DELETE/FLAG`, `SET_NETWORK`, `SET_CONNECTION_MODE`
- `ONLINE_UPGRADE_TOOL` is likely what the Windows "ZTE framework" conversion tool drives
- This build's URL_FILTER_ADD handler sends "MESSAGE TO MC" (IPC to another daemon), not
  directly to shell — the 2016 nvram-shell injection may be fixed at the web layer; the
  receiving daemon is the remaining injection candidate [TOOL]

### Web-UI credentials [COMM]
- Engineer login `Root` / `mbl_2019_SoL` (MF286R method) — **not present in Telia dump**;
  may exist in other variants [TOOL]
- Conversion packages imply per-variant known passwords ("pw admin" on Nordic B11 at
  192.168.32.1; "pw del wifi" for Elisa at 192.168.100.1; Three-to-OpenWrt expects
  192.168.1.1)

## 2. DHCP injection idea — analyzed [DUMP: unlikely]

Audited `usr/share/udhcpc/default.script` and `sbin/udhcpc.sh` (used in
`opms_wan_mode=AUTO_BACKUP` — the ethernet-WAN backup mode, so a rogue DHCP server CAN
feed these if that mode is on):
- All DHCP-supplied values (`$ip $subnet $router $broadcast`, classless static routes)
  are passed **unquoted but as argv** to BusyBox applets (`ifconfig`, `route`) or to the
  `nv set` binary — no `eval`, no shell command strings, no resolv.conf script injection
  found in default.script
- BusyBox applets parse argv without invoking a shell ⇒ `;`/backtick payloads die as
  invalid arguments
- Verdict: **classic post_up-style injection does not land**. If we enable WAN-eth mode
  on the bench anyway, a 10-minute empirical fuzz of options 12/15/119/249 with shell
  metachars costs nothing [TOOL]

## 3. The Windows "ZTE framework" tool [TOOL → largely triaged this session]

Artifact: `data/zte-mf286d/Three to Openwrt zte mf286d 192.168.1.1 pw ---.zip`
(407,315,425 B, sha256 `f3ab22f2c585ee50f24c850bcc1f362fb610f2eb696f05b84f513cdbb7246062`,
from Hecatae's mega link, OpenWrt forum t/151965). Extracted to `framework/` (143 files).

### Identification
- Main binary: **`ZTE_Sales_Update_Framework.exe`** — official ZTE "Terminal Software
  Update Framework" (ZTSUF V1.0.1B02), the carrier-shop flashing tool. Repackaged by the
  community with a custom `UPDATE/` folder (original `app.config.ini` still points at
  `E:\Play to Nordic zte mf286d 192.168.32.1 pw ---\UPDATE`).
- Components: `QMSL_MSVC10R/6R.dll` (official Qualcomm MSM Software Load), 
  `SLA_Challenge.dll` (QC secure-boot challenge), ADB (`AdbWinApi/UsbApi.dll`),
  `libcurl.dll` + `cndms.ztems.com` self-update endpoint, `InstallZAS.exe`,
  `UsbDeviceManager.exe`, `zsrst.exe`, `file_aut.exe`
- Flash payload in `UPDATE/`: **`root_uImage` + `SHA256SUMS`** (main CPU) + full modem
  MDM9650 set (`contents.xml` manifest w/ fastboot partition map, `ENPRG9x55.mbn`
  firehose programmer, `appsboot.mbn`, `mdm9650-*.ubi`, `partition.mbn`) + `FOTA_FS/*.tgz`

### Key finding: NO signature on root_uImage in this path
`SHA256SUMS` contains exactly one line (sha256 of `root_uImage`). The download-mode flow
integrity-checks with a plain sha256sum, not the openssl chain (that chain gates the OTA
`image.zip` path only, per `update_control` RE). ⇒ **any custom OpenWrt `root_uImage` +
regenerated `SHA256SUMS` should flash through this tool.** [TOOL: verify]

### Community patch
`Plugins/BL_DL_LTE_QualComm_Net.dll` (+459,776 vs 456,192 B) and
`Plugins/BI_LTE_Qualcomm.dll` are patched vs their `.bak` originals (~410k / ~46k
differing bytes; patch is compiled code — no string-level diff). Likely retargets the
tool (device IP/version/signature acceptance). Disassembly pending.
The `.bak` files preserve the originals — diff target for RE.

### Safety triage (static)
- Executables: PE32, Authenticode-signed ZTE binaries (only embedded URLs are
  thawte/verisign CRL endpoints — no C2/downloader indicators)
- Network egress risk: `cndms.ztems.com` self-update — **must be blocked at runtime**
- Patched DLLs are unsigned by definition (modified) — treat whole package as untrusted
- No execution outside a disposable container (see below)

### Container execution plan (docker + wine available on this host)
```
docker run --rm -i \
  --user 1000:1000 \
  --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges \
  --network <bench-macvlan>            # reaches device only; DNS/blackhole for ztems.com
  -v $PWD/framework:/work:ro \
  -v $PWD/wine-work:/home/user        # only writable path
  wine ZTE_Sales_Update_Framework.exe
```
- Wireshark on the host side of the bench NIC for protocol capture (goal: reimplement,
  not rerun — the zycast pattern)
- `docker diff`/pre-post export to observe side effects
- Wine prefix in a tmpfs; snapshot container filesystem before first run

## 4. Bench priority list (no-serial)

1. Web UI at 192.168.0.1: identify operator variant + firmware version (decides
   passwords/backdoors)
2. One-curl tries, in order (all harmless if they fail):
   a. Engineer login `Root`/`mbl_2019_SoL` then `exploit.dat` update path (MF286R method)
   b. CHANGE_MODE factory backdoor variants incl. `login_9527` /
      `onceuponatimeinparadise` magic [needs strings-context RE first]
   c. URL_FILTER_ADD `&&telnetd&&` injection (2016 method)
3. Any success → telnet 4719 → **immediately back up mtd1 (ART), mtd2 (mac), mtd4
   (cfg-param) + full set via tftp** → private inventory
4. From root: OpenWrt install without serial = `nandwrite`/mtd write to kernel+rootfs
   (never touch SPI NOR mtd12–19; U-Boot blank-TFTP fallback at 192.0.0.1/8 is the
   no-serial safety net)
5. If all injections fail: run/reimplement the ZTE framework tool path (§3)

## Session artifacts

- `data/zte-mf286d/Three to Openwrt zte mf286d 192.168.1.1 pw ---.zip` — 388.4MB
  (sha256 recorded after completion)

## 5. Other options researched (2026-11-02)

### webFac factory protocol — NOT present in our build [DUMP]
`douniwan5788/zte_modem_tools` (`zte_factroymode.py`) implements ZTE's factory-mode web
backdoor for ZXHN GPON devices: POST `/webFac` (`RequestFactoryMode.gch`, `SendSq.gch?rand=N`),
then AES-ECB-encrypted commands to `/webFacEntry` (`CheckLoginAuth.gch`, `Factorymode.gch?mode=2`)
— key = 24 bytes from a hardcoded pool indexed by rand-derived position, XOR 0xA5.
Success returns telnet credentials. Requires ISP factory-account user/pass (Chinese ISP
defaults listed in the tool).
⇒ Checked our GoAhead: no `webFac`/`.gch` endpoints — different firmware family. Methodology
  applies (challenge keys live in the web binary), endpoints do not. Worth a 30-second
  blind probe at bench anyway (`POST /webFac` → expect 404).

### MF286R engineer-login method [COMM]
github `dikeckaan/mf286r-telnet-openwrt-exploit`: web login `Root`/`mbl_2019_SoL` →
upload `exploit.dat` as firmware → telnetd on 23/2323/random. Not in Telia dump
(`mbl_2019_SoL` absent) — variant-dependent, one free try at bench.

### CHANGE_MODE internals [DUMP — RE pending]
Our GoAhead: `zte_goform_mgmt_change_mode_process` with `change_mode=1` → `telnetd &` +
`iptables ACCEPT 4719`; login machinery strings: `zte_mgmt_login`, `login_9527`,
`onceuponatimeinparadise`, `zte_mgmt_login_timemark_check` (time-gated session),
password transform (`psw1` → `temp_psw`). Blog (2017 MF286): CHANGE_MODE password =
RSA-encrypted IMEI. RE of this one handler in the ARM binary is the whole exploit.

### Dismissed / deprioritized
- **DHCP injection**: argv-only sinks, no eval — analyzed §2, unlikely
- **TR-069**: `tr069 func is not support, return!` in this build — dead
- **WAN telnet whitelist** (`firewall_sys_fw.sh:291+`): needs authed config change first
- **Pure web UI local upgrade with OpenWrt image**: stock web UI validates vendor image
  structure; OpenWrt root_uImage rejected on unconverted firmware (community evidence);
  works only after Nordic conversion per Hecatae

## 5b. Web-UI upload / downgrade / boot-gate analysis (2026-11-02) [DUMP]

Question: can we craft/checksum an image for the stock web UI, or downgrade to an old
vulnerable stock via the UI?

### Where enforcement actually lives
- **Web UI upload path**: goahead goforms `UPLOAD_FILENAME` + `FOTA_UPDATE` → file lands
  as `/etc_rw/fota/image.zip` → `update_control` runs the full RSA chain
  (`openssl dgst -sha256 -verify` vs `/etc/public_root.pem` → package key →
  `root_uImage.signature`) **plus** version/variant gates (inner/outer version compare;
  community: TIM refused Elisa loads "invalid version", DNA loader refused "newer
  version installed"). Unsigned/modified image: **dead**. Signed-but-old: **version-gated,
  unreliable**.
- **U-Boot (mtd18) does NOT enforce signatures on retail units**: it contains
  `do_boot_signedimg` / `secure_authenticate <sw_id> <img_addr> <img_size>` machinery
  with a `"secure authentication scm call is not supported"` fallback — and community
  boots unsigned OpenWrt initramfs via `tftpboot` on stock U-Boot. Boot gate = **uImage
  header CRC32 only**. ⇒ *any* single write primitive to mtd9 (root shell, download
  mode, blank-TFTP) is sufficient — no "checksum to figure out" at boot level.
- `root.pem` in the ZTSUF package = **Equifax TLS root** (libcurl trust for
  `cndms.ztems.com`), not firmware signing material.
- ZTSUF `BL_DL_LTE_QualComm_Net.dll` speaks RNDIS/AT to read the device version
  (`GetVersion_by_Rndis`, `Read sw version failed, ATRsp`) and has version-conditional
  behavior ("The current version does not support CRC check!" / "...flash partition bad
  block check!") — these are likely exactly what the community patch removed. `SHA256SUMS`
  appears to be a PC-side integrity check by the tool, not a device-side signature.

### Verdict
Downgrade-to-old-stock is **not an entry primitive** — it needs the same write access
we're chasing (web-UI path is version-gated; version vars live in cfg-param and are only
settable with root). It IS a **post-entry amplifier**: once ZTSUF download mode works it
can flash anything — prefer OpenWrt `root_uImage` directly; old-stock flash only as a
diagnostic/exploit-fallback step.

## 5c. Fake update server / forged-TLS path — evaluated (2026-11-02) [DUMP + web]

Question: can we stand up a fake update server (using certs forged from the leaked CA
keys) and push a fake update?

### How OTA actually works on this device [DUMP: mtd4 cfg-param]
- DM (device management) session: `https://dmeu.ztems.com:443/zxmdmp/dm` (ZXMDMP,
  TR-069-style), offers live on device; unit had a pending offer
  `…/TELIA_MF286DV1.0.0B08-TELIA_MF286DV1.0.0B09.up`
- Package download: `https://dleu.ztems.com/zxmdmp/download.do?...` (`.up` package)
- Result report: `https://upgrade.ztems.com/UpdateEntry.aspx`
- After download, `update_control` verifies the payload with the **on-device RSA chain**
  (`/etc/public_root.pem` → package `public_ver.pem`/`key.signature` →
  `root_uImage.signature`, `openssl dgst -sha256 -verify`)

### Answers
1. **Is the gate SSL? No.** TLS is transport-only. The payload carries end-to-end RSA
   signatures verified against pubkeys **pinned in firmware**. A perfect TLS MITM with a
   fully trusted cert changes nothing: a fake payload still fails `verify` and the
   upgrade aborts. Only ZTE's update-signing key can mint an installable package.
2. **Would the leaked-CA certs even validate?** The leak = eMudhra (Oct 2026, eight
   *intermediate* CA keys, weak RNG; browsers/Go shipped emergency distrust). Our
   firmware's trust store is frozen at build time (2021-04): it predates the distrust
   AND very likely doesn't contain eMudhra/emSign roots at all (embedded ZTE stacks
   typically pin ZTE's own CA — the only cert material found on-device is ZTE
   self-signed `dualcore_cert` + the firmware-signing pubkeys). Untested but doubly moot
   per (1).
3. **What a fake server WOULD need** (replay variant — serve a *genuine* signed package):
   a network position that redirects `dmeu/dleu.ztems.com` on the **LTE WAN** (feasible
   for us only via lab SIM/APN/DNS control), DM-protocol emulation (ZXMDMP), a TLS cert
   the 2021 client accepts, and then the **version/variant gates** still decide
   (community evidence: cross-variant loads die with "invalid version"). That is three
   unknowns + infrastructure vs zero for the ZTSUF/download-mode path.
4. Symmetry worth noting: ZTE locked the one network-facing channel (OTA: RSA payload
   chain) and left the factory/local channels open (download mode: SHA256SUMS only;
   U-Boot: CRC only). Attack the open channels, not the locked one.

### Verdict: dismissed as primary path. Exotic replay-downgrade remains a theoretical
fallback requiring lab-LTE infrastructure + DM-client RE; strictly dominated by
CHANGE_MODE exploit / ZTSUF download mode.

## 6. Approach comparison — recommendation

| Approach | Speed to first flash | Tooling value | Risk | Effort |
|---|---|---|---|---|
| A. Blind ZTSUF run (wine/container) | fastest if it works | zero | untrusted patched DLLs, GUI automation, reflashes modem too, opaque | low |
| B. Pure static RE of ZTSUF | slow | high | none (offline) | very high (MFC GUI app) |
| C. Live-capture ZTSUF session + targeted RE | medium | **high** (protocol → Python reimpl) | contained (sandboxed, captured) | medium |
| D. Dump-side goform RE → exploit → root → in-device flash | medium | **highest** (full control, selective flash) | none to low (read-only until root) | medium |
| E. Serial (excluded by requirement) | — | — | — | — |

**Recommendation: D primary, C as guaranteed fallback, A never blind.**

D: we already possess the device binary (GoAhead) with the backdoor machinery anchored by
strings; one handler function + the login transform is a tractable ARM RE task. Any root
shell on telnet 4719 gives us: backups → selective main-CPU OpenWrt flash from the device
itself (tftp from our host + nandwrite) — no Windows, no modem reflash, fully reversible
(U-Boot blank-TFTP safety net). This also yields the conwrt-native flash path.

C: if D fails on the bench (variant differences), one sandboxed, Wireshark-captured ZTSUF
wine session gives the full download-mode message flow; targeted RE of the patched
`BL_DL_LTE_QualComm_Net.dll` then closes the crypto gaps; reimplement as Python. Even the
fallback improves tooling permanently.

Sequence at bench: identify variant → free probes (webFac 404, engineer login, CHANGE_MODE
variants, variant default passwords from package names: Nordic `admin`, Elisa `del wifi`)
→ if root: D path → else C path.

## 8. Session log 2026-11-03/05 — oracle run verdict, ZTE CDN discovery, remaining paths

### Oracle run (WinPE + real ZTSUF tool, bridged then macvtap-direct)
- Tool got further than ever: device row CONNECT ("Device is ready"), IMEI + NORDIC read,
  full goform cycle on-wire (300+ FactoryResult), but **no flash transport**: udp/500
  ISAKMP openers from the tool were never answered. Lane verdict (community-corroborated):
  **the network download transport was changed/removed in post-B04 firmware** — the
  Windows network flash path is closed on B09. Evidence: `ORACLE-ANALYSIS.md`,
  `flash-evidence2/`, `opener.hex` (440B ISAKMP proposal), pcaps + 8s screenshot series
  under `/home/ubuntu/mf286d-vm/`.
- E3 download-env findings: after hardware factory-reset (RESET 10–15 s) the device boots
  a factory stage at **192.168.32.1** running DHCP+DNS+HTTP (stable, not transient!),
  goform `SwitchFactoryMode` cycles, DNS maps `cndms.ztems.com → 192.168.82.3`; device
  re-homes to **192.168.82.1** and ARP-hunts `.82.2/.82.3/.82.10` (the peer subnet).
  No listener ever appears (54-port + full UDP scans negative in every phase).

### ZTE DMS CDN is ALIVE and serves signed OTA packages [verified 2026-11-05]
- Working URL pattern (from our unit's cfg-param, confirmed 200):
  `https://dleu.ztems.com/zxmdmp/download.do?doWhat=getUp&filename=firmwarepackages/DE/ZTE/MF286D/234370/TELIA_MF286DV1.0.0B08-TELIA_MF286DV1.0.0B09.up`
  → 14.6 MB zip: `root_uImage.mld` (delta!), `delta.package`, `delta.signature`,
  `key.signature`, `public_ver.pem`, `root_uImage.signature`, `cpe_postprocessing.sh`.
  **This is our variant's exact B09 stock in signed OTA form** (kit `root_uImageorig`
  was only B02).
- Blind enumeration of newer/more-variant paths returns 404 (Telia catalog ends at B09;
  Nordic name/PLMN guesses all missed). Community mega mirrors (Elisa folder, 6.95 GB
  kit folder) are dead (-9/ENOENT) — only the already-downloaded kit survives.

### Remaining no-serial paths (scripts staged in /home/ubuntu/mf286d-vm/)
1. **FOTA offer probe** (`fota_probe.py`, creds+login hash from working recipe): authed
   LOGIN → `FOTA_UPDATE` → poll `ota_new_version_state`/`detect_new_version` → if an
   offer exists, accept via `DM_ConfirmDownload/Install` (device pulls genuine signed
   update from ZTE over its LTE). Any B10+ result = code family with the proven
   `NIGHT_MODE_INFO_SETTINGS` exec injection → root → native mtd flash of OpenWrt.
2. **E3 surface enumeration** (`e3_probe.py`): the factory stage at .32.1 runs HTTP with
   goforms and possibly an upload/update endpoint outside the stock RSA chain (the
   B04-era tool cooperated with this env). Map before assuming closed.
3. **Serial** (approved ender): FT232 on `/dev/ttyUSB1`, capture armed since Nov 3
   18:42 (`serial_capture.py`, zero bytes so far — wiring never completed). U-Boot →
   tftp root_uImage from armed 192.0.0.1 recovery net → bootm.

### Bench state at time of writing
Device **powered off since Nov 3 ~18:30** (zero frames all captures; serial silent).
Link clean: br-min, only recovery-TFTP at 192.0.0.1/8, bridge capture running.
Blocker: physical — power on (serial wiring optional but valuable).

## 7. Continuation plan (2026-11-02, superseded by §8 paths)

Offline (anytime, no device needed):
1. RE `goahead` CHANGE_MODE handler + `zte_mgmt_login` password transform (ARM; anchors:
   `login_9527`, `onceuponatimeinparadise`, `change_mode=1` → `telnetd &`) → produce a
   working curl recipe against telnet 4719
2. RE the ZTSUF patch: `BL_DL_LTE_QualComm_Net.dll` vs `.bak` diff (targets: version/CRC
   gates — "current version does not support CRC check!") → documents what the tool
   requires before it will flash
3. Assemble bench kit: OpenWrt ipq40xx initramfs + sysupgrade for `zte_mf286d` (with
   sha256s), TFTP config (192.168.0.22 / 192.0.0.1/8), free-probe script (webFac,
   engineer login, CHANGE_MODE variants, variant passwords)

Bench (device required, ~1 session):
4. MAC/serial gate specimen → private inventory
5. Web UI: variant + version → run free-probe script
6. Any root: telnet 4719 → backup mtd1/2/4 + full set (tftp) → flash OpenWrt rootfs
   (nandwrite; never touch SPI NOR) → verify → record timings for recipe
7. No root: containerized+captured ZTSUF session (§3 runbook) → flash OpenWrt
   root_uImage → capture = protocol RE input for native reimplementation

Tooling outcomes:
8. `conwrt` native MF286D flash path (exploit-based or download-mode-based), model JSON
   after live validation, updated notes.md with validated timings
- References: OpenWrt forum t/151965 (Hecatae), ISPreview t/38732 (framework thread),
  blog.asiantuntijakaveri.fi 2017 MF286 backdoor, sec-consult ZTE MS910S advisory
  (GoAhead pattern), github dikeckaan/mf286r-telnet-openwrt-exploit

## 9. TR-069 lane (2026-11-05) — Zyxel playbook transfers to MF286D

Triggered by operator review of Amperstrand/zyxel-research (their network-only OpenWrt
install on WX5600-T0: DHCP option 43 → fake ACS/CWMP → SPV/Download; tools
`tools/acs/fake-acs.py`, `tools/network/dhcp-wan-server.py` — battle-tested).

Our dump confirms the prerequisites on MF286D B09 [DUMP]:
- `zte_tr069_new` (507KB ARM ELF) exists in stock rootfs, full CWMP/TR-143 stack
  (Inform, SPV/GPV, Download/Upload, TR-143 diagnostics: IPPing/TraceRoute/
  DownloadDiag/Udpecho — the classic injection-adjacent params)
- **Option 43 provisioning**: `tr069/core/cfg/tr069_cfg_opt43.c`, strings
  `copy option43 info wan=%s acs=%s`, `WANC_ID:%s AcsUrl:%s ProvisionCode:%s
  RetryMinWaitInterval:%d RetryIntervalMuti:%d`, `option43 type is PreConfig` —
  ACS URL is DHCP-provisioned; no scheme restriction seen in strings (http:// ACS
  plausibly accepted → TLS question may be moot)
- libcurl used with CURLOPT_CAINFO/SSLCERT — TLS posture at the CAINFO layer TBD;
  device cert store is ZTE self-signed (`dualcore_cert`)
- No RSA/openssl-verify strings inside zte_tr069_new itself; firmware Download
  routes to `/etc_rw/fota/image.zip` (signed path) — but the SPV parameter-write
  surface is unexplored on ZTE
- WAN ethernet mode exists (`AUTO_BACKUP` in dump; E3 web exposes
  SET_CONNECTION_MODE / WAN_GATEYMODE_PPPOE forms) → device becomes OUR DHCP client

Chain to test: stock (after RESTORE_FACTORY via E3 web) → eth-WAN mode → our DHCP
with option 43 (ZTE encoding candidates below) → fake ACS (their fake-acs.py adapted)
→ observe Inform → probe SPV tree + Download semantics.

opt43 wire format: disasm anchored (string VA 0x75e41, literal pool at VA 0x374d0;
parser region ~0x374xx — decode pending). Empirical candidates to try in order:
1. ASCII `key=value` ZTE-ONT style, e.g. `acs=http://<bench-host>:7547/acs`
   (and `url=`/`WANC_ID=` variants, `;`- or `,`-separated)
2. TLV suboptions (1-byte type, 1-byte len): {0x01: wan-id, 0x02: url-ascii}
3. Their Zyxel opt43 payload verbatim (from dhcp-wan-server.py) as control

Bench state 2026-11-05 08:30: device UP in E3 (ARP+ICMP+HTTP at 192.168.32.1,
ZTE-Webs/2.5.0, full web app — 160 goformIds incl IF_UPGRADE/CHANGE_MODE/
SET_CONNECTION_MODE/REBOOT_DEVICE/RESTORE_FACTORY_SETTINGS; NO local upload form;
E3 auth model: HAS_LOGIN flag + AD=md5(md5(rd0+rd1)+RD) with rd0/rd1 currently
empty on the served page). Address-flux fixed: host addresses only on br-min.

## 10. Session log 2026-11-05 evening — DM cycle live, download-mode probed, state parked

- **WAN restored**: roaming SIM (Orange PL on Telenor NO) — enable via web Connection
  Mode page checkbox (Playwright drives it; raw goform rejected). WAN = PPP,
  10.181.52.213. `simcard_status=READY` (note: `simcard_state` var is empty — use
  `simcard_status`).
- **Real DM cycle works**: `IF_UPGRADE` check → dmeu.ztems.com delivers signed package
  over LTE → reboot applies via zdu. Result: `cr_version Nordic_MF286D_B10→B12`
  (modem/framework side only; `wa_inner_version` stays BD_TELIAMF286DV1.0.0B09 =
  Telia store-only goahead — the injection family is NOT live on the unit).
- **Download mode observed live**: device re-homes 192.0.0.2, RRQ `PROBE.txt` ~20s
  after boot (server-alive check), then the real filename request. Our 38MB alias
  answer to the probe aborted the session → device fell back to applying its NAND
  delta. factory_tftp.py now fenced: whitelist (PROBE.txt/root_uImage), sha256 at
  serve, single bind 192.0.0.1:69.
- **eko.one.pl NORDIC/B12/mtd9.bin = community OpenWrt 22.03-rc5 dump** (NOT stock):
  LuCI assets, full OFS extracted at data/zte-mf286d/b12-openwrt-rootfs (local).
  Its retained goahead carries the CVE-2023-25649 exec sink verbatim (PLT-verified).
- TR-069: full config written + module TR181 set; daemon never starts
  (`tr069_enable` nv stays 0; writer unknown — carrier-provisioned).
- Next: (a) repeat DM cycle for the next delta (B14? — if a delta ever replaces the
  wa/web side, the Nordic goahead + injection arrive), (b) RE the zdu RRQ-name window
  for redirect-to-root_uImage, (c) tr069_enable writer hunt.
