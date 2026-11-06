# MF286D BL_DL plugin — RE findings (BL_DL_LTE_QualComm_Net.dll @ 0x10000000 base)

All addresses are image VA (PE base 0x10000000). Analysis: radare2 -A + objdump cross-checks.

## 1. Goform state machine (exact HTTP, in order)

HTTP verbs that exist in this DLL (complete list, verified by string xrefs):

| # | verb | function | evidence |
|---|------|----------|----------|
| 1 | `GET /goform/goform_get_cmd_process?isTest=false&cmd=Language,cr_version,wa_inner_version&multi_data=1` | `fcn.1000fe80` (called from AD-recipe `fcn.100103c0`) | str 0x10057430 |
| 2 | `GET /goform/goform_get_cmd_process?isTest=false&cmd=RD` | `fcn.10010120` (called from `fcn.100103c0`) | str 0x100574b0 |
| 3 | `POST /goform/goform_process` body `goformId=SwitchFactoryMode&SwitchCMD=Open[&AD=…]` | `fcn.1000fb80` | str 0x100573b8, URL 0x10057398 |
| 4 | same, body `goformId=SwitchFactoryMode&SwitchCMD=Query[&AD=…]` | `fcn.1000d500` | str 0x10056d3c |
| 5 | `POST /goform/goform_process` body `goformId=ONLINE_UPGRADE_TOOL&command=get_current_version` | `fcn.1000d890` ("GetVersion_by_Rndis") | str 0x10056da8 |

**AD recipe** (`fcn.100103c0`, called by both Open and Query before POSTing):
1. fetch versions (verb 1); parse `"cr_version":"` (plain) and `"wa_inner_version":"` — **wa value truncated at first `]` inclusive if pos>=3, else at `"}`** (0x10010631–0x100106ea).
2. `pre1 = wa + cr` (concat order WA first — `fcn.10002850(&x, wa, cr)`; plain concat, no separator).
3. `md5_1 = md5hex(pre1)` — **lowercase** (`fcn.1004b290`: 16× `sprintf("%02x")`, digest→global 0x1006bb50).
4. fetch RD (verb 2); take **exactly 32 chars** after `"RD":"` (Mid(pos+6, 0x20) @ 0x1001081f).
5. `AD = md5hex(md5_1 + RD)` → returned via arg2 → appended as `&AD=`.

**Open** (`fcn.1000fb80`): success if response contains `SUCCESS` OR `FACTORY:OK` (Find, 0x1000fccc). **Query** (`fcn.1000d500`): response checked in order: `fail`→0, `OPENED`→1, `CLOSED`→0 (case-sensitive Find, 0x1000d663–0x1000d766).

**There is NO REBOOT_DEVICE in this plugin.** No such string exists. Reboot is done by:
- `fcn.1001e880` "RebootCpe" — called only **after** download (fallback chain @ 0x10010d55 / repair-mode 0x10010dc0): closes factory mode ("Close factory mode fail." 0x100597e0), closes sockets, then reboots via the Sahara/firehose channel (`<?xml…><power DelayInSeconds="5" value="reset"/></data>` str 0x1005…, "Firehose reset fail.") — never via goform.

**Orchestration** `DownloadProcessThread` (vtable `CBLService.0` @ 0x1005fb68+0x0c = `fcn.100109a0`):
1. `SwitchToFactory` loop: up to **120 × (call Open + Sleep 2000ms)** (0x10010a33–0x10010a7a); fail ⇒ return −1.
2. `fcn.10020760` (UI/database notify only — no HTTP) → **Sleep(5000)**.
3. `InitPortAndGetClientIP` loop: up to **300 × (call + Sleep 500ms)** (0x10010aeb–0x10010b3b); wrapper `fcn.1000ed20` → service vtable+0x1c8.
4. log `CPE Client Ip Address: [%s]` (0x10010bd0) → mode branch → download fns (`fcn.10010fa0` normal / `fcn.100125f0` repair) → fallback chain incl. RebootCpe only if download result==0.

**Answer to "which verb after Query=Opened": NONE.** The tool stops HTTP and waits on UDP. `FACTORYRESULT:OPENED/CLOSED`, second `SwitchCMD=Query` string (0x10057554) are unreferenced leftovers. Mode detection (`CBLService::virtual_8` = 0x1000ddd0) uses Query ("Device is (not) factory mode", 0x1000e15b) then verb 5; it also (re)starts the TFTP server when `ITEM_LINUX_URGENT_DL` set (0x1000de78).

**Why REBOOT_DEVICE fails on factory side**: it's a stock-web verb; factory linux doesn't implement it (returns failure). The tool's factory-side model = device pulls on its own after being armed; reboot there happens only via firehose/AT post-download.

## 2. InitPortAndGetClientIP / UDP ports

- Real bind: `fcn.1004c8a0` — WSAStartup(2.2) → `socket(AF_INET, SOCK_DGRAM, 0)` → `inet_addr(cfg[0x180])` → `htons(cfg[0x184])` → **bind()** → socket stored at `this+0x1b8`. **Pure listen: no sendto, no broadcast, no SO_BROADCAST, no announce.**
- Config (`fcn.1003c9b0`, section `DOWNLOADBL`): `ITEM_TFTP_SERVER_IP` default **"192.0.0.1"** (cfg+0x180), `ITEM_TFTP_SERVER_PORT` default **69** (cfg+0x184), `ITEM_TFTP_MONITOR_INTERVAL` default **15000 ms** (cfg+0x188), `ITEM_WAIT_URGDL_RESULT_TIMEOUT` default **45000 ms** (cfg+0x18c).
- Server startup `fcn.10025330`: bind, then threads: `StartLinuxUrgAutoDLThread` (0x10024c00), `DLStatusMonitorThread` (0x10024770), `DLResultMonitorThread` (0x100249c0). Wait — recvfrom dispatch loop is `fcn.10024550`→`fcn.10024f00`: ntohs(opcode), jump table @0x1002531c: **1=RRQ→`fcn.100254b0`, 2/3, 4=ACK, 5=ERROR** — it's a real TFTP server with RFC2348/2349 option parsing ("timeout" str 0x1005b04c).
- RRQ handling (`fcn.100254b0`): parses filename/mode/options, matches against configured file ("The file name is different, config File=%s, request file=%s" 0x1005b0c8), per-IP worker allocation from a **pool of 8** ("No idle thread or ip already exists" 0x1005b120; arrays `this+0x1e8` (0x2c×8), `this+0x348` (0x208×8), ports/IPs at +0x1428/+0x14ec/+0x150c/+0x1590).
- **Client IP** = source addr of first UDP packet (RRQ / "linux upgrade resp packet"); tool machine IP comes from config / SetIP feature (`ITEM_SetIP`, `IDC_CHECK_SETIP`, "ID_HINT_SETIP*"); device default IP string "192.168.1.1" @ ctor 0x1000cd46, real device IP set per mode (192.168.32.1 in this kit).

## 3. DownloadSaharaArmPrg (`fcn.10023c30`, called from `fcn.100125f0` repair / `fcn.10015670` normal)

State flow inside:
1. **`Send Hello_Resp`** (vtable+0x330; fail ⇒ err 0xa) — the tool only ever *responds* to a device-initiated HELLO (str 0x1005a728). Tool never sends HELLO first (client blasting HELLO at the device will never work).
2. Mode select 0x0D vs 0x07 (64/32-bit read) via `fcn.10016910` (0x10023d75).
3. Loop: **`Read data`** (vtable+0x334) → serve armprg bytes → **`Write data`** → progress "armprgFileTotalLen=%d, WrittenTotalLen=%d" → **`Sahara Done`** (vtable+0x33c) (0x10023e4a–0x100240f4).
4. Post-Done: Sleep(**500** ms normal / **5000** ms if cfg[0x2c]) (0x100241be/0x100241e8), then **`fcn.1000ec80` Init port** (args incl. 0x1c200) → "Init port success, port=%d" / "Failed to init port".
5. **Hello wait for stage-2 boot**: loop **8 retries × Sleep(1000)** — vtable+0x19c(idx,2), 99-byte scratch, vtable+0xf4 = CheckHello; success breaks; 8 misses ⇒ "Thread %d, Hello handshake failed" (0x10024361–0x100244ec).
Device by then: stage-1 = factory agent/armprg bootstrap sends HELLO; after armprg transfer + reboot into armprg, **stage-2 HELLO from the programmer**, then firehose ("Receive High-speed download ready response0x29 failed" str 0x10058d8c; `<?xml…power value="reset"…>` reset).

## 4. ITEM_* inventory (config = encrypted `BusinessCfg/*_DL.config`; loader `fcn.1003c9b0`, getters `fcn.10040680/100404f0/10040720` via get-framework)

Ports/timeouts/mode: `ITEM_TFTP_SERVER_IP` ("192.0.0.1"), `ITEM_TFTP_SERVER_PORT` (69), `ITEM_TFTP_MONITOR_INTERVAL` (15000), `ITEM_WAIT_URGDL_RESULT_TIMEOUT` (45000), `ITEM_LINUX_URGENT_DL` (cfg+0x60), `ITEM_SetIP`, `ITEM_WriteLog` (cfg+0x16c), `ITEM_CHECKDOWNLOADMODE`, `ITEM_CHECK_FLASH_BAD_BLOCK` (cfg+0x170), `ITEM_MAX_FLASH_BAD_BLOCK_NUM` (f64, cfg+0x178), `ITEM_PARTITION_MAX_FLASH_BAD_BLOCK_RATE` (f64, cfg+0x1a0), `ITEM_CHECK_CRCCODE` (cfg+0x190), `ITEM_CONFIG_CRCCODE` (cfg+0x194), `ITEM_DOWNLOAD_FILElIST`, `ITEM_DOWNLOAD_OPTION_FILELIST`, `ITEM_DOWNLOAD_URGFLIELIST`, `ITEM_DOWNLOAD_PLATFORM`, `ITEM_DOWNLOAD_RECEIVE_No_RSP`, `ITEM_DL_armprg_type_Sahara`, `ITEM_e_armprg_download_version`, `ITEM_e_armprg_skipaddr_config`, `ITEM_ModemMD5File`, `ITEM_ModemZipFile`, plus RK/MSC USB items. Config files (both ours & kit's) are encrypted blobs (header `690e3214…`); decryption lives in the get-framework (MyGetCore/get.public.setting), not this DLL — not yet reversed.

## 5. Patch vs .bak (one line)

Community rebuild (+3584 B): adds `MF286R` factory-switch debug flow strings (`before call SwitchToFactory(%d)…`, `SwitchToFactory fail`, `before call Download failed…`), drops the hardcoded cache-buster `&_=1479091268994` from the version query, and carries the `SwitchFactoryMode&SwitchCMD=Open`+AD MF286R path — rest is compiler/reloc noise.

## 6. Sahara cmd 0x39 (bonus, partial)

String `SW donot support cmd_0x39` @ 0x1005711c: a capability check in the high-speed/firehose handshake — the tool refuses devices whose stage-2 programmer *requires* cmd 0x39 (a ZTE vendor Sahara command this tool build doesn't implement). Static only; no handler exists in this build.

## 7. IKE / cndms.ztems.com (live pivot)

- Opener (440 B, `/tmp/opencode/opener.hex`): IKEv1, **exchange 0xF3 (ZTE vendor)**, flags 0, msgid 0; payloads: `0x85` vendor(4×00), SA (DOI 1, AES-128-CBC/SHA1/**DH group 19 ECP-256**/life 7200 s), `0x87` vendor(`00030000`), NONCE 48 B, VIDs incl. **MD5("RFC 3947")** + fragmentation, NAT-D ×2, KE = raw X‖Y 64 B.
- Initiator = the ZAS tool VM (placeholder identity; hostname/MAC redacted from evidence) → hijacked cndms.ztems.com; it's the framework **self-updater** (`app.config.ini ENDPOINT=cndms.ztems.com, DIR=/ZSUF/UpdateTool/Release/`), not the flash path. Responder: `ike_responder.py` (selftested mirror-accept; logs hex).
- Tool proven on MF286D: `zte_plugin.db3` row `SUF_DL_MF286D→MF287+-DL-BackUpNV-N-01_DL.config`; kit preconfigured "zte mf286d Nordic to Nordic_B11 192.168.32.1 pw admin".

## 8. Root/vuln surface (notes)

- Trust chain: factory agent TFTP-pulls firmware from us with **no signature visible in-tool** (CRC/MD5 items are all served by us too) ⇒ whoever holds UDP/69 during factory mode owns the flash (≈arbitrary code at boot).
- Factory web exposes `ONLINE_UPGRADE_TOOL&command=get_current_version` (returns IMEI matrix) unauthenticated-in-practice on .32.1 — enumerate further `command=` values for device-side exec.
- MF268/MF286D module: fastboot + EDL over USB also reachable (community guide) once case-open; ADB/telnet paths exist in Nordic firmware (`telnetd` w/ admin/IMEI in O2-CZ build).

## Artifacts

- `ike_parse.py` — ISAKMP/parser with VID fingerprints
- `ike_responder.py` — UDP/500 responder (selftest OK)
- `factory_tftp.py` — UDP/69 TFTP server + Sahara watcher (selftest OK); serve from `ztsuf/UPDATE/` (armprg.bin 108164 B, e_armprg.bin 107128 B, NPRG9x55.mbn, sbl1/rpm/uboot, *.ubi/ubifs, FOTA_FS/*.tgz, zte_dload_boot.xml, partition_nand.xml)
- `RUNBOOK.md` — live sequence
