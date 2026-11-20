# MF286D Modem Firmware RE — ISD-R Access-Control Analysis (EXP-034)

Offline static RE of the ZTE MF286D modem firmware (B02 kit image, 2019).
Date: 2026-11-08. All artifacts under `~/mf286d-work/evidence/modem-fw-re/`.

## Executive summary

1. **The modem is NOT Qualcomm.** It is a Marvell **PXA1826 "Nezha3" (NZ3)** SoC with
   **ASRMICRO**-derived firmware (Marvell modem IP lineage). The "Qualcomm MDM9xxx /
   AMSS" assumption in earlier research (EXP-031/032/033) is WRONG and is corrected
   here. QMI is implemented as a Qualcomm-*compatible* protocol, not on Qualcomm silicon.
2. **The modem is a self-contained Linux system**: OpenWrt-style rootfs (SYSJ, squashfs)
   on the AP core + a 10.2 MB baseband RTOS image (**ARBI**) on the CP core, loaded at
   **0x06480000**. The AT engine is **`/bin/atcmdsrv`** (726 KB ARM ELF on modem Linux).
3. **The AT layer contains NO ISD-R gate.** `AT+CCHO/+CGLA/+CCHC/+CSIM/+CRSM/*EUICC`
   handlers in atcmdsrv are pure pipes: they parse arguments and forward **CI
   ("Card Interface") primitives** through `/dev/ccidatastub` → kernel (`acipc`/MSOCK)
   → CP firmware (`sacCi` card stack). The refusal for ISD-R is generated BELOW
   atcmdsrv.
4. **No ISD-R AID literal exists anywhere** in the modem firmware (AP userspace, kernel,
   or CP image): no `A0 00 00 55 59 10 10…` bytes, no ASCII "ISD-R". The policy is
   therefore NOT a simple AID-string blocklist compiled into the image. Remaining
   candidates: computed/prefix AID comparison in CP code, an NV-item/policy flag, or a
   card-access-rule mechanism — all live in the CP (`sacCi`) or its NV provisioning.
5. **ADB root shell is built in and auto-starts** (`adbd` 5.0.2, `/etc/init.d/adbd`
   START=80, `S80adbd` symlink). Default USB composition on normal boots includes the
   `adb` function (`rndis,acm,marvell_diag,adb`, PID `19D2:1489` in this kit). A TCP
   ADB listener on **port 5555** is implied and firewalled unless `cfg get adb_enable=1`.
   This is the practical lever for the live follow-up: root on modem Linux → read/patch
   atcmdsrv, drive `/dev/ccidatastub` directly, dump live CP memory and NV, and settle
   the ISD-R mechanism definitively.

## 1. Container format (mission Q4): FBF + TIM, fully decoded

`FBF_h.bin` (27,799,556 B) = Marvell "FBF" (Flash Boot Format), magic `DFBF` +
`Marvell_FBF`. Structure (see `fbf_parse.py`, `fbf_crc_probe.py`):

- Header 0x000–0x143 (`0x44` = partition-table size 0x314; `0x28–0x30` = payload size ×3).
- Partition table @ **0x144**, 9 entries, stride **0x34**:
  `[tag(4)] [type][0][size][3][pid][size2][flash_offset] [z×4] [crc(4)]`
  tags stored little-endian (byte-reversed in file).
- Each image in the file is preceded by a 4-byte `0xFFFFFFFF` marker.

| # | tag | file offset | size2 | flash off | content |
|---|-----|-------------|-------|-----------|---------|
| 0 | TIM4 | 0x01000 | 0x1C74 | 0x120000 | TIM manifest (TIMH magic, `3AZN`/`CMM`, 2014-06-01 toolchain, RDDT/DDR-init table) |
| 1 | OSLO | 0x03000 | 0x866F0 | 0x1080000 | bootloader ARM code (contains an ELF @ +0x6a493) |
| 2 | TIM1 | 0x8A000 | 0x794 | 0x100000 | second TIM variant |
| 3 | OEMD | 0x8B000 | 0x1E0000 | 0x5B00000 | UBI area (factory-fresh, mostly erased) — NV lives here at runtime |
| 4 | SYSJ | 0x26B004 | 0x729988 | 0x1580000 | **squashfs rootfs** (modem Linux) |
| 5 | ZIMG | 0x995004 | 0x2EEBDC | 0x1180000 | zImage (magic 0x016f2818) + appended DTB |
| 6 | ARBI | 0xC84004 | 0x9BEC34 | 0x58000 | **baseband RTOS firmware** (the "modem" itself) |
| 7 | GRBI | 0x1644000 | 0x400000 | 0x18000 | data (sparse) |
| 8 | RFBI | 0x1A44000 | 0x40000 | 0x14000 | data |

`Dkb.bin` = separate "DKBI"-tagged boot image (ARM branch entry), not embedded in the FBF.
`*_timheader.bin` = the TIM manifests shipped alongside (content differs from TIM4/TIM1
copies; DKB header carries a 32-byte hash at +0xB8 — the image is **signed/hashed**, see
§7 feasibility).

Carved artifacts: `extracted/{TIM4,OSLO,TIM1,OEMD,SYSJ.squashfs,ZIMG.img,ARBI.img,GRBI,RFBI}.bin`,
rootfs at `extracted/sysj-root/` (1,290 files), decompressed kernel `extracted/vmlinux.bin`
(5.8 MB, gzip payload at zImage+0x632C).

## 2. What the firmware is (corrections to prior belief)

- SoC: **Marvell PXA1826**, board "Profile 701" (`Marvell PXA1826(Nezha3) Profile 701 Board`
  in DTB; `!mrvl,pxa1822-dkb`, `nz3-pcie`, `pxa1826-fb` etc.). ASR string: `ASRMICRO` @ ARBI+0x694b8.
- Baseband build string (`etc/mversion`): **`BB14.07_pxa1826p701_rls2331_2.157.047_20190329_07_23_bld28`**
  → baseband 14.07, release 2331, built 2019-03-29 (matches kit date).
- Modem Linux: kernel 3.10.33 (Marvell SDK), uClibc 1.0.25, procd/ubus/uci OpenWrt userland,
  plus ZTE service layer (`zte_adapter_sim/stk/pbm`, `zte_topsw_*` — the router's web UI
  proxies SIM/STK/PBM to these over USB).
- CP protocol stack: Marvell "AB" modules (`w:\3g_ps\rls\tplgsm\model\psnas\ab.mod\...`
  Windows-CE build paths), SAC middleware (`sac_*.c`, `sac_shell_engine.c`),
  card stack `sac_sim.c` + `sacCi*`.
- Architecture of the SIM path:

```
router (IPQ806x) ──USB── modem gadget (android_usb composite)
   │ AT  (acm/marvell_modem ports)      ──► /bin/atcmdsrv ── CI client ──┐
   │ RIL (libmarvellril.so ─ AT loopback)                               │
   │ QMI (cdc-wdm0 → B12 composition; server not in userspace strings,  ▼
   │      terminates in kernel f_modem/pxa910 pipe or CP)      /dev/ccidatastub
   │                                                           kernel acipc/MSOCK
   │                                                                │
   └── modem Linux                                                 ▼
                                                    CP core: ARBI @0x06480000
                                                    sac shell engine → sacCi (card
                                                    interface, CIRC_* codes) → AB SIM → UICC
```

## 3. The AT path, handler by handler (mission Q1/Q2 — AT side answered)

AT dispatch table found at `atcmdsrv` .data file 0xA77xx; entry
`[name,ctx,type,help,0,handler]`. Extracted handlers (Thumb):

| command | handler | what it does |
|---------|---------|--------------|
| +CCHO | 0x442cc | parses `<dfname>` hex AID (≤0x1fe chars) → **`SIM_RestrictedAccess` (src/sim_api.c:1435)** → sends CI primitive **0x2C** |
| +CGLA | 0x44490 | same pipe (restricted access) |
| +CCHC | 0x4421c | close logical channel |
| +CSIM | 0x431b0 (`ciGenericAccessSim`) | → **`SIM_GenericAccess` (src/sim_api.c:1562)** → CI primitive **0x01** |
| +CRSM | 0x4300c | restricted SIM access |
| *EUICC | 0x4483c (`ciEUICC`) | read-only (op=2): if euicc-state byte (0xC5C4C / 0xC5C51 alt-SIM) == 1 → `*EUICC: <n>` where n = counter @ 0xC5E00/0xC6048; else +CME 10 (SIM not inserted). Set-op → ERROR. |
| *ISIMAID | 0x44b50 | ISIM AID query |

- Send function: `0x5E23C(handle, primId, req, …)` via global CI client 0xCB798→+0x14.
- Confirmations: e.g. CCHO CNF handler @ 0x46504 prints `+CCHO: %d\r\n` on success
  (error==0) or calls **`libDisplaySimRc` @0x46180** which maps CI return codes
  (CIRC_SIM_CODE ≤ 30 via a 31-entry stack table) to `ERROR` / `+CME ERROR` strings.
  The live `AT+CSIM → "operation not supported"` and `AT+CCHO → ERROR` are these
  mapped **CI/CIRC error codes** — the decision comes from the CP, not atcmdsrv.
- **No AID compare, no blocklist, no policy branch in any AT handler.** The AT-side
  "not supported" for CSIM is a CI-level rejection (generic-access primitive refused),
  i.e. the same class of block as QMI's "Access denied", consistent with both being
  enforced under atcmdsrv, in the CI chain (kernel/CP).

Full dumps: `atcmdsrv-sim-decomp.c` (Ghidra decompiles of the 6 handlers + CI helpers),
annotated disassembly via `arm_annot.py`, AT table dump `at-table.txt`.

## 4. The eUICC machinery (present, gated)

- `libmarvellril.so` (RIL vendor lib): `handle_euicc`, `wait_euicc_ok`,
  `wait_sim_detect_and_euicc`, `signal_euicc_indication`, `EuiccState::waitReady`,
  `closeLogicalChannel`, **`downloadProfile`** — an LPA-ish integration that WAITS for
  eUICC readiness before SIM IO. `AT*EUICC?` is its probe.
- ARBI (CP): `*EUICC: %d` handler near 0x67E16B8 (CP-side AT engine), 
  `sacDevGLSwapRecvEuiccInd(Ds)` asserts @0x149070/0x9481E0 — eUICC swap indication
  handling in the SAC device layer.
- atcmdsrv globals: euicc-state bytes 0xC5C4C/0xC5C51, counters 0xC5E00/0xC6048.
- Interpretation: the firmware DETECTS eUICC cards (state byte=1 when present) and has
  profile-download plumbing compiled in, but exposes no management channel to the host
  beyond CCHO/CGLA — which the CP refuses for ISD-R. The `*EUICC` machinery is how the
  modem itself gates ITS OWN eUICC operations.

## 5. Where the ISD-R block actually lives (mission Q1 — ANSWERED as far as static RE can)

Ruled out by direct evidence:
- ❌ Not in atcmdsrv's AT handlers (handlers are pure pipes — §3).
- ❌ **Not an AID comparison ANYWHERE in the compiled images**: exhaustive scans of
  ARBI.img, atcmdsrv, libmarvellril.so, vmlinux.bin for (a) ISD-R AID literals
  `A0 00 00 55 59 10 10…` and every prefix ≥4 bytes, (b) ASCII forms, (c) pool/literal
  constants, (d) **Thumb-2 `movw` immediates** for all AID fragments (0xA000, 0x0055,
  0x5910, 0x1010, 0x8900) — ZERO hits. The modem firmware does not, in compiled code,
  recognize "this is the ISD-R AID".
- ❌ Not in modem userspace QMI — **the QMI server IS atcmdsrv itself**: the modem
  kernel has NO wdm/qmi_wwan/cdc-wdm strings at all; the USB `marvell_modem` gadget
  function (pxa910_f_modem.c) forwards its data to userspace
  (`gs_marvell_modem_send_to_atcmdsrv`); and atcmdsrv contains a **QMI service/message
  registry** at file 0x99A1D–0x99CD4 (`[svc][ver][msg-block-start]` entries, services
  0x01–0x11+ all v10, including **svc 0x0B v10 = UIM** — matching the live "UIM v10"
  observation; UIM msg blocks start at 0x2C/0x47/0x66/0x90/0xBA/0xD2/0xEA — QMI UIM
  OPEN LOGICAL CHANNEL **0x0042** falls in the first block).
- ❌ Not carrier-branded config in the FBF (carrier names in ARBI @0x90ADD9–0x90BE4D
  are the PLMN operator-name table; rootfs `etc/config` has generic APN defaults —
  `uwap.orange.co.il` etc.; the kit OEMD/UBI NV area is factory-empty).

Additional structural facts:
- The AT open-logical-channel funnel is a SINGLE function for ALL frontends:
  `SIM_RestrictedAccess` **@ 0x46FCC** (src/sim_api.c — the 0x47164 I first labelled
  as the function was mid-body). Its three `bl 0x5E23C` call sites (0x4706A/0x4714E/
  0x472B0) send CI primitive **44 (0x2C)** — the ONLY senders of 0x2C in the binary.
  CSIM sends primitive **1 (GENERIC_CMD)**, close-channel **17 (0x11)**.
- **AP-side dedicated wrapper for prim 0x2C**: `ciRequest()` @0x5E23C special-cases
  (svcIndex==5 = SIM client) && (primId==0x2C) → diverts to a transformer @ **0x5FA44**
  (builds an alternate request, references composite keys 0x6F3B..0x6F4B, ciRespond
  machinery; semantics unresolved statically). Candidate location for AP-side
  channel-proxy behavior ("ciProxySet … proxy channel allready opened" strings).
  Live instrumentation (or deeper decompile) will settle whether this wrapper can
  deny/redirect independently of the CP.
- **CP-side dispatcher trace (sac_shell_engine)**: `SacCiReqEntry` @0x65ADEA0 parses
  {svgId, primId(u16)@+4, handle@+8} → prim switch @0x65AF8A0-area → prim 0x2C maps
  to handler-id **0x5B** → tail-dispatch 0x67BDC9E via RUNTIME table
  `[*[0x0660DD1C][simIdx]]`. Static analysis terminates at this runtime boundary;
  the actual handler + any policy are boot-time-registered (cfg_service.db/NV world).
  A config-DB feature-gate family @0x653E8AX (flags at ctx 0x06600064+0xB2C/0xB2D)
  exists; the +0xB2C-bit7 gate is referenced ONLY from the prim-0x2C branch (controls
  request LOGGING, not denial). Resolver tool staged (`cp_resolve.py`).

- CI protocol inventory (from atcmdsrv trace tables): `CI_SG_ID_{CC,SS,SIM,MSG,PS,PB,MM,DEV,DAT,…}`,
  SIM primitives ≤ 0x81, including **`CI_SIM_PRIM_DOWNLOADPROFILE_REQ/CNF`** — a
  dedicated eSIM profile-download primitive in the CI protocol itself (pairs with
  libmarvellril's `downloadProfile`).
- `CIRC_SIM_*` return codes include **`CIRC_SIM_ACCESS_DENIED`** — the code the CP
  returns and atcmdsrv's QMI layer translates to QMI error 82 "Access denied"; the AT
  side renders the same class of failure as plain `ERROR` (codes >30 print as
  "unknown" via libDisplaySimRc).

**Conclusion:** since the firmware cannot be comparing the ISD-R AID in compiled code,
the ISD-R-specific denial must be **data-driven at runtime**:
1. An **NV/provisioned policy table** (AID list loaded from the UBI/OEMD NV area via
   NVMC/nvmproxy — factory-empty in the kit image), or
2. **Card-response-driven enforcement** (access rules / SW1SW2 mapping), with the
   differential (ISD-R denied vs others "not found") coming from card state the modem
   queries — noting the same card yields to the NR7101's modem, so any card-side
   component is triggered by the MF286D's specific query pattern.
Both live in runtime state that ADB-root can read (and potentially flip). This also
means the block is likely **changeable without firmware patching** — a major positive
result for the campaign. Caveat: the kit is B02; the live unit runs B12 — the live
check (via ADB) will confirm whether B12 matches this architecture.


## 6. ADB root shell on the modem (live follow-up lever — CONFIRMED in firmware)

- `usr/bin/adbd` (95 KB, Android **5.0.2_r1**, FunctionFS transport `/dev/usb-ffs/adb/ep0/1`).
- `/etc/init.d/adbd` START=80, `etc/rc.d/S80adbd` → **auto-starts at boot** unless
  `/etc/mversion` contains `asr1802s` (it doesn't: pxa1826p701).
- USB composition (`etc/init.d/usb_init`, run by `etc/telinit` when `PROD=0 or 5`):
  **`rndis,acm,marvell_diag,adb`**, VID/PID **`19D2:1489`** (this kit; prod-boot
  `prod_usb_init` = `19D2:1490`, functions `acm,marvell_diag` — no adb).
  NOTE: live B12 enumerates `19D2:1485` — its composition scripts differ from this B02
  kit; adb-function presence on B12 must be verified live (the adbd binary + S80adbd
  are in the B02 rootfs and were present across the family).
- **Mode switch AT command: `AT*PROD=(0-2)`** (`zte_usb_mode.sh` uses `AT*PROD=1` =
  download, `AT*PROD=0` = normal; atcmdsrv strings: `*PROD=(0-2)`, `/tmp/prod_mode`,
  production AT channel handling).
- **TCP ADB**: `firewall_sys_fw.sh` (modem-side zte_conf package) drops tcp/udp **5555**
  unless `cfg get adb_enable == 1` ⇒ adbd's TCP listener is expected; port reachable
  from the router over the internal rndis/wwan link once un-firewalled.
- adbd property deps (`ro.secure`, `ro.adb.secure`, `service.adb.root`,
  `service.adb.tcp.port`) are served by a **uci-backed shim** (`getprop`→`libprop2uci.so`);
  no `default.prop` exists ⇒ likely unset ⇒ insecure/root behavior — verify live.
- Bonus surfaces: `zte_conf/scripts/zte_debug.sh` (des3-compressed debug config,
  default password `20170417`, drives `diag_mdlog` QXDM logging), `usr/bin/diag` +
  `marvell_diag` USB function (QXDM-style diag → classic NV read/write route),
  `rj45_mode_switch.sh`, `zte_kill_process.sh`, `MRD_dump.sh`.

Post-ADB plan for the ISD-R question:
1. `adb shell` on modem → read `cfg` store (`cfg show`), NV (`nvmproxy`, /nvmram, UBI),
   live `/tmp/prod_mode`, adbd props.
2. Drive `/dev/ccidatastub` directly with CI primitive 0x2C + ISD-R AID (bypass
   atcmdsrv entirely) → if refused, CP-side confirmed definitively.
3. Dump CP memory (`/dev/cpmem`, rdp/ramdump paths in `rdp_init`) → resolve the
   runtime sacCi tables against `ARBI.img` base 0x06480000 → locate the primId-0x2C
   handler → read the actual policy check (code or NV-loaded flag).
4. If NV-flag: flip it. If code: one-byte patch class (see feasibility).

## 7. Patch feasibility & integrity model (mission Q3 context)

Secure-boot assessment (static, kit B02):
- The TIM manifest module index contains **CRCS** (CRC module) and feature flags
  (Phee/CPSR/HAWK/IMSD/PROD/PIPE/FAST3), plus one **ENCK** module in TIM4
  (@+0x9C, carrying ~0x80+ bytes of key-like data). **No KEYM/SIGM/CERT modules**
  — no RSA/x.509 signature chain is described by the manifest.
- OSLO (bootloader, U-Boot-based) strings show only **CRC32** verification
  ("Bad Data CRC", "header crc mismatch", "ISRAM area CRC: expected…actual"),
  plus generic ramdump-signature detection. No RSA/SHA/authenticate strings.
- No ≥128-byte high-entropy (sig-like) spans in TIM4/TIM1/timheaders.
- Conclusion: **integrity = CRC32-level, secure boot NOT evidently enforced** in this
  kit. Modifying ARBI and reflashing via the ZAS/Sahara path would face CRC (fixable)
  rather than crypto — BUT the live B12 may differ, and modem-brick risk (no recovery)
  makes this a last resort per campaign constraints. The primary path remains
  runtime-data modification (NV/config via ADB/diag), not firmware patching.

## 7b. DIAG surface (second live primitive besides ADB)

`/bin/diag` (modem Linux, auto-started with telephony) exposes a service-ID-based
diag protocol over `/dev/diagdev` with capabilities including:
- **cpdump** — CP memory dump machinery ("cpdump: diag buffer…", ramdump slots)
- **CPMRDFileRead / MRD read from flash** — modem RAM-dump region reads
- **arbitrary write**: "Write to addr:0x%lx with value:0x%lx" (calibration-class)
- `/dev/cpmem` — direct CP memory device node
The USB `marvell_diag` gadget function carries this protocol to the host (present in
B02 compositions incl. production boot). If B12 keeps marvell_diag, the ROUTER can
reach diag without ADB — a second path to CP memory/NV (relevant if B12's adb
composition differs from the kit's).

## 7c. Live B12 acquisition & verification plan (staged, read-only first)

CI open-logical-channel request struct (as built by atcmdsrv `SIM_RestrictedAccess`
@0x46FCC / transformed by @0x5FA44) — needed for any direct `/dev/ccidatastub` client:

```
+0x00  u16  primId (=0x2C)
+0x02  u8   sub/flags (2 for RUN_GSM path)
+0x03  u8   req type (0x20 seen)
+0x66  u8   selector/len byte (0x88 in RunGSM; 0xB2/0xDC/0xC0 app-cases in wrapper)
+0x67  u8   file path element count
+0x68  u8   path len2
+0x69  u8   AID/path length (present flag: 0xFF = absent?)
+0x6A..    path/AID bytes (up to 0x66 copied by wrapper)
+0x105 u8   path component
+0x16A u8   aid-present (1 if r7>0)
+0x169 u8   flag (1/0)
+0x16C u16  session id
```
(Send via ciRequest(handle, prim, ctx, req, …) → ioctl on /dev/ccidatastub; the
kernel side validates a "cci magic" on ioctl. Exact ioctl numbers still to be
extracted from the kernel driver — string `ccidatastub_ioctl: cci magic number is
wrong!` located in vmlinux.bin.)

Transport refinement (PLT/GOT analysis): atcmdsrv imports `ioctl` (GOT 0xB1430,
PLT stub 0xB2B0) but has **ZERO callers** — the CI client does NOT use ioctls.
`ciClientStubInit` (ci_stub/src/ci_client_ttc.c) opens /dev/ccidatastub and spawns
a reader thread; requests are queued (`ciShRequest_1`, svcIdx-5/6 special-cased)
and written as framed CI signal structs by a writer task. Wire format = the same
structs the CP dispatcher parses ({svgId@0, primId(u16)@+4, handle@+8, data…}).
A direct client therefore only needs open()+write()+read() with correct structs —
the kernel "cci magic" check applies to the kernel ioctl path, not the data path.
The AP-side prim-0x2C wrapper @0x5FA44 was decompiled (`atcmdsrv-prim2c-wrapper.c`):
it is a **SELECT-path normalizer/request transformer** (parses path at req+0x6A,
rebuilds ops 0x10/0x16/0x31, composite keys 0x6F3B/0x6F3C/0x6F4B) — plumbing with
no AID-value policy, corroborating that no AP-side ISD-R denial exists.

1. Router-side recon: `lsusb`-equivalent (sysfs) for the modem's interfaces on B12
   (composition, adb fn present?), `/dev/cdc-wdm0` QMI svc list, AT `AT*PROD?` /
   `AT^ZVERSION?`-class queries.
2. If adb fn present: `adb devices` from router (android-tools) or usbip to bench →
   root shell expected (empty property store ⇒ insecure adbd) →
   `cat /etc/mversion /tmp/prod_mode`, `cfg show`, `ps`.
3. CP runtime resolution (tool ready: `cp_resolve.py`):
   read u32@0x0660dd1c → [sim0 tbl] → entry 0x5B = open-channel handler;
   read bytes@0x06600064+0xB2C (cfg feature bits); u32@0x0660db30 (data base);
   then disassemble the handler from the live dump.
4. NV policy hunt: `nvmproxy`/NVMC files (UBI OEMD area), `cfg_service.db`,
   any euicc/sim policy items; diff against factory-blank kit image.
5. Direct CI test (needs ccidatastub client — build from atcmdsrv's own struct
   layouts in §3): send CI prim 0x2C with ISD-R AID bypassing AT/QMI layers;
   observe CIRC result → definitively localizes the denial.
6. Only after all read-only steps: consider a test flip of a candidate NV flag
   (reversible, documented) — NOT firmware modification.


## 8. Tooling produced (this directory)

- `fbf_parse.py`, `fbf_crc_probe.py`, `extract_fbf.py` — container parse + carve.
- `dump_at_table.py` — atcmdsrv AT-command table enumerator.
- `arm_annot.py` — Thumb disassembly w/ literal+string annotation (objdump-based).
- `find_str_xref.py`, `find_adr_refs.py`, `thumb_refscan.py` — pc-relative ref scanners.
- `find_sim_handlers.py`, `qmi_circ_trace.py` (Ghidra) — atcmdsrv targeted decompiles.
- `arbi_targeted.py/2/3.py` (Ghidra) — selective ARBI region disassembly+decompile
  (sac_shell_engine + sac_sim + sac_dev regions; produced the dispatcher trace §5).
- `cp_resolve.py` — **live CP dispatch-chain resolver**: given a runtime memory
  fragment set or full CP dump, resolves `*[0x0660dd1c][sim]→tbl→tbl[0x5B]` handler,
  cfg feature bits @0x06600064+0xB2C, and disassembles the result.
- `live-probe.sh` — staged read-only live checks (router + adb).
- Outputs: `atcmdsrv-sim-decomp.c`, `atcmdsrv-circ-qmi-decomp.c`, `arbi-sac-decomp.c`,
  `arbi-sacsim-decomp.c`, `arbi-dispatcher.c`, `arbi-strings.txt`, `zimg-strings.txt`,
  `libmarvellril-strings.txt`, `at-table.txt`, `extracted/` (all partitions +
  sysj-root rootfs + vmlinux.bin).

## 9. Open items

- QMI UIM handler mapping inside atcmdsrv (which handler serves msg 0x0042 and whether
  it adds any check before forwarding to CI prim 0x2C) — registry found; the
  per-service handler table and a 100-entry `{enabled,key,value}` map seen in the
  confirm path are both **.bss/runtime-initialized** (0xC73E8/0xCC53C/0xC6C24 are
  beyond the file-backed segment) — the entire platform follows one pattern:
  dispatch tables and policy-shaped maps are boot-time data, invisible statically.
  Settles definitively into the live-dump plan (§7c).
- Exact sacCi open-logical-channel policy check (§5) — needs live CP/NV dump (ADB).
- B12 (live unit) modem-firmware acquisition: the B02 kit ≠ B12; if ADB lands, the
  live ARBI/partition dump supersedes the kit image for exact-code analysis.
- `*USBT:(0,1)` semantics (USB test toggle) — table row layout at that offset differs;
  low priority.


