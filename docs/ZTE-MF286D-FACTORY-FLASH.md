# ZTE MF286D — factory-mode flash (SUF/ZAS kit path)

Status: **RE complete, live bring-up in progress** (Nov 2025). Device: ZTE MF286D
(MDM9650 module), stock web 192.168.0.1 → factory linux 192.168.32.1 → download
mode (ARPs for its tool host). Kit: ZTE_Sales_Update_Framework (ZTSUF) community
build with `BL_DL_LTE_QualComm_Net.dll` + `BusinessCfg/MF287+-DL-BackUpNV-N-01_DL.config`.

Companion docs: [ZTE-MF286D-RE-FINDINGS.md](ZTE-MF286D-RE-FINDINGS.md) (full
disassembly evidence, addresses) · [ZTE-MF286D-RUNBOOK.md](ZTE-MF286D-RUNBOOK.md)
(step list). Tools: `scripts/zte_factory_tftp.py`, `scripts/zte_cfg_decrypt.py`,
`scripts/zte_ike_responder.py`.

## Flow (validated pieces bold)

1. **Stock web (192.168.0.1):** fetch `wa_inner_version,cr_version,RD` →
   **`SwitchFactoryMode&SwitchCMD=Open` with `AD=md5hex(md5hex(wa+cr)+RD)`**
   (lowercase hex; wa value truncated at first `]`) → re-fetch RD → REBOOT_DEVICE.
   Device boots into factory linux at **192.168.32.1** (web pw `admin`).
2. Factory web: same AD recipe; `Query` → `OPENED`; `get_current_version` works.
   **Do NOT send REBOOT_DEVICE here** — stock-only verb, returns failure by design.
3. **Download mode:** after factory-mode arming + power-cycle the device's agent
   ARPs for its tool host at **192.0.0.1** (hardcoded default of
   `ITEM_TFTP_SERVER_IP` in the plugin; the kit config has no override) and pulls
   from **UDP/69**: `armprg.bin` via TFTP, then Sahara (device-initiated HELLO,
   tool replies HELLO_RESP, READ_DATA serves armprg; stage-2 HELLO ≤8×1 s after
   DONE) → firehose flash per `UPDATE/zte_dload_boot.xml` partition map.
   The tool NEVER initiates UDP and never uses broadcast — the device talks first.
4. **Config crypto:** `BusinessCfg/*_DL.config` = 20-byte header
   (magic `690e3214` | crc32 | plainlen | IV) + **3DES-CBC** (16-byte 2-key key
   `0dcf8cd088bb47e190f591f3a5a62a4c` hardcoded in `get.public.setting.dll`
   @0x21a28040). Decryptor: `scripts/zte_cfg_decrypt.py`.

## Gotchas (cost us hours)

- **Tool host must own 192.0.0.1 on the device-facing L2** — anything else on
  the segment answering that ARP steals the download session.
- Single-NIC discipline on the tool host (community-proven; matches the DLL's
  adapter handling). Extra bridges/aliases break it.
- The kit's updater phones home IKE (vendor exchange 0xF3) to `cndms.ztems.com`
  — harmless noise; `scripts/zte_ike_responder.py` answers/logs it.
- `ITEM_DOWNLOAD_FILElIST` is empty in the kit configs — the real flash manifest
  is `UPDATE/zte_dload_boot.xml` + `SHA256SUMS2` + `pstcrc.txt`.
- Sahara cmd 0x39: this tool build refuses it ("SW donot support cmd_0x39") —
  if a device demands 0x39 you need a newer programmer/tool pair.
