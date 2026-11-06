# RUNBOOK — MF286D factory flash, Linux side (single-NIC discipline)

Files: work in /tmp/opencode/ztsuf/work. Firmware root: ztsuf/UPDATE/ (armprg.bin,
e_armprg.bin, NPRG9x55.mbn, sbl1.mbn, rpm.mbn, uboot.bin, *.ubi/.ubifs, FOTA_FS/).

## 0. Pre-flight (community-proven: Skubi, eko.one.pl thread 22831 post #9)
- ONE active interface facing the device; bring down/ignore every other L3 path
  (extra bridges, the .82.3 alias netns, docker/veth). The ZTE tool fails exactly
  like ours when multiple adapters are up; same physics applies to us.
- Confirm: device factory web 192.168.32.1 answers; we are 192.168.32.2 (same IP
  the device sees as HTTP source — the agent pulls toward the IP it knows).

## 1. Start the server stack BEFORE arming
  sudo python3 factory_tftp.py --bind 192.0.0.1 --port 69 --root ztsuf/UPDATE/  # download-mode agent ARPs for 192.0.0.1 (ITEM_TFTP_SERVER_IP default)
  # (optionally, on another box/if: python3 ike_responder.py --bind 192.168.82.3)

## 2. Arm factory mode (already live-proven)
  1) GET cmd=Language,cr_version,wa_inner_version&multi_data=1
  2) GET cmd=RD                                  (32-char RD)
  3) POST SwitchCMD=Open  + &AD=md5hex(md5hex(wa+cr)+RD)   # lowercase; wa truncated at first ']'
  4) POST SwitchCMD=Query → OPENED               (sanity)

## 3. Trigger: do NOT send REBOOT_DEVICE (stock-only verb; fails here by design).
  Power-cycle the device. Watch factory_tftp log:
    - [RRQ] filename=...   → serve, then expect Sahara HELLO (stage-1) on UDP
    - [UDP-NON-TFTP] maybe-sahara cmd_le=0x1 → stage-1 HELLO; reply HELLO_RESP
      (01|ver|len ... mirror; then serve armprg via Sahara READ_DATA loop)
    - after armprg DONE: device reboots into programmer; second HELLO within
      8×1 s (tool model) → firehose stage (zte_dload_boot.xml partition flow)

## 4. If no RRQ within ~60 s of power-cycle
  - try e_armprg.bin name too; log the EXACT requested filename (config mismatch
    string in tool: "The file name is different") and alias it in UPDATE root
  - re-run Open (tool retries 120×2 s itself; arm is idempotent)
  - last resort: bootloader TFTP recovery (hold reset at power-on, MF283+-style)

## 5. Notes
  - Item defaults: TFTP 69, monitor 15 s, urg-result timeout 45 s, hello retry 8×1 s.
  - IKE to cndms.ztems.com = tool self-updater noise; ike_responder.py silences/observes it.
  - RE evidence & addresses: RE-FINDINGS.md.
