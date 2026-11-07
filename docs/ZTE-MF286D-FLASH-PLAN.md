# FLASH-PLAN — audited end-to-end plan for OpenWrt on the one-shot MF286D (B09/Nordic-B10)

Status: FINAL DRAFT for coordinator sign-off. Sources: RE-FINDINGS, UBOOT-ENTRY,
POSTMORTEM, ADVERSARIAL-REVIEW, USB-ANALYSIS, live observations. All RE claims have
file:offset evidence in those docs.

## 0. TOOLING DECISION — Linux-native ONLY (no Windows VM, no wine)

**Decision: flash with our own hardened TFTP server on Linux. Do NOT use the Windows VM
or wine ZTSUF tool for the flash.**

Rationale (all verified):
1. The Windows tool is NOT required by the device — the U-Boot download engine talks
   plain TFTP to a hardcoded 192.0.0.1:69 (uboot.bin: server string + own-TFTP init
   [g+0x8c]=69, UBOOT-ENTRY §1c). The ZTSUF tool merely re-implements what our
   200-line server does.
2. wine path is BROKEN today: the tool hard-crashes without cndms.ztems.com
   ("Check update fail." + page fault — observed twice, ADVERSARIAL-REVIEW §1),
   needs the fake-cndms stack + single-instance discipline just to START, and its
   TFTP-on-RRQ filename behavior is unverified.
3. The tool's Start button drives the DANGEROUS path (zte_dload_boot.xml = SBL/TZ/RPM
   modem chain, POSTMORTEM S4 / ADVERSARIAL-REVIEW §5). We never want it one click away.
4. Windows VM oracle is RETAINED as a read-only fallback (see §6) — only if the
   Linux-native trigger fails and we need to observe the tool's handshake.
   Setup recipe for that fallback is documented (cndms_fake.py + ike_responder.py +
   hosts entry + stop any prior instance via its recorded PID).

## 1. Prereqs (checklist, from POSTMORTEM priorities)

- [ ] S2 FENCE: exactly ONE UDP :69 listener, bound to 192.0.0.1 ONLY; filename
      whitelist = { root_uImage }; everything else logged+refused. Re-verify:
      `ss -ulpn | grep :69` shows nothing else on any IP.
- [ ] Served file: ztsuf/UPDATE/root_uImage, sha256
      01f6f7bc310c26e5bbee5992aa79dbf4e5683a0f40226152ad307c92f02071d3 at serve time
      AND re-hashed after transfer. (root_uImage_s stays UNSERVED — different mode.)
- [ ] Bench host: single NIC to device, owns 192.0.0.1/32, ARP winner vs 0e:77:…
- [ ] tcpdump full session to pcap (only progress display we have).
- [ ] Probe ledger running (timestamped list of OUR outbound :69 packets — for S6 rule).
- [ ] S3 bench test done: server passes both OACK-path and plain-512 fallback against
      a real tftp client.
- [ ] Power stable; nobody else on the segment; no second TFTP anywhere.

## 2. Trigger sequence (what we actually send)

VERB AUDIT (NEW, from the real stock B09 web `/tmp/opencode/sq_s/usr/bin/goahead`,
uClibc ARM 2019-10-29, strings @0x88ecc–0x88f68):
- **SwitchFactoryMode&SwitchCMD = {Open, Query, Close} ONLY. There is NO "Download"
  verb in the stock web.** Any earlier "SwitchCMD=Download" attempt either hit
  FactoryResult:Failed or was accepted by the DIFFERENT E3-rescue web. The plan must
  not depend on it.
- Open semantics (live-proven): arms factory; reboot lands in factory linux
  192.168.32.1 (pw admin). AD = md5hex(md5hex(wa+cr)+RD) — NOTE live correction:
  FULL untruncated wa_inner_version matched, not the ]-truncated variant.
- The U-Boot download mode (ARPs for 192.0.0.1) is entered from hardware/boot state —
  reset-hold during power-on (the live lane's "reset-hold + Open" sequence produced it)
  — NOT from a stock verb. Boot-side decision cluster uboot 0x1cfc4–0x1e650
  ("timer=%lx ha=%x" handshake, self-IP/MAC construction, `run lr`).

Sequence:
1. (Optional sanity) factory web: LOGIN → Query → "Opened" (device already armed — skip).
2. Power-off. Hold RESET. Power-on, keep holding ~10 s (empirical; the E3 entry
   window). Release.
3. Wait for `who-has 192.0.0.1` ARPs (~5.3 s cadence live-observed) → mode confirmed.

## 3. The flash window — expected exchanges and decision points

Mode A (`run lr`, the one we want):
- RRQ filename `root_uImage` (dir= empty; UBOOT-ENTRY §1c). Whitelist serves it.
- 38,797,312 B transfer, negotiated blksize; then SILENT NAND write minutes
  (erase/write 0x1000000+0x800000 and 0x1800000+0x1D00000 — POSTMORTEM S7 says RAM
  safe). DO NOT power-cycle during silence.
- Completion = no re-RRQ for ≥60 s (this mode sends no fin; the fin belongs to the
  blank/zdu flow — UBOOT-ENTRY §1e). Device reboots itself into OpenWrt.
Mode B (zdu/blank — NOT wanted): RRQ `<4-hex>.img` (e.g. 4801A8C9.img style). Our
  whitelist REFUSES it (logged). Response: power-cycle and re-enter via reset-hold;
  if B repeats 3×, fall back to §6 oracle. DO NOT serve root_uImage under an .img
  name unless we consciously choose the zdu path (it validates ZDF01.05 heads and
  would reject our file anyway — no brick risk, POSTMORTEM S4).
Success criteria: Mode A transfer complete + silence + device re-appears (OpenWrt
  default LAN; image is official 22.03.0-rc5 zte,mf286d build — POSTMORTEM S1 audit)
  answering ping/ssh.

## 4. Failure handling (pre-agreed, from POSTMORTEM)

- No RRQ in 120 s after ARPs → power-cycle once; second failure → stop, do NOT improvise.
- Transfer stalls (no ACK progress) >3 min → server keeps retransmitting (client
  re-RRQs per netretry); intervene only by aborting SERVER-side (client falls to error
  state 3 → normal boot attempt; U-Boot survives — S5).
- Never interrupt during the post-transfer silence (write window).
- If device boots stock/factory web again: no harm done, retry from §2.2.
- Absolute worst case (unbootable rootfs): U-Boot still alive (NOR APPSBL untouched);
  re-enter download mode and re-serve the KNOWN-GOOD stock Nordic root_uImage — for
  that, stage `root_uImage.stock` NOW from the Nordic-only kit variant (todo below)
  so rollback never depends on the internet.

## 5. Rollback stock image (pre-stage now)

The kit's root_uImage IS the OpenWrt one (S1 audit). For rollback we need the
**Nordic stock rootfs image** — source: the community "Nordic to Nordic_B11" bundle's
UPDATE/root_uImage (same MEGA folder family the kit came from) — obtain and pin its
sha256 BEFORE the window; serve under the same whitelist entry when rolling back.

## 6. Windows/wine oracle fallback (only if §2–3 fail)

Purpose: observe, not flash. Setup: wineprefix fresh, hosts→127.0.0.1 for
cndms/upgrade/dmeu/dleu.ztems.com, cndms_fake.py :80 + ike_responder.py :500,
stop the prior instance via its recorded PID (single-instance mutex; avoid pattern pkill on shared hosts), xvfb + screenshot + OCR.
Expect: HTTP :80 verbs only (Query/get_current_version), its own cndms traffic.
NEVER click Start (SBL path). If the oracle reveals a required extra trigger verb,
port it to our stack and return to Linux-native.

## 7. Open RE items (parking lot)

- sq_s stock goahead handler internals (Open/Close write what flag where) — binary
  at /tmp/opencode/sq_s/usr/bin/goahead (29 KB libzte_goahead.so is glue). Handler
  RE pending; PIC idiom differs, pool scan inconclusive so far.
- 3535/8787 binder: not in e3root/sq_s/kit dumps (coincidental script hits only);
  identify by live banner probe from bench (read-only) before the window.
- fin packet exact payload (S6) — capture when Mode B ever runs.
- MODE_SWITCH/FACTORY + debugmode echo paths (T-Mobile build) — documented in
  EXPLOIT-ANALYSIS.md, not needed for this plan.
