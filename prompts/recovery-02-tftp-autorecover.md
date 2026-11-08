# No-serial TFTP recovery (staged-server runbook)

Use when a no-serial NAND device fails to boot its main system and the species has a
bootloader auto-TFTP recovery mode (worked example: ZTE MF286D — U-Boot pulls
`root_uImage` from a server at 192.0.0.1/8 when the kernel is unbootable; verified
against bootloader disasm, documented on the MF286 sibling). Generic enough for any
"bootloader pulls a fixed filename from a fixed server IP" species.

## Preconditions (from the species notes / model JSON)

1. The recovery filename, the bootloader's expected server IP, and the subnet are
   KNOWN (disasm/wiki — do not guess).
2. A known-good image for that filename exists and is hash-verified (stock template
   or the community/official image, per the recovery goal).
3. Run `prompts/brick-risk-audit.md` first — recovery writes are flash writes too.

## Runbook

1. **Isolate the link**: bench interface directly to the device, nothing else on that
   L2 (the recovery server address is often a whole /8 or a subnet you must own
   exclusively during the window).
2. **Stage the server** (one terminal, stays up for the whole session):
   - Assign the expected server address(es) to the bench interface (e.g.
     `192.0.0.1/8` plus any fallbacks the species tries).
   - Serve the image directory over TFTP/UDP :69 with full logging. Reference
     implementation: `dload_client.py --listen --ifaddr <addr> --tftp-root <dir>`
     (RFC2348 blksize/OACK, logs every RRQ).
   - Optional but recommended: a full-window packet capture with a visible positive
     control (see observer discipline in AGENTS.md).
3. **Trigger the recovery boot**: species-specific — usually "make the main kernel
   unbootable state persist + reboot" (the bootloader detects it) or a
   recovery-mode flag/button. Never *create* the unbootable state without a verified
   backup of the region you're invalidating.
4. **Observe**: device ARP for the server address → RRQ for the recovery filename →
   transfer → device self-flashes → reboot. Do not power-cycle during the transfer.
5. **Verify**: device boots; identify the running build; record ledger row
   (hypothesis/observer/verdict/evidence).
6. **Tear down**: remove the recovery addresses from the bench interface (they can
   conflict with real networks — a /8 on 192.0.0.0 especially).

## Failure branches

- No ARP from the device: the bootloader may expect a different server address or the
  trigger condition isn't met — capture first, conclude second (do not flap power;
  bounded cycles only, per Escape-Hatch Discipline).
- RRQ for an unexpected filename: serve it if a verified image matches that name;
  otherwise log it, do NOT improvise an image.
- Transfer loops: suspect NAND bad blocks (species with known bad-block sensitivity:
  check the species notes) or a truncated image (re-verify sha256 against the source).
