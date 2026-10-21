# D-Link Recovery-Flash Runbook — consolidated operational checklist

Scope: **D-Link COVR-X1860 A1** (primary species; the one-request recovery-server
class). Consolidates the 2026-10-14/15/16 bench sessions into one operational
procedure. Species-level by design — operator-private rig specifics (hostnames,
tunnel endpoints, port maps) live in bench session logs and the bench repo's
AGENTS.md, not here.

Evidence base: `models/dlink-covr-x1860-a1.json` `bench_observations`
(commits `8269043`, merged as PR #198 `9edb378`), AGENTS.md
"D-Link Recovery Flashing" (commit `3462db4`), issues #91 / #228 / #229 / #230,
`recipes/dlink/covr-x1860/notes.md`, `scripts/flash/upload.py`,
`scripts/flash-recovery.sh`, `scripts/flash/chromium_upload.py`
(real-Chromium driver: browser-cache drift fallback, local-form
first-request-POST default, outcome classification).

---

## 1. When to recovery-flash (and when not to)

| Unit state | Use | Do NOT use | Why |
|---|---|---|---|
| Running OpenWrt, SSH works | `conwrt flash` sysupgrade path | recovery-http | sysupgrade is ~3 min and keeps config options available (README "Flash Methods") |
| Stock firmware, web UI reachable | recovery-http (this runbook) | `dlink-hnap` | HNAP upload succeeds but `GetFirmwareValidation` rejects OpenWrt images — **no successful HNAP flash has ever been recorded** (README "D-Link HNAP Flash Method"; recipes notes) |
| Dark, no auth, red-blinking (recovery mode) | recovery-http (this runbook) | — | the only network door on this species |
| Recovery HTTP accepted-but-never-boots repeatedly | serial ladder (last resort) | another HTTP attempt | Sept matrix suspects unit-specific NAND-write corruption in the U-Boot recovery writer; serial is the discriminator (`bench_observations.upload_client_sensitivity`) |

Full decision tree: `docs/process.md` §12. Serial-first principle when any
serial path exists: AGENTS.md "Serial-First Recovery Principle".

## 2. Hard rules (each paid for in bench hours)

1. **The recovery HTTP server answers exactly ONE request.** Any GET burns the
   window; afterwards every new SYN is RST. Detect arming by ARP only.
   (AGENTS.md 2026-10-14/15 rule 1; `bench_observations.bench_switch_recovery_rig_2026_10_14`)
2. **Upload with a real Chromium** (headless Playwright) posting a LOCAL form so
   the multipart POST is the first request. curl/WebKit-shaped bodies were the
   Sept #91 eliminators, but the Oct matrix proved the client was never the
   variable for stock images — never blame the client without a pcap.
   (AGENTS.md rule 2; `scripts/flash/upload.py:69-99` documents the
   curl-multipart hazard and a `client="webkit"` option)
3. **Dual-image boot takes 15–20+ minutes** (main→backup copy + double reboot).
   Do not declare failure before ~25 min of silence; watch 45+ min on
   first-seen units. (AGENTS.md rule 3; `bench_observations.dual_image_boot`,
   `recovery_flash_matrix_2026_10_14`: one unit booted at ~17 min)
4. **ASU profile names use DASHES in the model part**: `dlink_covr-x1860-a1`.
   The all-underscore registry form returns HTTP 400 "Unsupported profile".
   (AGENTS.md rule 4; check `openwrt.profile` in the model JSON)
5. **Baked dropbear keys go stale.** Rebuild via ASU with the CURRENT fleet key
   before flashing any parked/dark unit — case-sealed, no practical second
   door. (AGENTS.md rule 5; `recovery_flash_matrix_2026_10_14`)
6. **Image format is critical**: U-Boot recovery mode wants
   `squashfs-recovery.bin`, NOT `factory.bin` (factory via recovery caused
   red-LED boot failure on some units; OpenWrt commit `0a18259e`;
   `recipes/dlink/covr-x1860/notes.md` "Image format is critical").
7. **Recovery mode is time-boxed**: the server exits recovery ~5–8 min after
   entry; a late-started flash finds stock firmware instead
   (`bench_observations.recovery_idle_timeout_seconds`).
8. **Both jacks are first-class in recovery, one after boot**: recovery answers
   on either port; booted OpenWrt only speaks on the port labeled "ethernet"
   (LAN). (`bench_observations.ports`; PR #222, open)

## 3. Pre-flight (before touching the unit)

- [ ] **Image freshness**: rebuilt since the last fleet key rotation. Verify the
      baked key against the CURRENT fleet public key:
      `ssh-keygen -lf <keyfile>` compared with the key you will SSH from.
      (AGENTS.md rule 5; issue #228)
- [ ] **Image flavour**: `squashfs-recovery.bin` for the recovery path
      (rule 6 above). Sourced via `conwrt image --model-id dlink-covr-x1860-a1`
      or ASU profile `dlink_covr-x1860-a1` (rule 4).
- [ ] **Image boots**: if the image build is unproven, flash a known-healthy
      unit first or use a cached verified image. (issue #230 body;
      `docs/process.md` "Verify recovery path before starting")
- [ ] **Seat egress**: one recovery-client IP (e.g. the model's `client_ip`,
      `192.168.0.10`) on the seat SVI — **one VLAN at a time, never flip
      mid-upload** (failure table below). (issue #230 body)
- [ ] **Stale-subnet sweep**: delete stale same-subnet secondaries on the seat
      bridge before driving the unit (a stale `192.168.1.x` secondary on the
      switch shadows the jump path — `bench_switch_recovery_rig_2026_10_14`).
- [ ] **Tunnel chain** (if driving remotely): host → bench host → switch →
      `192.168.0.1:80`, self-healing launchers per AGENTS.md
      "Long-Running Remote Work Dies With Its Pane". Specifics: bench session
      logs / bench repo AGENTS.md.
- [ ] **DHCP responder**: dnsmasq on the seat SVI with a leasefile (boot
      watcher path 2). Exactly one DHCP authority per segment — the unit's own
      default dnsmasq must NOT be live on a shared segment
      (AGENTS.md "Rogue-DHCP Discipline").
- [ ] **PCAP**: tcpdump on the seat VLAN for byte-delivery verification.
- [ ] **Boot watcher**: all three paths — static `192.168.1.1` (ethernet/LAN
      port), DHCP lease from the responder, source-MAC appearance in the pcap.

## 4. Arming and flash (unit blinking red = recovery mode live)

LED language (`bench_observations.led_language`): red blink = recovery mode;
red constant = failed boot limbo (falls back to recovery on next power cycle);
orange blink = OpenWrt starting; white constant = OpenWrt up.

- [ ] Enter recovery: hold the recessed reset button (under the unit) while
      powering on; wait for red blink. (recipes notes "Reset button")
- [ ] **Detect arming by ARP ONLY**: `ip neigh | grep 192.168.0.1` — the
      recovery server uses the model-wide soft MAC `3e:85:be:87:55:42`
      (locally administered). NEVER GET the page (rule 1).
      (`bench_switch_recovery_rig_2026_10_14`)
- [ ] `scripts/flash-recovery.sh` now probes ARP-only by default
      (`FORCE_HTTP_PROBE=1` restores the GET probe for GL.iNet-class
      multi-request servers) — still NEEDS-BENCH-VERIFY on this species
      (§8 reg#1) before it replaces the manual `ip neigh` check above.
- [ ] Fire headless Chromium (Playwright) against a LOCAL form so the multipart
      POST is the first and only HTTP request (rule 2). Post the
      `squashfs-recovery.bin` to the upload endpoint.
- [ ] **Verify delivery**: HTTP 200 + pcap byte count == image size on the wire
      (issue #230 body). HAR + pcap recorded to the bench evidence dir
      (`recovery_flash_matrix_2026_10_14`).

## 5. Boot watch (15–45 minutes — do NOT declare early failure)

- [ ] Expect TWO reboots: kernel from main image → main→backup copy → reboot →
      OpenWrt (`bench_observations.dual_image_boot`).
- [ ] Watch all three paths (§3) for 45+ min on first-seen units before
      concluding failure (rule 3; ~17 min observed, 30+ min silence on the
      failing stock-image case).
- [ ] Boot signature: ARP appears with the unit's REAL MAC (distinct from the
      soft MAC), then ICMP, then SSH banner.

## 6. Post-flash validation

- [ ] **SSH from a fleet-key host** (the bench switch is not one — issue #230
      body). Expect the #229 pitfall below.
- [ ] Confirm identity: MAC/serial against the specimen record before any
      further state change (AGENTS.md "Verify the SPECIMEN, Not Just the Model").
- [ ] Rogue-DHCP check: a fresh unit bridging onto a shared segment must have
      `dhcp.lan.ignore='1'`, `dhcp.lan.ra='disabled'`, `dhcp.lan.dhcpv6='disabled'`
      — read back the values (AGENTS.md "Rogue-DHCP Discipline").
- [ ] Set the static seat IP + gateway per the seat plan; update the lab
      registry / exporter so the unit is visible (bench repo tooling; AGENTS.md
      "Lab Single Source of Truth").
- [ ] Close the loop: pcap byte count matches the image size (evidence trail).

### The #229 pitfall — SSH lockout with a CORRECT key (root-caused; fix in PR #235)

Recovery-flashed bare-config images boot, ARP+ICMP answer, and SSH still
rejects the exact key that was baked in (`Permission denied (publickey)`;
issue #229). Root cause (source-level, PR #235): the ASU firstboot script's
exit status was `uci commit dropbear` (its last line), and OpenWrt's
`uci_apply_defaults` deletes a uci-defaults script only when it exits 0 —
so a lost authorized_keys write was masked by the successful commit, the
script was deleted instead of retried, and the #155 key-only hardening made
the half-applied state a permanent lockout. The recovery flow has no
post-flash SSH repair pass (unlike sysupgrade), which is why only this
path showed it. Fix: verify-gate (`grep -qF <key> || exit 1`) before the
hardening lines — failure now retains the script for a next-boot retry.

Mitigation ladder (updated):

1. **Images built after PR #235 self-heal**: a failed key write leaves the
   password door open (hardening unreached) and the script retries next
   boot — power-cycle once before diagnosing further.
2. Older images: build WITHOUT `PasswordAuth='off'` in the image's
   uci-defaults until the unit is verified in (keeps the password path and
   the empty-root-password telnet:23 default as candidate doors).
3. If any shell is reached: `ls -ld /etc/dropbear` — non-root-owned or
   group-writable makes dropbear silently refuse ALL keys (AGENTS.md
   Dark-Device rule 7, seen in the wild on image-build artifacts).
4. Post-boot forensics on a locked unit (serial or next flash cycle):
   check whether `/etc/uci-defaults/` still contains the script — a deleted
   script with a missing key is the pre-fix failure signature.

**If locked out**: there is no on-device door without opening the sealed case
(serial header exists on the board — labeled, 3.3 V, 115200 8n1; recipes notes
"Serial") — so the practical recovery is a NEW flash cycle with a corrected
image (rule 5; `recovery_flash_matrix_2026_10_14`).

## 7. Rollback / abort handling

| Situation | Action |
|---|---|
| New SYN RST during arming/upload | Window burned (a request was made) → power-cycle the unit to re-enter recovery; the server also self-exits after ~5–8 min idle (rule 7) |
| Connection reset MID-upload | Egress address flipped VLAN mid-flight — lock the client IP to ONE seat VLAN for the whole flash (§3; issue #230 failure table) |
| HTTP 200, then no boot < 25 min | STILL WORKING — dual-image copy (rule 3). Keep watching |
| HTTP 200, no boot ≥ 45 min, red constant | Power-cycle → unit falls back to recovery mode → retry with a fresh/current image; if it repeats with byte-perfect delivery, stop HTTP attempts (Sept matrix: unit-specific NAND-write corruption suspected) and escalate to serial |
| Locked out after successful boot | See §6 #229 pitfall — new flash cycle; serial only by opening the case |
| Wrong image accepted | No rollback on this species — the flash already happened; re-enter recovery and flash the correct `squashfs-recovery.bin` (rule 6) |

Serial last resort: `scripts/serial-flash.py` bypasses the recovery HTTP
server entirely IF NAND is healthy — **NEEDS-BENCH-VERIFY on this species**
(discriminator named in `upload_client_sensitivity`, never exercised).
Serial procedure: `docs/serial-console.md`, prompts `serial-01`…`serial-06`.

## 8. NEEDS-BENCH-VERIFY register

| # | Item | Source of doubt |
|---|---|---|
| 1 | ARP-only arming probe in `scripts/flash-recovery.sh` — **code-done** (ARP default, `FORCE_HTTP_PROBE=1` escape hatch for GL.iNet-class servers); on-device confirmation still NEEDS-BENCH | AGENTS.md rule 1; arming verdict unproven on a live one-request unit |
| 2 | #229 on-device confirmation: recovery-flash an image built after PR #235 and observe the verify-gate behavior (self-heal on next boot, or lockout-free harden) | root-caused at source level; the physical flash is bench work |
| 3 | serial-flash NAND bypass on this species | never exercised; case-sealed |
| 4 | Stock-image accepted-but-no-boot root cause (NAND write corruption vs bootloader-variant reject) | Sept elimination matrix + Oct matrix attempt (1) |
| 5 | Exact boot-latency distribution beyond "17 min observed, 45+ min watch" | two data points |

## 9. References

- Issues: #91 (recovery upload accepted-no-boot), #228 (trust-on-first-boot),
  #229 (uci-defaults authorized_keys lockout), #230 (this runbook), #221/#222
  (dual-port doctrine, open PR)
- PRs: #198 merged `9edb378` (flash matrix + rig lessons, commits `8269043`,
  `3462db4`)
- Files: `models/dlink-covr-x1860-a1.json` (`bench_observations`),
  `recipes/dlink/covr-x1860/notes.md`, `scripts/flash/upload.py:30-104`,
  `scripts/flash-recovery.sh`, `docs/process.md` §12,
  `docs/DARK-DEVICE-PLAYBOOK.md` (adjacent methodology)
- Operator-private rig specifics: bench repo AGENTS.md + bench session logs
  (referenced from `bench_observations.evidence`)
