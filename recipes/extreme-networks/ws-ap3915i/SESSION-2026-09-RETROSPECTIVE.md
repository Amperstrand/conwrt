# Session Retrospective — 2026-09-21 (rescue + lan3/lan4 flash session)

Two sessions in one day: the bench rescue investigation (morning) and the
lan3/lan4 flash campaign (evening). Outcomes: lan4 = validated self-booting
24.10.2 success; lan3 = 25.12.2 on flash but wedged (recoverable); five stuck
units characterized; the bench's architectural flaws mapped and worked around.

## What happened (arc)

1. Found the testbed: ERX home router -> GS1900 (per-port VLANs) -> four AP3915i.
2. Morning: diagnosed lan6/7/8 (stuck from the May era) — kernel-alive but
   network-dead (lan7/8), fully dark (lan6). Exhausted every remote probe;
   serial is the only remaining channel for them.
3. Evening: user plugged two STOCK AP3915i (lan3/lan4). Detected via LLDP + OUI
   + DHCP behavior. Flashed lan3 to 25.12.2 (complete pipeline worked), but
   flash-BOOT failed through 5 variants. Pivoted to lan4 with the PROVEN tuple
   (24.10.2 + May-exact env): complete success, verified with TFTP down.
4. lan3 parked in the stock-script loop (variant C mistake), self-heal TFTP armed.

## Lessons learned (technical)

1. **The proven tuple is version-coupled**: `run boot_openwrt` flash-boots
   kernel 6.6 (24.10.x) but not 6.12 (25.12.x) on this 2012 U-Boot family.
   FIT forensics (gzip, same load/entry, same structure) don't explain it;
   tftpboot+bootm works for BOTH. Root cause requires serial visibility.
2. **Semicolon fallback tails only catch RETURNING commands.** A sourced stock
   script ending in `reset` never falls through. This is May's "Critical Error"
   repeated in September — the knowledge existed on disk and was still stepped on.
3. **The stock boot script lives in BootPRI** (readable from OpenWrt: dd mtd4 |
   strings): dual-image for-loop over ${order}, bootargs recomposition from
   mtdparts+static_bootargs, watchdog arming gated on WATCHDOG vars.
4. **Unzoned runtime VLANs silently drop inbound UDP** (fw4 default-drop):
   every TFTP/DHCP server "mystery" of the day traced to one missing nft rule.
5. **Same subnet on many VLANs = routing by insertion luck**; /32 route pins
   are the workaround, per-port subnets are the fix.
6. **dnsmasq lifecycle on the switch**: procd respawns the system instance;
   private instances stack and die on port conflicts; the system instance
   carries a bench-era 192.168.1.200-250 pool. Stop via init script, then run
   exactly one named-pidfile instance per active VLAN.
7. **Package-manager era map**: kmods at targets/<t>/generic/kmods/<hash>/
   (not the arch feed). 24.10=opkg (`--force-depends` on initramfs);
   25.x=apk (`--allow-untrusted --force-non-repository` on tmpfs).
8. **Old-stock quirk inventory**: service shell reboots ~5min without a
   controller; stock sshd hangs at banner intermittently (retry loop needed);
   stock tftp client works ONLY after the firewall rule; stock BusyBox lacks
   base64/od (use tr-based env extraction + printf-octal push).
9. **Discriminators that worked**: port-netdev tcpdump beats brctl (hardware
   FDB offload hides CPU traffic); PoE current telemetry distinguishes
   boot-loop (sawtooth) from idle-stuck (flat); HTTP is the only proof of a
   real boot (U-Boot answers ping during net loops); mount's upperdir
   (/tmp/root = initramfs, /overlay = flash) identifies what booted.
10. **CFG partial-write trick**: flashcp on a short file leaves the erased
    tail as 0xFF = the spec's padding — push only ~1.6KB of env, verify with
    a full-64K readback md5.

## Lessons learned (process) — the expensive ones

11. **`cmd | tail; echo $?` reports tail's exit code.** This faked TWO success
    gates (apk, opkg) and cost hours. Hash/readback gates never lie.
12. **Grep is not reading.** SESSION-WRITEUP.md contained both the exact
    failure mode (variant C) and its recovery; sampling the file with greps
    missed the warning that mattered.
13. **Proven-before-novel.** 25.12.2 was chosen for modernity before the
    24.10.2 recipe was validated on untouched hardware. lan4's clean run shows
    the cost of that ordering: one wedged unit + an evening of forensics.
14. **Fresh-boot = new dropbear host keys on initramfs** (RAM keys) — clear
    the known_hosts alias between sessions; flash-rooted boots stabilize keys.
15. **/tmp is RAM**: staged artifacts die with every reboot — re-stage after
    each cycle (bit us on the kmod + final-CFG phase).

## Would do differently

1. Read the full prior post-mortem BEFORE the first write to flash.
2. Validate the documented recipe on one unit end-to-end (24.10.2), THEN
   experiment with newer images on the next unit.
3. Buy the serial adapter before deep bootloader work — it converts every
   "which phase failed" mystery into a one-second log read. (All five stuck
   units + the sf-read root cause are serial-away from resolution.)
4. No exit-code gates behind pipes, ever; readback-or-nothing for flash writes.
5. Build the bench rig as tooling (flash-rig.sh: VLAN L3 + nft rule + dnsmasq
   lifecycle + space checks) instead of re-deriving it per session.
6. When a variant test needs "TFTP down" for discrimination, arm a cron/loop
   that re-arms TFTP automatically after the observation window — recovery
   should never depend on remembering.

## Artifacts

- NO-SERIAL-FLASH-24.10.2-VALIDATED.md (the recipe)
- AGENTS.md: "AP3915i No-Serial Flash" section (8 rules) + earlier
  "U-Boot Env Writes" section
- data/inventory.jsonl: [15-17] stuck units, [18] lan4 success, [19] lan3 parked
- data/sessions/: rescue + flash session records (gitignored)
- SERIAL-RESCUE-2026-09.md: the stuck-units runbook (serial pending)

## Post-script addendum: the misdirected-strikes incident (late evening)

While hardening the autonomous stabilization watcher for lan3, two compounding
process bugs caused every strike to hit **lan5** (the healthy reference unit)
instead of lan3 for ~15 minutes:

1. **Automation inherited ambient routing state**: the switch's `192.168.1.1/32`
   route pin pointed at lan5's VLAN (left over from the BootPRI dump). The
   watcher polled and struck through that pin. Four strikes, all wrong unit.
   FIX (v3): the watcher sets its own route pin EVERY iteration — automation
   must own its routing prerequisites, never inherit them.
2. **Abort paths that don't abort**: expect failure branches printed "ABORT"
   but fell through to the reboot send — rebooting the WRONG unit twice.
   lan5 absorbed both (flash-booting design self-recovered — the architecture
   paid for the mistake). FIX: every failure branch exits.

Damage: none (lan5 self-booted back; the strikes failed harmlessly on missing
files; lan3 was never touched — its meta-loop continued). Diagnosis keys that
exposed it: `apk: not found` (target ran 24.10.2, not 25.12.2), staged files
"missing" despite scp success, and a CFG1 readback hash matching none of our
blocks (it was lan5's own env, md5 98c26c66...).

New rules: (a) watchers own their prerequisites; (b) abort means exit; (c)
identity verification BEFORE any write (the v3 expect now prints
`system board` description and the operator can see which unit they're on).

## Final addendum: the matrix cell closes - the model INVERTS (end of session)

The decisive experiment ran late: lan3 (safe env restored, then sysupgraded to
24.10.2) failed the TFTP-down flash-boot test on 24.10.2 exactly as it had on
25.12.2. Combined with lan4 (different bootloader build) flash-booting 24.10.2:

**Flash-boot capability is a property of the unit's bootloader build, not the
image/kernel version.** The earlier "6.12 regression" theory was wrong. lan3's
Aug-2017 primary build cannot sf-read-flash-boot anything; it is permanently
TFTP-fallback-dependent (deterministic, 40s recovery, no watchdog involvement).
25.12.x flash-boot on healthy-bootloader units is untested - the lan4 upgrade
question reopens with a corrected prior.

Also: the "FLASH-BOOTED@5s" fast-ping/HTTP pattern struck THREE times tonight -
it is always the lingering pre-reboot session. Post-reboot verification must
wait past the boot time (60s+) or check uptime.
