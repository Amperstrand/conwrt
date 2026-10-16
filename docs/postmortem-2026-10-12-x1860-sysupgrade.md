# Postmortem: the x1860 25.12.5 sysupgrade incident (2026-10-12 → 10-13)

Status: **resolved** — device recovered, root cause fixed in-tree (PR #152),
hardening applied. Redacted per AGENTS.md (placeholders for bench subnets and
unit identifiers; full detail lives in the private registry
`conwrt-lab x1860-1.incident_2026_10_13_recovery` and the local inventory).

## Summary

An operator-authorized `sysupgrade` of the bench COVR-X1860 A1 from 24.10.7
to 25.12.5 (via the first mutating conwrt-2.0 operation, `examples/sysupgrade.rs`)
left the device apparently dead. It was not dead: the flashed image's baked
defaults set `network.lan.ipaddr` **without a netmask**, and OpenWrt 25.12's
netifd defaults a missing netmask to **/32** (24.10 defaulted to /24) — the
device answered ARP for its own address but had **no on-link route to reply**
to anything else. Every v4 probe looked like a dead box. A day of
misdiagnosis ("wedged first boot") ended when a long passive capture caught
odhcpd's 600-second Router Advertisements; recovery went in over IPv6, the
/32 was visible in one line, and a single explicit netmask restored the
device instantly.

Two independent one-line omissions caused everything:
1. `scripts/profile/builder.py` emitted `ipaddr` without `netmask` — latent
   forever, armed by the 24.10→25.12 default change (fixed: #151 / #152).
2. The probe host's bench interface had `disable_ipv6=1` — blinding the
   IPv6 recovery path for ~14 hours.

## Impact

- Device unmanageable over v4 for ~38 h (flash → fix), fully recovered with
  zero data/partition loss (Factory partitions preserved; config had been
  backed up pre-flash; the intended firmware 25.12.5 is running).
- One operator power-cycle into recovery mode (needed for the reflash).
- ~A working session of misdiagnosis and one unnecessary recovery reflash
  (the sysupgraded image was fine except the netmask).

## Timeline (UTC, from logs)

| When | What |
|---|---|
| 10-12 ~15:35 | Unit rediscovered on an unadvertised bench subnet via passive ARP (all *expected* subnets silent — records were stale: unit ran 24.10.7, not the recorded 25.12.5) |
| 10-12 ~17:00 | Read-only ring-3 validation passes (specimen MAC + board identity gates) |
| 10-12 ~19:05 | Authorized sysupgrade: ASU image (host key + static LAN `<bench-A>.60`, **no netmask**), on-device sha256 verified, exit-246 sentinel observed |
| 10-12 ~19:10–20:00 | Device "silent" on every candidate address; sweeps, short listens (8–30 s), v6 multicast probes — nothing. Verdict (wrong): post-flash no-boot. Recovery staged; registry incident recorded |
| 10-12 ~22:45 | Operator power-cycles into U-Boot recovery (flashing red) |
| 10-12 22:48–23:19 | Gated recovery script: 3 iterations (own gate bug failed **safe**; 1.x preflight alias rules; neutral-subnet host address requirement) — then the flasher's already-in-recovery skip path runs |
| 10-12 23:19–23:25 | Recovery reflash: upload accepted, sha256 verified both sides, flash completes +363 s |
| 10-12 23:25 → 10-13 ~13:00 | "Still silent": ARP-alive at `<bench-A>.60`, no ICMP/TCP. Verdict (wrong again): wedged first boot; operator asked for a plain power-cycle |
| 10-13 ~13:07 | **120-s passive listen catches ONE Router Advertisement** (RA interval 600 s — every shorter listen was statistically blind) |
| 10-13 ~13:10 | RA decoded: ULA `fd96:…::/64`, router at `::1`. Host-side blocker found: `net.ipv6.conf.<iface>.disable_ipv6=1` → `0`; host gains ULA+link-local; ICMPv6 answers in 0.8 ms |
| 10-13 ~13:20 | SSH over the ULA with the baked key: board identity ✓, release 25.12.5 ✓, and `br-lan: <bench-A>.60/32` — root cause in one line. `uci show network.lan` has **no netmask entry** |
| 10-13 ~13:25 | Fix: `network.lan.netmask='255.255.255.0'` (readback-verified), commit, reload → `/24`; v4 verified instantly (ping 0.6 ms, dropbear, board/MAC/key-auth all green) |
| 10-13–14 | Bug filed (#151) and fixed (PR #152: five emission sites, regression tests, the incident's own dry-run re-verified); device hardened (key-only dropbear, DHCP suppression); records finalized |

Note on the device's "1d14h uptime" quoted during the incident: pre-NTP
boxes without an RTC lie about time (this one believed it was July). The
true figure — ~38 h — matches continuous uptime since the recovery flash.

## Root cause

`network.lan.ipaddr` was emitted by the profile builder without an explicit
netmask. netifd's default for a missing netmask changed between releases
(24.10: classful /24; 25.12: /32). A /32 on br-lan means the interface owns
exactly one address with **no on-link subnet** — the kernel answers ARP for
that address (it is local) but there is no connected route back to the
sender's /24, so every reply (ICMP, TCP RST/ SYN-ACK, SSH banner) is
unroutable. The box was fully booted, serving IPv6 (RA/DHCPv6/DNS on the
ULA), the entire time.

**Why diagnosis took a day:** the v4 symptom set ("ARP answers, nothing
else") was interpreted as a userspace/boot problem instead of a routing
problem; the v6 recovery door was invisible because the *probe host's* IPv6
was disabled; and the RA beacon fires every 600 s, so every listen shorter
than that (ours were 8–30 s) was blind to it.

## What went well

- Every safety gate held: specimen MAC + board identity before each
  destructive step, config backup pre-flash, both-side sha256, never
  `sysupgrade -F`, `save_partitions` on, gated recovery script whose own
  bug failed **safe** (refused to flash on a parsing error).
- The AGENTS.md dark-device playbook (IPv6 before declaring death) is
  literally what recovered the box.
- The first mutating conwrt-2.0 operation failed loudly and honestly at
  every step (runner timeout, no fake success; watcher + durable records).
- Recovery was fully staged before it was needed (verified image, one
  command, durable backup, registry trail).

## What went wrong

1. We treated "ARP-alive, no IP services" as a boot problem. ARP-alive means
   the kernel is up and the address configured — the correct suspect is the
   *address config itself* (netmask/routes), not the services.
2. Our passive listens were shorter than the beacon interval (600 s). The
   playbook's own "listen 2–5 minutes" was under-followed — and even 5 min
   is a coin flip against a 10-min RA. We never *actively solicited* (a
   Router Solicitation elicits an RA in ~1 s).
3. We never audited the probe host: `disable_ipv6=1` made every v6 probe
   return "Network is unreachable", which we misread as target-side
   silence.
4. A single unexplained "connection refused" (a phantom — nothing lives at
   that address) anchored a wrong theory for hours.
5. The 1.x flasher's interface-alias rules (wants a neutral in-subnet host
   address; rejects its own client IPs as "stale"; skips the power-cycle
   dance when recovery HTTP is already live) were undocumented — three
   failed launch attempts before the successful one.
6. One unnecessary recovery reflash: the sysupgraded image was fine except
   the missing netmask; a v6 look would have fixed it without U-Boot.
7. Trusted an embedded box's clock/uptime (no RTC, pre-NTP) during
   diagnosis — the "1d14h uptime" was sysfixtime skew.

## Lessons (generalized)

- **L1** — ARP-alive + IP-dead ⇒ suspect the interface's address/netmask
  first; the box is up.
- **L2** — passive listening must exceed 2× the longest beacon interval —
  or just solicit actively.
- **L3** — audit the prober before the probed (your interface flags, your
  routes, your v6 state).
- **L4** — never rely on version-dependent defaults for anything emitted;
  emit the whole fact (ipaddr **and** netmask) or emit nothing.
- **L5** — regression tests must assert the *shape* of emitted config, not
  just that a key exists.
- **L6** — one-off unexplained evidence is not evidence; re-observe before
  theorizing.
- **L7** — pre-NTP, no-RTC boxes lie about time; never cite their clock or
  uptime in a diagnosis.

## Action items

| # | Action | Status |
|---|---|---|
| 1 | Builder emits netmask at all LAN-IP sites + regression tests | **PR #152** (closes #151) |
| 2 | Recovery/first-boot defaults: key-only dropbear, `dhcp.lan.ignore=1`, post-flash prefix-sanity health check | filed (see tracking issue) — applied ad-hoc on this unit during the security audit |
| 3 | `conwrt discover-v6`: active Router-Solicitation + RA decode + probe-host v6 self-check; auto-run on post-flash SSH timeout | filed |
| 4 | Document the 1.x flasher's bench-interface requirements (neutral in-subnet address; already-in-recovery skip path) | filed with #2 |
| 5 | conwrt-lab registry push access broken (system of record is single-copy local) | ops item for the operator |

## Security-audit notes from the incident (2026-10-14)

- Fixed: pre-flash config backup was world-readable (contained the unit's
  uci/dropbear/network configs) → `chmod 600`.
- Fixed live on the unit: default `PasswordAuth='on'`/`RootPasswordAuth='on'`
  (password-attempt surface) → key-only; `dhcp.lan` serving armed →
  `ignore=1` (the rogue-DHCP class that poisoned the house LAN twice).
  Key-login re-verified after hardening.
- Non-issue: the RSA key embedded in `scripts/dlink_sge_sign.py` is the
  D-Link GPL **test** key (documented public since the GPL release; AGENTS
  notes it) — grep hit, not a secret.
- Standing: U-Boot recovery HTTP has no authentication (inherent; mitigated
  by physical-segment isolation — the gated script's specimen-MAC check is
  the compensating control on our side).
