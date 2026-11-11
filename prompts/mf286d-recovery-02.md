# MF286D recovery-02 — continuation prompt (2026-11-11 session)

Hand this to a fresh session with device-1 (mf286d-d1) work. The router
is RECOVERED and healthy; the MODEM is not. This file is the warm start.

## State at close (all verified live)

**Router (device 1, MAC c8:ea:f8:c1:7e:c5)** — FULLY RECOVERED:
- OpenWrt 25.12.6, hostname `mf286d`, LAN 192.168.34.1/24 (CIDR — see
  AGENTS "Recovery Management Plane" for why), DHCP+RA quieted, ai-legion
  key installed, direct SSH from ai-legion (key: `~/.ssh/google_compute_engine`).
- Recovered via the RUST conwrt recovery (PR #685, first real-hardware
  dogfood): `conwrt blankdl fence` served the proven 38.8MB image
  (RRQ→26,429 blocks→fin in ~10s) and `conwrt blankdl trigger` ran the
  full gate ladder (MAC specimen gate → sha256 at target → mtd erase+
  write → readback verify → alive probe → reboot). Zero gate failures;
  the dry-run caught a partition-grep bug BEFORE any write.
- The v6 door that reached it when everything else was blind:
  `dbclient -y -y root@fe80::caea:f8ff:fec1:7ec5%switch.1007` from the
  bench switch (192.168.12.2). This works through PHY wedge, IP changes,
  and host route conflicts. v6-FIRST from now on (AGENTS has the ladder).

**Modem** — NOT recovered, stable failure state:
- USB crash-loop: qmi_wwan register/unregister every ~80-95s (dmesg on
  the router shows the cycles; the "router keeps power-cycling" report
  was this loop, not router reboots — LEDs lie, dmesg doesn't).
- In each ~80s window: AT answers (`ATI` → ZTE CORPORATION / MF286DMODULE).
  QMI never comes up ("Failed to connect to service" always).
- The loop SURVIVED: router reflash (22.03→25.12.6 via trigger+fence),
  multiple cold power cycles. This is persistent modem-side corruption
  from the v8 register crash (EXP-043: 0x67 register with valid 8B u64
  token = CRASHER, now banned).
- The "router-side reflash fixes modem" cure that worked on 2026-11-10
  (mtd-crash damage class) does NOT work for this class.

## Repair paths for the modem (ranked, none started)

1. **EFS/NV restore from the B12 corpus** — we hold the full backup
   (16/17 partitions, 4096-item NV sweep, 555-file EFS tree at
   `~/mf286d-work/evidence/modem-fw-re/live-b12/dumps/`). The v8 crash
   plausibly corrupted a persistent EFS file or NV item that the modem
   reads at boot; restoring the banked known-good values via DM (qfenix/
   QCSuper over /dev/ttyUSB0, alive in windows) is the surgical fix.
   FIRST STEP: capture the modem's own crash logs (DIAG F3) during a
   window — the research lane left a 15-hash watch-list + decision table
   in PR #664 (`EID-GATE-DIAGNOSTIC-PLAN.md`); it names the dying task.
2. **Modem firmware reflash** — the B12 firmware images are in the corpus.
   DANGER: the ZTE kit manifests describe the modem SoC's NOR chain —
   the brick-zone audit (AGENTS) applies in full. Last resort.
3. **Modem donor** — device 2's modem (documented option in the dossiers).

## eSIM research state (the reason the modem matters)

- Research lane close-out (PR #664): full 84-message UIM IDL decoded;
  LPA enable-gate prime candidate = **message 0x53** (v9 `enablecall`
  probe built, NOT run — device was down); DIAG F3 oracle staged.
- Ecosystem map committed: `docs/ESIM-ECOSYSTEM.md` (lpac QMI backend,
  standard APDU trio 0x42/0x3B/0x3F, Quectel QESIM enable-gate analogy,
  ZTE's own AT*EUICC + CI_SIM_PRIM_DOWNLOADPROFILE in our dumps).
- Operator has a programmable eUICC card (in an NR7101; rsim/physical
  move both options) — end-to-end provisioning test vehicle once the
  modem talks QMI again.

## Tooling follow-ups filed from this session

- `conwrt adopt` (the post-flash adoption sequence as code: v6 door →
  rogue-DHCP quiet → CIDR management IP → SSH key → verify; issue #686)
- Bench hygiene: stale `192.168.1.0/24` rig routes on ai-legion bays
  1003/1005/1006/1009 (the v4 breaker; conwrt-bench sweep item)
- Species model recovery observations → PR #663 lane

## The recovery recipe that worked (species-level, reusable)

1. Fence: `conwrt blankdl fence <image>#sha256:<pin> --allow-raw
   --firewall-iface <iface> --timeout 1800 --log-dir <dir>` (the proven
   image is NAND-padded — 0xff head, no uImage magic — hence --allow-raw
   with the sha pin as the real gate; image: root_uImage sha256
   01f6f7bc310c26e5bbee5992aa79dbf4e5683a0f40226152ad307c92f02071d3)
2. Trigger: `conwrt blankdl trigger root@<ip> -i <key> --trigger-image
   /tmp/trigger.img --expect-mac <mac> --partition rootfs [--reboot]`
   (trigger.img 393,216B sha256 f54a7e4ddccdbedca0aad168c0ac7186372df6f
   50416cd65aa812c4b42f9fdef)
3. Post-flash: expect the PHY wedge (carrier up, zero frames) — go v6
   from the switch, adopt (DHCP quiet → CIDR IP → key), sysupgrade if
   needed, re-verify.
4. BusyBox traps: `nohup` missing on rc5 — use `setsid`; no `timeout`/
   `od` on some images — guard from the host side.

Evidence: `/home/ubuntu/conwrt-blankdl-rs/flash-run/run.json` (fence run
record), fence-console.log, and this session's herdr transcript.
