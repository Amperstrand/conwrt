# conwrt labgrid bench

PoE power + network control for bench DUTs via a GS1900-8HP bench switch,
integrated with an existing labgrid stack. **Smoke-tested 2026-09-22**: full
chain labgrid -> coordinator -> exporter -> conwrt_poe backend -> SSH -> ubus ->
realtek-poe fork -> MCU, power-cycling a live DUT. Hardened same evening
(ap-lan5 hazard closed, NetworkService exports, exporter supervision notes).

Real hostnames/IPs/credentials live in local bench records only
(`data/sessions/`, gitignored) — this file publishes the pattern.

## Architecture

- **Coordinator**: an existing labgrid coordinator (shared with another rig;
  we run our own exporter, theirs untouched). Address never hardcoded in
  tooling: `LG_COORDINATOR` env or explicit arg (records live in
  `data/sessions/`).
- **Exporter**: ai-legion, config `exporter.yaml` (repo copy is the source of
  truth; live copy `~/conwrt-labgrid/exporter.yaml` — scp after edits, then
  restart). Supervised by the **systemd user service pattern in this
  directory** (`conwrt-exporter.service` — install once on the exporter host
  with `loginctl enable-linger`, then coordinator ping-timeout deaths
  self-heal; see the unit file header). After any coordinator blip, verify
  anyway: `pgrep -af labgrid-exporter` on ai-legion.
- **Backend**: conwrt_poe.py — a labgrid power backend speaking the fork's
  native action-string ubus form over SSH (source of truth: this directory;
  install copy: `labgrid/driver/power/conwrt_poe.py` inside the labgrid
  package on the driver host — reinstall after labgrid upgrades AND after
  backend edits). SSH connections are ControlMaster-multiplexed (30s persist)
  so power polls reuse one session.
- **Switch**: bench/PoE switch per docs/BENCH-SWITCH-PATTERN.md
- **Places**: `ap-lan2..ap-lan8` matched to `*/<place>/*` resources.
  **ap-lan5 deliberately has NO power resource** — the unit is
  TFTP-fallback-dependent (one-way trip until #61 / lifeline re-arm; PRTA
  ask 1, 2026-09-22).
- **DUT addressing**: per-VLAN statics `192.168.10N.51` (gateway `.10N.1` on
  the switch). There is NO DHCP on the bench (dnsmasq exists on the switch but
  serves only the TFTP lifelines) — adoption assigns statics via
  `bench_adopt.py`.

## Resources per place (2026-09-22)

| Place | NetworkPowerPort | NetworkService | NetworkSerialPort | Notes |
|---|---|---|---|---|
| ap-lan2 | ✓ | ✓ 192.168.10N.51 | queued (via lan4 bridge) | PRTA SUT; recovered 2026-09-22 evening; pw + keys; serial door proven 2026-09-23 |
| ap-lan3 | ✓ | — | — | recovered unit; adopt to statics, then export |
| ap-lan4 | ✓ | ✓ 192.168.10N.51 | (is the console host) | reference unit, adopted |
| ap-lan5 | **absent by design** | — | — | lifeline ARMED since 2026-09-23 (recoverable), still avoid cycling until #61 |
| ap-lan6 | ✓ | — | candidate | dark unit (serial-gated #62) — bridge gives it a console |
| ap-lan7 | ✓ | — | — | empty port |
| ap-lan8 | ✓ | ✓ 192.168.10N.51 | — | NR7101 SNAPSHOT, ADOPTED 2026-09-23 (reboot-verified; modem/SIM, no APN yet) |

Bench failsafes re-arm at every switch boot via `/etc/bench-arm.sh` (source:
`scripts/gs1900-bench-arm.sh`, wired in rc.local): fw4 `switch.10*` accept,
192.168.1.2 aliases on lifeline VLANs (1002+1005), dnsmasq TFTP serving the
md5-gated 24.10.2 sysup FIT, ap-lan2 watcher. The exporter on ai-legion is
supervised by a crontab watchdog (auto-restart within a minute).

Adding a resource is two steps, both required (T15): export it in
`exporter.yaml` AND `labgrid-client -p <place> add-match '*/<place>/<Class>'`
(the coordinator place keeps its old match list otherwise).

### Serial console via a second AP3915i (proven 2026-09-23)

A healthy AP3915i can listen on its own `/dev/ttyMSM0` to a *second* AP3915i's
console over a 3-wire 3.3V UART splice (TX/RX crossed, GND common, no VCC) — no
USB-TTL adapter on the bench. Full method, wiring, listener setup, and capture
commands: `recipes/extreme-networks/ws-ap3915i/SERIAL-VIA-AP3915I.md`.
Validated end-to-end: lan4 (reference unit) captured lan2's (ap-lan2) full boot
from PBL to shell; evidence `data/bench/ap-lan2/20260923-serial-via-lan4/`.

To expose it as a labgrid `NetworkSerialPort` (enables `SerialDriver` /
`UBootTFTPStrategy`-class flows, boot-log assertions): run a supervised
TCP→serial forwarder on the exporter host that SSH-jumps to the listener AP and
bridges the tty stream to a local TCP port, then export
`NetworkSerialPort { host: <exporter>, port: <fwd-port>, speed: 115200 }` on the
place and `add-match` it. A commented stanza lives in `exporter.yaml`. The
forwarder service on ai-legion is **not yet stood up** — until then use the
manual SSH flow in the recipe doc.

## Keeping the inventory honest (routers move between ports)

Routers get re-homed on bench ports; registries drift. Reconcile with a
read-only scan (never power-toggles to "discover" — owner directive):

    python3 scripts/bench_inventory.py scan --host <switch>            # report only
    python3 scripts/bench_inventory.py scan --host <switch> --probe    # + board/model via v6 (default)
    python3 scripts/bench_inventory.py scan --host <switch> \
        --emit-exporter -            # regenerated exporter.yaml stanzas to stdout
    python3 scripts/bench_inventory.py scan --host <switch> \
        --update-places --record     # rewrite places.json + append inventory.jsonl

The scan reads `ubus poe info`, `bridge fdb show` (dynamic entries only),
`ip neigh` per DUT VLAN, and optionally probes each unit over its EUI-64
link-local from the switch. It cross-references `data/bench/places.json`
and classifies: `ok` / `moved` (unit seen on a different port — registries
and exporter need updating) / `swapped` / `multi_mac` / `dark` (PoE but no
L2/L3 — escalate to `bench_discover.py`) / `empty` / `unregistered`.

Safety properties: no DUT writes, no power toggles, `--update-places`
preserves unknown keys (passwords, notes) verbatim and never deletes
fields (vacated places get `mac: ""` + dated note), and
`--emit-exporter` NEVER emits a NetworkPowerPort for places marked
`"power_export": false` in places.json (the ap-lan5 one-way-trip rule is
now machine-enforced, not just documented).

Exit code 1 on drift — cron-friendly:

    LG-aware cron: bench_inventory.py scan --host ... --record || notify

After a confirmed move: re-run with `--update-places --record`, review the
exporter diff, scp it to the exporter host, restart the exporter, and fix
coordinator matches (`labgrid-client -p <place> add-match`/`del-match`).

## Operations

    labgrid-client -x <coordinator> places
    labgrid-client -x <coordinator> -p ap-lan4 acquire
    labgrid-client -x <coordinator> -p ap-lan4 power off   # DUT loses PoE
    labgrid-client -x <coordinator> -p ap-lan4 power on    # DUT boots
    labgrid-client -x <coordinator> -p ap-lan4 release
    # manual check: ssh root@<switch> "ubus call poe info | jsonfilter -e '@.ports.lan4.status'"

### Serial console (ap-lan2 live, others add-able)

ap-lan2 exposes a `NetworkSerialPort` over the AP3915i-to-AP3915i bridge
(lan4 listens to lan2's console; recipe
`recipes/extreme-networks/ws-ap3915i/SERIAL-VIA-AP3915I.md`). Two supervised
services on the exporter host (both systemd user units; linger already on):

    systemctl --user status conwrt-serial-bridge@ap-lan2   # TCP:4002 -> lan4 ttyMSM0
    systemctl --user status conwrt-exporter                # exports the resources

Source of truth for both units + the bridge script: this repo (`labgrid/`,
`scripts/conwrt_serial_bridge.py`); live copies in `~/conwrt-labgrid/` +
`~/.config/systemd/user/` on the exporter host. To drive the console from a
test: acquire ap-lan2, bind a `SerialDriver` to the place's NetworkSerialPort,
read/write. To add another serial pair: see the recipe's labgrid section.

Restart the exporter after edits (two separate ssh calls — pkill patterns
self-match otherwise; use `setsid`, never bare `nohup`, when starting over
ssh — nohup'd children die with the session). With the systemd unit
installed this collapses to `systemctl --user restart conwrt-exporter`:

    ssh <exporter-host> 'systemctl --user restart conwrt-exporter'    # supervised
    ## legacy manual path:
    ssh <exporter-host> 'pkill -f "[l]abgrid-exporter"'
    ssh <exporter-host> 'cd ~/conwrt-labgrid && setsid sh -c "labgrid-exporter -c <coordinator> exporter.yaml > /tmp/conwrt-exporter.log 2>&1" < /dev/null > /dev/null 2>&1 &'

Locking discipline (owner directive 2026-09-22): per-DUT work = place acquire
only; switch-wide mutations (VLANs, reboots, poe-daemon or exporter restarts)
= global `amperstrand-bench` flock AND no place acquired. PRTA's scope is the
`ap-lan*` places only.

## Provisioning ladder — which method for which situation

We now have every rung documented. Pick by WHERE the device is, not by habit:

| Situation | Method | Doc | Risk |
|---|---|---|---|
| Healthy OpenWrt + SSH, want new image | `sysupgrade` (`conwrt flash` / manual) | README flash table | low |
| Healthy OpenWrt + SSH, want clean config | `bench_adopt` (firstboot + adopt) — envelope FIRST | scripts/bench_adopt.py + AGENTS.md Reset Failsafe Discipline | **medium** (dirty-overlay race if doubled) |
| Repeatable test runs, flash untouched | **initramfs via TFTP, net-first bootcmd** (image-per-run) | this file, below | low (RAM-only) |
| Flash boot broken | TFTP lifeline (`boot_net` fallback tail auto-fires) | NO-SERIAL-FLASH-24.10.2-VALIDATED.md | n/a (recovery) |
| Userspace auth-dead | v6 link-local → ip neigh → LuCI :80 → PoE cycle → serial | AGENTS.md Reset Failsafe rule 4 | low |
| Bootloader/stock, network-SSH-able | model flash method (recovery-http, extreme-rdwr-tftp, zycast…) | models/*.json + recipes/ | per-model |
| Last resort | serial (base64/XMODEM), needs #62 adapter | prompts/serial-*.md | low but slow |

**Key asymmetry (tested live)**: the `run boot_openwrt; run boot_net` fallback
tail only opens the TFTP door when FLASH BOOT FAILS — a healthy flash-booter
never enters `boot_net`. So TFTP is a *recovery* mechanism, not a *provisioning*
mechanism, unless you deliberately flip a unit to net-first (below).

### Image-per-run testing (PRTA pattern, no serial needed)

Prior art: aparcar/openwrt-tests — `UBootTFTPStrategy` power-cycles,
interrupts autoboot over serial, TFTP-boots an initramfs, SSHes in. Their
TFTP step is serial-gated; our bench has no serial, so we gate via the
bootcmd we control instead:

1. Dedicate one unit as the net-first test SUT. Write CFG1 with
   `bootcmd=run boot_net; run boot_openwrt` (REVERSED order — flash becomes
   the fallback). Use the proven CFG writer + full-64K readback gate.
2. Keep the per-VLAN dnsmasq TFTP root loaded with the test initramfs under
   the filename `boot_net` fetches (`vmlinux.gz.uImage.3912` on this bench).
3. Every `power cycle` = deterministic fresh image from RAM; overlay/flash
   untouched between runs. Zero reset risk (T9 cannot happen).
4. Tests drive it labgrid-side: `NetworkPowerPort` (cycle) +
   `NetworkService` (SSH into the initramfs, blank root) — a two-resource
   custom Strategy, or plain power+SSHDriver in the test harness.
5. Costs: TFTP server must be armed before every run (runtime-only on the
   switch — re-arm or supervise); boot latency grows by the DHCP/TFTP phase;
   the served filename is shared by every unit on that VLAN.

### Provisioning recommendation for PRTA (tollgate release testing)

- **Per-run determinism**: net-first image-per-run (above) — cleanest, no
  destructive state changes, matches aparcar's proven pattern.
- **Config changes / RC deploys on a running unit**: SSH via NetworkService
  (no power event at all — nothing to race).
- **Cold-boot persistence tests**: power cycle on the adopted unit (validated
  2026-09-22 evening: graceful reboot + cold PoE both survived with keys,
  password, statics intact).
- **Avoid `firstboot` as a per-run reset** — it is brick-class (T9), needs
  the full envelope every time, and double-firstboot is what caused the
  ap-lan2 incident. If a factory state is truly required, prefer
  `sysupgrade -n` with the release image (rewrites overlay wholesale) or the
  net-first initramfs (never touches state).
- Keep `reset_allowed=false` gating in places.json; respect `ap-lan5` absence.

## Smoke test (opt-in, hardware-mutating)

    BENCH_POWER_TEST=1 LG_COORDINATOR=<host:port> BENCH_SWITCH_HOST=<ip> \
        BENCH_PLACE=ap-lan4 pytest labgrid/test_bench_power.py

Required env: `LG_COORDINATOR`, `BENCH_SWITCH_HOST` (real coordinates live
in local bench records, not in git). Optional: `BENCH_PLACE`. VM tier
pattern: `qemu-x86-64.yaml.example` (QEMUDriver runs on the labgrid CLIENT
host, snapshot=on pristine boots). Follow-up hardening (pattern doc): fork
patch for enable-bools + uhttpd-mod-ubus -> stock labgrid ubus backend, no
SSH in the power path.
