# Bench Observability — how conwrt receives logs and monitors real time

Implemented from `.omo/plans/bench-observability.md` (Momus-validated; research
base: LAVA job-scoped evidence + health-check gating, KernelCI dying-words and
timeout taxonomy, labgrid `--lg-log`/CONSOLE capabilities, aparcar/openwrt-tests
CI pattern, rsyslog+files+ntfy stack sizing).

## Architecture

```
bench devices (switch + DUTs)
  ├─ bench_watch.py (Mac, survives device reboots)     ← NOW LIVE
  │    streams logread/dmesg per device (reconnect+backoff)
  │    SNAP polling (switch: poe RSS/ports — leak instrument;
  │                    openwrt: boot_id/uptime — reboot oracle)
  │    64KiB dying-words tail per stream (tail-64k.txt)
  │    events.jsonl → bench_alert.py
  │         ├─ alerts.jsonl (always, durable)
  │         ├─ ntfy phone push   (config-gated, staged)
  │         └─ osascript + say   (config-gated, local)
  ├─ remote syslog UDP:514 → rsyslog on ai-legion     ← LIVE (deployed +
  │    per-device/day files                              E2E-proven 2026-11-27:
  │                                                      scripts/bench_rsyslog_deploy.sh)
  └─ pytest runs via bench_run.py / make labgrid-test  ← per-run evidence:
       runs/<ts>-<name>/{manifest.json, pytest.log, report.xml, console_*}
```

CORRECTION (2026-11-28, live evidence): the netconsole claims above were
FALSE POSITIVES — the /dev/kmsg verification lines arrived via the
logd→logread syslog forwarder (logd consumes /dev/kmsg, so kernel lines
ride the syslog stream), not via netconsole. On this species (mt7621 +
DSA: br-lan over the `lan` DSA port), netconsole is genuinely MUTE: the
module loads, targets parse, "network logging started" prints, and ZERO
packets ever hit the wire (proven with wire captures across br-lan/lan/
eth0 sources, ARP resolved, firewall open — the DSA netpoll xmit class).
The baked `--netconsole` modules.d line additionally uses the `+`
dynamic-config form, which requires configfs (not mounted) — doubly
inert. Two real gotchas found while proving this: the UFW receiver rules
must cover the MAC-HASH source subnets (10/8 — the profile's first-boot
LAN is 10.<mac-hash>.x.1, not 192.168.1.x), and UDP 514 sends silently
fail until the target's ARP entry is warm.

The WORKING kernel-line path on this bench: the logd→logread forwarder
(`uci set system.@system[0].log_ip=<host>; uci set ...log_port='514';
uci commit system; /etc/init.d/log restart`) — logd reads /dev/kmsg, so
userspace AND kernel lines stream to the same per-device files (proven
on both the initramfs and the flash-rooted ASU image). Coverage starts
at the network stage (~10-15 s in); the pre-network window (bootloader
→ first printks) is serial-only on this species.

Division of coverage (do not blur): **remote syslog = userspace after network
init; serial/console (`--lg-log`, serial bridges) = bootloader + early boot;
SNAP polling = liveness oracle (log gaps are NEVER reboot evidence — UDP
lossiness rule; reboot = boot_id change CONFIRMED / uptime decrease LIKELY).**

## Running it

```bash
# watcher (currently live alongside the legacy record.sh for soak comparison)
python3 scripts/bench_watch.py --config data/bench/watch.json --validate-config
nohup python3 scripts/bench_watch.py --config data/bench/watch.json &
pkill -f bench_watch.py            # stop

# alerts (file sink only until ntfy/mac configured in data/bench/alert.json)
python3 scripts/bench_alert.py --events data/bench/watch/events.jsonl --watch
python3 scripts/bench_alert.py --events ... --test    # synthetic sink probe

# evidence-bundled test runs (aparcar trio + manifest, boot_id correlation)
make labgrid-test T=labgrid/test_bench_power.py DH=192.168.104.51
python3 scripts/bench_run.py --name serial-smoke --device-host <dut> -- pytest ...

# staged: rsyslog receiver on ai-legion (coordinate with fleet session first)
sh labgrid/bench_rsyslog_deploy.sh <ai-legion> <switch-ip>
# then per adopted DUT: uci set system.@system[0].log_ip=<ai-legion>; log_port=514
```

Config patterns: `labgrid/watch.json.example`, `labgrid/alert.json.example`
(real coordinates stay in gitignored `data/bench/`).

## Built-in alert rules (bench_alert)

| event | severity | guard |
|---|---|---|
| reboot (boot_id/uptime oracle) | critical | 5 min cooldown |
| disconnected | warning | ≥3 in 10 min (flap guard) |
| spawn_error / quota_warning | warning | cooldown |
| snap_unparsable | info | cooldown |
| poe_rss_growth | warning | >8 kB/h slope, 1 h cooldown — the realtek-poe `mcu_no_response()` leak instrument |

## Deferred by design
VictoriaLogs (when file+ripgrep hurts), ntfy server on ai-legion (O6),
DUT `log_ip` enrollment (O5, rides adoption windows), daily LAVA-style
health-check job (O7), any Prometheus/Loki/ELK (refused at this scale).
