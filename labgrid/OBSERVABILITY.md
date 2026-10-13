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
  ├─ remote syslog UDP:514 → rsyslog on ai-legion     ← STAGED (config ready,
  │    per-device/day files                              deploy coordinated with
  │                                                      the fleet session)
  └─ pytest runs via bench_run.py / make labgrid-test  ← per-run evidence:
       runs/<ts>-<name>/{manifest.json, pytest.log, report.xml, console_*}
```

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
