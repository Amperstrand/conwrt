# PoE Backend Decision — GS1900-8HP bench power control (2026-09-25)

Decision owner context: user directive — "converge on one [PoE backend]; PoE
control must remain secure and not just open on the LAN". Research: labgrid
upstream docs + discussions (#845, #1515), live bench evidence, and today's
wedge incident on the OpenWrt switch.

## The lineage (three implementations, one hardware truth)

| Implementation | Where | Shape | Status |
|---|---|---|---|
| `PoePowerController` | tollgate-lab branch `laptop-main-20260925` (`tollgate_lab/hardware/poe.py`, 342 lines) | Library class: rich PoeStatus enum, transient handling, budget guard, protected ports, frozen-daemon detection | Unmerged (laptop decommission; 1 commit on diverged base) |
| `conwrt_poe` | conwrt repo `labgrid/conwrt_poe.py` + copy installed INTO labgrid site-packages on ai-legion | labgrid `NetworkPowerPort` model backend (power_set/power_get functions) — ported FROM PoePowerController "with permission" | Live on the bench (ai-legion exporter, model: conwrt_poe) |
| `ZyxelPoEDriver` + `ZyxelPoePort` | tollgate-lab main worktree (`tollgate_lab/drivers/zyxel_poe.py`) | Proper labgrid Driver + Resource (PowerProtocol), registered via target_factory | Proven GREEN on live hardware 3× today; hardened with the conwrt_poe verification semantics |

All three speak the same fork API over SSH: `ubus call poe manage
{"port","action"}` (+ `set_port_config` fallback) with `poe info` poll-verify.

## Decision: converge on tollgate-lab ZyxelPoEDriver

1. **Pattern** — upstream guidance (labgrid discussion #845, maintainer
   reply): custom non-upstreamable power backends belong in client-side
   Drivers registered with `target_factory`; `NetworkPowerPort` model
   backends require patching `labgrid/driver/power/` in site-packages on
   every client — the conwrt_poe header itself warns it must be reinstalled
   after every labgrid upgrade and that staging copies drift. A pip-installed
   package (tollgate-lab) registering a Driver has no such failure mode.
2. **Substance** — the driver now carries the full bench-verified hardening
   (ported from conwrt_poe, itself derived from PoePowerController):
   manage + poll-until-reflected verification, T23 settling tolerance
   (35 s), frozen-snapshot wedge detection (DROPPED), bounded retry for the
   MCU not-ready/bad-checksum transient class (observed live 2026-09-25,
   twice), protected-port refusal (lan1/lan8), BCM59121 8 s re-enable delay.
   It detected today's real daemon↔MCU wedge live — before any human noticed.
3. **Security** — SSH key auth only, `BatchMode`, host keys verified
   (`accept-new`, vs conwrt_poe's `StrictHostKeyChecking=no`); NO
   uhttpd-mod-ubus / unauthenticated-ubus HTTP on the switch (the stock
   labgrid `ubus` backend is rejected for exactly that reason — it would
   make PoE control open to the LAN). Coordinator exposure is handled
   separately (see consolidation notes): labgrid's coordinator protocol is
   unauthenticated and must be network-restricted.

## Migration phases

- **Phase 1 (done 2026-09-25)**: ZyxelPoEDriver hardened + live-proven
  (19 unit tests; PRTA smoke test green on the lan5 AP3915i, 93.8 s).
- **Phase 2 (after the serial-bench plan executes)**: re-shape the ai-legion
  exporter — replace `NetworkPowerPort {model: conwrt_poe}` stanzas with
  exported `ZyxelPoePort {host, port}` resources (pure scalars, wire-safe
  over the coordinator via the ResourceEntry fallback — drivers never cross
  the wire; the client env lists `ZyxelPoEDriver`). Then delete the
  site-packages copy on ai-legion. Requires: tollgate-lab importable in the
  client venv (one conftest line).
- **Phase 2.5 (needs a commit — user nod required)**: merge tollgate-lab
  `laptop-main-20260925` (brings `PoePowerController` home), then unify:
  either the Driver delegates to the Controller or the Controller's extras
  (budget guard, rich enum) are absorbed into the Driver. Removes the
  third copy of the same logic.
- **Phase 3 (long-term)**: upstream an SSH-based realtek-poe backend to
  labgrid (`labgrid/driver/power/realtek_poe.py`, model: realtek-poe) per
  the maintainer's stated preference — then even the custom Driver can
  retire and stock `NetworkPowerPort` works everywhere without local patches.

## Stock GS1900-8HP #2 (V2.90) as a second power surface

User goal: both switches side by side. Rationale beyond capacity:
- Same silicon (ST32F100 MCU + BCM59121 PSE) on both units — if the stock
  ZyXEL daemon never wedges while the fork does, the wedge root cause is
  the fork's MCU driver, not hardware. Today's incident gives the fork a
  documented failure signature to compare against.
- Control redundancy: today the whole rig's power control was a single
  wedged daemon away from dead.
- Stock control path = web API (`cmd=773` status / `cmd=775` toggle, proven
  May 2026, session-authenticated admin (<secrets:fleet.bench_root_password>)). SSH on stock is
  read-only. A future `StockZyxelPoEDriver` speaks HTTP with session
  cookie + XSSID token; still authenticated, still not LAN-open.
- Investigation in flight (herdr agent `stock-poe`): discovery on the LAN,
  credentials verification, wire-level API capture with curl evidence, one
  verified port-2 power cycle, wedge-behavior comparison. Report:
  `~/stock-2.90-investigation.md` when complete.

## Incident log (validation evidence, 2026-09-25)

- 10:24 — driver run 2 raises `poe manage DROPPED` (frozen snapshot at
  "Delivering power", 41 s past settle): first live wedge detection.
- 10:29 — lan5 AP goes network-dark (stale port state during wedge).
- 10:40 — manual confirmation: snapshot byte-identical 6 s apart; logread
  silent for dropped manages (07:12 "MCU rejected command: not-ready" was
  the earlier tell).
- 10:4x — recovery per bench rule (flock + `/etc/init.d/poe restart`,
  user-approved): control restored, manage reflects again. Observed: the
  restart did NOT power-blip healthy PDs (lan2/lan3 uptimes continuous);
  only the wedged lan5 renegotiated → dark AP recovered.
- 10:5x — smoke test GREEN again with the retry-hardened driver.
