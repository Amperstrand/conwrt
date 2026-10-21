# Lab hardware alignment block (append to project AGENTS.md)

Copy everything below the line into the AGENTS.md of any project that touches
lab hardware (routers, ESP32, STM32, fixtures).

---

## Lab hardware: one single source of truth (2026-09-28)

All lab hardware — routers, ESP32/STM32 fixtures, switches, power, serial —
is declared in the **private repo `Amperstrand/conwrt-lab`** (`lab.yaml`:
devices, MACs, IPs, topology, VLANs, labgrid places). This project does NOT
own hardware state.

Rules for code and agents in this repo:

1. **Never hardcode device IPs, MACs, or serial-port paths.** Resolve from the
   registry: `CONWRT_LAB=<conwrt-lab checkout>` +
   `python3 $CONWRT_BENCH/scripts/lab_registry.py …`, or from a labgrid place.
2. **Access hardware through labgrid places** (coordinator `ai-legion:20408`):
   `labgrid-client -p <place> ssh|console|power`. Acquire/release for
   exclusivity during tests.
3. **Flashing/adoption goes through conwrt tooling** (`Amperstrand/conwrt-bench`):
   `scripts/dut_recover.py --from-lab <device-id>` for recovery flashes,
   `scripts/bench_net.py` for bay/VLAN changes. These update the registry.
4. **State changes end with a registry commit** in conwrt-lab — if you changed
   a device (flashed, moved, adopted), lab.yaml must reflect it before you
   walk away.
5. **When surprised, reconcile first**:
   `python3 $CONWRT_BENCH/scripts/lab_registry.py reconcile` detects dead
   devices, switch reboots, and place drift in one command.

Env: `CONWRT_LAB` (this registry checkout) and `CONWRT_BENCH` (conwrt-bench
checkout) are the two paths every hardware-touching tool understands.
