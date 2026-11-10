# conwrt

**Turn any old router into a TollGate.**

Point conwrt at any old router — stock, carrier-locked, half-bricked — and it autodetects what the unit is, flashes it to working OpenWrt, configures cellular + eSIM provisioning, and verifies health. All from Linux. No Windows tools. No bricks.

**[→ Device Support Matrix](https://amperstrand.github.io/conwrt/)** — supported devices, flash methods, and tested hardware.
**[→ Use Case Test Results](https://tests.tollgate.me/)** — live test evidence from Nostr/Blossom (select "conwrt" tab).
**[→ conwrt v2 Vision (#676)](https://github.com/Amperstrand/conwrt/issues/676)** — the Rust engine + data-driven species models architecture.
**[→ eSIM Research (#682)](https://github.com/Amperstrand/conwrt/issues/682)** — how we cracked the "impossible" eSIM lock on carrier ZTE routers.

## What it does

```
Any old router → conwrt detect → conwrt backup → conwrt recover → conwrt configure → TollGate
                     │                 │                  │                  │
              MAC OUI, USB,      full flash + NV    bootloader trigger   SSH key, IP, modem,
              firmware probes    + EFS, sha256      + TFTP fence +       APN, eSIM profile,
              (species JSON)     (safety-gated)     sysupgrade path      health check
```

## The three stages

### 1. AI-assisted discovery (`prompts/`)
Encounter an unknown router → identify it → fingerprint its attack surface → plan a capture strategy → determine flash methods and boot signatures. This is how new router models get onboarded.

### 2. Automated flashing + recovery (`scripts/` + `models/`)
Once a species is defined (as structured JSON), flashing is fully automated:
- Detect recovery mode → upload firmware → verify → inventory
- Backup all partitions (router + modem) with safety gates and sha256 verification
- Recover bricked/locked units via bootloader triggers, TFTP fences, sysupgrade

### 3. Configuration + modem management (`configure/` + `modem/`)
After flash: SSH keys, IP plan, hostname, DHCP policy, cellular modem bring-up (QMI/AT/DM), eSIM provisioning (via the modem's internal LPA interface where available), and health verification.

## Species models (the "any router" part)

Each supported router is defined as a structured JSON file in `models/`. The engine is generic; the knowledge is data. Adding a new species = writing a JSON file, not code.

```json
{
  "identity": { "mac_oui": ["c8:ea:f8"], "usb_ids": [...] },
  "partitions": { "safe_to_read": [0,3,4,5,...], "crasher_partitions": [1,2] },
  "recovery": { "strategies": [{ "name": "bootloader_trigger", ... }] },
  "modem": { "interfaces": { "at": {...}, "qmi": {...}, "dm": {...} } },
  "safety": { "never_write_partitions": [...], "crasher_partitions": [1,2] }
}
```

See [models/zte-mf286d-v2.json](models/zte-mf286d-v2.json) for the full working example — every lesson from a 48-hour reverse-engineering campaign baked into structured data.

## Proven on real hardware

| Device | Flash | Recovery | Modem | eSIM |
|---|---|---|---|---|
| ZTE MF286D | ✅ bootloader trigger | ✅ full backup + restore | ✅ QMI + AT + DM | 🔓 35/44 LPA messages reachable |
| Zyxel NR7101 | ✅ | ✅ | ✅ | ✅ (via lpac) |
| D-Link COVR X1860 | ✅ | ✅ | n/a | n/a |
| Zyxel GS1900-8HP | ✅ | ✅ | n/a | n/a |
| Extreme WS-AP3915i | ✅ | ✅ | n/a | n/a |

## Key capabilities

- **No Windows tools required** — the ZTE flashing/recovery path replaces the proprietary Windows-only "ZTE Sales Update Framework" entirely
- **Safety-first** — partition safety maps (which partitions crash the device if read), canary protocols, flight checklists, fail-closed gates at every step
- **Full backup** — router flash + modem flash + NV items + EFS tree, all sha256-verified
- **Recovery from any state** — bootloader triggers, TFTP fences, sysupgrade, DM-protocol resets
- **Modem management** — QMI/AT/DM/ADB abstraction, data connection lifecycle, eSIM profile operations
- **eSIM research** — we proved the "impossible" eSIM lock on carrier ZTE routers is actually a managed LPA interface with 35 externally-reachable QMI messages ([#682](https://github.com/Amperstrand/conwrt/issues/682))

## Quick Start

Plug the router into this machine's ethernet port and run:

```bash
python3 scripts/conwrt.py watch
```

conwrt scans for routers in recovery mode (and running OpenWrt), identifies the model by probe evidence, and asks before it flashes. Confirm, and it builds a fresh image with your SSH keys and config baked in (from `config.toml`), flashes, and verifies over SSH.

> **DISCLAIMER**: conwrt flashes firmware onto real hardware. You must have legal authority to modify any device you use it on. Verify model definitions and firmware images before every flash. The authors accept no liability for bricked devices or data loss.

## Documentation

- [AI-assisted RE methodology](docs/AI-ASSISTED-RE-METHODOLOGY.md) — how we use coordinated AI agents + Ghidra to reverse-engineer locked devices
- [Brick-risk audit checklist](prompts/brick-risk-audit.md) — the 23-item pre-flight safety gate
- [Species recovery prompts](prompts/) — continuation prompts for each research thread
- [MF286D recovery documentation](recipes/zte/mf286d/RECOVERY-2026-11-10.md) — the complete bootloader trigger + TFTP fence recovery path

## Roadmap (conwrt v2)

→ [Issue #676](https://github.com/Amperstrand/conwrt/issues/676): Rust engine, data-driven species models, built-in diagnostics, flight checklists as code.

## License

See [LICENSE](LICENSE).
