# conwrt

**Flash any old router with OpenWrt, apply a profile, verify health. All from Linux.**

conwrt autodetects what a router is (any state: stock, carrier-locked, half-bricked), flashes it with OpenWrt, configures it with your chosen profile, and verifies everything works. The profile system is pluggable — from a plain OpenWrt router to a VPN gateway to a cellular tollgate with eSIM provisioning.

**[→ Device Support Matrix](https://amperstrand.github.io/conwrt/)** — supported devices, flash methods, and tested hardware.
**[→ Use Case Test Results](https://tests.tollgate.me/)** — live test evidence (select "conwrt" tab).

## How it works

```
Any old router → detect → backup → flash/recover → configure profile → verify
                    │         │           │              │              │
              MAC OUI,   full flash  bootloader    profile YAML:    QMI/AT/DM
              USB IDs,   + NV + EFS  trigger,      network, SSH,    health
              firmware   (safety-    TFTP fence,   packages,        checks
              probes     gated)      sysupgrade    modem, eSIM
```

## The three stages

### 1. AI-assisted discovery (`prompts/`)
Encounter an unknown router → identify it → fingerprint its attack surface → determine flash methods and boot signatures. This is how new router models get onboarded into conwrt.

### 2. Automated flashing + recovery (`scripts/` + `models/`)
Once a species is defined, flashing is fully automated: detect recovery mode, upload firmware, verify, inventory. Full backup first (router + modem flash, NV items, EFS tree — all sha256-verified). Recovery from bricked/locked units via bootloader triggers, TFTP fences, and sysupgrade.

### 3. Profile configuration
After flash, apply a profile:
- **Plain router**: IP plan, SSH keys, hostname, DHCP policy
- **VPN router**: WireGuard/OpenVPN, kill switch, DNS
- **Cellular tollgate**: modem bring-up (QMI/AT), APN, band config, eSIM profile provisioning (lpac integration for providers like nadanada, silent.link)
- **Your own**: profiles are YAML — define what you need

## Species models (the "any router" part)

Each supported router is defined as structured JSON in `models/`. The engine is generic; the knowledge is data. Adding a new species = writing a JSON file, not code.

See [models/zte-mf286d-v2.json](models/zte-mf286d-v2.json) for a full example — every lesson from a 48-hour reverse-engineering campaign captured as structured data: partition safety maps, recovery strategies, modem interfaces, diagnostics, and eSIM capabilities.

## Quick Start

Plug the router into this machine's ethernet port and run:

```bash
python3 scripts/conwrt.py watch
```

conwrt scans for routers in recovery mode (and running OpenWrt), identifies the model by probe evidence, and asks before it flashes. Confirm, and it builds a fresh image with your SSH keys and config baked in (from `config.toml`), flashes, and verifies over SSH.

> **DISCLAIMER**: conwrt flashes firmware onto real hardware. You must have legal authority to modify any device you use it on. Verify model definitions and firmware images before every flash. The authors accept no liability for bricked devices or data loss.

## Proven on real hardware

| Device | Flash | Recovery | Modem | Notes |
|---|---|---|---|---|
| ZTE MF286D | ✅ | ✅ full backup + bootloader trigger | ✅ QMI + AT + DM | eSIM LPA interface mapped ([#682](https://github.com/Amperstrand/conwrt/issues/682)) |
| Zyxel NR7101 | ✅ | ✅ | ✅ | eSIM via lpac |
| D-Link COVR X1860 | ✅ | ✅ | n/a | |
| Zyxel GS1900-8HP | ✅ | ✅ | n/a | |
| Extreme WS-AP3915i | ✅ | ✅ | n/a | |

## What makes this different

- **No Windows tools** — replaces vendor-specific Windows-only flashing utilities (ZTE, others) with pure Linux
- **Safety-first** — partition safety maps, canary protocols, flight checklists, fail-closed gates
- **Full backup before any write** — router + modem + NV + EFS, sha256-verified
- **Recovery from any state** — bootloader triggers, TFTP fences, DM-protocol resets
- **Modem management** — QMI/AT/DM/ADB abstraction for cellular routers
- **eSIM provisioning** — lpac integration for eSIM profile management; on ZTE MF286D we proved the modem's internal LPA is externally reachable ([#682](https://github.com/Amperstrand/conwrt/issues/682))

## Documentation

- [AI-assisted RE methodology](docs/AI-ASSISTED-RE-METHODOLOGY.md) — how we use coordinated AI agents + Ghidra for firmware research
- [Brick-risk audit checklist](prompts/brick-risk-audit.md) — the 23-item pre-flight safety gate
- [Species recovery prompts](prompts/) — continuation prompts for research threads
- [MF286D recovery documentation](recipes/zte/mf286d/RECOVERY-2026-11-10.md) — bootloader trigger + TFTP fence recovery path

## Roadmap

→ [Issue #676](https://github.com/Amperstrand/conwrt/issues/676): Rust engine, data-driven species models, built-in diagnostics, flight checklists as code.
→ [Issue #677](https://github.com/Amperstrand/conwrt/issues/677): eSIM profile download via modem's internal LPA.
→ [Issue #675](https://github.com/Amperstrand/conwrt/issues/675): Stock firmware modem communication research.

## License

See [LICENSE](LICENSE).
