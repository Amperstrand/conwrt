# Design: on-switch (Rust) reflash — conwrt-agent executing the AP391x recipe

Status: PLAN (2026-11-18), written after the ap3915i-3893 zero-serial
bring-up. Vision: an OpenWrt switch (GS1900-8HP class) running conwrt as a
Rust agent re-flashes attached DUTs end-to-end — no laptop, one switch
reflashing a neighbor's devices over L2.

## What the field-proven Python flow does (the contract to port)

The 2026-11-18 bring-up executed, via host-Python + the switch as vantage:
vLAN seat + DHCP/TFTP vantage → stock SSH door (admin/new2day, legacy
algos) → forensics (env from raw CFG1, `uboot_env.py`) → full MTD backup
(raw dd over ssh stdout) → CFG1 staged writes (flashcp from stock,
readback-gated) → boot_net TFTP initramfs → sysupgrade (setsid/foreground)
→ final env write (kmod-mtd-rw + `mtd write` from initramfs) → adoption
(keys before password; uci readbacks). Hardware proof + trap ledger:
conwrt-bench sessions/2026-11-18-ap3915i-3893-bringup.md.

## Component mapping (Python today → Rust target)

| Flow step (Python today) | Rust home | Status |
|---|---|---|
| Env block parse/build (`scripts/uboot_env.py`) | `conwrt-core::uboot_env` | DONE this PR (no_std, byte-parity tests vs Python) |
| Species recipe data (`models/*.json`) | `conwrt-types` model registry | exists (load_dir + json feature) |
| Plan/workflow orchestration | `conwrt-core::plan` + `conwrt-executor` | exists (Tier-A engine, provider traits) |
| Host CLI driver | `apps/conwrt-cli` | exists (~1.4k lines); add `flash ap391x` subcommand consuming the above |
| On-device agent | `apps/conwrt-agent` + `conwrt-agent-proto/io` | STUB (73 lines) — the porting frontier |
| TFTP serve (dnsmasq on switch) | keep dnsmasq (config-driven) or tiny embedded TFTP later | already on-switch |
| PoE control (`ubus call poe manage`) | agent shells `ubus` + wedge guard (jitter-probe, restart-once) | port `poe_wedge_guard.py` logic into the agent |
| Stock SSH door (legacy algos, sshpass) | agent spawns `dbclient`/`ssh` with options OR russh with legacy KEX | open question (see risks) |
| Raw dd pulls over ssh stdout | same transport once SSH client decided | trivial after SSH |
| Image staging | switch `/tmp` (RAM; ~58MB free; images 9-10MB) or streamed | feasible |

## Phased plan

- **P0 (this PR)**: env codec in Rust + unit/e2e tests against real
  (redacted) fixtures + Python byte-parity. The flash recipe is pinned by
  the `flash_recipe_application_matches_the_field_verified_change_set` test
  driven by the model registry itself.
- **P1**: `conwrt-cli flash ap391x` — the host drives the whole recipe
  through the switch (today's Python flow, Rust binary, dry-run + confirm
  gates, readback verification at every write, automatic bait arming).
  Test against the operator's next spare unit.
- **P2**: `conwrt-agent` on the switch (apk, mips_24kc): the agent runs the
  same `conwrt-core` engine (Tier-A already no_std+alloc) against a local
  provider implementing the capability traits over: ubus (PoE), exec
  (dnsmasq/ubus/ssh), files (/tmp staging). `conwrt-agent-proto` already
  defines the wire side. Safety gates (readback, CFG1-only, bait-armed,
  wedge-guard) become engine-level invariants, not operator discipline.
- **P3**: switch-to-switch (the vision): one switch's agent drives a
  neighboring switch's agent via agent-proto over the management VLAN —
  the same plan/engine, remote provider. Requires the L2 trust boundary
  documented (agent auth is a design question: fleet key at minimum).

## Risks / open questions

1. **Legacy SSH client**: stock doors need ssh-rsa + dh-group1-sha1.
   dbclient's forcing options are limited; openssh-client on-switch is an
   apk dependency (feeds currently partial); russh with legacy features is
   the clean long-term answer but adds a crypto surface to audit.
2. **Switch storage/RAM**: images (9-10MB) + backups (30MB+) exceed the
   overlay (5.4MB free) — staging must live in /tmp and stream out over
   the network before any reboot-class operation.
3. **The poe-manage wedge** is environment state, not code: the agent MUST
   embed the wedge guard (jitter probe + single restart + refuse-on-MCU-
   wedge) or power cycles silently no-op again.
4. **Safety invariants** (CFG2 pristine, readback gates, identity keys
   immutable, bootcmd shape) must be enforced by the engine, refusing
   hand-rolled writes — encode as types/validation in conwrt-core, not as
   docs.
