# Router fleet tooling — comparative research digest (2026-11-23)

What exists in the wild for the problems conwrt solves, what they do
well, what to steal, what to avoid. Sources are primary (project docs,
repos, wiki revisions) and cited inline; everything unverified was
dropped. Companion to the 2026-11-23 overnight audit.

## The frame

conwrt's job is threefold: (1) flash/adopt arbitrary stock or dark
routers onto OpenWrt, (2) configure them from typed, parity-tested
plans, (3) keep a species-knowledge registry (models/*.json) that
makes the first two safe. Each comparison below attacks a different
one of those.

## 1. OpenWrt ASU / owut — the upgrade problem (vs our flash pipeline)

**What exists.** Attended SysUpgrade: an on-device client (LuCI app,
`auc`, now `owut`) that inventories the running system's packages and
requests a custom image from a server (`sysupgrade.openwrt.org`) that
coordinates ImageBuilders and caches results in Redis; builds run
container-isolated per request. Clients validate checksums before
flashing. The server publishes branch metadata (`overview.json`)
including `package_changes` pinned to revisions — e.g. the
firewall→firewall4 transition pinned at revision 18611.
Sources: openwrt.org wiki (attended.sysupgrade, sysupgrade.owut),
github.com/openwrt/asu README.

**What they do well.** The revision-pinned package_changes metadata is
machine-readable upgrade-drift data: a client can know *before*
flashing that a branch transition will swap its firewall. Their
client-side checksum gate before install is exactly our
sha256-at-download rule, enforced at the last moment it matters.

**What to steal.** A conwrt-local equivalent of `overview.json`: our
toolchain-pin guard (scripts/sdk_rust_version.py +
openwrt-toolchain.json) is the same idea done as a periodic audit; a
fetched, versioned upstream-metadata file would turn it into a
first-class gate. Their `uci-defaults` first-boot-script mechanism is
what our ASU overlay already rides — nothing new there.

**What to avoid.** The Redis image cache as a trust boundary: a cached
image served without rebuild is fine for their threat model (vendor
builds), wrong for ours (flash-safety-critical bench artifacts must be
byte-accounted, sha-pinned, and regenerated — the rustvm-artifact and
trigger-image lessons).

## 2. Gluon autoupdater — the fleet-update problem (vs our fleet ops)

**What exists.** Freifunk's firmware distro ships an on-node
autoupdater: signed manifests (ECDSA via ecdsautils), M-of-N
`good_signatures` required per branch (e.g. 2 for stable), a
`PRIORITY`-day stochastic rollout window after `DATE` (update
probability ramps 0→1 over N days, checks hourly at a random minute,
installs mostly 04:00–05:00), mirror lists with IPv6 mandated, and a
fallback trigger for NTP-less nodes. Manifests sign the header above a
`---` separator; signatures are append-only and idempotent under
`contrib/sign.sh`.
Sources: gluon.readthedocs.io (autoupdater, site configuration),
Bremen Freifunk wiki (signing practice).

**What they do well.** The M-of-N signing policy is the cleanest
answer in this space to "who is allowed to put firmware on my nodes"
— the exact question our tollgate distribution and ASU-baked images
raise. The PRIORITY-stretched rollout is a herd-thundering control we
have never needed at bench scale but will on any real fleet move.

**What to steal (direct hit on an open TODO).** tollgate.py's
`--allow-untrusted: tollgate packages are unsigned (TODO: sign
releases)` — Gluon's manifest+ecdsautils pattern is the implemented
precedent: sign a manifest (branch, date, image URLs+hashes), bake
N pubkeys into the fleet image, require M. Filed as an issue with
this research attached.

**What to avoid.** Their 4–5am install window and random-minute
polling assume unattended consumer nodes; our units are bench-managed
and the windows would just make flash attempts unpredictable.

## 3. probe-rs — the species-registry problem (vs our model JSONs)

**What exists.** The closest structural analogue to conwrt in the Rust
world: host-side tooling that flashes/debugs heterogeneous targets.
Targets are YAML `ChipFamily`/variant descriptions (memory maps, flash
algorithms as data — base64 instruction blobs with PC offsets), built
into the binary at compile time via build.rs AND addable at runtime
through a `Registry`. Crucially, most target files are GENERATED:
`target-gen` converts vendor CMSIS-Packs (and ELF files) into the YAML
descriptions; humans only hand-tune the residue.
Sources: github.com/probe-rs/probe-rs (target-gen README, targets/
STM32G0_Series.yaml, docs.rs probe_rs::config).

**What they do well.** Three things, all directly load-bearing for us:
1. **Generate the registry from the vendor's own metadata.** They do
   not hand-author 3,478-line chip files; they generate from CMSIS
   and curate the delta. OpenWrt's equivalent vendor metadata exists
   (imagebuilder profiles, devices.json, ASU's per-profile data) and
   we already speak part of it (ASU profile names, the
   D-Link-dashes lesson).
2. **Variants as first-class objects.** A family file carries many
   variants sharing flash algorithms — the exact modeling question
   behind #663's mf286d-v2 ontology (family file + variants, not
   parallel model files that drift).
3. **Builtin + runtime registry split.** Species knowledge compiles in
   for the shipped tool, loads ad hoc for experiments — a cleaner
   answer to "custom bench species" than our current single models/
   directory.

**What to steal.** A `model-gen` that emits model-JSON *stubs* from
OpenWrt metadata (target, profile names, partition hints where
published), leaving flash_methods/bench_observations as the hand-added
delta. Filed as an issue. The variant precedent is posted on #663 as
decision input.

**What to avoid.** Flash algorithms as opaque base64 blobs — their
constraint (ROM-resident routines) doesn't apply to us; our
flash-method recipes must stay readable text (the decode-before-probe
rule depends on it).

## 4. OpenWISP / netjsonconfig — the configuration problem (vs our plan system)

**What exists.** A server-centric NMS: NetJSON `DeviceConfiguration`
as the interchange format, config templates with variables, an
on-device agent (openwisp-config) that polls and applies. Their
netjsonconfig library compiles NetJSON → OpenWrt UCI (the same layer
our typed PlanOp → shell render occupies, approached from the config-
model side). Sources: openwisp.org, netjsonconfig.openwisp.org,
netjson.org implementations page.

**What they do well.** NetJSON gives them a standard import/export
shape — device configs are portable across their tooling and
third-party consumers. Template+variable indirection is how they scale
one config across a fleet.

**What to steal (low priority).** NetJSON *import* as an optional
front door for use-case params: if a customer already has NetJSON
device configs, mapping them onto our presets is a cheap
interoperability win. Not our default — our param contracts are
validated and parity-pinned, and NetJSON has no equivalent of the
gate-ladder semantics.

**What to avoid.** The standing-server + on-device-agent model
entirely: conwrt is agentless by design because its primary case is
the unit that just got flashed (or is dark) — exactly when no agent
exists. OpenWISP optimizes steady-state management; we optimize the
transitions.

## Steal-these-five (each names the conwrt component it changes)

1. **Gluon ECDSA manifests, M-of-N** for tollgate/firmware
   distribution — closes the unsigned-releases TODO; changes the
   release pipeline + a `good_signatures` field in the fleet profile.
2. **probe-rs target-gen analogue (`model-gen`)** — generate model-JSON
   stubs from OpenWrt metadata; changes models authoring (hand work
   becomes the bench-observations delta only).
3. **probe-rs variant modeling** — family files with variants for the
   #663 mf286d-v2 ontology decision; changes schemas/model.schema.json
   + the Rust DeviceModel.
4. **ASU overview.json-style drift metadata** — machine-readable
   upstream package/toolchain changes feeding the pin guard; changes
   openwrt-toolchain.json consumers.
5. **NetJSON import (optional)** — param front door for
   interoperability; changes the use-case param layer only.

## Non-findings (checked, healthy — 2026-11-23 audit)

- Injection surface: every use-case f-string interpolation passes a
  token/charset gate (openperf port int-cast+range, net_roles
  interface_name, ddns/iot/ipv6-wan charsets — the #448 class is
  closed across the registry).
- No tracked secrets: credential modules are env-driven with
  gitignored recovery records (device_credentials.py policy).
- `.target-rustvm` untrack HELD (the stale-checkout scare was local
  only); ignore line present on master.
- Test discipline: >1:1 test-to-source line ratio (57.6k test lines
  vs 56.8k source in scripts/), parity corpus covers 45/46 use cases
  (gap: maas-portable-lab — filed).
