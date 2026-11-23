# Detection & Recovery Tooling (#323) — coverage map and design choices

The 2026-10-20 fleet recovery proved the patterns
(recipes/detection-and-recovery.md); #323 asks to automate them so the
playbook becomes the DEFAULT first move for any dark unit, before
anyone reaches for serial. This doc maps what landed where, and records
the design choices with their rationale.

## Coverage map

| #323 item | Status | Where |
|---|---|---|
| 1. `conwrt probe` — L2 alias probing, MAC-matched | Engine landed; CLI promotion next | scripts/bench_discover.py (plan/run ladder) |
| 2. `conwrt listen` — boot-capture classifier, JSON verdict + next action | **Landed** | scripts/conwrt/bootlisten.py (`conwrt listen`) |
| 3. `conwrt adopt-door` — MAC-pinned lease seat | Superseded by the v6 door | `conwrt v6door` + `conwrt adopt` (PR #751) |
| 4. Model-JSON detection hints | **Landed (schema + first species)** | schemas/model.schema.json `detection`, models/extreme-networks-ws-ap3915i.json |

## Choice A — the door is v6-first; the dnsmasq lease seat is the fallback

The issue sketched `adopt-door` as a dnsmasq seat with a MAC-pinned
lease (a v4 mechanism). We landed the v6 door instead as the default:
`conwrt v6door` dials `fe80::<EUI-64>` derived from ANY observed source
MAC, from an on-link host (bench switch, dbclient).

Why: link-local v6 survives every failure mode a fresh flash exhibits
in v4 — PHY blindness, default-IP roulette (vendor defaults differ),
stale bench routes, ARP staleness — because it never depended on v4
configuration in the first place. The 2026-11-11 MF286D recovery burned
hours walking five v4 failure modes before the v6 door worked; that
ordering is now the code's ordering. A dnsmasq MAC-pinned seat remains
the documented fallback for units whose v6 stack is disabled (rare on
Linux/OpenWrt gear; the empty-password factory state still answers v6).

## Choice B — `conwrt listen` is a PURE classifier (text in → verdict out)

The classifier takes tcpdump `-ne` LINES from any source — live capture
(`--iface`), a saved transcript (`--pcap-text`), or the always-on bench
netlog — and never touches hardware itself.

Why: purity makes the brain provable offline. Every verdict path
(kernel-up → v6door, ARP-leak → alias-probe, DHCP-client → rogue check
+ adopt, vendor beacon → model-JSON subnets, silence → PHY-first) is
pinned by fixture tests with real-shaped tcpdump lines; no hardware
window is needed to prove classification logic. This is the same shape
that made `conwrt adopt` testable (FakeDoor) and the parity corpus
reliable (goldens). PoE cycling and capture logistics stay OUT of the
classifier on purpose: the bench already owns them (netlog capture
service, switch PoE control), and bundling them would make the logic
untestable without a bench window.

Verdict JSON carries `next_action` + `next_action_reason` so sweeps can
act without parsing prose.

## Choice C — `conwrt probe` promotes bench_discover, it does not rewrite it

scripts/bench_discover.py already encodes the methodology the hard way:
layer-0 positive control (refuse negatives when the control fails),
v6-first link-local, v4 archaeology (inventory history + own-subnet +
RFC1918), banner identify, and a credential ladder that is PRINTED,
never executed. The remaining gap is ergonomics: it is a bench script,
not a `conwrt` subcommand, so the default first move still requires
knowing where it lives. Promotion = a thin CLI wrapper over
`build_ladder`/`run_ladder`, not a second implementation — the ladder's
invariants (control gate, never-auto-exec credentials) are the parts
worth keeping verbatim.

## Choice D — model hints are an OPTIONAL schema'd `detection` block

Species-level hints (`watts` signatures, `vendor_subnets` to alias-probe,
`beacon_ports` for `conwrt listen`) live in the model JSONs — where the
rest of the species knowledge already lives — under an optional
`detection` object validated by schemas/model.schema.json.

Why optional keys: no model churn (dozens of models gain nothing they
don't have evidence for), and the schema documents the shape for the
next contributor. The block is EVIDENCE-ONLY: the AP3915i example
carries `vendor_subnets: ["192.168.1.0/24"]` because its stock/recovery
IPs are documented as 192.168.1.x in the same file; `watts` and
`beacon_ports` stay ABSENT until someone measures them — placeholder
telemetry would poison exactly the automated decisions this block
exists to feed.

## Verification ladder (how this stays honest)

- classifier: fixture tests per verdict path (tests/test_bootlisten.py)
- schema: existing model validation suite picks up the new optional block
- live behavior: `conwrt listen --pcap-text <netlog slice> --json` runs
  against real bench captures with zero hardware setup
- doors: `conwrt v6door --mac ... --via <switch> --vlan N --cmd 'uname -a'`
  (probe), then `conwrt adopt ...` (the gate ladder) — both from #751
