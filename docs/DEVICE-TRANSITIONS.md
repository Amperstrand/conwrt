# Device Transitions — unifying conwrt under the labgrid resource/strategy pattern

Design note (2026-09-22). Status: PROPOSAL — read, critique, then implement in
phases (end of file). Premise: **conwrt is a state-transition engine**. Every
thing it does — flash, adopt, recover, configure — takes a device from one
state to another, using whatever interfaces (resources) that device exposes.
labgrid models exactly this shape: resources × drivers × strategies × places.
The bench already speaks labgrid (power); this doc generalizes the pattern to
the whole framework, including the case where **the resource is a human**.

## 1. State vocabulary (one namespace for conwrt + labgrid + PRTA)

| State | Meaning | Detected by |
|---|---|---|
| `off` | no power | link down, PoE draw ~0 |
| `dark` | powered, zero frames ever | bench_discover ladder (the ONLY serial-gated class) |
| `uboot` | bootloader prompt/recovery | pcap boot signatures, router-probe |
| `recovery` | vendor recovery mode (e.g. D-Link HTTP) | model signature (subnet + HTTP probe) |
| `stock` | vendor firmware | fingerprint / model heuristics |
| `openwrt-fresh` | OpenWrt, factory defaults | board_name + no keys/password |
| `openwrt-adopted` | OpenWrt + keys + password + bench/static addressing | bench_adopt verify stage |
| `wedge` | alive at L2/L3 but no auth/answers | auth-dead classifier, ICMP-filter ladder |

`router-probe.py` already emits off/uboot/openwrt; this table extends it and
matches labgrid `Status` semantics (off / bootloader / shell).

## 2. Resource classes — including the human

Every DUT exposes a subset. A **place** (bench or desk) is the named set:

| Class | Bench form | Desk form (x1860 case) | labgrid resource/driver |
|---|---|---|---|
| Power control | PoE via conwrt_poe | **the human** unplugs/plugs | `NetworkPowerPort` / **`ManualPowerDriver`** |
| Physical switch | — (reset button, if reachable) | **the human** holds reset | **`ManualSwitchDriver`** |
| Console | FT232R serial (#62 era) | same | `SerialPort` + `SerialDriver` |
| Network | per-VLAN statics + v6 link-local | subnet attach on the Mac iface | `NetworkService` + `SSHDriver` |
| Boot observer | pcap capture on the switch | tcpdump on the Mac | (custom driver — conwrt's monitor) |
| Human channel | operator at the bench | `say` voice prompts / terminal prompt | manual drivers block until confirmed |

Key point: **conwrt's macOS `say` voice guidance is already a manual driver** —
"hold the reset button…" is a ManualSwitchDriver step with a voice UI. Making
this explicit means every transition can declare its resource requirements and
REFUSE to run when the place lacks them — the failsafe becomes structural,
not prose.

## 3. Transition table (per flash method)

The `Requires` column of the README's method table, formalized. A method is
runnable on a place iff every listed resource is present AND the envelope
precondition (recovery path before the risky step — AGENTS.md discipline)
holds:

| Method | From → To | Resources required | Envelope precondition |
|---|---|---|---|
| `sysupgrade` | openwrt* → openwrt-fresh | NetworkService | board_name == model profile |
| `recovery-http` | any → openwrt-fresh | **manual power + manual switch** + subnet attach | factory image type verified |
| `tftp-boot` | uboot/flash-failed → openwrt-fresh(RAM) | power + TFTP server armed | bootcmd fallback tail verified |
| `tftp-lifeline` | flash-boot-failed → openwrt-adopted | PoE + TFTP armed | (is the recovery path itself) |
| `adopt` (firstboot) | openwrt* → openwrt-fresh → adopted | NetworkService (v6 LL) | **R1 envelope: password + keys + lifeline + recorder** |
| `serial-base64/xmodem` | any → any | SerialPort | Factory/calibration dumped FIRST |
| `zycast` | stock(zloader) → openwrt | power + multicast L2 | kill-sender plan after flash |
| `extreme-rdwr-tftp` | stock → openwrt | stock NetworkService + TFTP | CFG blocks backed up, CFG2 pristine |
| `configure` | openwrt-* → openwrt-adopted(+profile) | NetworkService | dry-run plan shown, `uci changes` clean |
| `discover` (dark ladder) | dark → any | passive observer + v6 probe host | positive control on a known-good host first |

New rule this table implies (generalizing tonight's lessons): **a transition
without its envelope precondition is not runnable — refuse, like bench_adopt's
`reset_allowed` gate, but derived from declared requirements instead of
hand-maintained flags.**

## 4. Worked example — the x1860 desk rig (human as infrastructure)

Local labgrid target (no coordinator needed — labgrid supports in-process
targets from YAML; the desk case stays zero-infra):

```yaml
## targets/x1860-desk.yaml — D-Link COVR-X1860 A1, operator-driven
targets:
  main:
    resources:
      ManualPowerPort: {}
      ManualSwitchPort: {}
      NetworkService:
        address: 192.168.0.1     ## recovery subnet (no SSH yet — observer only)
        username: root
    drivers:
      ManualPowerDriver:
        message: "Power the x1860 OFF, then press Enter"
      ManualSwitchDriver:
        message: "Hold RESET, power ON, release when LED blinks fast, then Enter"
```

The `recovery-http` transition on this rig = ManualPowerDriver.step(off) →
ManualSwitchDriver.step(hold-reset) → wait for model's HTTP signature →
conwrt upload+verify (existing code) → NetworkService becomes real SSH after
first boot → `adopt`. Every human step blocks until confirmed; nothing races
the operator; the session log records who-did-what-when (inventory material).

## 5. Two labgrid modes, one pattern

- **Bench (remote)**: coordinator + exporter + places (what we run today:
  ap-lan2..8). Locking, multi-agent, PRTA interop.
- **Desk (local)**: in-process target from YAML, zero infrastructure. The
  x1860, the lab 24E, any kitchen-table flash. Same strategies, same resource
  vocabulary — `conwrt flash` can drive either.

## 6. Migration phases

- **P0 (this doc)** — shared vocabulary + transition table. Review and amend.
- **P1 — mechanical**: add `resources_required` + `envelope` fields to
  `models/*.json` flash-method entries (schema-gated, `make validate-models`);
  write the desk YAML for one manual rig (x1860) + one PoE rig (ap-lan4) as
  reference; map `say` prompts onto manual-driver semantics in
  `scripts/conwrt.py` (prompt + blocking confirm), no engine rewrite.
- **P2 — integration**: a `conwrt.strategy` module exposing each method as a
  transition runnable against a labgrid Target (local or remote); bench tests
  (PRTA + ours) acquire places and call transitions; envelope preconditions
  enforced in code (machine-checked AGENTS rules).
- **P3 — optional**: exporter for desk rigs when the Mac is on the bench
  network, so PRTA can see "desk-x1860" as a place too.

## 7. What we deliberately do NOT do

- No rewrite of the pcap event engine, the flash executors, or bench_switch /
  bench_adopt — they are battle-tested; they become the driver/step layer.
- No coordinator dependency for desk flows (local targets only).
- No new lock protocol — labgrid place acquire + the flocks we already run.
- Human-channel steps stay OPTIONAL: an unattended bench place with PoE never
  blocks on a human; a desk place without PoE always knows it must ask.
