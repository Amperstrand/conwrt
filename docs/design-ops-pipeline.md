# Design Decisions: Ops Pipeline Evolution

Date: 2026-06-02
Status: Approved — proceeding with recommended sequence

## Background

conwrt has a transport-agnostic ops pipeline: each use case produces typed `Op` dataclasses (UciSet, UciCommit, ShellCommand, etc.) that are rendered to either shell scripts (`render_shell`) or ubus HTTP RPC calls (`render_ubus`). Today, every use case maintains **two** implementations — a shell string builder (`_build_X()`) and an ops builder (`_build_X_ops()`) — kept in sync by roundtrip tests.

The goal: make ops the single source of truth, extend ubus coverage, and add WiFi support over ubus. Four design decisions were researched.

## Research Sources

### Codebase analysis
- `scripts/profile/ops.py` — Op types, render_shell, render_ubus, RpcCall
- All 13 use case modules in `scripts/use_cases/` — formatting patterns in `_build_X()` outputs
- `tests/helpers.py` — roundtrip test helper that strips comments/blanks/echo
- `scripts/ubus_utils.py` — UbusClient with login, call, uci_get, uci_set, etc.

### External projects researched
- **pyinfra** (pyinfra-dev/pyinfra) — generator-based ops model, StringCommand/FunctionCommand, no shell script renderer, no comment support. Human labels via `name=` in logs only.
- **Ansible** (ansible/ansible) — templates rendered fresh (no comment round-tripping), `ansible_managed` header for generated files, `comment` filter for block delimiters.
- **wrtkit** (tlamadon/wrtkit) — OpenWrt config tool. Plain UCI commands for execution, section headers in preview output. Strips comments on import.
- **openwrt-configurator** (jasrusable/openwrt-configurator) — Same split: commented build plans for humans, plain command streams for devices.
- **OpenWrt UCI system** — Rewrites config files wholesale, deletes comments. Source: openwrt.org/docs/guide-user/base-system/uci
- **Pinecone SDK** (pinecone-io/python-sdk) — Explicit "transport parity" test naming pattern.
- **Ansible integration tests** — Parametrized: same playbook against SSH/local/WinRM connections.
- **Home Assistant OpenWrt ubus** (kvj/hass_openwrt, FUjr/homeassistant-openwrt-ubus) — Production code doing `network.wireless status` for radio discovery over ubus HTTP.
- **OpenWrt wireless.uc** — Source of `network.wireless` ubus object with `status`, `reconf`, `up`, `down` methods.
- **LuCI JS client** — Two-phase flow: `network.wireless status` → discover radios → `uci.set` to configure → `uci.apply`/`confirm`.

---

## Decision 1: Ops as Single Source of Truth

**Status**: Proceed now

### Problem

Every use case has two hand-maintained implementations that can drift. The roundtrip tests catch drift, but the duplication is the root problem.

### What we lose (formatting inventory)

Surveyed all 13 use case shell builders. Found exactly 3 decorative formatting patterns, used consistently:

| Pattern | Example | Count |
|---|---|---|
| Section header comment | `# --- AdGuard Home ---` | all 13 |
| Blank line separators | between logical groups | all 13 |
| Final status echo | `echo "SQM configured: ..."` | 12 of 13 |

There are **zero** inline trailing comments after commands in any use case.

Structural formatting (heredocs in auto_sqm/usb_tether, backslash continuations in tollgate) already works as ShellCommand ops.

### How other tools handle this

The universal pattern across pyinfra, Ansible, wrtkit, openwrt-configurator, and OpenWrt UCI itself: **keep the model pure, add a separate human-readable layer**.

- wrtkit: plain UCI commands for execution, `# Commands to add:` headers in preview
- openwrt-configurator: plain command stream for devices, commented build plans for humans
- pyinfra: no shell renderer at all, human labels in verbose logs
- Ansible: templates always rendered fresh, no comment preservation

### Solution

Add two formatting ops that are invisible to ubus:

```python
@dataclass
class Comment(Op):
    text: str
    # render_shell → "# {text}"
    # render_ubus → skipped

@dataclass
class BlankLine(Op):
    # render_shell → ""
    # render_ubus → skipped
```

Plus an optional `comment: str = ""` field on existing ops that render_shell appends as an inline comment. render_ubus ignores it.

Example — adguard ops become:

```python
def _build_adguard_ops(params):
    r = _resolve_params(params)
    return [
        Comment(f"AdGuard Home"),
        UciSet(config="adguardhome", section="adguardhome", values={
            "enabled": "1",
            "http_address": f"{r['listen_ip']}:{r['web_port']}",
            "dns_port": str(r["dns_port"]),
        }),
        UciCommit(config="adguardhome"),
        ServiceAction(name="adguardhome", action="enable"),
        ShellCommand(command="/etc/init.d/adguardhome start 2>/dev/null || true"),
        BlankLine(),
        UciSet(config="dhcp", section="@dnsmasq[0]", values={"noresolv": "1"}),
        UciAddList(config="dhcp", section="@dnsmasq[0]", option="server", value=f"127.0.0.1#{r['dns_port']}"),
        UciCommit(config="dhcp"),
        ShellCommand(command="/etc/init.d/dnsmasq restart 2>/dev/null || true"),
    ]
```

Then delete `_build_adguard()`. The roundtrip test becomes an identity test: `render_shell(ops) == render_shell(ops)`.

### Implementation steps

1. Add `Comment` and `BlankLine` dataclasses to `ops.py`
2. Update `render_shell` to handle them
3. Update `render_ubus` to skip them
4. Migrate use cases one at a time: add Comment/BlankLine to ops, delete `_build_X()`, update roundtrip test
5. Remove `build_configure` field from `UseCase` dataclass (replaced by `build_configure_ops` + `render_shell`)

### Impact

- ~15 lines new code (2 dataclasses + render_shell/render_ubus branches)
- 13 use case files modified (delete `_build_X()`, add formatting ops)
- `UseCase.build_configure` field deprecated then removed
- Roundtrip tests become simpler — no more `_config_lines` stripping

---

## Decision 2: ShellCommand → Typed Ops Promotion

**Status**: Postpone until hardware testing

### Problem

6 use cases use `ShellCommand` for operations that could be `UciSet`, `UciDelete`, etc. These are invisible to ubus transport (`apply_ubus` skips them with `fallback=True`).

### Why postpone

- Section creation (`uci set mwan3.wan=interface`) has no clean op equivalent — it's type-declaration syntax, not key-value
- Some commands genuinely need shell (`wget`, `ping`, `heredoc`, `cat > file`)
- mwan3 is the hardest — mixes section creation, typed values, and list operations
- No external tool provided a compelling pattern for this
- We don't know which use cases actually benefit from ubus promotion until we test on hardware

### Revisit when

After testing `conwrt configure --transport ubus` on a real device. The gaps will be empirically clear.

---

## Decision 3: WiFi over ubus

**Status**: Design approved, implement when hardware is available

### Problem

WiFi steps have `ops=[]` because radio names aren't known at plan-build time. SSH path handles this with runtime `uci get wireless.radioN.band`. ubus path currently skips WiFi entirely.

### Solution: Two-phase apply (confirmed by LuCI's own pattern)

LuCI (OpenWrt's web UI) and Home Assistant's OpenWrt integration both do exactly this flow:

**Phase 1 — Discover radios:**
```
POST /ubus
{"jsonrpc":"2.0","method":"call","params":["<token>","network.wireless","status",{}]}
→ {"radio0": {"config": {"band": "2g", ...}}, "radio1": {"config": {"band": "5g", ...}}}
```

Response keyed by radio name. `config.band` field tells us which radio is which.

Source: [wireless.uc status method](https://github.com/openwrt/openwrt/blob/ed2a36afae03b62de7b9a09b2e3eb62c5eae31bb/package/network/config/wifi-scripts/files/lib/netifd/wireless.uc#L507-L519)

**Phase 2 — Configure via uci:**
```
ubus call uci set '{"config":"wireless","section":"default_radio0","values":{"ssid":"MyNetwork",...}}'
ubus call uci commit '{"config":"wireless"}'
```

**Phase 3 — Apply:**
```
ubus call network.wireless reconf
```

### Available ubus calls

| Object | Method | Purpose |
|---|---|---|
| `network.wireless` | `status` | Discover all radios + interfaces |
| `network.wireless` | `reconf` | Reconfigure wireless without full restart |
| `network.wireless` | `up` / `down` | Bring radio up/down |
| `uci` | `get` | Load whole config (sections enumerated client-side) |
| `uci` | `set` | Set values on a section |
| `uci` | `commit` | Persist changes |
| `uci` | `apply` / `confirm` | Apply and confirm |

There is **no separate `wireless.radio` ubus object**. Everything goes through `network.wireless` and `uci`.

### Implementation sketch

`apply_ubus()` gets a WiFi-specific path:

```python
# In apply_ubus(), before the main step loop:
wifi_steps = [s for s in plan.steps if s.kind in (StepKind.WIFI_STA, StepKind.WIFI_AP)]
if wifi_steps:
    radios = _discover_radios_ubus(client)  # network.wireless status → {band: radio_name}
    for step in wifi_steps:
        target_band = step.wifi_params.get("band", "")
        radio = radios.get(band_to_openwrt(target_band))
        if radio:
            concrete_ops = wifi_sta_ops(radio, step.wifi_params) if step.wifi_role == "sta" else wifi_ap_ops(radio, step.wifi_params)
            calls = render_ubus(concrete_ops)
            for call in calls:
                client.call(call.object_name, call.method, call.params)
    client.call("network.wireless", "reconf", {})
```

### Revisit when

A device is available for ubus testing. The API shape is confirmed by LuCI source code and two independent production integrations.

---

## Decision 4: SSH/ubus Parity Testing

**Status**: Implement after Decision 1 (ops shape will change)

### Problem

No test verifies that `render_ubus(ops)` produces equivalent UCI state to `render_shell(ops)`. If a renderer maps an op wrong, nothing catches it.

### Solution: Pinecone-style explicit parity tests

Pattern from Pinecone SDK: each test names its transport and references the equivalence claim.

```python
# tests/test_transport_parity.py

def test_adguard_parity():
    """Transport parity: render_shell and render_ubus produce equivalent UCI state."""
    ops = _build_adguard_ops(DEFAULT_PARAMS)
    shell_state = _extract_uci_state(render_shell(ops))
    ubus_state = _extract_uci_state_from_rpc(render_ubus(ops))
    assert shell_state == ubus_state

def _extract_uci_state(shell: str) -> dict[tuple[str, str], dict[str, str]]:
    """Parse 'uci set X.Y.Z=W' lines into {(config, section): {key: value}}."""
    ...
```

The `_extract_uci_state` parser handles `uci set`, `uci add_list`, `uci commit`, `uci delete` — extracting the key-value pairs that represent the final UCI state. This is pure unit testing, no hardware needed.

### Why this pattern

- **Pinecone SDK**: Explicit naming, lightweight, no infrastructure
- **Ansible parametrized**: Same test against multiple connections — overkill for our 2 transports
- **Terraform golden files**: Deterministic snapshots — too heavy for our case
- **ConfigDiff**: Semantic config comparison — useful concept, but we just need tuple comparison

### Implementation steps

1. Write `_extract_uci_state(shell: str) -> dict` parser
2. Write `_extract_uci_state_from_rpc(calls: list[RpcCall]) -> dict` extractor
3. One test per use case that asserts both produce the same state
4. Run after any renderer change

---

## Recommended Sequence

| Order | Decision | Effort | Dependencies |
|---|---|---|---|
| 1 | Comment/BlankLine ops + ops-as-source-of-truth | Medium (13 use cases) | None |
| 2 | Transport parity tests | Low (parser + ~13 tests) | After D1 (ops shape changes) |
| 3 | WiFi two-phase ubus | Medium | Hardware available |
| 4 | ShellCommand promotion | TBD | After hardware testing reveals gaps |

## Key Metrics (pre-work)

- 713 tests passing
- 13 use case modules with ops
- 8 Op types (UciSet, UciAdd, UciDelete, UciAddList, UciCommit, ServiceAction, ShellCommand, + RpcCall for ubus)
- 2 transport renderers (render_shell, render_ubus)
- `make ci` = ruff lint + pyright typecheck + pytest + smoke
