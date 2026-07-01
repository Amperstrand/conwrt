# conwrt Virtual Testing Plan

## Goal

Integrate conwrt into the physical-router-test-automation framework with
virtual OpenWrt routers. Start with SQM (easiest), expand to WireGuard and
multi-WAN later.

## Architecture: Two-Tier Testing

```
Tier 1: Docker CI (conwrt repo, GitHub Actions, free)
  ┌─────────────────────────────────────────┐
  │ GitHub Actions Runner                    │
  │  ├── OpenWrt rootfs Docker container     │
  │  │   ├── dropbear (SSH)                  │
  │  │   ├── sqm-scripts package             │
  │  │   └── /etc/config/ writable          │
  │  ├── conwrt configure --use-case sqm    │
  │  └── Verify: uci show sqm (config)      │
  └─────────────────────────────────────────┘
  Tests: config correctness only (no kernel modules for tc)

Tier 2: SHC Cloud VM (parent test repo, cheap)
  ┌─────────────────────────────────────────┐
  │ SHC VPS (QEMU nested virt)              │
  │  ├── OpenWrt x86_64 VM (full kernel)    │
  │  │   ├── sch_cake / sch_fq_codel        │
  │  │   ├── sqm-scripts                     │
  │  │   └── tc qdisc active                │
  │  ├── Debian client VM                   │
  │  │   └── iperf3 + ping (latency test)   │
  │  ├── conwrt configure --use-case sqm   │
  │  └── Verify: tc qdisc + iperf3 + ping  │
  └─────────────────────────────────────────┘
  Tests: functional (traffic actually shaped)
```

## Phase 1: Audit SQM preset (no VM, 30 min)

Compare conwrt's SQM use case against the OpenWrt wiki SQM guide.

| Check | conwrt value | Wiki recommendation |
|-------|-------------|-------------------|
| qdisc | cake (default) | cake for most connections |
| script | piece_of_cake.qos | simplest, good defaults |
| link_layer | none | "none" for ethernet, "atm" for VDSL |
| download/upload | configurable | must match actual link speed |
| interface | wan | correct — shape at WAN egress |

Action: Read `scripts/use_cases/sqm.py`, compare against
https://openwrt.org/docs/guide-user/network/two_word_tips/bufferbloat,
fix discrepancies.

## Phase 2: Docker CI in conwrt (2-3 hours)

### Docker image

Build a custom OpenWrt Docker image:
```dockerfile
FROM openwrt/rootfs:x86_64
# Install sqm-scripts and dropbear via opkg
RUN mkdir -p /var/lock /var/run /tmp && \
    /sbin/opkg update && \
    /sbin/opkg install dropbear sqm-scripts
# Configure SSH
RUN echo "root:root" | chpasswd && \
    mkdir -p /etc/dropbear
EXPOSE 22
CMD ["/usr/sbin/dropbear", "-R", "-F", "-E"]
```

### Test file: `conwrt/tests/integration/test_configure_sqm.py`

```python
def test_conwrt_configure_applies_sqm(docker_openwrt):
    """Run conwrt configure with SQM, verify UCI state."""
    # SSH to the container
    ip = docker_openwrt.host
    port = docker_openwrt.port

    # Run conwrt configure
    subprocess.run([
        "python3", "scripts/conwrt.py", "configure",
        "--model-id", "virtual-x86",  # or generic model
        "--ip", f"{ip}",
        "--use-cases", "sqm",
    ], check=True)

    # Verify UCI state via SSH
    result = ssh(ip, port, "uci show sqm")
    assert "sqm.queue" in result
    assert "qdisc='cake'" in result
    assert "script='piece_of_cake.qos'" in result
    assert "enabled='1'" in result
```

### GitHub Actions workflow

```yaml
jobs:
  sqm-config-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t openwrt-test tests/integration/
      - run: docker run -d --privileged -p 2222:22 openwrt-test
      - run: pip install -e '.[dev]'
      - run: pytest tests/integration/ -v
```

### What this tests
- ✅ conwrt configure connects via SSH
- ✅ conwrt configure generates correct UCI commands
- ✅ UCI state is correct after configuration
- ✅ sqm-scripts package is installed
- ❌ tc qdisc actually works (no kernel modules in Docker)

## Phase 3: SHC functional tests in parent repo (1 day)

### New directory: `physical-router-test-automation/conwrt/`

```
conwrt/
├── conftest.py                 # Router fixtures (reuse lib.router.Router)
├── test_sqm_functional.py      # SQM traffic shaping verification
├── test_configure_flow.py      # Full conwrt configure → verify
└── README.md                   # How to run conwrt tests
```

### test_sqm_functional.py

```python
def test_sqm_reduces_bufferbloat(router, client):
    """Verify SQM actually shapes traffic under load."""
    # 1. Configure SQM via conwrt
    router.ssh("conwrt configure --use-cases sqm --download-kbps 10000")

    # 2. Baseline latency (no load)
    baseline = client.ping(router.ip, count=10)
    assert baseline.avg_ms < 20

    # 3. Generate load (iperf3 saturation)
    client.start_iperf(router.ip, "--bandwidth 20M")  # 2x SQM limit

    # 4. Measure latency under load
    loaded = client.ping(router.ip, count=10)
    loaded_avg = loaded.avg_ms

    # 5. Without SQM, latency would be 200-500ms under load
    #    With SQM (CAKE), should be < 50ms
    assert loaded_avg < 50, f"Bufferbloat not mitigated: {loaded_avg}ms"

def test_sqm_tc_qdisc_active(router):
    """Verify tc qdisc is configured after conwrt configure."""
    output = router.ssh("tc qdisc show dev eth0")
    assert "cake" in output or "fq_codel" in output
```

### SHC integration

The parent repo already has SHC provider support (`cloud-lab.py submit --cloud shc`).
The worker script would:
1. Spawn an OpenWrt x86_64 QEMU VM on SHC
2. Install conwrt on the host (pip install)
3. Run conwrt configure against the VM
4. Run iperf3/ping from a Debian client namespace
5. Report results

## Phase 4: Expand (future)

| Use case | Docker CI | SHC functional |
|----------|-----------|---------------|
| SQM | Phase 2 | Phase 3 |
| WireGuard | Add after SQM | Two-VM tunnel test |
| DoH | Add after WG | DNS resolution test |
| multi-WAN | Hard (needs 2 NICs) | mwan3 failover test |
| Guest WiFi | UCI only | mac80211_hwsim test |

## Key Decisions

1. **Docker for config tests** — Free CI, fast, tests UCI correctness
2. **SHC for functional tests** — Cheap cloud, tests actual traffic behavior
3. **SQM first** — Easiest to verify (latency under load is measurable)
4. **Full conwrt flow** — Tests `conwrt configure` end-to-end
5. **Parent repo integration** — New `conwrt/` directory in test framework

## Estimated effort

| Phase | Time | Deliverable |
|-------|------|------------|
| 1. Audit SQM | 30 min | Discrepancy report + fixes |
| 2. Docker CI | 2-3 hours | Working GitHub Actions test |
| 3. SHC functional | 1 day | iperf3-based bufferbloat test |
| 4. WireGuard | 2 days | Two-VM tunnel test |
