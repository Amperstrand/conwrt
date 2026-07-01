# conwrt Context-VM Test Plan

## Architecture

Tests run on SHC VMs ($0.03/run) with real QEMU OpenWrt. Artifacts
upload to Blossom, metadata publishes as Nostr NIP-94 events. GitHub
Pages renders results by fetching from Nostr — no direct publish.

```
SHC VM ($0.03)                    Nostr/Blossom              GitHub Pages
┌────────────────────┐           ┌───────────┐           ┌─────────────────┐
│ 1. Boot OpenWrt VM │           │           │           │                 │
│ 2. Bufferbloat:    │           │  Blossom  │           │  Static page    │
│    baseline (noSQM)│──upload──→│  (files)  │←─fetch───│  fetches latest │
│    conwrt configure│           │           │           │  kind 30078     │
│    with SQM        │           │  NIP-94   │           │  events, pulls  │
│    compare         │──publish─→│  (meta)   │←─fetch───│  artifacts from │
│ 3. VPN lifecycle   │           │           │           │  Blossom,       │
│ 4. Collect all     │           │  kind     │           │  renders charts │
│ 5. Upload+publish  │           │  30078    │           │  (Chart.js)     │
└────────────────────┘           │  (summary)│           └─────────────────┘
                                 └───────────┘
```

## Bufferbloat Test (Phase 1)

### Sequence (single OpenWrt VM, ~15 min)

```
1. Boot OpenWrt x86_64 VM (KVM, 512MB RAM)
2. Install iperf3 + sqm-scripts on VM
3. Start iperf3 server on VM

4. BASELINE (no SQM):
   a. iperf3 client → VM, 20s, 20M cap → save JSON
   b. During iperf3: ping every 0.5s → save timestamps
   c. During iperf3: mpstat 1-second samples → save CPU
   d. tc qdisc show → save qdisc state
   e. Record: max latency, avg latency, 99th percentile

5. CONFIGURE SQM:
   a. conwrt configure --model-id virtual-x86-64 --use-cases sqm
   b. Save conwrt stdout/stderr
   c. Wait 5s for SQM to settle
   d. uci show sqm → save UCI dump
   e. Verify: sqm enabled, qdisc=cake, correct speeds

6. WITH SQM:
   a. Repeat step 4 (same test, SQM now active)
   b. Save all artifacts with "sqm-" prefix

7. CAPTURE CONTEXT:
   a. dmesg → boot log
   b. logread → system log
   c. uname -a → kernel version
   d. free -m → memory
   e. cat /proc/cpuinfo → CPU info

8. RENDER:
   a. comparison.json — structured before/after data
   b. Generate comparison charts (Chart.js compatible JSON)
   c. Summary: "Latency reduced from Xms to Yms (Z% improvement)"

9. PUBLISH:
   a. Upload each artifact to Blossom (via nak blossom upload)
   b. Publish NIP-94 per artifact (via nak)
   c. Publish kind 30078 summary with all artifact URLs
```

### Artifacts per run

| Artifact | Format | Blossom content type |
|---|---|---|
| `baseline-iperf3.json` | JSON | application/json |
| `baseline-ping.txt` | Text | text/plain |
| `baseline-cpu.csv` | CSV | text/csv |
| `baseline-tc-qdisc.txt` | Text | text/plain |
| `sqm-iperf3.json` | JSON | application/json |
| `sqm-ping.txt` | Text | text/plain |
| `sqm-cpu.csv` | CSV | text/csv |
| `sqm-tc-qdisc.txt` | Text | text/plain |
| `comparison.json` | JSON | application/json |
| `uci-dump.txt` | Text | text/plain |
| `conwrt-output.txt` | Text | text/plain |
| `boot-log.txt` | Text | text/plain |
| `system-info.json` | JSON | application/json |
| `summary.md` | Markdown | text/markdown |

### Key Metrics in comparison.json

```json
{
  "bufferbloat": {
    "baseline": {
      "latency_avg_ms": 187.3,
      "latency_p99_ms": 312.0,
      "latency_max_ms": 445.0,
      "throughput_mbps": 18.7,
      "cpu_avg_pct": 12.4
    },
    "with_sqm": {
      "latency_avg_ms": 23.1,
      "latency_p99_ms": 41.2,
      "latency_max_ms": 67.0,
      "throughput_mbps": 9.4,
      "cpu_avg_pct": 34.8
    },
    "improvement": {
      "latency_reduction_pct": 87.7,
      "latency_reduction_ms": 164.2,
      "throughput_cost_pct": 49.7,
      "cpu_cost_pct": 22.4
    }
  }
}
```

## VPN Test (Phase 2)

### Sequence (two endpoints, ~20 min)

```
1. Boot OpenWrt VM (WG client) + configure host as WG server
2. Generate WG keys (server + client)
3. conwrt configure --use-cases wireguard-client
4. Verify:
   a. wg show → handshake successful
   b. ping through tunnel → connectivity OK
   c. iperf3 through tunnel → throughput + overhead
   d. Kill switch: block WG port → verify traffic stops
   e. Reconnect: unblock → verify auto-reconnect
5. Collect artifacts + publish (same pipeline as bufferbloat)
```

## GitHub Pages Renderer (Phase 3)

### Static page that fetches from Nostr

```html
<!-- docs/test-results.html -->
<script>
  // 1. Fetch latest kind 30078 event for conwrt test runs
  const events = await nak.req({
    kinds: [30078],
    "#d": ["conwrt-bufferbloat"],
    limit: 10,
  });

  // 2. For each run, fetch NIP-94 artifact events
  const artifacts = await nak.req({
    kinds: [1063],
    "#e": [event.id],
  });

  // 3. Fetch comparison.json from Blossom URL
  const comparison = await fetch(artifactUrl);

  // 4. Render with Chart.js
  renderLatencyChart(comparison);
  renderThroughputChart(comparison);
</script>
```

Uses `nostr-tools` library in the browser. No backend needed.

## Implementation Order

| Phase | Effort | Deliverable |
|---|---|---|
| **1a** | 3 hrs | Bufferbloat test runner script |
| **1b** | 1 hr | Artifact collector + comparison.json renderer |
| **1c** | 1 hr | Blossom/Nostr publisher (reuse existing tools) |
| **1d** | 2 hrs | GitHub Pages Nostr client renderer |
| **2** | 4 hrs | VPN lifecycle test |
| **3** | 2 hrs | Chart rendering + comparison visualization |
| **4** | 1 hr | SHC integration (lightweight bootstrap option) |

## SHC Lightweight Bootstrap

A conwrt-specific bootstrap that skips TollGate dependencies:

```bash
# Steps: 7 (vs 15 for TollGate)
1. Install QEMU + system packages
2. Download OpenWrt x86_64 QEMU image
3. Clone conwrt repo
4. pip install conwrt
5. Configure network bridge
6. Load KVM modules
7. Run conwrt tests
```

Saves ~10 minutes of provisioning (no Rust, nak, cashu, CDK, BlossomFS, vwifi).

## Triggering

- **GitHub Actions QEMU test**: Every PR (free, config correctness only)
- **SHC functional test**: Manual dispatch via `cloud-lab.py submit --cloud shc`
- **Both publish to Nostr/Blossom**: GH Actions uses nak CLI, SHC uses same
