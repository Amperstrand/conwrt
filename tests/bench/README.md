# VPN bench — repeatable NordVPN technology benchmarks

Measures every NordVPN technology conwrt supports on a physical router:
tunnel establishment (via `conwrt configure`, isolated temp config — your
repo `config.toml` is never touched), exit verification, and iperf3
throughput in both directions with router CPU sampled at 1 Hz.

## Run

```bash
make bench-vpn                                     # all default scenarios
CONWRT_BENCH_ONLY=nordlynx make bench-vpn          # one scenario
CONWRT_BENCH_IPSEC=1 make bench-vpn                # + IKEv2 (needs baked image)
pytest tests/bench -m "bench and openvpn"          # by marker
```

Results: `test-results/vpn-bench-<ts>/` (gitignored) — `results.json` +
`summary.md`. Comparable across runs and routers: every row is keyed by
scenario name and carries router board/release/cores.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `CONWRT_BENCH_ROUTER` | 192.168.1.1 | router IP (suite skips if unreachable) |
| `CONWRT_BENCH_MODEL` | auto | conwrt model id (auto-detected from board.json) |
| `CONWRT_BENCH_IFACE` | enp5s0 | host interface for configure |
| `CONWRT_BENCH_TOKEN` | from config.toml | NordVPN access token |
| `CONWRT_BENCH_SERVER` | inr2.cashu.exchange | iperf3 server |
| `CONWRT_BENCH_SECONDS` | 10 | per-direction iperf duration |
| `CONWRT_BENCH_AP_SSID/KEY` | unset | include VPN-exit AP in scenarios |
| `CONWRT_BENCH_ONLY` | all | comma-separated scenario names |

## Scenarios

`nordlynx` (WireGuard/ChaCha20), `openvpn-udp-cbc`, `openvpn-udp-gcm`,
`openvpn-tcp`; with `CONWRT_BENCH_IPSEC=1` also `ikev2-cbc-nohw` /
`ikev2-cbc-hw` (EIP-93 hardware crypto on/off — the latter documents the
SAD-install verdict on kernels where the driver misbehaves with xfrm).

Add a scenario in `scenarios.py`; the tests, markers, and result keys
follow automatically.
