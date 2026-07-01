#!/usr/bin/env python3
"""Bufferbloat comparison test — measures latency under load before and after SQM.

Boots OpenWrt VM, measures baseline (no SQM), configures SQM via conwrt,
re-measures, produces comparison data with all artifacts.

Usage:
    python3 tests/integration/run_bufferbloat_test.py \
        --host 127.0.0.1 --port 2222 \
        --key ~/.ssh/vm_key \
        --iperf3-port 5201 \
        --conwrt-repo ~/src/conwrt \
        --output-dir results/bufferbloat-$(date +%Y%m%d)

Artifacts produced:
    baseline-iperf3.json     iperf3 throughput JSON (no SQM)
    baseline-ping.txt        Ping timestamps during load (no SQM)
    baseline-cpu.csv         CPU utilization during load (no SQM)
    baseline-tc-qdisc.txt    tc qdisc state (no SQM)
    sqm-iperf3.json          iperf3 throughput JSON (with SQM)
    sqm-ping.txt             Ping timestamps during load (with SQM)
    sqm-cpu.csv              CPU utilization during load (with SQM)
    sqm-tc-qdisc.txt         tc qdisc state (with SQM)
    uci-dump.txt             UCI configuration after conwrt configure
    conwrt-output.txt        conwrt configure stdout/stderr
    boot-log.txt             dmesg / kernel boot log
    system-info.json         VM hardware/kernel info
    comparison.json          Structured before/after comparison
    summary.md               Human-readable summary
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean


def ssh(host: str, port: int, key: str | None, command: str, timeout: int = 30) -> str:
    args = [
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=5",
        "-o", "LogLevel=ERROR",
        "-p", str(port),
    ]
    if key:
        args.extend(["-i", key])
    args.append(f"root@{host}")
    args.append(command)
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        print(f"  SSH warning (rc={r.returncode}): {r.stderr.strip()[:200]}", file=sys.stderr)
    return r.stdout.strip()


def run_local(command: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout)


def measure_phase(
    label: str,
    ssh_host: str, ssh_port: int, ssh_key: str | None,
    iperf3_port: int,
    duration: int = 20,
    rate_cap: str = "20M",
) -> dict:
    print(f"\n{'='*60}")
    print(f"  Measuring {label}...")
    print(f"{'='*60}")

    results = {}

    ssh(ssh_host, ssh_port, ssh_key, "pgrep iperf3 || iperf3 -s -D", timeout=10)
    time.sleep(1)

    ssh(ssh_host, ssh_port, ssh_key, "tc qdisc show > /tmp/tc-qdisc.txt")
    results["tc_qdisc"] = ssh(ssh_host, ssh_port, ssh_key, "cat /tmp/tc-qdisc.txt")

    cpu_stop = threading.Event()
    cpu_samples = []

    def collect_cpu():
        while not cpu_stop.is_set():
            out = ssh(ssh_host, ssh_port, ssh_key,
                      "top -bn1 | head -5 | tail -1", timeout=5)
            m = re.search(r"(\d+\.?\d*)%id", out)
            if m:
                cpu_idle = float(m.group(1))
                cpu_samples.append(100.0 - cpu_idle)
            time.sleep(1)

    cpu_thread = threading.Thread(target=collect_cpu, daemon=True)
    cpu_thread.start()

    ping_latencies = []
    ping_stop = threading.Event()

    def collect_ping():
        while not ping_stop.is_set():
            r = run_local([
                "ping", "-c", "1", "-W", "1", ssh_host
            ], timeout=3)
            m = re.search(r"time=([\d.]+) ms", r.stdout)
            if m:
                ping_latencies.append(float(m.group(1)))
            time.sleep(0.5)

    ping_thread = threading.Thread(target=collect_ping, daemon=True)
    ping_thread.start()

    print(f"  Running iperf3 ({duration}s, {rate_cap} cap)...")
    iperf = run_local([
        "iperf3", "-c", ssh_host, "-p", str(iperf3_port),
        "-t", str(duration), "-b", rate_cap, "-J"
    ], timeout=duration + 10)

    ping_stop.set()
    cpu_stop.set()
    ping_thread.join(timeout=2)
    cpu_thread.join(timeout=2)

    results["iperf3"] = json.loads(iperf.stdout) if iperf.stdout.strip().startswith("{") else {}
    results["ping_latencies"] = ping_latencies
    results["cpu_samples"] = cpu_samples

    if ping_latencies:
        sl = sorted(ping_latencies)
        results["latency_avg"] = round(mean(ping_latencies), 1)
        results["latency_p99"] = round(sl[int(len(sl) * 0.99)], 1)
        results["latency_max"] = round(max(ping_latencies), 1)
    else:
        results["latency_avg"] = 0
        results["latency_p99"] = 0
        results["latency_max"] = 0

    if cpu_samples:
        results["cpu_avg"] = round(mean(cpu_samples), 1)
    else:
        results["cpu_avg"] = 0

    throughput = 0
    end_data = results["iperf3"].get("end", {})
    sum_sent = end_data.get("sum_sent", end_data.get("sum", {}))
    if sum_sent:
        bps = sum_sent.get("bits_per_second", 0)
        throughput = round(bps / 1_000_000, 1)
    results["throughput_mbps"] = throughput

    print(f"  Latency avg: {results['latency_avg']}ms, max: {results['latency_max']}ms")
    print(f"  Throughput: {results['throughput_mbps']} Mbps")
    print(f"  CPU avg: {results['cpu_avg']}%")

    return results


def save_artifacts(output_dir: Path, phase: str, data: dict) -> None:
    d = output_dir
    d.mkdir(parents=True, exist_ok=True)

    if data.get("iperf3"):
        (d / f"{phase}-iperf3.json").write_text(
            json.dumps(data["iperf3"], indent=2))

    if data.get("ping_latencies"):
        with open(d / f"{phase}-ping.txt", "w") as f:
            for i, lat in enumerate(data["ping_latencies"]):
                ts = i * 0.5
                f.write(f"{ts:.1f}\t{lat:.1f}\n")

    if data.get("cpu_samples"):
        with open(d / f"{phase}-cpu.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["sample", "cpu_pct"])
            for i, cpu in enumerate(data["cpu_samples"]):
                w.writerow([i, cpu])

    if data.get("tc_qdisc"):
        (d / f"{phase}-tc-qdisc.txt").write_text(data["tc_qdisc"])


def build_comparison(baseline: dict, sqm: dict) -> dict:
    lat_reduction = baseline["latency_avg"] - sqm["latency_avg"]
    lat_pct = (lat_reduction / baseline["latency_avg"] * 100) if baseline["latency_avg"] else 0
    tp_cost = baseline["throughput_mbps"] - sqm["throughput_mbps"]
    tp_pct = (tp_cost / baseline["throughput_mbps"] * 100) if baseline["throughput_mbps"] else 0
    cpu_cost = sqm["cpu_avg"] - baseline["cpu_avg"]

    return {
        "bufferbloat": {
            "baseline": {
                "latency_avg_ms": baseline["latency_avg"],
                "latency_p99_ms": baseline["latency_p99"],
                "latency_max_ms": baseline["latency_max"],
                "throughput_mbps": baseline["throughput_mbps"],
                "cpu_avg_pct": baseline["cpu_avg"],
            },
            "with_sqm": {
                "latency_avg_ms": sqm["latency_avg"],
                "latency_p99_ms": sqm["latency_p99"],
                "latency_max_ms": sqm["latency_max"],
                "throughput_mbps": sqm["throughput_mbps"],
                "cpu_avg_pct": sqm["cpu_avg"],
            },
            "improvement": {
                "latency_reduction_ms": round(lat_reduction, 1),
                "latency_reduction_pct": round(lat_pct, 1),
                "throughput_cost_mbps": round(tp_cost, 1),
                "throughput_cost_pct": round(tp_pct, 1),
                "cpu_cost_pct": round(cpu_cost, 1),
            },
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Bufferbloat before/after comparison test")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--key", default=None)
    parser.add_argument("--iperf3-port", type=int, default=5201)
    parser.add_argument("--conwrt-repo", default=str(Path.home() / "src" / "conwrt"))
    parser.add_argument("--output-dir", default=f"results/bufferbloat-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    parser.add_argument("--duration", type=int, default=20, help="iperf3 duration per phase (seconds)")
    parser.add_argument("--rate-cap", default="20M", help="iperf3 bandwidth cap")
    parser.add_argument("--download-kbps", type=int, default=10000)
    parser.add_argument("--upload-kbps", type=int, default=5000)
    args = parser.parse_args()

    out = Path(args.output_dir)
    conwrt = Path(args.conwrt_repo)

    print(f"Output: {out}")
    print(f"conwrt: {conwrt}")
    print(f"Router: {args.host}:{args.port}")

    out.mkdir(parents=True, exist_ok=True)

    print("\n--- Installing iperf3 on router ---")
    ssh(args.host, args.port, args.key, "opkg update 2>/dev/null; opkg install iperf3 2>&1 | tail -3", timeout=60)

    print("\n--- Capturing system info ---")
    sysinfo = {
        "openwrt_release": ssh(args.host, args.port, args.key, "cat /etc/openwrt_release 2>/dev/null"),
        "uname": ssh(args.host, args.port, args.key, "uname -a"),
        "cpuinfo": ssh(args.host, args.port, args.key, "grep -c processor /proc/cpuinfo") + " cores",
        "memory": ssh(args.host, args.port, args.key, "free -m | grep Mem"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    (out / "system-info.json").write_text(json.dumps(sysinfo, indent=2))

    boot_log = ssh(args.host, args.port, args.key, "dmesg 2>/dev/null | head -200", timeout=10)
    (out / "boot-log.txt").write_text(boot_log)

    print("\n=== PHASE 1: BASELINE (no SQM) ===")
    ssh(args.host, args.port, args.key,
        "uci -q set sqm.@queue[0].enabled=0 2>/dev/null; "
        "/etc/init.d/sqm stop 2>/dev/null; "
        "/etc/init.d/sqm disable 2>/dev/null; true")
    time.sleep(2)

    baseline = measure_phase("BASELINE", args.host, args.port, args.key,
                             args.iperf3_port, args.duration, args.rate_cap)
    save_artifacts(out, "baseline", baseline)

    print("\n=== PHASE 2: CONFIGURE SQM VIA CONWRT ===")
    config = conwrt / "config.toml"
    backup = conwrt / "config.toml.bak"
    if config.exists():
        backup.write_text(config.read_text())
    try:
        config.write_text(
            f"[password]\nmode = \"none\"\n\n"
            f"[network]\nlan_ip_mode = \"static\"\nlan_ip = \"{args.host}\"\n\n"
            f"[use_cases]\nenabled = [\"sqm\"]\n\n"
            f"[use_cases.sqm]\ndownload_kbps = {args.download_kbps}\nupload_kbps = {args.upload_kbps}\n"
        )
        result = run_local([
            "python3", str(conwrt / "scripts" / "conwrt.py"), "configure",
            "--model-id", "virtual-x86-64",
            "--ip", args.host,
        ], timeout=120)
        (out / "conwrt-output.txt").write_text(
            f"exit={result.returncode}\n\nSTDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}")
        if result.returncode != 0:
            print(f"conwrt configure FAILED: {result.stderr[:200]}", file=sys.stderr)
    finally:
        if backup.exists():
            config.write_text(backup.read_text())
            backup.unlink()

    uci_dump = ssh(args.host, args.port, args.key, "uci show sqm 2>/dev/null || echo 'no sqm config'")
    (out / "uci-dump.txt").write_text(uci_dump)
    time.sleep(5)

    print("\n=== PHASE 3: WITH SQM ===")
    sqm = measure_phase("WITH SQM", args.host, args.port, args.key,
                       args.iperf3_port, args.duration, args.rate_cap)
    save_artifacts(out, "sqm", sqm)

    print("\n=== BUILDING COMPARISON ===")
    comparison = build_comparison(baseline, sqm)
    (out / "comparison.json").write_text(json.dumps(comparison, indent=2))

    b = comparison["bufferbloat"]
    summary = (
        f"# Bufferbloat Test Results\n\n"
        f"**Date:** {sysinfo['timestamp']}\n"
        f"**Router:** {sysinfo['uname']}\n"
        f"**SQM:** {args.download_kbps}/{args.upload_kbps} Kbit/s CAKE\n\n"
        f"| Metric | Baseline (no SQM) | With SQM | Change |\n"
        f"|--------|------------------|----------|--------|\n"
        f"| Avg latency | {b['baseline']['latency_avg_ms']}ms | {b['with_sqm']['latency_avg_ms']}ms | "
        f"{b['improvement']['latency_reduction_pct']}% reduction |\n"
        f"| P99 latency | {b['baseline']['latency_p99_ms']}ms | {b['with_sqm']['latency_p99_ms']}ms | |\n"
        f"| Max latency | {b['baseline']['latency_max_ms']}ms | {b['with_sqm']['latency_max_ms']}ms | |\n"
        f"| Throughput | {b['baseline']['throughput_mbps']} Mbps | {b['with_sqm']['throughput_mbps']} Mbps | "
        f"{b['improvement']['throughput_cost_pct']}% cost |\n"
        f"| CPU usage | {b['baseline']['cpu_avg_pct']}% | {b['with_sqm']['cpu_avg_pct']}% | "
        f"+{b['improvement']['cpu_cost_pct']}% |\n\n"
        f"**Latency reduced from {b['baseline']['latency_avg_ms']}ms to {b['with_sqm']['latency_avg_ms']}ms "
        f"({b['improvement']['latency_reduction_pct']}% improvement)**\n"
    )
    (out / "summary.md").write_text(summary)
    print(f"\n{summary}")
    print(f"\nArtifacts saved to: {out}")


if __name__ == "__main__":
    main()
