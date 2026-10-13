"""VPN bench stories — functional gate, then throughput + CPU per scenario.

Story vocabulary (mirrors the parent project's marker-driven selection):

    story "tunnel-establishes"   — the technology comes up via conwrt configure
    story "exit-via-nordvpn"    — the router's exit IP belongs to the VPN provider
    story "download-throughput" — iperf3 download Mbit/s + CPU busy%
    story "upload-throughput"   — iperf3 upload Mbit/s + CPU busy%

Select with:  pytest tests/bench -m bench
              pytest tests/bench -m "bench and nordlynx"
              CONWRT_BENCH_ONLY=nordlynx,openvpn-tcp pytest tests/bench -m bench

The apply_scenario fixture returns the live results entry (a dict) —
throughput stories mutate it in place and the session dump persists it.
"""
from __future__ import annotations

import pytest

from .conftest import iperf

pytestmark = [pytest.mark.bench]


def test_tunnel_establishes(apply_scenario, router) -> None:
    """story: tunnel-establishes — conwrt switches the router to the scenario
    and the tunnel verifies (wg handshake / tun0 address / INSTALLED SA)."""
    entry = apply_scenario()
    assert "error" not in entry, entry


def test_exit_via_nordvpn(apply_scenario, router) -> None:
    """story: exit-via-nordvpn — the router's public exit belongs to the VPN
    provider, not the house ISP."""
    entry = apply_scenario()
    exit_ip = entry.get("exit", "")
    assert exit_ip, "no exit IP recorded"
    assert "85.166." not in exit_ip, f"exit is the house ISP: {exit_ip}"


def test_download_throughput(apply_scenario, router) -> None:
    """story: download-throughput — Mbit/s and CPU% for the download direction."""
    entry = apply_scenario()
    mbits, cpu = iperf("down")
    entry["down_mbits"] = mbits
    entry["cpu_down"] = cpu
    assert mbits > 0, "iperf3 download failed"


def test_upload_throughput(apply_scenario, router) -> None:
    """story: upload-throughput — Mbit/s and CPU% for the upload direction
    (house uplink-capped on this bench; CPU% at the shared cap still
    separates protocols)."""
    entry = apply_scenario()
    mbits, cpu = iperf("up")
    entry["up_mbits"] = mbits
    entry["cpu_up"] = cpu
    assert mbits > 0, "iperf3 upload failed"
