"""bench_venue — the S4 venue axis derivation for tests/bench (plan §5)."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

from venues import Venue  # noqa: E402

def _load_bench_venue():
    ns: dict = {}
    src = (Path(__file__).resolve().parents[1] / "tests" / "bench" / "conftest.py").read_text()
    start = src.index("def bench_venue(")
    end = src.index("def pytest_collection_modifyitems")
    body = src[start:end]
    header = (
        "import sys\n"
        f"sys.path.insert(0, {str(Path(__file__).resolve().parents[1] / 'tests')!r})\n"
        "from venues import Venue, direct_device\n"
    )
    exec(header + body, ns)
    return ns["bench_venue"]


bench_venue = _load_bench_venue()


class TestBenchVenue:
    def test_no_venues_means_no_override(self):
        assert bench_venue([]) == (None, "")

    def test_qemu_only_is_not_a_bench_router(self):
        assert bench_venue([Venue("qemu-session", "qemu-session")]) == (None, "")

    def test_single_direct_venue_resolves_full_device(self, monkeypatch, tmp_path):
        # #329: the registry's port/key ride along, not just the host
        lab = tmp_path / "lab.yaml"
        lab.write_text(
            "devices:\n  x1860-desk: {mgmt: 192.168.104.52,"
            " ssh_port: 2222, ssh_key: /home/op/.ssh/bench}\n")
        import venues as vmod
        monkeypatch.setattr(vmod, "LAB_YAML", lab)
        dev, label = bench_venue([Venue("direct:x1860-desk", "direct")])
        assert dev == {"host": "192.168.104.52", "port": 2222,
                       "key": "/home/op/.ssh/bench", "model": None}
        assert label == "direct:x1860-desk"

    def test_labgrid_venue_refused_on_router_axis(self):
        # #330: a labgrid selection must not silently fall back to
        # CONWRT_BENCH_ROUTER while labeling results with the place.
        with pytest.raises(ValueError, match="exporter-proxied execution not implemented"):
            bench_venue([Venue("labgrid:ap-lan4", "labgrid")])

    def test_two_hardware_venues_refused(self):
        with pytest.raises(ValueError, match="ONE hardware venue"):
            bench_venue([Venue("labgrid:ap-lan4", "labgrid"),
                         Venue("direct:x1860-desk", "direct")])
