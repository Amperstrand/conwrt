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

    def test_single_direct_venue_resolves_host(self, monkeypatch, tmp_path):
        lab = tmp_path / "lab.yaml"
        lab.write_text("devices:\n  x1860-desk: {mgmt: 192.168.104.52}\n")
        import venues as vmod
        monkeypatch.setattr(vmod, "LAB_YAML", lab)
        ip, label = bench_venue([Venue("direct:x1860-desk", "direct")])
        assert ip == "192.168.104.52"
        assert label == "direct:x1860-desk"

    def test_labgrid_venue_keeps_own_router(self):
        ip, label = bench_venue([Venue("labgrid:ap-lan4", "labgrid")])
        assert ip is None
        assert label == "labgrid:ap-lan4"

    def test_two_hardware_venues_refused(self):
        with pytest.raises(ValueError, match="ONE hardware venue"):
            bench_venue([Venue("labgrid:ap-lan4", "labgrid"),
                         Venue("direct:x1860-desk", "direct")])
