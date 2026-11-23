"""#306: router_display passes the DETECTED address (and interface)
through to `conwrt flash` — the child re-detects otherwise."""
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent / "scripts"))

from router_display import _specimen_args


def test_ip_and_model_pass_through():
    r = SimpleNamespace(model_id="dlink-covr-x1860-a1", ip="192.168.0.42",
                        interface="en9")
    assert _specimen_args(r) == ["--model-id", "dlink-covr-x1860-a1",
                                 "--ip", "192.168.0.42",
                                 "--interface", "en9"]


def test_iface_alias_and_optionals():
    r = SimpleNamespace(model_id="", ip="10.0.0.9", iface="eth5")
    assert _specimen_args(r) == ["--ip", "10.0.0.9", "--interface", "eth5"]
    bare = SimpleNamespace(model_id=None, ip=None)
    assert _specimen_args(bare) == []
