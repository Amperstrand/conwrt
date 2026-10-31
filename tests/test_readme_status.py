"""README self-documentation: the generated test-status block must
match its sources (drift = red). Edit the SOURCES (_pins.py, the
parity matrix, the registry), never the block; refresh: make gen-status."""
from pathlib import Path

import pytest

sys_path_root = Path(__file__).resolve().parents[1]
import sys  # noqa: E402

sys.path.insert(0, str(sys_path_root / "scripts"))
from gen_status import BEGIN, END, generate  # noqa: E402


def test_readme_status_block_matches_sources():
    readme = (sys_path_root / "README.md").read_text()
    committed = readme.split(BEGIN)[1].split(END)[0]
    expected = "\n" + generate() + "\n"
    assert committed == expected, (
        "README test-status block is stale — run `make gen-status` "
        "(or fix the sources if the block was hand-edited)"
    )


def test_markers_present_exactly_once():
    readme = (sys_path_root / "README.md").read_text()
    assert readme.count(BEGIN) == 1 and readme.count(END) == 1


def test_version_claim_is_the_pin():
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_pins", sys_path_root / "tests" / "integration" / "_pins.py"
    )
    pins = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pins)
    assert f"OpenWrt **{pins.OPENWRT_VERSION}**" in generate()
