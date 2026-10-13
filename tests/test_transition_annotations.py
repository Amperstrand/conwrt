"""Every model's flash methods carry transition annotations
(resources_required + envelope) — the machine-checkable precondition layer
from docs/DEVICE-TRANSITIONS.md. Kept complete forever: a new method without
annotations fails here before it can ship."""
import glob
import json
from pathlib import Path

MODELS = sorted((Path(__file__).resolve().parent.parent / "models").glob("*.json"))


def _load(path):
    return json.load(open(path))


def test_every_flash_method_annotated():
    missing = []
    for path in MODELS:
        model = _load(path)
        for name, fm in model.get("flash_methods", {}).items():
            if not fm.get("resources_required"):
                missing.append(f"{model['id']}::{name}: resources_required")
            if not fm.get("envelope"):
                missing.append(f"{model['id']}::{name}: envelope")
    assert not missing, "unannotated flash methods:\n" + "\n".join(missing)


def test_sysupgrade_envelope_includes_board_name_match():
    for path in MODELS:
        model = _load(path)
        fm = model.get("flash_methods", {}).get("sysupgrade")
        if fm:
            assert "board-name-match" in fm["envelope"], model["id"]
            assert "ssh-service" in fm["resources_required"], model["id"]


def test_known_broken_methods_are_marked():
    model = _load(Path(__file__).resolve().parent.parent / "models" / "dlink-covr-x1860-a1.json")
    assert "known-broken" in model["flash_methods"]["dlink-hnap"]["envelope"]
