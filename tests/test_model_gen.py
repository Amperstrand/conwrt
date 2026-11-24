"""Tests for model_gen (#766) — the probe-rs target-gen analogue.

Done-when gates from the issue:
1. stub generation end-to-end for zyxel_nr7101 from a REAL-shape
   profiles.json fixture;
2. round-trip: regenerating must NOT clobber hand-added keys;
3. schema validation green on the generated+curated output (the real
   schemas/model.schema.json via validate_models' Draft7Validator).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from model_gen import GENERATED_KEYS, gen_stub, load_profiles, merge  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "tests" / "fixtures" / "model_gen_profiles.json"

pytest.importorskip("jsonschema")


@pytest.fixture(scope="module")
def profiles():
    return load_profiles(FIXTURE)


class TestStubGeneration:
    def test_zyxel_nr7101_stub(self, profiles):
        stub = gen_stub(profiles, "zyxel_nr7101")
        assert stub["id"] == "zyxel-nr7101"          # underscores -> dashes
        assert stub["vendor"] == "Zyxel"
        assert "NR7101" in stub["description"]
        ow = stub["openwrt"]
        assert ow["target"] == "ramips/mt7621"
        assert ow["device"] == "zyxel,nr7101"        # supported_devices[0]
        assert ow["profile"] == "zyxel_nr7101"
        assert ow["version"] == "25"
        assert any("sysupgrade" in i["name"] for i in ow["images"])
        assert all(len(i["sha256"]) == 64 for i in ow["images"])

    def test_unknown_profile_aborts(self, profiles):
        with pytest.raises(SystemExit, match="not in profiles.json"):
            gen_stub(profiles, "not_a_profile")

    def test_vendor_fallback_from_profile_prefix(self, profiles):
        stub = gen_stub(profiles, "generic_sofubar_1")  # fixture: no titles
        assert stub["vendor"] == "Generic"


class TestRoundTrip:
    def test_regenerate_preserves_hand_keys(self, profiles):
        """THE #766 gate: hand curation survives regeneration."""
        curated = json.loads((REPO / "models" / "zyxel-nr7101.json").read_text())
        hand_snapshot = {k: v for k, v in curated.items() if k not in GENERATED_KEYS}
        hand_openwrt = {k: v for k, v in curated["openwrt"].items()
                        if k not in ("target", "device", "profile", "version", "images")}

        merged = merge(curated, gen_stub(profiles, "zyxel_nr7101"))

        for k, v in hand_snapshot.items():
            assert merged.get(k) == v, f"hand key clobbered: {k}"
        for k, v in hand_openwrt.items():
            assert merged["openwrt"].get(k) == v, f"hand openwrt key clobbered: {k}"
        # while the generated surface DID refresh
        assert merged["openwrt"]["images"], "generated images must refresh"

    def test_merge_into_absent_file(self, profiles):
        stub = gen_stub(profiles, "zyxel_nr7101")
        assert merge(None, stub) == stub

    def test_generated_block_lists_owned_keys(self, profiles):
        stub = gen_stub(profiles, "zyxel_nr7101")
        assert tuple(stub["_generated"]["generated_keys"]) == GENERATED_KEYS


class TestSchemaValidation:
    def test_generated_plus_curated_validates(self, profiles, tmp_path):
        """The merged output must pass the REAL model schema."""
        curated = json.loads((REPO / "models" / "zyxel-nr7101.json").read_text())
        merged = merge(curated, gen_stub(profiles, "zyxel_nr7101"))
        schema = json.loads((REPO / "schemas" / "model.schema.json").read_text())
        from jsonschema import Draft7Validator
        errors = list(Draft7Validator(schema).iter_errors(merged))
        assert not errors, "\n".join(f"{list(e.path)}: {e.message}" for e in errors)

    def test_cli_end_to_end(self, profiles, tmp_path):
        """Full flow: CLI regenerates a copy of the real model file."""
        src = REPO / "models" / "zyxel-nr7101.json"
        dst = tmp_path / "zyxel-nr7101.json"
        dst.write_text(src.read_text())
        before = json.loads(dst.read_text())
        r = subprocess.run(
            [sys.executable, str(REPO / "scripts" / "model_gen.py"),
             "--profiles", str(FIXTURE), "--profile", "zyxel_nr7101",
             "--out", str(dst)],
            capture_output=True, text=True, timeout=60)
        assert r.returncode == 0, r.stderr
        after = json.loads(dst.read_text())
        assert after["flash_methods"] == before["flash_methods"]
        assert after["partition_layout"] == before["partition_layout"]
        assert after["_generated"]["version_number"] == "25.12.6"
