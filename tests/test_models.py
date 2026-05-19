from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft7Validator

from model_loader import list_models, load_model


ROOT = Path(__file__).resolve().parents[1]


def test_all_models_validate_against_schema() -> None:
    schema = json.loads((ROOT / "schemas" / "model.schema.json").read_text())
    validator = Draft7Validator(schema)
    for path in sorted((ROOT / "models").glob("*.json")):
        errors = list(validator.iter_errors(json.loads(path.read_text())))
        assert errors == [], f"{path.name}: {errors}"


def test_model_loader_loads_every_model_by_id() -> None:
    for model in list_models():
        loaded = load_model(model["id"])
        assert loaded["id"] == model["id"]
        assert loaded["openwrt"]["target"]
        assert loaded["openwrt"]["device"]
        assert loaded["openwrt"]["profile"]
        assert loaded["flash_methods"]


def test_model_id_matches_filename() -> None:
    for path in sorted((ROOT / "models").glob("*.json")):
        data = json.loads(path.read_text())
        assert data["id"] == path.stem, f"{path.name}: id must match filename"


def test_flash_methods_have_descriptions() -> None:
    for model in list_models():
        for name, method in model["flash_methods"].items():
            assert name
            assert method.get("description")
