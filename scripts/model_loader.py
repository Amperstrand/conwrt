#!/usr/bin/env python3
"""model_loader — shared model registry reader for conwrt.

Loads device model definitions from JSON files in the models/ directory.
All conwrt scripts use this instead of hardcoding device data.

Usage as module:
    from model_loader import load_model, list_models, get_flash_method

CLI usage:
    python3 scripts/model_loader.py list
    python3 scripts/model_loader.py show dlink-covr-x1860-a1
    python3 scripts/model_loader.py flash-methods dlink-covr-x1860-a1
"""

import json
import sys
from pathlib import Path
from typing import Any, Optional

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"


def load_model(model_id: str) -> dict[str, Any]:
    """Load a model definition by ID (filename without .json).

    Raises FileNotFoundError if the model file doesn't exist.
    """
    path = MODELS_DIR / f"{model_id}.json"
    if not path.is_file():
        available = [p.stem for p in MODELS_DIR.glob("*.json")]
        raise FileNotFoundError(
            f"Model '{model_id}' not found. Available: {', '.join(sorted(available))}"
        )
    with open(path) as f:
        return json.load(f)


def list_models() -> list[dict[str, Any]]:
    """Load all model definitions."""
    models = []
    for path in sorted(MODELS_DIR.glob("*.json")):
        with open(path) as f:
            models.append(json.load(f))
    return models


def get_flash_method(model_id: str, method: str) -> Optional[dict[str, Any]]:
    """Get a specific flash method for a model.

    Returns None if the model or method doesn't exist.
    """
    try:
        model = load_model(model_id)
    except FileNotFoundError:
        return None
    return model.get("flash_methods", {}).get(method)


def find_model_by_target(target: str) -> Optional[dict[str, Any]]:
    """Find a model by its OpenWrt target string (e.g. 'ramips/mt7621')."""
    for model in list_models():
        if model.get("openwrt", {}).get("target") == target:
            return model
    return None


def find_model_by_mac_oui(oui: str) -> list[dict[str, Any]]:
    """Find models matching a MAC OUI prefix (e.g. 'BC:22:28')."""
    oui_upper = oui.upper()
    matches = []
    for model in list_models():
        for model_oui in model.get("mac_oui", []):
            if model_oui.upper() == oui_upper:
                matches.append(model)
    return matches


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: model_loader.py <list|show|flash-methods|find-by-target> [args]")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "list":
        for model in list_models():
            oid = model["id"]
            vendor = model.get("vendor", "?")
            desc = model.get("description", "?")
            target = model.get("openwrt", {}).get("target", "?")
            methods = ", ".join(model.get("flash_methods", {}).keys()) or "none"
            print(f"  {oid:40s}  {vendor:10s}  {target:20s}  [{methods}]  {desc}")

    elif cmd == "show":
        if len(sys.argv) < 3:
            print("Usage: model_loader.py show <model-id>")
            sys.exit(1)
        model = load_model(sys.argv[2])
        print(json.dumps(model, indent=2))

    elif cmd == "flash-methods":
        if len(sys.argv) < 3:
            print("Usage: model_loader.py flash-methods <model-id>")
            sys.exit(1)
        model = load_model(sys.argv[2])
        for name, cfg in model.get("flash_methods", {}).items():
            print(f"  {name}: {cfg.get('description', '?')}")

    elif cmd == "find-by-target":
        if len(sys.argv) < 3:
            print("Usage: model_loader.py find-by-target <target>")
            sys.exit(1)
        model = find_model_by_target(sys.argv[2])
        if model:
            print(json.dumps(model, indent=2))
        else:
            print(f"No model found for target '{sys.argv[2]}'")

    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)


if __name__ == "__main__":
    main()
