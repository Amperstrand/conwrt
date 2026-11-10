#!/usr/bin/env python3
"""model_loader — shared model registry reader for conwrt.

Loads device model definitions from JSON files in the models/ directory.
All conwrt scripts use this instead of hardcoding device data.

OpenWrt naming:
  - conwrt ``id`` (hyphenated slug) == ``models/{id}.json`` filename
  - ``openwrt.device`` — DTS / image Makefile device name (e.g. ``dlink,covr-x1860-a1``)
  - ``openwrt.profile`` — ImageBuilder / ASU profile (e.g. ``dlink_covr-x1860-a1``)
  - ``openwrt.board_name`` — optional ``/tmp/sysinfo/board_name`` match
"""

from __future__ import annotations

import json
import sys
import warnings
from pathlib import Path
from typing import Any, Optional

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"

# Legacy underscore ids → canonical hyphenated id (filename stem)
_ID_ALIASES: dict[str, str] = {
    "dlink_covr-x1860-a1": "dlink-covr-x1860-a1",
    "glinet_gl-ar150": "glinet-gl-ar150",
    "glinet_gl-ar300m-lite": "glinet-gl-ar300m-lite",
    "glinet_gl-ar300m-nand": "glinet-gl-ar300m-nand",
    "glinet_gl-ar300m-nor": "glinet-gl-ar300m-nor",
    "glinet_gl-mt3000": "glinet-mt3000",
    "linksys_whw03": "linksys-whw03-v1",
    "linksys_whw03v2": "linksys-whw03-v2",
    "zyxel_ex5700-telenor": "zyxel-ex5700-telenor",
    "zyxel_gs1900-24e": "zyxel-gs1900-24e",
    "zyxel_nr7101": "zyxel-nr7101",
    "zyxel_wx5600-t0": "zyxel-wx5600-t0",
}

_warned_aliases: set[str] = set()


def normalize_model_id(model_id: str) -> str:
    """Map legacy ids to canonical hyphenated slug."""
    canonical = _ID_ALIASES.get(model_id, model_id)
    if canonical != model_id and model_id not in _warned_aliases:
        _warned_aliases.add(model_id)
        warnings.warn(
            f"Model id '{model_id}' is deprecated; use '{canonical}'",
            DeprecationWarning,
            stacklevel=3,
        )
    return canonical


def load_model(model_id: str) -> dict[str, Any]:
    """Load a model definition by canonical id (filename stem without .json)."""
    model_id = normalize_model_id(model_id)
    path = MODELS_DIR / f"{model_id}.json"
    if not path.is_file():
        for candidate in sorted(MODELS_DIR.glob("*.json")):
            with open(candidate) as f:
                model = json.load(f)
            if model.get("id") == model_id:
                return model
        available = [p.stem for p in MODELS_DIR.glob("*.json")]
        raise FileNotFoundError(
            f"Model '{model_id}' not found. Available: {', '.join(sorted(available))}"
        )
    with open(path) as f:
        model = json.load(f)
    if model.get("id") != model_id:
        raise ValueError(
            f"Model file {path.name} has id '{model.get('id')}' but expected '{model_id}'"
        )
    return model


def openwrt_asu_profile(model: dict[str, Any]) -> str:
    """Return ASU ImageBuilder profile name (never the conwrt slug)."""
    profile = model.get("openwrt", {}).get("profile", "")
    if not profile:
        raise ValueError(f"Model '{model.get('id')}' missing openwrt.profile")
    return profile


def list_models() -> list[dict[str, Any]]:
    """Load all model definitions."""
    models = []
    for path in sorted(MODELS_DIR.glob("*.json")):
        with open(path) as f:
            models.append(json.load(f))
    return models


def get_flash_method(model_id: str, method: str) -> Optional[dict[str, Any]]:
    """Get a specific flash method for a model."""
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


def find_model_by_board_name(board_name: str) -> Optional[dict[str, Any]]:
    """Find model by OpenWrt board_name or device string."""
    for model in list_models():
        ow = model.get("openwrt", {})
        if board_name in (ow.get("board_name"), ow.get("device")):
            return model
        if model.get("id", "").replace("-", "_") == board_name.replace(",", "_"):
            return model
    return None


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
            profile = model.get("openwrt", {}).get("profile", "?")
            methods = ", ".join(model.get("flash_methods", {}).keys()) or "none"
            print(f"  {oid:40s}  {vendor:10s}  {target:20s}  {profile:28s}  [{methods}]  {desc}")

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
