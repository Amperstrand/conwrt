#!/usr/bin/env python3
"""Validate all conwrt model JSON files against schemas/model.schema.json."""
from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    from jsonschema import Draft7Validator
except ImportError:
    print("ERROR: jsonschema is required for model validation.", file=sys.stderr)
    print("  Install with: pip install jsonschema", file=sys.stderr)
    raise SystemExit(1) from None


ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = ROOT / "models"
SCHEMA_PATH = ROOT / "schemas" / "model.schema.json"


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text())
    validator = Draft7Validator(schema)
    failed = False
    for path in sorted(MODELS_DIR.glob("*.json")):
        data = json.loads(path.read_text())
        errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
        stem = path.stem
        if data.get("id") != stem:
            failed = True
            print(f"FAIL: {path.name}: id '{data.get('id')}' must match filename stem '{stem}'", file=sys.stderr)
        ow = data.get("openwrt", {})
        if not ow.get("device"):
            print(f"WARN: {path.name}: missing openwrt.device", file=sys.stderr)
        if not ow.get("profile"):
            failed = True
            print(f"FAIL: {path.name}: missing openwrt.profile (ASU ImageBuilder name)", file=sys.stderr)
        if errors:
            failed = True
            print(f"FAIL: {path}", file=sys.stderr)
            for error in errors:
                location = ".".join(str(p) for p in error.path) or "<root>"
                print(f"  {location}: {error.message}", file=sys.stderr)
        else:
            tested = data.get("tested_hardware", {})
            methods = set(data.get("flash_methods", {}).keys())
            untested = methods - set(tested.keys())
            if untested:
                print(f"  note: {path.name}: flash methods without tested_hardware: {', '.join(sorted(untested))}")
            print(f"OK: {path.name}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
