#!/usr/bin/env python3
"""Validate all conwrt model JSON files against schemas/model.schema.json."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from jsonschema import Draft7Validator


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
        if errors:
            failed = True
            print(f"FAIL: {path}", file=sys.stderr)
            for error in errors:
                location = ".".join(str(p) for p in error.path) or "<root>"
                print(f"  {location}: {error.message}", file=sys.stderr)
        else:
            print(f"OK: {path.name}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
