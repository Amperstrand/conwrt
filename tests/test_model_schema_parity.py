"""Model-schema parity (#118): the tightened sections are a DUAL-LANGUAGE
contract. This is the Python half:

- the real corpus validates cleanly against the tightened schema, and
- every fixture under tests/fixtures/schema-negative/ is REJECTED.

The Rust half (same corpus accepted, same fixtures rejected — parse or
validation failure) runs via `make parity-check` in the Rust CI job.
A fixture rejected here but accepted by Rust (or vice versa) is schema
drift and fails CI.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")

ROOT = Path(__file__).parents[1]
SCHEMA = json.loads((ROOT / "schemas" / "model.schema.json").read_text())
NEGATIVES = ROOT / "tests" / "fixtures" / "schema-negative"


@pytest.fixture(scope="module")
def validator():
    return jsonschema.Draft7Validator(SCHEMA)


def test_real_corpus_validates_cleanly(validator):
    models = sorted((ROOT / "models").glob("*.json"))
    assert len(models) >= 20, "model corpus unexpectedly small"
    failures = []
    for path in models:
        errors = list(validator.iter_errors(json.loads(path.read_text())))
        if errors:
            failures.append(f"{path.name}: {errors[0].message}")
    assert not failures, "corpus regressed against the tightened schema:\n" + "\n".join(failures)


@pytest.mark.parametrize(
    "case_dir",
    sorted(p for p in NEGATIVES.iterdir() if p.is_dir()),
    ids=lambda p: p.name,
)
def test_negative_fixture_rejected(validator, case_dir):
    fixtures = list(case_dir.glob("*.json"))
    assert len(fixtures) == 1, "one model per negative case directory"
    data = json.loads(fixtures[0].read_text())
    errors = list(validator.iter_errors(data))
    assert errors, (
        f"{case_dir.name}: schema ACCEPTED a fixture the Rust side "
        f"rejects — the two validators have drifted (#118 parity)"
    )
