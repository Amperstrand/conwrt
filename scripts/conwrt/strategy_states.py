"""strategy_states — the dark-device ladder as DATA (#777).

Loads scripts/discover_states.json, validates it as a well-formed state
machine (unique state ids, transitions reference existing states, exactly
one initial state, terminals marked, entry hints resolve), and provides:

- ladder correspondence: every bench_discover.build_ladder() rung layer
  maps to a transition, and vice versa (drift between the JSON and the
  implemented ladder is a CI-visible bug, not prose divergence)
- listen composition: bootlisten verdict next_action ids resolve to a
  starting state (entry_hints) so `conwrt listen` seeds `conwrt discover`
- run audit: a recorded run's (transition, verdict) sequence must walk a
  legal path in the graph — a transition taken that the machine forbids
  is a bug, not a surprise (the audit property #777 asks for)

This module is deliberately read-only plumbing: it changes no probe
behavior; `bench_discover --json` attaches the state view it computes.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
STATES_PATH = REPO_ROOT / "discover_states.json"

VALID_KINDS = {"initial", "terminal", "reachable"}
VALID_VERDICTS = {"positive", "negative", "skipped", "planned", "control-failed"}


class StrategyStateError(Exception):
    """The states artifact is not a well-formed machine."""


def load_states(path: Path = STATES_PATH) -> dict[str, Any]:
    return json.loads(path.read_text())


def validate(doc: dict[str, Any]) -> list[str]:
    """Return a list of structural problems (empty list = valid)."""
    problems: list[str] = []
    states = doc.get("states") or []
    ids = [s.get("id") for s in states]
    if len(ids) != len(set(ids)) or any(not i for i in ids):
        problems.append("state ids must be unique and non-empty")
    idset = set(ids)
    initials = [s for s in states if s.get("kind") == "initial"]
    if len(initials) != 1:
        problems.append(f"exactly one initial state required, found {len(initials)}")
    for s in states:
        if s.get("kind") not in VALID_KINDS:
            problems.append(f"state {s.get('id')}: bad kind {s.get('kind')!r}")
    seen_transitions: set[str] = set()
    for t in doc.get("transitions") or []:
        tid = t.get("id")
        if not tid or tid in seen_transitions:
            problems.append(f"transition ids must be unique and non-empty ({tid!r})")
            continue
        seen_transitions.add(tid)
        for edge in ("on_positive", "on_negative"):
            if t.get(edge) not in idset:
                problems.append(f"transition {tid}: {edge} -> unknown state {t.get(edge)!r}")
        if t.get("from") not in idset:
            problems.append(f"transition {tid}: from -> unknown state {t.get('from')!r}")
    hints = doc.get("entry_hints") or {}
    for verdict, target in hints.items():
        if verdict.startswith("_"):
            continue
        if target not in idset:
            problems.append(f"entry hint {verdict!r} -> unknown state {target!r}")
    return problems


def validate_or_raise(doc: dict[str, Any]) -> None:
    problems = validate(doc)
    if problems:
        raise StrategyStateError("; ".join(problems))


def transition_for_layer(doc: dict[str, Any], layer: str) -> dict[str, Any] | None:
    """The transition implementing a ladder rung layer ('1-v6', ...)."""
    for t in doc.get("transitions") or []:
        if t.get("layer") == layer:
            return t
    return None


def ladder_layers(doc: dict[str, Any]) -> set[str]:
    return {t["layer"] for t in doc.get("transitions") or [] if t.get("layer")}


def initial_state(doc: dict[str, Any]) -> str:
    for s in doc.get("states") or []:
        if s.get("kind") == "initial":
            return s["id"]
    raise StrategyStateError("no initial state")


def entry_state_for_listen(doc: dict[str, Any], next_action: str) -> str | None:
    return (doc.get("entry_hints") or {}).get(next_action)


def audit_run(doc: dict[str, Any], steps: list[dict[str, Any]]) -> dict[str, Any]:
    """Audit a recorded run's step sequence against the machine.

    steps: the step dicts from a bench_discover --json payload (each has
    layer + status). Returns {'legal': bool, 'path': [...], 'problems':
    [...]} — every step's layer must resolve to a transition and the
    walked from->to edges must connect; control-failed is terminal.
    """
    by_layer: dict[str, list[dict[str, Any]]] = {}
    for t in doc.get("transitions") or []:
        if t.get("layer"):
            by_layer.setdefault(t["layer"], []).append(t)
    problems: list[str] = []
    path: list[str] = []
    current = initial_state(doc)
    for i, step in enumerate(steps):
        layer, status = step.get("layer", ""), step.get("status", "")
        if status not in VALID_VERDICTS:
            problems.append(f"step {i}: unknown status {status!r}")
            continue
        candidates = by_layer.get(layer) or []
        if not candidates:
            problems.append(f"step {i}: layer {layer!r} has no transition in the machine")
            continue
        # Same-layer rung families (e.g. two 3-service rungs) disambiguate
        # by from-state: accept the transition whose declared origin is
        # where the run actually is; the first-step seed jump (listen-
        # seeded start away from dark) is tolerated once.
        t = next((c for c in candidates if c.get("from") == current), None)
        if t is None and i == 0:
            t = candidates[0]
        if t is None:
            problems.append(
                f"step {i}: no {layer!r} transition declares from {current!r}")
            continue
        edge = "on_positive" if status == "positive" else "on_negative"
        nxt = t.get(edge)
        path.append(f"{current} -[{t['id']}:{status}]-> {nxt}")
        if nxt is None:
            problems.append(f"step {i}: transition {t['id']} lacks {edge}")
            continue
        current = nxt
    return {"legal": not problems, "path": path, "problems": problems}
