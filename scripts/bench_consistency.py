#!/usr/bin/env python3
"""bench_consistency — the OFFLINE exporter↔registry cross-check engine.

Pure logic, no network, no coordinator, no labgrid package, no PyYAML:
powers `make labgrid-check` (via bench_doctor crosscheck) and the doctor's
L2. Drift classes caught (the T15 add-match / registry-drift family):

  - a places.json place with power_export!=false and no NetworkPowerPort
    stanza (powered but unexported)
  - a power_export=false place WITH a stanza (the one-way-trip rule,
    machine-enforced — AGENTS ap-lan5 class)
  - a NetworkSerialPort exported for a place places.json knows nothing
    about, or whose entry has no serial_console field

Exporter.yaml is parsed with a strict stanza grammar (it is machine-written
by bench_inventory --emit-exporter and hand-commented) so anything
unexpected raises instead of silently mis-parsing.
"""

from __future__ import annotations

import json
from pathlib import Path

# One stanza tree: place -> resource class -> param -> value (all strings).
Stanzas = dict[str, dict[str, dict[str, str]]]

# Resource classes the cross-check reasons about.
POWER_RESOURCE, SERIAL_RESOURCE, SERVICE_RESOURCE = (
    "NetworkPowerPort", "NetworkSerialPort", "NetworkService")


class DoctorError(Exception):
    """Doctor input is unusable (unparsable registry/exporter)."""


class ExporterParseError(DoctorError):
    """exporter.yaml does not match the strict stanza grammar."""


def parse_exporter(text: str) -> Stanzas:
    """Strict parse of the exporter stanza grammar.

    place:/  ResourceClass:/  key: value — indents 0/2/4 exactly. Lines
    starting with '#' (any count: ## comments, single-# Jinja) and Jinja
    {{ }}/{% %} lines are skipped. Inline '# ...' comments are stripped from
    values. Anything else raises ExporterParseError so drift is loud, never
    silently mis-parsed.
    """
    stanzas: Stanzas = {}
    place = resource = None
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if "{%" in line or "{{" in line:
            continue
        indent = len(line) - len(line.lstrip())
        content = line.strip()
        where = f"line {lineno}"
        if indent == 0:
            if not content.endswith(":"):
                raise ExporterParseError(f"{where}: place line must end ':': {content!r}")
            place = content[:-1]
            if place in stanzas:
                raise ExporterParseError(f"{where}: duplicate place {place!r}")
            stanzas[place] = {}
            resource = None
        elif indent == 2:
            if place is None or not content.endswith(":"):
                raise ExporterParseError(f"{where}: resource line must follow a place and end ':': {content!r}")
            resource = content[:-1]
            if resource in stanzas[place]:
                raise ExporterParseError(f"{where}: duplicate resource {place}/{resource}")
            stanzas[place][resource] = {}
        elif indent == 4:
            if resource is None:
                raise ExporterParseError(f"{where}: param outside a resource: {content!r}")
            key, sep, value = content.partition(":")
            if not sep:
                raise ExporterParseError(f"{where}: param must be 'key: value': {content!r}")
            stanzas[place][resource][key.strip()] = value.split("#", 1)[0].strip()
        else:
            raise ExporterParseError(f"{where}: unexpected indent ({indent}): {content!r}")
    return stanzas


def load_places(path: Path) -> dict | None:
    """Parse places.json; None when absent; DoctorError when corrupt."""
    if not path.is_file():
        return None
    try:
        registry = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise DoctorError(f"{path} does not parse: {e}") from e
    if not isinstance(registry.get("places"), list):
        raise DoctorError(f"{path}: top-level 'places' list missing")
    return registry


def crosscheck(registry: dict | None, stanzas: Stanzas | None) -> tuple[bool, list[str]]:
    """OFFLINE exporter-vs-registry consistency.

    Returns (clean, lines). clean=False only on FAIL-class drift; 'note'
    lines are informational (empty-port stanzas, bridges not stood up yet).
    Absent inputs are a skip, not drift (standalone checkout).
    """
    lines: list[str] = []
    if registry is None and stanzas is None:
        return True, ["note no local bench registries (places.json / exporter.yaml both absent — standalone or CI checkout)"]
    if registry is None:
        return True, ["note places.json absent — registry side of the cross-check skipped (standalone checkout)"]
    if stanzas is None:
        return True, ["note exporter.yaml absent — exporter side of the cross-check skipped (not a labgrid checkout)"]

    entries = {e.get("name"): e for e in registry["places"] if isinstance(e, dict)}
    clean = True
    for name, entry in entries.items():
        place = stanzas.get(name)
        powered = bool(entry.get("power_export", True))
        has_power = place is not None and POWER_RESOURCE in place
        if powered and not has_power:
            clean = False
            lines.append(f"FAIL {name}: powered place (power_export!=false) has no {POWER_RESOURCE} stanza")
        if not powered and has_power:
            clean = False
            lines.append(f"FAIL {name}: power_export=false place HAS a {POWER_RESOURCE} stanza (one-way-trip rule)")
        has_serial_field = bool(str(entry.get("serial_console", "") or "").strip())
        if has_serial_field and (place is None or SERIAL_RESOURCE not in place):
            lines.append(f"note {name}: serial_console registered but no {SERIAL_RESOURCE} stanza (bridge not stood up?)")
        if place is not None and SERVICE_RESOURCE in place:
            addr = place[SERVICE_RESOURCE].get("address", "?")
            lines.append(f"note {name}: {SERVICE_RESOURCE} {addr}")
    for name, resources in stanzas.items():
        if SERIAL_RESOURCE in resources and name not in entries:
            clean = False
            lines.append(f"FAIL {name}: {SERIAL_RESOURCE} exported but no places.json entry for the place")
        elif SERIAL_RESOURCE in resources and not str(entries.get(name, {}).get("serial_console", "") or "").strip():
            clean = False
            lines.append(f"FAIL {name}: {SERIAL_RESOURCE} exported but places.json has no serial_console field")
        if POWER_RESOURCE in resources and name not in entries:
            lines.append(f"note {name}: exporter stanza without a places.json entry (empty bench port?)")
    return clean, lines
