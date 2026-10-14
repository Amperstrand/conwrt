"""Venue resolution for conwrt's device/VM test tiers.

Implements §3 of docs/plans/prta-transition-plan.md: a venue is anything
that can execute a shell command on an OpenWrt system. The venue list is
chosen by the RUNNER via ``CONWRT_VENUES`` (default: the QEMU session VM
only — a bare ``make integration`` never touches hardware):

    qemu-session            the tests/integration session VM fixture
    labgrid:<place>         a labgrid place (coordinator + exporter path;
                            address/key come from the place's NetworkService,
                            never hardcoded)
    direct:<name>           a direct-SSH device named in data/lab.yaml

Unresolvable or protected venues raise an actionable error at collection
time; DARK venues (device unreachable at run time) are a skip decision the
fixtures make — this module only resolves and validates names.

The labgrid interactions go through an injectable ``Runner`` (subprocess
callable) so unit tests need no coordinator — the pattern proven by prta's
``lib/labgrid_venue.py``.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

REPO_ROOT = Path(__file__).resolve().parents[1]
LAB_YAML = REPO_ROOT / "data" / "lab.yaml"

Runner = Callable[[list[str]], "subprocess.CompletedProcess[str]"]

VALID_KINDS = ("qemu-session", "labgrid", "direct")


@dataclass(frozen=True)
class Venue:
    key: str    # "qemu-session" | "labgrid:ap-lan4" | "direct:x1860-desk"
    kind: str   # "qemu-session" | "labgrid" | "direct"

    @property
    def place(self) -> Optional[str]:
        """Place/device name for labgrid:/direct: venues, else None."""
        _, _, rest = self.key.partition(":")
        return rest or None


def default_runner(args: list[str]) -> "subprocess.CompletedProcess[str]":
    coordinator = os.environ.get("CONWRT_LABGRID_COORDINATOR", "ai-legion:20408")
    client = os.environ.get("CONWRT_LABGRID_CLIENT", "labgrid-client")
    return subprocess.run(
        [client, "-x", coordinator, *args],
        capture_output=True, text=True, timeout=40, check=False,
    )


def default_place_list() -> str:
    """Place names from the labgrid coordinator (one per line)."""
    result = default_runner(["places"])
    if result.returncode != 0:
        raise RuntimeError(
            f"labgrid places query failed (coordinator down?): "
            f"{result.stderr.strip()[-200:]}"
        )
    return result.stdout


def default_protected_places() -> set[str]:
    """Places marked protected in data/lab.yaml (the lab SSOT).

    Returns an empty set when the registry is absent — places are GENERATED
    from the registry, so a coordinator place implies registry membership;
    the protection flag is what the registry adds.
    """
    if not LAB_YAML.exists():
        return set()
    import yaml

    data = yaml.safe_load(LAB_YAML.read_text()) or {}
    protected: set[str] = set()
    for place in data.get("places", []) or []:
        name = place.get("name", "") if isinstance(place, dict) else ""
        if name and place.get("protected"):
            protected.add(name)
    return protected


def venues_from_env(
    env: Optional[dict[str, str]] = None,
    place_list: Callable[[], str] = default_place_list,
    protected_places: Callable[[], set[str]] = default_protected_places,
) -> list[Venue]:
    """Resolve CONWRT_VENUES (comma-separated) into Venue objects.

    Defaults to ``["qemu-session"]``. Raises ValueError with an actionable
    message for unknown venue syntax, coordinator-unknown places, or
    protected devices (unless CONWRT_VENUE_ALLOW_PROTECTED is set).
    """
    env = dict(os.environ) if env is None else env
    raw = (env.get("CONWRT_VENUES") or "").strip() or "qemu-session"
    allow_protected = bool(env.get("CONWRT_VENUE_ALLOW_PROTECTED"))

    venues: list[Venue] = []
    needs_places = False
    for token in (t.strip() for t in raw.split(",")):
        if not token:
            continue
        if token == "qemu-session":
            venues.append(Venue("qemu-session", "qemu-session"))
            continue
        kind, sep, rest = token.partition(":")
        if not sep or not rest:
            raise ValueError(
                f"unknown venue {token!r}: expected one of "
                f"'qemu-session', 'labgrid:<place>', 'direct:<name>'"
            )
        if kind not in ("labgrid", "direct"):
            raise ValueError(
                f"unknown venue kind {kind!r} in {token!r}: "
                f"expected 'labgrid' or 'direct'"
            )
        if kind == "labgrid":
            needs_places = True
        venues.append(Venue(token, kind))

    if needs_places:
        known = {
            line.split()[0]
            for line in place_list().splitlines()
            if line.strip()
        }
        protected = protected_places() if not allow_protected else set()
        for venue in venues:
            if venue.kind != "labgrid":
                continue
            place = venue.place or ""
            if place not in known:
                raise ValueError(
                    f"labgrid place {place!r} not known to the coordinator — "
                    f"check data/lab.yaml / `lab_registry.py reconcile`"
                )
            if place in protected:
                raise ValueError(
                    f"venue {place!r} is marked protected in data/lab.yaml — "
                    f"it is not a test venue (set CONWRT_VENUE_ALLOW_PROTECTED "
                    f"to override deliberately)"
                )

    return venues
