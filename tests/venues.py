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
import re
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Optional

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


def lab_registry_path() -> Path:
    """The lab registry the documented way: the private ``CONWRT_LAB``
    checkout's lab.yaml, falling back to the repo-local data/lab.yaml."""
    lab_env = os.environ.get("CONWRT_LAB")
    if lab_env:
        candidate = Path(lab_env) / "lab.yaml"
        if candidate.exists():
            return candidate
    return LAB_YAML


def default_protected_places() -> set[str]:
    """Places marked protected in the lab registry (the lab SSOT).

    The registry resolves the documented way: the private ``CONWRT_LAB``
    checkout's lab.yaml first, then the repo-local data/lab.yaml. Both
    registry shapes count: the legacy ``places:`` list and the canonical
    ``devices:`` mapping (a device entry with ``protected: true`` protects
    its ``labgrid_place``, or its own id when no place is named).

    FAILS CLOSED when no registry can be read: unresolvable protection
    data is not "nothing is protected" (set CONWRT_LAB, add a
    data/lab.yaml, or pass CONWRT_VENUE_ALLOW_PROTECTED to override).
    """
    import yaml

    registry = lab_registry_path()
    if not registry.exists():
        raise RuntimeError(
            "no lab registry found (CONWRT_LAB/lab.yaml or data/lab.yaml) — "
            "cannot resolve protected places; refusing to run unprotected "
            "(set CONWRT_LAB, or CONWRT_VENUE_ALLOW_PROTECTED to override)"
        )
    data = yaml.safe_load(registry.read_text()) or {}
    protected: set[str] = set()
    for place in data.get("places", []) or []:
        name = place.get("name", "") if isinstance(place, dict) else ""
        if name and place.get("protected"):
            protected.add(name)
    for dev_id, dev in (data.get("devices") or {}).items():
        if isinstance(dev, dict) and dev.get("protected"):
            protected.add(dev.get("labgrid_place") or dev_id)
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
    saw_token = False
    for token in (t.strip() for t in raw.split(",")):
        if not token:
            continue
        saw_token = True
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

    if not saw_token:
        raise ValueError(
            f"CONWRT_VENUES={raw!r} contains no venue — a separator-only "
            "value would run an empty suite (use qemu-session or "
            "labgrid:<place>/direct:<name> entries)"
        )
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


def default_lab_yaml() -> dict:
    """Parsed data/lab.yaml ({} when absent)."""
    if not LAB_YAML.exists():
        return {}
    import yaml

    return yaml.safe_load(LAB_YAML.read_text()) or {}


def direct_device(
    name: str,
    lab_yaml: Optional[Callable[[], dict]] = None,
) -> dict:
    """Connection parameters for a ``direct:<name>`` venue from data/lab.yaml.

    Consumes the canonical registry schema (labgrid/lab.yaml.example):
    ``devices:`` is a mapping keyed by device id; the venue host is the
    device's ``mgmt`` address, with optional ``ssh_port`` / ``ssh_key``
    (absolute or ~ path) / ``model`` (conwrt model id) extensions.
    Addresses live ONLY in data/lab.yaml (local, gitignored) — never in
    code, commits, or docs.

    Raises ValueError with an actionable message for a missing registry or
    unknown device.
    """
    loader = lab_yaml or default_lab_yaml
    data = loader()
    devices = data.get("devices") or {}
    if not data:
        raise ValueError(
            "direct: venue requested but data/lab.yaml is absent — the lab "
            "registry (SSOT) must declare the device first"
        )
    dev = devices.get(name)
    if dev is None:
        known = ", ".join(filter(None, devices)) or "none"
        raise ValueError(
            f"direct device {name!r} not in data/lab.yaml devices "
            f"(known: {known})"
        )
    if not dev.get("mgmt"):
        raise ValueError(f"direct device {name!r} has no mgmt address in data/lab.yaml")
    return {
        "host": dev["mgmt"],
        "port": int(dev.get("ssh_port", 22)),
        "key": dev.get("ssh_key"),
        "model": dev.get("model"),
    }


class ProtectedPlaceError(ValueError):
    """A mutating fixture was pointed at a protected place/device."""


@dataclass(frozen=True)
class FlashLease:
    """What flash_lease() yields: identity of the hold it took."""

    place: str
    reservation: str   # the cancelable name handed to `reserve --name`
    dry: bool = False  # True = local no-op, no coordinator was contacted


def _lease_token(value: str) -> str:
    """Sanitize a session/story fragment for a reservation name."""
    return re.sub(r"[^A-Za-z0-9_.-]", "-", value)[:60] or "x"


@contextmanager
def flash_lease(
    place: str,
    *,
    session: str,
    story: str,
    runner: Optional[Runner] = None,
    env: Optional[dict[str, str]] = None,
    protected_places: Callable[[], set[str]] = default_protected_places,
) -> Iterator[FlashLease]:
    """§4.3 of the transition plan: an exclusive, named hold on a place.

        reserve(name=f"conwrt-<session>-<story>") --wait
            → acquire → yield FlashLease → release

    The reservation NAME carries the session id, so a crashed run leaves a
    *named*, cancelable reservation (``labgrid-client cancel-reservation
    <name>``) instead of a silent lockout. One mutating fixture per place
    per run; VM flash work keeps the dedicated ``flash_vm`` shape — a QEMU
    overlay is its own lease.

    Safety order (identity gates stay in force):
      1. protected places are refused BEFORE any coordinator call
         (ProtectedPlaceError, a ValueError — same contract as
         venues_from_env);
      2. ``CONWRT_FLASH_LEASE_DRY=1`` (or truthy in ``env``) makes the
         lease a local no-op — zero subprocess calls, dry=True on the
         handle. CI and hardware-safe development never touch the
         coordinator through this fixture.

    The runner contract matches default_runner (args only; the runner
    adds client + coordinator flags). Reserve/acquire failures raise
    RuntimeError with the stderr tail — a failed lease must never yield.
    """
    run = runner or default_runner
    env = dict(os.environ) if env is None else env
    reservation = "conwrt-{}-{}".format(
        _lease_token(session), _lease_token(story)
    )

    if place in protected_places():
        raise ProtectedPlaceError(
            f"flash_lease: place {place!r} is marked protected in "
            f"data/lab.yaml — mutating fixtures never run there"
        )

    if env.get("CONWRT_FLASH_LEASE_DRY", "").lower() in ("1", "true", "yes"):
        yield FlashLease(place=place, reservation=reservation, dry=True)
        return

    reserved = run(["reserve", f"name={place}", "--name", reservation, "--wait"])
    if reserved.returncode != 0:
        raise RuntimeError(
            f"flash_lease: reserve of {place!r} failed (reservation "
            f"{reservation!r} may need cancel-reservation): "
            f"{reserved.stderr.strip()[-200:]}"
        )
    acquired = run(["-p", place, "acquire"])
    if acquired.returncode != 0:
        run(["cancel-reservation", reservation])
        raise RuntimeError(
            f"flash_lease: acquire of {place!r} failed (reservation "
            f"{reservation!r} canceled): {acquired.stderr.strip()[-200:]}"
        )
    try:
        yield FlashLease(place=place, reservation=reservation)
    finally:
        run(["-p", place, "release"])
