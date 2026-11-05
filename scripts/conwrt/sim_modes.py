"""SIM-mode plans for the Zyxel NR7101 (local eSIM, physical card, Android SAP).

This is a renderer/validator, not a flasher. It reads the model's
``cellular.sim_modes`` and ``cellular.carrier_profiles`` and emits the exact
UCI plan for the selected mode. The two secrets in the remote-SAP mode (the
reader spec and the SIM PIN) are read from the environment or ``--reader`` and
are **redacted by default**; ``--show-secrets`` is for a private terminal.

Why a plan instead of an apply command: a SIM-mode change can strand the very
link used to reach the router. The operator stages the UCI values, proves them
with ``uci get``, commits, restarts wwand, and keeps a power-cycle escape
hatch. The tool never writes to a device.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL = REPO_ROOT / "models" / "zyxel-nr7101.json"

MODE_IDS = (
    "local_esim_silentlink",
    "local_physical_ice",
    "remote_android_sap",
)
REMOTE_MODE = "remote_android_sap"

ENV_READER = "CONWRT_RSIM_READER"
ENV_PIN = "CONWRT_SIM_PIN"
REDACTED = "<redacted>"

SECRET_ENV = {
    "network.wwmodem_auto.rsim_reader": ENV_READER,
    "network.wwmodem_auto.pincode": ENV_PIN,
}

# Anything that looks like a real subscriber or radio identifier must never
# appear in this public model. The renderer only ever sees placeholders.
_ICCID_RE = re.compile(r"\b\d{19,20}\b")
_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")


class SimModeError(Exception):
    """Bad mode/model or a missing required secret."""


def load_model(path: str | Path | None = None) -> dict[str, Any]:
    model_path = Path(path) if path else DEFAULT_MODEL
    try:
        return json.loads(model_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SimModeError(f"model not found: {model_path}") from exc
    except json.JSONDecodeError as exc:
        raise SimModeError(f"invalid model JSON in {model_path}: {exc}") from exc


def cellular(model: dict[str, Any]) -> dict[str, Any]:
    value = model.get("cellular")
    return value if isinstance(value, dict) else {}


def sim_modes(model: dict[str, Any]) -> dict[str, Any]:
    value = cellular(model).get("sim_modes")
    return value if isinstance(value, dict) else {}


def carrier_profiles(model: dict[str, Any]) -> dict[str, Any]:
    value = cellular(model).get("carrier_profiles")
    return value if isinstance(value, dict) else {}


def mode_ids(model: dict[str, Any]) -> list[str]:
    present = sim_modes(model)
    ordered = [mid for mid in MODE_IDS if mid in present]
    ordered.extend(mid for mid in present if mid not in ordered)
    return ordered


def _is_placeholder(value: Any) -> bool:
    return isinstance(value, str) and value.startswith("<") and value.endswith(">")


def validate_model(model: dict[str, Any]) -> list[str]:
    """Return a list of model errors; an empty list means the model is usable."""
    errors: list[str] = []
    modes = sim_modes(model)
    profiles = carrier_profiles(model)

    if not modes:
        errors.append("cellular.sim_modes is missing or empty")
    for mid in MODE_IDS:
        if mid not in modes:
            errors.append(f"missing required SIM mode: {mid}")
    if not profiles:
        errors.append("cellular.carrier_profiles is missing or empty")

    for mid in mode_ids(model):
        mode = modes.get(mid)
        if not isinstance(mode, dict):
            errors.append(f"{mid}: mode is not an object")
            continue
        for key in ("label", "location", "carrier_profile", "requires", "uci", "verify"):
            if key not in mode:
                errors.append(f"{mid}: missing {key}")
        cp = mode.get("carrier_profile")
        if cp and cp not in profiles:
            errors.append(f"{mid}: carrier_profile {cp!r} not in carrier_profiles")
        for key in ("requires", "verify"):
            value = mode.get(key)
            if not isinstance(value, list) or not value:
                errors.append(f"{mid}: {key} must be a non-empty list")
        uci = mode.get("uci")
        if not isinstance(uci, dict) or not uci:
            errors.append(f"{mid}: uci must be a non-empty object")
            continue
        for uci_key, uci_value in uci.items():
            if not str(uci_key).startswith("network."):
                errors.append(f"{mid}: uci key {uci_key!r} is not under network.")
            if isinstance(uci_value, str) and "cfun" in uci_value.lower():
                errors.append(f"{mid}: uci value for {uci_key} mentions a CFUN reset")
        reader = uci.get("network.wwmodem_auto.rsim_reader")
        if mid.startswith("local_"):
            if reader is not None:
                errors.append(f"{mid}: a local mode must delete rsim_reader (got {reader!r})")
            if uci.get("network.wwmodem_auto.pincode") is not None:
                # A local PIN is legal at render time via --pin-env, but the
                # model itself must stay value-free.
                errors.append(f"{mid}: model must not carry a local pincode value")
        if mid == REMOTE_MODE:
            secrets = mode.get("secrets") or []
            if "rsim_reader" not in secrets:
                errors.append(f"{mid}: secrets must include rsim_reader")
            if reader is None:
                errors.append(f"{mid}: must set network.wwmodem_auto.rsim_reader")
            elif not _is_placeholder(reader):
                errors.append(f"{mid}: rsim_reader must be a <placeholder> in the public model")
            pin = uci.get("network.wwmodem_auto.pincode")
            if pin is not None and not _is_placeholder(pin):
                errors.append(f"{mid}: pincode must be a <placeholder> in the public model")
            if reader is not None and "network.wwmodem_auto.pincode" not in uci:
                errors.append(f"{mid}: must declare the pincode key (null/placeholder)")

    for pid, profile in profiles.items():
        if not isinstance(profile, dict):
            errors.append(f"carrier profile {pid}: not an object")
            continue
        for key in ("label", "carrier", "apn", "pdp_type"):
            if not profile.get(key):
                errors.append(f"carrier profile {pid}: missing {key}")
        if profile.get("pdp_type") not in ("ipv4", "ipv6", "ipv4v6"):
            errors.append(f"carrier profile {pid}: pdp_type must be ipv4, ipv6 or ipv4v6")

    blob = json.dumps({"sim_modes": modes, "carrier_profiles": profiles})
    if _ICCID_RE.search(blob):
        errors.append("SIM-mode data contains a 19-20 digit identifier (ICCID-like)")
    if _MAC_RE.search(blob):
        errors.append("SIM-mode data contains a real-looking MAC address")

    return errors


def _effective_apn(mode: dict[str, Any], profile: dict[str, Any],
                   apn: str | None) -> str:
    if apn:
        return apn
    for key, value in (mode.get("uci") or {}).items():
        if key.endswith(".apn") and isinstance(value, str):
            return value
    return str(profile.get("apn") or "")


def _effective_pdp(mode: dict[str, Any], profile: dict[str, Any],
                   pdp_type: str | None) -> str:
    if pdp_type:
        return pdp_type
    for key, value in (mode.get("uci") or {}).items():
        if key.endswith(".pdp_type") and isinstance(value, str):
            return value
    return str(profile.get("pdp_type") or "")


def _secret_environment(key: str, pin_env: str) -> str:
    if key == "network.wwmodem_auto.pincode":
        return pin_env
    return SECRET_ENV.get(key, ENV_READER)


def render_mode(
    model: dict[str, Any],
    mode_id: str,
    *,
    reader: str | None = None,
    pin_env: str = ENV_PIN,
    apn: str | None = None,
    pdp_type: str | None = None,
    show_secrets: bool = False,
    environ: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Build a redacted-by-default plan for one mode.

    ``reader`` or ``$CONWRT_RSIM_READER`` supplies the SAP reader. The SIM PIN
    comes only from the environment variable named by ``pin_env`` so it never
    lands in shell history. Secret values are printed only with
    ``show_secrets``; otherwise the plan references the env var.
    """
    modes = sim_modes(model)
    mode = modes.get(mode_id)
    if not isinstance(mode, dict):
        available = ", ".join(mode_ids(model)) or "none"
        raise SimModeError(f"unknown SIM mode {mode_id!r} (available: {available})")

    env = os.environ if environ is None else environ
    profiles = carrier_profiles(model)
    profile_key = str(mode.get("carrier_profile") or "")
    profile = profiles.get(profile_key) if profile_key else None
    profile = profile if isinstance(profile, dict) else {}

    raw_uci: dict[str, Any] = dict(mode.get("uci") or {})
    if apn:
        raw_uci["network.wwan0.apn"] = apn
    if pdp_type:
        raw_uci["network.wwan0.pdp_type"] = pdp_type

    secrets = [str(item) for item in (mode.get("secrets") or [])]
    sources: dict[str, str] = {}
    missing: list[str] = []
    warnings: list[str] = []

    if mode_id == REMOTE_MODE:
        reader_value = reader if reader is not None else env.get(ENV_READER)
        if reader_value:
            raw_uci["network.wwmodem_auto.rsim_reader"] = reader_value
            sources["network.wwmodem_auto.rsim_reader"] = (
                "argument" if reader is not None else "environment")
        else:
            missing.append("rsim_reader")
            warnings.append(
                f"rsim_reader is not set; export {ENV_READER} or pass --reader "
                "before running the plan")
        pin_value = env.get(pin_env) if pin_env else None
        if pin_value:
            raw_uci["network.wwmodem_auto.pincode"] = pin_value
            sources["network.wwmodem_auto.pincode"] = "environment"
        else:
            raw_uci.pop("network.wwmodem_auto.pincode", None)
            warnings.append(
                f"SIM PIN is not set; if the phone SIM is PIN-protected, export "
                f"{pin_env} before running the plan")

    if mode_id.startswith("local_"):
        pin_value = env.get(pin_env) if pin_env else None
        if pin_value:
            raw_uci["network.wwmodem_auto.pincode"] = pin_value
            sources["network.wwmodem_auto.pincode"] = "environment"
        else:
            raw_uci["network.wwmodem_auto.pincode"] = None

    display_uci: dict[str, Any] = {}
    commands: list[str] = []
    redacted = False
    for key, value in raw_uci.items():
        secret = key.rsplit(".", 1)[-1] in secrets
        env_name = _secret_environment(key, pin_env)

        if value is None:
            display_uci[key] = None
            commands.append(f"uci -q delete {key}")
            continue

        if not secret:
            display_uci[key] = value
            commands.append(f"uci set {shlex.quote(f'{key}={value}')}")
            continue

        provided = key in sources
        if show_secrets:
            display_uci[key] = value
            commands.append(f"uci set {shlex.quote(f'{key}={value}')}")
        elif provided:
            display_uci[key] = REDACTED
            commands.append(f'uci set {key}="${env_name}"')
            redacted = True
            if sources.get(key) == "argument":
                warnings.append(
                    f"{key.rsplit('.', 1)[-1]} came from --reader and is redacted; "
                    f"export {env_name} or add --show-secrets to make the plan runnable")
        else:
            display_uci[key] = f"<set {env_name}>"
            commands.append(f'uci set {key}="${env_name}"')
            redacted = True

    if missing and any(key.endswith("rsim_reader") for key in missing):
        # The command above is present but not runnable until the env is set.
        pass

    if apn:
        warnings.append(f"APN overridden to {apn}")
    if pdp_type:
        warnings.append(f"PDP type overridden to {pdp_type}")

    return {
        "mode": mode_id,
        "label": mode.get("label"),
        "location": mode.get("location"),
        "carrier_profile": profile_key,
        "carrier": profile.get("carrier"),
        "apn": _effective_apn(mode, profile, apn),
        "pdp_type": _effective_pdp(mode, profile, pdp_type),
        "requires": list(mode.get("requires") or []),
        "verify": list(mode.get("verify") or []),
        "notes": list(mode.get("notes") or []),
        "uci": display_uci,
        "commands": commands,
        "commit": "uci commit network",
        "restart": "/etc/init.d/wwand restart",
        "missing_secrets": missing,
        "warnings": warnings,
        "redacted": redacted,
        "ready": not missing,
        "show_secrets": show_secrets,
    }


def format_plan(plan: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"SIM mode: {plan['mode']}")
    lines.append(f"  label:    {plan.get('label') or '-'}")
    lines.append(f"  location: {plan.get('location') or '-'}")
    lines.append(f"  carrier:  {plan.get('carrier') or '-'} (profile {plan.get('carrier_profile') or '-'})")
    lines.append(f"  APN/PDP:  {plan.get('apn') or '-'} / {plan.get('pdp_type') or '-'}")
    if plan.get("requires"):
        lines.append("  requires:")
        lines.extend(f"    - {item}" for item in plan["requires"])
    lines.append("  UCI plan:")
    lines.extend(f"    {cmd}" for cmd in plan["commands"])
    lines.append(f"    {plan['commit']}")
    lines.append(f"    {plan['restart']}")
    if plan.get("verify"):
        lines.append("  verify:")
        lines.extend(f"    - {item}" for item in plan["verify"])
    if plan.get("warnings"):
        lines.append("  warnings:")
        lines.extend(f"    ! {item}" for item in plan["warnings"])
    if plan.get("notes"):
        lines.append("  notes:")
        lines.extend(f"    - {item}" for item in plan["notes"])
    return "\n".join(lines)


def format_modes(model: dict[str, Any]) -> str:
    rows = [("MODE", "LOCATION", "CARRIER", "APN/PDP")]
    profiles = carrier_profiles(model)
    for mid in mode_ids(model):
        mode = sim_modes(model).get(mid) or {}
        profile = profiles.get(mode.get("carrier_profile") or "") or {}
        apn = _effective_apn(mode, profile, None) or "-"
        pdp = _effective_pdp(mode, profile, None) or "-"
        rows.append((mid, str(mode.get("location") or "-"),
                     str(profile.get("carrier") or "-"), f"{apn} / {pdp}"))
    widths = [max(len(str(row[i])) for row in rows) for i in range(len(rows[0]))]
    return "\n".join(
        "  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row)).rstrip()
        for row in rows)


def cmd_sim(args: argparse.Namespace) -> int:
    try:
        model = load_model(getattr(args, "model", None))
    except SimModeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    command = getattr(args, "sim_command", None) or "modes"

    if command == "modes":
        if getattr(args, "json_out", False):
            print(json.dumps({mid: sim_modes(model)[mid] for mid in mode_ids(model)},
                             indent=2, sort_keys=True))
        else:
            print(format_modes(model))
        return 0

    if command == "validate":
        errors = validate_model(model)
        if getattr(args, "json_out", False):
            print(json.dumps({"ok": not errors, "errors": errors}, indent=2))
        elif errors:
            print("SIM-mode model validation FAILED:")
            for error in errors:
                print(f"  - {error}")
        else:
            print(f"OK: {len(mode_ids(model))} SIM modes, "
                  f"{len(carrier_profiles(model))} carrier profiles")
        return 0 if not errors else 1

    if command == "render":
        mode_id = getattr(args, "mode", None)
        if not mode_id:
            print("error: render needs a mode (see `conwrt sim modes`)", file=sys.stderr)
            return 2
        env = os.environ
        try:
            plan = render_mode(
                model, mode_id,
                reader=getattr(args, "reader", None),
                pin_env=getattr(args, "pin_env", ENV_PIN),
                apn=getattr(args, "apn", None),
                pdp_type=getattr(args, "pdp_type", None),
                show_secrets=bool(getattr(args, "show_secrets", False)),
                environ=env,
            )
        except SimModeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if getattr(args, "json_out", False):
            print(json.dumps(plan, indent=2, sort_keys=True))
        else:
            print(format_plan(plan))
        return 0 if plan["ready"] else 2

    print(f"error: unknown sim command {command!r}", file=sys.stderr)
    return 2


def _add_subcommands(sub: Any) -> None:
    modes = sub.add_parser("modes", help="List the model's SIM modes and carrier profiles")
    modes.add_argument("--model", default=None, help="Model JSON path (default: zyxel-nr7101)")
    modes.add_argument("--json", dest="json_out", action="store_true")

    render = sub.add_parser("render", help="Render the UCI plan for one SIM mode")
    render.add_argument("mode", help="Mode ID (see `conwrt sim modes`)")
    render.add_argument("--model", default=None, help="Model JSON path (default: zyxel-nr7101)")
    render.add_argument("--reader", default=None,
                        help=f"Remote-SAP reader spec (or ${ENV_READER}); redacted by default")
    render.add_argument("--pin-env", default=ENV_PIN,
                        help=f"Env var holding the SIM PIN (default: {ENV_PIN})")
    render.add_argument("--apn", default=None, help="Override the carrier profile APN")
    render.add_argument("--pdp-type", choices=["ipv4", "ipv6", "ipv4v6"], default=None)
    render.add_argument("--show-secrets", action="store_true",
                        help="Print reader/PIN values; run only in a private terminal")
    render.add_argument("--json", dest="json_out", action="store_true")

    validate = sub.add_parser("validate", help="Validate the SIM-mode model data")
    validate.add_argument("--model", default=None, help="Model JSON path (default: zyxel-nr7101)")
    validate.add_argument("--json", dest="json_out", action="store_true")


def add_parser(subparsers: Any) -> Any:
    parser = subparsers.add_parser(
        "sim",
        help="Render/validate SIM-mode plans (local eSIM, physical ICE, Android SAP)")
    sub = parser.add_subparsers(dest="sim_command")
    parser.set_defaults(sim_command="modes")
    _add_subcommands(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="conwrt sim")
    sub = parser.add_subparsers(dest="sim_command")
    parser.set_defaults(sim_command="modes")
    _add_subcommands(sub)
    args = parser.parse_args(argv)
    return cmd_sim(args)


if __name__ == "__main__":
    sys.exit(main())
