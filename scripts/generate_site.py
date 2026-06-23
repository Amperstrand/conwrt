#!/usr/bin/env python3
"""Generate the conwrt web bundle for the interactive wizard.

Emits ``docs/wizard-bundle.json``: the models + flows + per-(model, flow)
rendered shell/markdown templates with ``{{param}}`` placeholders. The wizard
SPA (``docs/wizard.html``) substitutes user-filled params client-side, so
Python remains the sole renderer and the published site can never drift from
the CLI — the same flow renders the live run, the script, the Markdown, and
the web page.
"""
from __future__ import annotations

import datetime
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent


def _typename(t: type) -> str:
    return {str: "string", int: "int", bool: "bool"}.get(t, "string")


def _serialize_params(params: dict) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for name, pdef in params.items():
        out[name] = {
            "type": _typename(pdef.type),
            "required": bool(pdef.required),
            "description": pdef.description,
            "default": pdef.default,
            "choices": list(pdef.choices) if pdef.choices else [],
        }
    return out


def _placeholder_params(flow) -> dict[str, str]:
    return {name: "{{" + name + "}}" for name in flow.params}


def build_bundle() -> dict[str, Any]:
    sys.path.insert(0, str(ROOT / "scripts"))
    from flows import Flow, Step, registry as flow_registry
    from flows.render import render_flow_markdown, render_flow_shell
    from model_loader import list_models

    full_models = list_models()
    models = [{
        "id": m["id"],
        "vendor": m.get("vendor", ""),
        "description": m.get("description", ""),
        "target": m.get("openwrt", {}).get("target", ""),
        "capabilities": m.get("capabilities", []),
    } for m in full_models]

    flows = [{
        "name": f.name,
        "description": f.description,
        "params": _serialize_params(f.params),
    } for f in flow_registry().values()]

    rendered: dict[str, dict[str, dict[str, str]]] = {}
    for flow in flow_registry().values():
        placeholders = _placeholder_params(flow)
        for model in full_models:
            mid = model["id"]
            rendered.setdefault(mid, {})[flow.name] = {
                "shell": render_flow_shell(flow, model, placeholders),
                "markdown": render_flow_markdown(flow, model, placeholders),
            }

    password_snippet = _password_snippet(full_models[0])

    return {"models": models, "flows": flows, "rendered": rendered,
            "password_snippet": password_snippet}


def _password_snippet(sample_model: dict[str, Any]) -> dict[str, str]:
    from flows import Flow, Step
    from flows.render import render_flow_markdown, render_flow_shell

    pw_flow = Flow(name="_password", description="",
                   steps=[Step(kind="password", title="Set a random root password")])
    shell_full = render_flow_shell(pw_flow, sample_model, {})
    md_full = render_flow_markdown(pw_flow, sample_model, {})
    shell_block = shell_full[shell_full.find("# ---"):]
    md_block = md_full[md_full.find("## "):]
    return {"shell": shell_block, "markdown": md_block}


def main() -> None:
    bundle = build_bundle()
    bundle["generated_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs" / "wizard-bundle.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bundle, indent=2))
    count = len(bundle["models"]) * len(bundle["flows"])
    print(f"Generated {out} ({len(bundle['models'])} models × {len(bundle['flows'])} flows = {count} rendered)")


if __name__ == "__main__":
    main()
