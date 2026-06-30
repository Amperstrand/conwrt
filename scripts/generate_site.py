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
    from flows import registry as flow_registry
    from flows.render import render_flow_markdown, render_flow_shell
    from model_loader import list_models

    full_models = list_models()
    models = [{
        "id": m["id"],
        "vendor": m.get("vendor", ""),
        "description": m.get("description", ""),
        "target": m.get("openwrt", {}).get("target", ""),
        "version": m.get("openwrt", {}).get("version", ""),
        "capabilities": m.get("capabilities", []),
    } for m in full_models]

    flows = [{
        "name": f.name,
        "description": f.description,
        "params": _serialize_params(f.params),
    } for f in flow_registry().values()]

    versions = sorted({m["version"] for m in models if m["version"] and m["version"] != "snapshot"})

    rendered: dict[str, dict[str, dict[str, dict[str, str]]]] = {}
    for flow in flow_registry().values():
        placeholders = _placeholder_params(flow)
        for model in full_models:
            mid = model["id"]
            for ver in versions:
                rendered.setdefault(mid, {}).setdefault(flow.name, {})[ver] = {
                    "shell": render_flow_shell(flow, model, placeholders, version=ver),
                    "markdown": render_flow_markdown(flow, model, placeholders, version=ver),
                }

    addons_out = _addons_bundle(full_models[0])

    return {"models": models, "flows": flows, "versions": versions,
            "rendered": rendered, "addons": addons_out}


def _addons_bundle(sample_model: dict[str, Any]) -> list[dict[str, Any]]:
    from flows import Flow, addons
    from flows.render import render_flow_markdown, render_flow_shell

    out: list[dict[str, Any]] = []
    for name, ao in addons.registry().items():
        if ao.build_step is None:
            continue
        placeholders = {k: "{{" + k + "}}" for k in ao.params}
        step = ao.build_step(placeholders)
        flow = Flow(name="_addon_" + name, description="", steps=[step])
        shell_full = render_flow_shell(flow, sample_model, {})
        md_full = render_flow_markdown(flow, sample_model, {})
        out.append({
            "name": name,
            "title": ao.title,
            "description": ao.description,
            "params": _serialize_params(ao.params),
            "shell": shell_full[shell_full.find("# ---"):],
            "markdown": md_full[md_full.find("## "):],
        })
    return out


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
