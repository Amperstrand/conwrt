#!/usr/bin/env python3
# pyright: reportMissingImports=false, reportOptionalMemberAccess=false
"""Handler for `conwrt flow` — deploy or generate a composite flow.

list              show available flows
script            print a runnable host shell script
instructions      print Markdown instructions
run               execute the flow against an already-flashed router at --ip
"""
from __future__ import annotations

import os
import subprocess
import sys
from types import SimpleNamespace

from flows import registry as flow_registry
from flows.render import render_flow_markdown, render_flow_shell
from model_loader import load_model


def _parse_overrides(items: list[str]) -> dict[str, str]:
    params: dict[str, str] = {}
    for raw in items or []:
        if "=" not in raw:
            raise SystemExit(f"--set must be KEY=VALUE, got: {raw!r}")
        key, value = raw.split("=", 1)
        params[key] = value
    return params


def _resolve_flow(args) -> tuple[object, dict[str, str]]:
    flows = flow_registry()
    flow = flows.get(args.flow)
    if flow is None:
        known = ", ".join(sorted(flows)) or "none"
        raise SystemExit(f"Unknown flow {args.flow!r}. Known: {known}")
    params = _parse_overrides(args.overrides)
    missing = [name for name, pdef in flow.params.items() if pdef.required and name not in params]
    if missing:
        raise SystemExit(f"Missing required params for flow {args.flow!r}: {', '.join(missing)}")
    return flow, params


def cmd_flow(args: SimpleNamespace) -> int:
    flow_command = getattr(args, "flow_command", None) or "list"

    if flow_command == "list":
        flows = flow_registry()
        if not flows:
            print("No flows registered.")
            return 0
        for name, flow in sorted(flows.items()):
            print(f"  {name:20s} {flow.description[:72]}")
        return 0

    flow, params = _resolve_flow(args)
    if getattr(args, "set_password", False):
        from flows import Flow, Step
        pw_step = Step(kind="password", title="Set a random root password",
                       detail="Generates a random 16-char root password and prints it once.")
        flow = Flow(name=flow.name, description=flow.description,
                    params=flow.params, steps=[pw_step] + list(flow.steps))
    model = load_model(args.model_id)

    if flow_command == "script":
        sys.stdout.write(render_flow_shell(flow, model, params, version=args.version))
        return 0

    if flow_command == "instructions":
        sys.stdout.write(render_flow_markdown(flow, model, params, version=args.version))
        return 0

    if flow_command == "run":
        script = render_flow_shell(flow, model, params, version=args.version)
        env = {**os.environ, "IP": args.ip}
        sys.stderr.write(f"[flow] running {flow.name} on {args.model_id} at {args.ip}\n")
        sys.stderr.write("[flow] (assumes the router is already flashed and reachable)\n")
        return subprocess.run(["sh", "-c", script], env=env).returncode

    raise SystemExit(f"Unknown flow command: {flow_command!r}")
