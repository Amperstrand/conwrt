from __future__ import annotations
import sys
import argparse
from pathlib import Path

_CONWRT_DIR = str(Path(__file__).resolve().parent)
if _CONWRT_DIR not in sys.path:
    sys.path.insert(0, _CONWRT_DIR)

from config import load_config as _load_config
from model_loader import load_model
from profile import build_plan, print_plan


def cmd_profile_plan(args: argparse.Namespace) -> int:
    """Print the profile plan from config.toml (dry-run preview)."""
    cfg = _load_config()
    model_caps: list[str] = []
    if args.model_id:
        try:
            model = load_model(args.model_id)
            model_caps = model.get("capabilities", [])
        except FileNotFoundError as exc:
            print(f"Warning: {exc}", file=sys.stderr)
    plan = build_plan(cfg, mode="preview", model_capabilities=model_caps)
    print_plan(plan)
    return 0
