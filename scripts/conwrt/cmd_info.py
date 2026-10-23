# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false
import argparse
import json
import shutil
import sys
from pathlib import Path

from model_loader import MODELS_DIR, load_model, list_models


def cmd_list(args: argparse.Namespace) -> int:
    """List the model corpus (deprecated — parity-matrix §7, item 1).

    Output is byte-aligned with the Rust successor ``conwrt models``
    (``cmd_models_validate`` in apps/conwrt-cli): flash-method names are
    SORTED (the Rust side reads them from a BTreeMap — deterministic;
    JSON insertion order here would drift with any key rewrite of a
    model file) and the table ends with the ``N model(s) valid in
    <dir>`` footer. A model with no flash methods prints ``[]``, as the
    Rust side does (unreachable on a valid corpus — the schema requires
    minProperties 1). Both sides are byte-pinned against one golden by
    tests/test_parity_rust_models.py.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from rust_migration import soft_deprecated

    soft_deprecated("conwrt models", "model listing/validation")
    models = list_models()
    if not models:
        print("No models found in models/ directory.", file=sys.stderr)
        return 1

    print(f"{'Model ID':<40s}  {'Vendor':<12s}  {'Target':<22s}  {'Flash Methods':<20s}  Description")
    print("-" * 140)
    for model in models:
        model_id = model.get("id", "?")
        vendor = model.get("vendor", "?")
        target = model.get("openwrt", {}).get("target", "?")
        methods = ", ".join(sorted(model.get("flash_methods", {}).keys()))
        desc = model.get("description", "")
        print(f"{model_id:<40s}  {vendor:<12s}  {target:<22s}  [{methods}]  {desc}")
    print(f"\n{len(models)} model(s) valid in {MODELS_DIR.name}")
    return 0


def cmd_list_use_cases(args: argparse.Namespace) -> int:
    """List all available use case presets with optional model compatibility."""
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from use_cases import registry as _uc_registry

    uc_reg = _uc_registry()
    if not uc_reg:
        print("No use case presets found in scripts/use_cases/.", file=sys.stderr)
        return 1

    model_caps: list[str] = []
    model_name = ""
    if args.model_id:
        try:
            model = load_model(args.model_id)
            model_caps = model.get("capabilities", [])
            model_name = model.get("id", args.model_id)
        except (OSError, ValueError) as e:
            print(f"Warning: could not load model '{args.model_id}': {e}", file=sys.stderr)

    print(f"{'Use Case':<25s}  {'Status':<14s}  {'Description':<40s}  {'Pkgs':<5s}  {'Caps':<12s}  Post")
    print("-" * 120)
    for name in sorted(uc_reg.keys()):
        uc = uc_reg[name]
        pkg_count = len(uc.packages)
        caps = ", ".join(uc.requires_capabilities) if uc.requires_capabilities else "-"
        post_flash = "yes" if uc.configure_via == "ssh" else "-"
        status = uc.test_status

        if model_caps and uc.requires_capabilities:
            missing = set(uc.requires_capabilities) - set(model_caps)
            status = "INCOMPAT" if missing else "ok"
        elif model_caps and not uc.requires_capabilities:
            status = "ok"
        else:
            status = ""

        line = f"{name:<25s}  {status:<14s}  {uc.description[:40]:<40s}  {pkg_count:<5d}  {caps:<12s}  {post_flash}"
        if status == "INCOMPAT":
            line += f"  ** incompatible with {model_name} **"
        elif status == "ok":
            line += "  compatible"
        print(line)

    if model_name:
        print(f"\nModel: {model_name}  Capabilities: {', '.join(sorted(model_caps)) or 'none'}")

    print("\nConfig snippet:")
    print("  [use_cases]")
    names = ", ".join(f'"{n}"' for n in sorted(uc_reg.keys())[:3])
    print(f"  enabled = [{names}, ...]")
    for name in sorted(uc_reg.keys())[:3]:
        uc = uc_reg[name]
        required = [p for p, d in uc.params.items() if d.required]
        if required:
            print(f"  [use_cases.{name}]")
            for p in required:
                print(f"  # {p} = \"...\"  # {uc.params[p].description}")

    return 0


