# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false
import argparse
import json
import shutil
import sys
from pathlib import Path

from model_loader import load_model, list_models


def cmd_list(args: argparse.Namespace) -> int:
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
        methods = ", ".join(model.get("flash_methods", {}).keys()) or "none"
        desc = model.get("description", "")
        print(f"{model_id:<40s}  {vendor:<12s}  {target:<22s}  [{methods}]  {desc}")
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
        except Exception as e:
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
            line += f"  compatible"
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


def cmd_cache(args: argparse.Namespace) -> int:
    images_dir = Path(__file__).resolve().parent.parent / "images"

    if args.cache_command == "list":
        return _cache_list(images_dir)
    elif args.cache_command == "clean":
        return _cache_clean(images_dir, args)
    else:
        print("Usage: conwrt cache <list|clean>", file=sys.stderr)
        return 1


def _cache_list(images_dir: Path) -> int:
    if not images_dir.is_dir():
        print("No images/ directory found.", file=sys.stderr)
        return 1

    entries = []
    for model_dir in sorted(images_dir.iterdir()):
        if not model_dir.is_dir():
            continue
        for hash_dir in sorted(model_dir.iterdir()):
            if not hash_dir.is_dir():
                continue
            model_id = model_dir.name
            cache_key = hash_dir.name
            metadata_files = list(hash_dir.glob("*.metadata.json"))
            metadata = {}
            if metadata_files:
                try:
                    with open(metadata_files[0]) as f:
                        metadata = json.load(f)
                except (json.JSONDecodeError, OSError):
                    pass

            bin_files = list(hash_dir.glob("*.bin"))
            image_types = []
            total_size = 0
            for bf in bin_files:
                if "sysupgrade" in bf.name:
                    image_types.append("sysupgrade")
                elif "recovery" in bf.name:
                    image_types.append("recovery")
                elif "factory" in bf.name:
                    image_types.append("factory")
                else:
                    image_types.append(bf.stem)
                total_size += bf.stat().st_size

            build_info = metadata.get("version", "?")
            if metadata.get("version_code"):
                build_info += f" ({metadata.get('version_code', '')[:20]})"

            entries.append({
                "model": model_id,
                "hash": cache_key[:12],
                "version": build_info,
                "types": ", ".join(sorted(set(image_types))) or "none",
                "size_mb": f"{total_size / 1024 / 1024:.1f}",
            })

    if not entries:
        print("No cached firmware images found.")
        return 0

    print(f"{'Model':<30s}  {'Hash':<14s}  {'Version':<35s}  {'Types':<30s}  {'Size':>8s}")
    print("-" * 130)
    for e in entries:
        print(f"{e['model']:<30s}  {e['hash']:<14s}  {e['version']:<35s}  {e['types']:<30s}  {e['size_mb']:>7s} MB")
    print(f"\nTotal: {len(entries)} cached build(s)")
    return 0


def _cache_clean(images_dir: Path, args: argparse.Namespace) -> int:
    if not images_dir.is_dir():
        print("No images/ directory found.", file=sys.stderr)
        return 1

    targets = []
    for model_dir in sorted(images_dir.iterdir()):
        if not model_dir.is_dir():
            continue
        if args.model_id and model_dir.name != args.model_id and model_dir.name != args.model_id.replace("-", "_"):
            continue

        hash_dirs = sorted(model_dir.iterdir(), key=lambda d: d.stat().st_mtime)
        hash_dirs = [h for h in hash_dirs if h.is_dir()]

        if args.keep_latest and len(hash_dirs) > 1:
            targets.extend(hash_dirs[:-1])
        elif not args.keep_latest:
            targets.extend(hash_dirs)

    if not targets:
        if args.model_id:
            print(f"No cached images found for model '{args.model_id}'.")
        else:
            print("No cached images found.")
        return 0

    total_size = sum(
        f.stat().st_size
        for d in targets
        for f in d.iterdir()
        if f.is_file()
    )
    print(f"Will remove {len(targets)} cached build(s) ({total_size / 1024 / 1024:.1f} MB):")
    for d in targets:
        print(f"  {d.parent.name}/{d.name[:12]}...")

    if not args.yes:
        try:
            response = input("Continue? [y/N] ")
            if response.lower() not in ("y", "yes"):
                print("Cancelled.")
                return 0
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

    removed = 0
    for d in targets:
        shutil.rmtree(d)
        removed += 1

    print(f"Removed {removed} cached build(s) ({total_size / 1024 / 1024:.1f} MB freed).")
    return 0
