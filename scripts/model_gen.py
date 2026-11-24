#!/usr/bin/env python3
"""model_gen — generate model-JSON stubs from OpenWrt metadata (#766).

probe-rs target-gen analogue: OpenWrt's imagebuilder profiles.json is
vendor metadata we already consume piecemeal (ASU profile names, image
shas); this tool emits the DERIVABLE surface of a model JSON from it so
humans curate only the delta. Generated keys (id, vendor, description,
openwrt.target/device/profile/version/images) refresh on every run;
everything else a hand added (flash_methods, partition_layout,
bench_observations, species warnings, lan_subnet, mac_oui…) is
preserved byte-for-byte — the merge is path-scoped by the _generated
provenance block, so regenerating never clobbers curation (the #766
round-trip gate, pinned by tests).

Sources: any imagebuilder profiles.json (local checkout or download);
the schema keys used are stable across 24.10/25.x.

Usage:
  python3 scripts/model_gen.py --profiles <ib>/bin/targets/<t>/profiles.json \
      --profile zyxel_nr7101 [--out models/zyxel-nr7101.json] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent

#: The key paths this tool owns. The merge replaces EXACTLY these (plus
#: the _generated block); anything else in an existing model file is
#: hand curation and survives regeneration untouched.
GENERATED_KEYS = ("id", "vendor", "description", "openwrt")


def load_profiles(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def gen_stub(profiles: dict[str, Any], profile_id: str) -> dict[str, Any]:
    """The derivable model surface from one IB profile entry."""
    entry = (profiles.get("profiles") or {}).get(profile_id)
    if entry is None:
        raise SystemExit(f"profile {profile_id!r} not in profiles.json")
    title = (entry.get("titles") or [{}])[0]
    vendor = title.get("vendor") or profile_id.split("_", 1)[0].title()
    model = title.get("model") or profile_id
    supported = entry.get("supported_devices") or []
    version_number = str(profiles.get("version_number", ""))
    version_major = version_number.split(".")[0] if version_number else ""
    images = [
        {"name": img.get("name", ""), "type": img.get("type", ""),
         "sha256": img.get("sha256", ""), "size": img.get("size", 0)}
        for img in entry.get("images") or []
    ]
    return {
        "id": profile_id.replace("_", "-"),
        "vendor": vendor,
        "description": f"{vendor} {model}",
        "openwrt": {
            "target": profiles.get("target", ""),
            "device": supported[0] if supported else "",
            "profile": profile_id,
            "version": version_major,
            "images": images,
        },
        "_generated": {
            "source": "imagebuilder profiles.json",
            "version_number": version_number,
            "generated_keys": list(GENERATED_KEYS),
            "note": "regeneration refreshes ONLY the generated_keys paths; "
                    "hand-added keys (flash_methods, partition_layout, "
                    "observations…) are preserved — see tests/test_model_gen.py",
        },
    }


def merge(existing: dict[str, Any] | None, stub: dict[str, Any]) -> dict[str, Any]:
    """Round-trip-safe merge: refresh generated paths, preserve curation.

    Deep-merges the openwrt block (hand keys like default_ip survive
    while target/device/profile/version/images refresh); top-level
    generated keys are replaced; _generated is rewritten wholesale.
    """
    if existing is None:
        return stub
    out = dict(existing)
    for key in GENERATED_KEYS:
        if key == "openwrt":
            merged = dict(existing.get("openwrt") or {})
            merged.update(stub.get("openwrt") or {})
            out["openwrt"] = merged
        else:
            out[key] = stub[key]
    out["_generated"] = stub["_generated"]
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--profiles", type=Path, required=True,
                    help="imagebuilder profiles.json (bin/targets/<target>/profiles.json)")
    ap.add_argument("--profile", required=True, help="IB profile id (e.g. zyxel_nr7101)")
    ap.add_argument("--out", type=Path, default=None,
                    help="model JSON path (default: models/<id>.json)")
    ap.add_argument("--dry-run", action="store_true", help="print the result, write nothing")
    args = ap.parse_args(argv)

    profiles = load_profiles(args.profiles)
    stub = gen_stub(profiles, args.profile)
    out_path = args.out or (ROOT / "models" / f"{stub['id']}.json")
    existing = json.loads(out_path.read_text()) if out_path.exists() else None
    merged = merge(existing, stub)

    if args.dry_run:
        print(json.dumps(merged, indent=2, ensure_ascii=False))
        return 0
    out_path.write_text(json.dumps(merged, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {out_path} ({len(merged)} top-level keys; "
          f"generated surface refreshed, hand keys preserved)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
