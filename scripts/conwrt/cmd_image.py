# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false
"""Handler for `conwrt image` — download + verify a vanilla OpenWrt image."""
from __future__ import annotations

import argparse
import sys

from flash.context import log

from conwrt.image_source import fetch_image, resolve_image_url, resolve_release


def cmd_image(args: argparse.Namespace) -> int:
    model_id = args.model_id
    try:
        release = resolve_release(model_id, getattr(args, "release", None))
        url = resolve_image_url(model_id, release)
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    log(f"Model:   {model_id}")
    log(f"Release: {release}")
    log(f"URL:     {url}")

    try:
        path = fetch_image(
            model_id,
            release=release,
            dest_dir=getattr(args, "dest", None),
            force=bool(getattr(args, "force", False)),
        )
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(path)
    return 0
