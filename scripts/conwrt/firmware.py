# pyright: reportMissingImports=false, reportOptionalMemberAccess=false, reportArgumentType=false, reportCallIssue=false, reportAttributeAccessIssue=false

import argparse
import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path
from typing import Optional

from flash.context import log, sha256_file
from model_loader import load_model, openwrt_asu_profile

import importlib
_firmware_manager = importlib.import_module("firmware-manager")
firmware_request = _firmware_manager.cmd_request
firmware_find = _firmware_manager.cmd_find
IMAGES_DIR = _firmware_manager.IMAGES_DIR


def _resolve_asu_profile(model_id: str) -> str:
    return openwrt_asu_profile(load_model(model_id))


def _request_custom_image(
    model_id: str,
    ssh_key_path: Optional[str],
    password: Optional[str],
    wan_ssh: bool,
    flash_method: str,
    say_fn,
) -> tuple[Optional[str], dict]:
    asu_profile = _resolve_asu_profile(model_id)
    say_fn("Requesting custom firmware image from ASU...")
    log(f"ASU profile: {asu_profile}")

    model = load_model(model_id)
    target = model.get("openwrt", {}).get("target", "")
    version = model.get("openwrt", {}).get("version", "24.10.2")

    request_args = argparse.Namespace(
        profile=asu_profile,
        version=version,
        target=target or None,
        packages=None,
        ssh_key=ssh_key_path,
        password=password,
        wan_ssh=wan_ssh,
        model_capabilities=model.get("capabilities", []),
    )

    request_buf = io.StringIO()
    with redirect_stdout(request_buf):
        rc = firmware_request(request_args)
    if rc != 0:
        log("ERROR: ASU firmware request failed.")
        return None, {}

    recovery_methods = {
        "recovery-http",
        "uboot-http",
        "uboot-tftp",
        "zycast",
        "dlink-hnap",
        "mtd-write",
        "extreme-rdwr-tftp-initramfs",
        "oem-http",
    }
    if flash_method in recovery_methods:
        preferred_types = ["recovery", "factory", "initramfs"]
    else:
        preferred_types = ["sysupgrade"]

    image_path = None
    for img_type in preferred_types:
        find_args = argparse.Namespace(
            profile=asu_profile,
            type=img_type,
        )
        find_buf = io.StringIO()
        with redirect_stdout(find_buf):
            firmware_find(find_args)
        candidate = find_buf.getvalue().strip()
        if candidate and os.path.isfile(candidate):
            image_path = candidate
            break

    if not image_path:
        find_args = argparse.Namespace(
            profile=asu_profile,
            type=None,
        )
        find_buf = io.StringIO()
        with redirect_stdout(find_buf):
            firmware_find(find_args)
        image_path = find_buf.getvalue().strip()

    if not image_path or not os.path.isfile(image_path):
        profile_dir = IMAGES_DIR / asu_profile
        if profile_dir.exists():
            for hash_dir in sorted(profile_dir.iterdir(), reverse=True):
                if not hash_dir.is_dir():
                    continue
                for f in sorted(hash_dir.iterdir()):
                    if f.is_file() and f.suffix in (".bin", ".img", ".tar"):
                        image_path = str(f)
                        break
                if image_path and os.path.isfile(image_path):
                    break

    if not image_path or not os.path.isfile(image_path):
        log("ERROR: No firmware image file found after ASU request.")
        return None, {}

    metadata = {}
    try:
        image_obj = Path(image_path)
        meta_path = image_obj.parent / "build.metadata.json"
        if meta_path.is_file():
            metadata = json.loads(meta_path.read_text())
    except (OSError, json.JSONDecodeError):
        metadata = {}

    log(f"Firmware image: {image_path}")

    if flash_method in {"edgeos-kernel-swap", "extreme-rdwr-tftp-initramfs", "oem-http"}:
        initramfs_path = ""
        if image_path:
            image_dir = Path(image_path).parent
            for candidate in sorted(image_dir.iterdir()):
                if candidate.is_file() and "initramfs" in candidate.name:
                    initramfs_path = str(candidate)
                    log(f"Initramfs image: {initramfs_path}")
                    break
        if not initramfs_path:
            log("WARNING: No initramfs image found in build directory.")
        metadata["initramfs_path"] = initramfs_path

    return image_path, metadata
