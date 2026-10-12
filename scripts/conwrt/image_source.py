"""Resolve and download vanilla OpenWrt sysupgrade images for a model.

conwrt normally flashes either a locally supplied ``--image`` or a custom ASU
build (``--request-image``). Operators recovering a device from U-Boot (no SSH,
so no auto-detection) often just want *the stock OpenWrt image for this model*.
This module builds the standard OpenWrt download URL from the model's
``openwrt`` block, downloads it into ``images/``, and verifies its SHA-256
against the target's ``sha256sums`` index.

Design notes:

* Release precedence is ``override`` (CLI/env) > ``openwrt.release`` (model) >
  :data:`DEFAULT_RELEASE`. Only full versions (``24.10.2``) are downloadable;
  the model's ``openwrt.version`` (``"24"``) is the ASU major and is untouched.
* OpenWrt publishes a per-directory ``sha256sums`` file (there is no per-image
  ``.sha256``). Verification parses that index.
"""

from __future__ import annotations

import hashlib
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional, Union

from flash.context import log
from model_loader import load_model

# Bump when the default vanilla image release changes. Per-model
# ``openwrt.release`` overrides this; ``--release`` / the env var override both.
DEFAULT_RELEASE = "24.10.2"

DEFAULT_BASE_URL = "https://downloads.openwrt.org"

_RELEASE_RE = re.compile(r"^\d+\.\d+\.\d+$")
_ENV_RELEASE_VARS = ("CONWRT_OPENWRT_RELEASE", "OPENWRT_RELEASE")
_ENV_BASE_VARS = ("CONWRT_OPENWRT_BASE",)

ModelLike = Union[str, dict]


def downloads_base() -> str:
    """Return the OpenWrt downloads base URL (overridable for mirrors/tests)."""
    for name in _ENV_BASE_VARS:
        value = os.environ.get(name)
        if value:
            return value.rstrip("/")
    return DEFAULT_BASE_URL


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def images_dir() -> Path:
    """Directory where sourced images are cached (gitignored)."""
    return repo_root() / "images"


def _as_model(model: ModelLike) -> dict:
    if isinstance(model, str):
        return load_model(model)
    return model


def _env_release() -> Optional[str]:
    for name in _ENV_RELEASE_VARS:
        value = os.environ.get(name)
        if value:
            return value
    return None


def resolve_release(model: ModelLike, override: Optional[str] = None) -> str:
    """Resolve the full OpenWrt release for *model*.

    Precedence: explicit ``override`` > ``CONWRT_OPENWRT_RELEASE``/``OPENWRT_RELEASE``
    env > ``openwrt.release`` in the model > :data:`DEFAULT_RELEASE`.
    """
    model = _as_model(model)
    candidate = (
        override
        or _env_release()
        or model.get("openwrt", {}).get("release")
        or DEFAULT_RELEASE
    )
    candidate = str(candidate).strip()
    if not _RELEASE_RE.match(candidate):
        raise ValueError(
            f"Invalid OpenWrt release {candidate!r}: expected a full version "
            f"like 24.10.2 (the model's openwrt.version is the ASU major, not a "
            f"download release)."
        )
    return candidate


def image_filename(model: ModelLike, release: str) -> str:
    """Return the vanilla sysupgrade image basename for *model*."""
    model = _as_model(model)
    openwrt = model.get("openwrt", {})
    target = openwrt.get("target", "")
    profile = openwrt.get("profile", "")
    if "/" not in target:
        raise ValueError(
            f"Model '{model.get('id', '?')}' has invalid openwrt.target "
            f"{target!r}: expected '<target>/<subtarget>'"
        )
    if not profile:
        raise ValueError(f"Model '{model.get('id', '?')}' is missing openwrt.profile")
    _, subtarget = target.split("/", 1)
    return f"openwrt-{release}-{target.replace('/', '-')}-{profile}-squashfs-sysupgrade.bin"


def target_dir_url(model: ModelLike, release: str) -> str:
    """Return the OpenWrt target directory URL containing the image."""
    model = _as_model(model)
    target = model.get("openwrt", {}).get("target", "")
    return f"{downloads_base()}/releases/{release}/targets/{target}"


def resolve_image_url(model: ModelLike, release: Optional[str] = None) -> str:
    """Return the full vanilla sysupgrade download URL for *model*."""
    resolved = resolve_release(model, release)
    return f"{target_dir_url(model, resolved)}/{image_filename(model, resolved)}"


def parse_sha256sums(text: str, filename: str) -> Optional[str]:
    """Return the SHA-256 recorded for *filename* in a ``sha256sums`` file.

    OpenWrt's index uses ``<hash> *<filename>`` (binary-mode marker); plain
    ``<hash>  <filename>`` is also accepted.
    """
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        digest, listed = parts
        listed = listed.lstrip("*").strip()
        if listed == filename:
            return digest.lower()
    return None


def sha256_file(path: Union[str, os.PathLike]) -> str:
    h = hashlib.sha256()
    with open(str(path), "rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _http_get_text(url: str, timeout: float = 30.0) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "conwrt/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        data: bytes = resp.read()
    return data.decode("utf-8", errors="replace")


def _download_file(url: str, dest: Path, timeout: float = 300.0) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "conwrt/1.0"})
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        with open(tmp, "wb") as f:
            while True:
                chunk = resp.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
    tmp.replace(dest)


def fetch_image(
    model: ModelLike,
    release: Optional[str] = None,
    dest_dir: Optional[Union[str, os.PathLike]] = None,
    *,
    verify: bool = True,
    force: bool = False,
    log_fn=log,
) -> str:
    """Download + verify the vanilla sysupgrade image for *model*.

    Returns the local path. A cached file with a matching SHA-256 is reused
    unless *force* is set.
    """
    resolved = resolve_release(model, release)
    filename = image_filename(model, resolved)
    url = resolve_image_url(model, resolved)

    if dest_dir is None:
        target_dir = images_dir()
    else:
        target_dir = Path(dest_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    dest = target_dir / filename

    expected_sha: Optional[str] = None
    if verify:
        sums_url = f"{target_dir_url(model, resolved)}/sha256sums"
        log_fn(f"Fetching checksums: {sums_url}")
        try:
            sums_text = _http_get_text(sums_url)
        except (urllib.error.URLError, OSError) as exc:
            raise RuntimeError(f"Could not fetch {sums_url}: {exc}") from exc
        expected_sha = parse_sha256sums(sums_text, filename)
        if not expected_sha:
            raise RuntimeError(
                f"{filename} not found in {sums_url} — the model's openwrt "
                f"target/profile may not match release {resolved}."
            )

    if dest.is_file() and not force:
        if not verify or sha256_file(dest) == expected_sha:
            log_fn(f"Using cached image: {dest}")
            return str(dest)

    log_fn(f"Downloading: {url}")
    try:
        _download_file(url, dest)
    except (urllib.error.URLError, OSError) as exc:
        raise RuntimeError(f"Download failed for {url}: {exc}") from exc

    if verify and expected_sha:
        actual = sha256_file(dest)
        if actual != expected_sha:
            try:
                dest.unlink()
            except OSError:
                pass
            raise RuntimeError(
                f"SHA-256 mismatch for {filename}: expected {expected_sha}, got {actual}"
            )
        log_fn(f"SHA-256 verified: {actual}")

    log_fn(f"Image ready: {dest}")
    return str(dest)
