"""#460 — the VM image cache must be VALIDATED, not trusted.

A legacy `.openwrt.img` from the direct-boot era carries accumulated
mutations; accepting it as pristine permanently poisons the one-time
qcow2 base. The gate: a sha256 sidecar recorded at creation time (after
prep — prep mutates the image in place); reuse requires the sidecar to
exist AND match. Anything else re-downloads from scratch.
"""
from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "intg_conftest", Path(__file__).parent / "integration" / "conftest.py")
intg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(intg)


def _write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def test_missing_sidecar_is_invalid_legacy_cache(tmp_path, monkeypatch):
    # the direct-boot era left images with no digest record — untrusted
    _write(tmp_path / ".openwrt.img", b"legacy dirty bytes")
    monkeypatch.setattr(intg, "VM_IMAGE", tmp_path / ".openwrt.img")
    monkeypatch.setattr(intg, "DIGEST_SIDECAR", tmp_path / ".openwrt.img.sha256")
    assert intg.VM_IMAGE.exists()
    assert not intg._image_cache_valid()


def test_digest_mismatch_is_invalid(tmp_path, monkeypatch):
    img = tmp_path / ".openwrt.img"
    _write(img, b"mutated since recording")
    _write(tmp_path / ".openwrt.img.sha256",
           hashlib.sha256(b"original bytes").hexdigest().encode())
    monkeypatch.setattr(intg, "VM_IMAGE", img)
    monkeypatch.setattr(intg, "DIGEST_SIDECAR", tmp_path / ".openwrt.img.sha256")
    assert not intg._image_cache_valid()


def test_matching_sidecar_is_valid(tmp_path, monkeypatch):
    img = tmp_path / ".openwrt.img"
    _write(img, b"pristine prepped bytes")
    _write(tmp_path / ".openwrt.img.sha256",
           hashlib.sha256(b"pristine prepped bytes").hexdigest().encode())
    monkeypatch.setattr(intg, "VM_IMAGE", img)
    monkeypatch.setattr(intg, "DIGEST_SIDECAR", tmp_path / ".openwrt.img.sha256")
    assert intg._image_cache_valid()
