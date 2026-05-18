from __future__ import annotations

import pytest

from use_cases import apply_defaults


def test_apply_defaults_rejects_unknown_params() -> None:
    with pytest.raises(ValueError, match="unknown param"):
        apply_defaults("sqm", {"download_kbps": 1000, "upload_kbps": 500, "surprise": True})


def test_apply_defaults_requires_required_params() -> None:
    with pytest.raises(ValueError, match="requires param 'upload_kbps'"):
        apply_defaults("sqm", {"download_kbps": 1000})


def test_apply_defaults_rejects_wrong_type() -> None:
    with pytest.raises(TypeError, match="must be int"):
        apply_defaults("sqm", {"download_kbps": "1000", "upload_kbps": 500})


def test_apply_defaults_rejects_bool_for_int() -> None:
    with pytest.raises(TypeError, match="must be int"):
        apply_defaults("sqm", {"download_kbps": True, "upload_kbps": 500})


def test_apply_defaults_applies_defaults() -> None:
    params = apply_defaults("sqm", {"download_kbps": 1000, "upload_kbps": 500})
    assert params["qdisc"] == "cake"
    assert params["interface"] == "wan"
