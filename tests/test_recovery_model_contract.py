"""Model-registry contract: models declaring recovery IPs expose them to the
recovery script.

`scripts/flash-recovery.sh` resolves a model's recovery/client IPs through
`flash.device_profile.build_profile_from_model` — the same path conwrt uses.
If a model JSON drifts (schema change, renamed key, new preference-tier
method shadowing the recovery one) the script would silently lose its arming
detection. These tests make that drift loud, and pin the runbook contract
for the D-Link species (192.168.0.1 / 192.168.0.10, netns test dependency).
"""

from __future__ import annotations

import glob
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from flash.device_profile import build_profile_from_model  # noqa: E402


def _models_declaring_recovery() -> list[str]:
    ids = []
    for path in sorted(glob.glob("models/*.json")):
        model = json.loads(Path(path).read_text())
        methods = model.get("flash_methods") or {}
        if any(isinstance(cfg, dict) and "recovery_ip" in cfg for cfg in methods.values()):
            ids.append(model["id"])
    return ids


@pytest.mark.parametrize("model_id", _models_declaring_recovery())
def test_profile_exposes_recovery_addrs(model_id: str):
    profile = build_profile_from_model(model_id)
    assert profile.recovery_ip, f"{model_id}: profile lost its recovery_ip"
    assert profile.client_ip, f"{model_id}: profile lost its client_ip"


def test_dlink_covr_x1860_runbook_contract():
    """Runbook + netns test depend on these exact addresses."""
    profile = build_profile_from_model("dlink-covr-x1860-a1")
    assert (profile.recovery_ip, profile.client_ip) == ("192.168.0.1", "192.168.0.10")
