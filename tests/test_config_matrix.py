"""Config matrix: build_plan for all models x use cases.

Catches regressions where a model+use_case combo breaks plan generation.
No hardware required — tests plan construction only.
"""
from __future__ import annotations

import pytest

from config import ConwrtConfig, UseCaseConfig, WifiAPConfig, WifiSTAConfig
from model_loader import list_models
from profile import build_plan
from profile.plan import StepKind
from use_cases import registry

ALL_MODEL_IDS = [m["id"] for m in list_models()]
USE_CASE_NAMES = sorted(registry().keys())
BANDS = ["2.4ghz", "5ghz"]


@pytest.mark.parametrize("model_id", ALL_MODEL_IDS)
def test_build_plan_minimal_config(model_id: str) -> None:
    cfg = ConwrtConfig()
    plan = build_plan(cfg, mode="post_install", model_id=model_id)
    assert len(plan.steps) >= 0


@pytest.mark.parametrize("model_id", ALL_MODEL_IDS)
@pytest.mark.parametrize("use_case_name", USE_CASE_NAMES)
def test_build_plan_with_each_use_case(model_id: str, use_case_name: str) -> None:
    uc = registry()[use_case_name]
    params = {}
    for pname, pdef in uc.params.items():
        if pdef.required:
            if pdef.type is int:
                params[pname] = pdef.min_value or 1000
            else:
                params[pname] = "test"
    cfg = ConwrtConfig(use_cases=[UseCaseConfig(name=use_case_name, params=params)])
    plan = build_plan(cfg, mode="post_install", model_id=model_id)
    assert len(plan.steps) > 0


@pytest.mark.parametrize("band", BANDS)
def test_build_plan_wifi_sta_per_band(band: str) -> None:
    cfg = ConwrtConfig(
        wifi_sta=WifiSTAConfig(band=band, ssid="TestNet", encryption="psk2", key="pass"),
        use_cases=[UseCaseConfig(name="sqm", params={"download_kbps": 1000, "upload_kbps": 500})],
    )
    plan = build_plan(cfg, mode="post_install")

    assert any(s.kind == StepKind.WWAN_SETUP for s in plan.steps)
    assert any(s.kind == StepKind.WIFI_STA for s in plan.steps)
    assert any(s.kind == StepKind.USE_CASE for s in plan.steps)
    assert "sqm-scripts" in plan.all_packages()


@pytest.mark.parametrize("band", BANDS)
def test_build_plan_wifi_ap_per_band(band: str) -> None:
    cfg = ConwrtConfig(
        wifi_aps=[WifiAPConfig(band=band, ssid="MyAP", encryption="psk2", key="pass")],
    )
    plan = build_plan(cfg, mode="post_install")
    assert any(s.kind == StepKind.WIFI_AP for s in plan.steps)


def test_build_plan_sta_ap_simultaneous() -> None:
    cfg = ConwrtConfig(
        wifi_sta=WifiSTAConfig(band="5ghz", ssid="Upstream", encryption="psk2", key="pass"),
        wifi_aps=[WifiAPConfig(band="2.4ghz", ssid="MyAP", encryption="psk2", key="pass")],
    )
    plan = build_plan(cfg, mode="post_install")
    assert any(s.kind == StepKind.WIFI_STA for s in plan.steps)
    assert any(s.kind == StepKind.WIFI_AP for s in plan.steps)


def test_build_plan_asu_mode_has_firstboot_scripts() -> None:
    cfg = ConwrtConfig(
        wifi_sta=WifiSTAConfig(band="5ghz", ssid="Upstream", encryption="psk2", key="pass"),
        use_cases=[UseCaseConfig(name="sqm", params={"download_kbps": 1000, "upload_kbps": 500})],
    )
    plan = build_plan(cfg, mode="asu_build")
    script = plan.asu_defaults_script()
    assert "network.wwan" in script
    assert "sqm" in script.lower() or "download" in script.lower()


def test_all_models_have_valid_target() -> None:
    for m in list_models():
        target = m.get("openwrt", {}).get("target", "")
        assert target, f"Model {m['id']} missing openwrt.target"
        assert "/" in target, f"Model {m['id']} target should be arch/subtarget: {target}"
