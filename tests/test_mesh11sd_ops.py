"""Characterization and wiring tests for mesh11sd.py ops.

Characterization tests lock the current output of render_shell(_build_mesh11sd_ops).
Wiring tests verify that render_shell(ops) matches the UseCase's build_configure.
"""
from profile.ops import render_shell
from use_cases import get as get_uc
from use_cases.mesh11sd import _build_mesh11sd_ops


DEFAULT_PARAMS = {"mesh_id": "my-mesh"}
WITH_KEY_PARAMS = {
    "mesh_id": "test-mesh",
    "ssid": "CustomSSID",
    "encryption": "2",
    "key": "secret123",
    "auto_config": "1",
}


class TestMesh11sdCharacterization:
    def _render(self, params: dict) -> str:
        return render_shell(_build_mesh11sd_ops(params))

    def test_default_output(self):
        script = self._render(DEFAULT_PARAMS)
        assert "uci set mesh11sd.setup.auto_mesh_id='my-mesh'" in script
        assert "uci commit mesh11sd" in script
        assert "service mesh11sd restart" in script

    def test_with_key_output(self):
        script = self._render(WITH_KEY_PARAMS)
        assert "uci set mesh11sd.setup.mesh_gate_key='secret123'" in script


class TestMesh11sdOpsWiring:
    def _assert_config_match(self, params: dict) -> None:
        ops = _build_mesh11sd_ops(params)
        rendered = render_shell(ops)
        uc = get_uc("mesh11sd")
        expected = uc.build_configure(params)
        assert rendered == expected, f"\n--- rendered ---\n{rendered}\n--- expected ---\n{expected}\n"

    def test_default_params(self):
        self._assert_config_match(DEFAULT_PARAMS)

    def test_with_key(self):
        self._assert_config_match(WITH_KEY_PARAMS)

    def test_without_key(self):
        self._assert_config_match({"mesh_id": "simple-mesh", "ssid": "Net", "encryption": "0"})

    def test_auto_config_enabled(self):
        self._assert_config_match({"mesh_id": "auto-mesh", "auto_config": "2"})
