"""Roundtrip tests for mesh11sd.py UCI generators.

Roundtrip tests verify that render_shell(_build_mesh11sd_ops(...)) matches
the configuration lines from _build_mesh11sd(...) (excluding comments/echo).
"""
from helpers import config_lines as _config_lines
from profile.ops import render_shell
from use_cases.mesh11sd import _build_mesh11sd, _build_mesh11sd_ops


DEFAULT_PARAMS = {"mesh_id": "my-mesh"}
WITH_KEY_PARAMS = {
    "mesh_id": "test-mesh",
    "ssid": "CustomSSID",
    "encryption": "2",
    "key": "secret123",
    "auto_config": "1",
}


class TestMesh11sdOpsRoundtrip:
    def _assert_config_match(self, params: dict) -> None:
        script = _build_mesh11sd(params)
        ops = _build_mesh11sd_ops(params)
        rendered = render_shell(ops)
        expected = "\n".join(_config_lines(script))
        assert rendered == expected, f"\n--- rendered ---\n{rendered}\n--- expected ---\n{expected}\n"

    def test_default_params(self):
        self._assert_config_match(DEFAULT_PARAMS)

    def test_with_key(self):
        self._assert_config_match(WITH_KEY_PARAMS)

    def test_without_key(self):
        self._assert_config_match({"mesh_id": "simple-mesh", "ssid": "Net", "encryption": "0"})

    def test_auto_config_enabled(self):
        self._assert_config_match({"mesh_id": "auto-mesh", "auto_config": "2"})
