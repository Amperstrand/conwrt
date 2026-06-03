from helpers import config_lines as _config_lines
from profile.ops import render_shell
from use_cases.openclash import _build_openclash, _build_openclash_ops


DEFAULT_PARAMS = {}
CUSTOM_PARAMS = {"proxy_type": "vmess", "core_type": "Dev", "dns_mode": "fake-ip"}


class TestOpenclashOpsRoundtrip:
    def _assert_config_match(self, params: dict) -> None:
        script = _build_openclash(params)
        ops = _build_openclash_ops(params)
        rendered = render_shell(ops)
        expected = "\n".join(_config_lines(script))
        assert rendered == expected, f"\n--- rendered ---\n{rendered}\n--- expected ---\n{expected}\n"

    def test_default_params(self):
        self._assert_config_match(DEFAULT_PARAMS)

    def test_custom_params(self):
        self._assert_config_match(CUSTOM_PARAMS)

    def test_fake_ip_dns(self):
        self._assert_config_match({"dns_mode": "fake-ip"})
