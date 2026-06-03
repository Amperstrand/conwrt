"""Characterization and roundtrip tests for tollgate.py UCI generators.

Characterization tests lock the current output of _build_tollgate so
refactoring to ops can be verified.

Roundtrip tests verify that render_shell(_build_tollgate_ops(...)) matches
the configuration lines from _build_tollgate(...) (excluding comments/echo).
"""
from helpers import config_lines as _config_lines
from profile.ops import render_shell
from use_cases.tollgate import _build_tollgate, _build_tollgate_ops


DEFAULT_PARAMS: dict = {}
BAKE_PARAMS: dict = {
    "deploy_mode": "bake",
    "ipk_url": "http://example.com/tollgate.ipk",
}
BAKE_FULL_PARAMS: dict = {
    "deploy_mode": "bake",
    "ipk_url": "http://example.com/tollgate.ipk",
    "mint_url": "https://mint.example.com",
    "lightning_address": "user@domain.com",
    "price_per_minute": 5,
}
POSTFLASH_MINT_PARAMS: dict = {
    "mint_url": "https://mint.example.com",
}
POSTFLASH_FULL_PARAMS: dict = {
    "mint_url": "https://mint.example.com",
    "lightning_address": "user@domain.com",
    "price_per_minute": 5,
}
BAKE_NO_URL_PARAMS: dict = {
    "deploy_mode": "bake",
}


class TestTollgateCharacterization:
    def test_default_post_flash(self):
        script = _build_tollgate(DEFAULT_PARAMS)
        assert "uci set nodogsplash.@nodogsplash[0].enabled='1' 2>/dev/null || true" in script
        assert "uci commit nodogsplash 2>/dev/null || true" in script
        assert "/etc/init.d/nodogsplash enable 2>/dev/null || true" in script
        assert "/etc/init.d/nodogsplash restart 2>/dev/null || true" in script
        assert "tollgate" not in script.split("nodogsplash")[-1]

    def test_bake_with_ipk_url(self):
        script = _build_tollgate(BAKE_PARAMS)
        assert "_i=0" in script
        assert "while [ $_i -lt 30 ]; do" in script
        assert "wget -O /tmp/tollgate-wrt.ipk" in script
        assert "opkg install /tmp/tollgate-wrt.ipk" in script
        assert "/etc/init.d/tollgate-wrt enable 2>/dev/null || true" in script

    def test_post_flash_with_mint_url(self):
        script = _build_tollgate(POSTFLASH_MINT_PARAMS)
        assert "uci set tollgate.@tollgate[0].mint_url='https://mint.example.com' 2>/dev/null || true" in script
        assert "uci commit tollgate 2>/dev/null || true" in script
        assert "touch /etc/config/tollgate 2>/dev/null || true" in script

    def test_post_flash_with_lightning_only(self):
        script = _build_tollgate({"lightning_address": "pay@node.com"})
        assert "uci set tollgate.@tollgate[0].lightning_address='pay@node.com' 2>/dev/null || true" in script
        assert "uci commit tollgate 2>/dev/null || true" in script

    def test_post_flash_with_price_only(self):
        script = _build_tollgate({"price_per_minute": 10})
        assert "uci set tollgate.@tollgate[0].price_per_minute='10' 2>/dev/null || true" in script
        assert "uci commit tollgate 2>/dev/null || true" in script


class TestTollgateOpsRoundtrip:
    def _assert_config_match(self, params: dict) -> None:
        script = _build_tollgate(params)
        ops = _build_tollgate_ops(params)
        rendered = render_shell(ops)
        expected = "\n".join(_config_lines(script))
        assert rendered == expected, (
            f"\n--- rendered ---\n{rendered}\n--- expected ---\n{expected}\n"
        )

    def test_default_post_flash(self):
        self._assert_config_match(DEFAULT_PARAMS)

    def test_bake_with_ipk_url(self):
        self._assert_config_match(BAKE_PARAMS)

    def test_bake_with_all_config(self):
        self._assert_config_match(BAKE_FULL_PARAMS)

    def test_post_flash_with_mint_url(self):
        self._assert_config_match(POSTFLASH_MINT_PARAMS)

    def test_post_flash_with_lightning_address(self):
        self._assert_config_match({"lightning_address": "pay@node.com"})

    def test_post_flash_with_all_config(self):
        self._assert_config_match(POSTFLASH_FULL_PARAMS)

    def test_bake_no_ipk_url_fallback(self):
        self._assert_config_match(BAKE_NO_URL_PARAMS)

    def test_bake_with_mint_url_only(self):
        self._assert_config_match({
            "deploy_mode": "bake",
            "ipk_url": "http://example.com/tollgate.ipk",
            "mint_url": "https://mint.example.com",
        })
