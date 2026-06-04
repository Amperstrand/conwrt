"""Ops characterization tests for tollgate.py.

render_shell(_build_tollgate_ops(...)) is the authoritative output.
"""
from profile.ops import render_shell
from use_cases.tollgate import _build_tollgate_ops


DEFAULT_PARAMS: dict = {}
MINT_PARAMS: dict = {
    "mint_url": "https://mint.example.com",
}
FULL_PARAMS: dict = {
    "mint_url": "https://mint.example.com",
    "lightning_address": "user@domain.com",
    "price_per_minute": 5,
}


class TestTollgateOpsDefault:
    def test_default_nodogsplash(self):
        rendered = render_shell(_build_tollgate_ops(DEFAULT_PARAMS))
        assert "uci set nodogsplash.@nodogsplash[0].enabled='1'" in rendered
        assert "uci commit nodogsplash" in rendered
        assert "/etc/init.d/nodogsplash enable" in rendered
        assert "/etc/init.d/nodogsplash restart" in rendered

    def test_default_no_wget(self):
        rendered = render_shell(_build_tollgate_ops(DEFAULT_PARAMS))
        assert "wget" not in rendered
        assert "opkg install" not in rendered

    def test_default_no_tollgate_config(self):
        rendered = render_shell(_build_tollgate_ops(DEFAULT_PARAMS))
        assert "uci set tollgate" not in rendered
        assert "uci commit tollgate" not in rendered

    def test_default_no_defensive_wrappers(self):
        rendered = render_shell(_build_tollgate_ops(DEFAULT_PARAMS))
        assert "2>/dev/null" not in rendered
        assert "|| true" not in rendered


class TestTollgateOpsPayment:
    def test_mint_url(self):
        rendered = render_shell(_build_tollgate_ops(MINT_PARAMS))
        assert "uci add tollgate tollgate" in rendered
        assert "uci set tollgate.@tollgate[-1].mint_url='https://mint.example.com'" in rendered
        assert "uci commit tollgate" in rendered

    def test_lightning_address(self):
        rendered = render_shell(_build_tollgate_ops({"lightning_address": "pay@node.com"}))
        assert "uci set tollgate.@tollgate[-1].lightning_address='pay@node.com'" in rendered

    def test_price_only(self):
        rendered = render_shell(_build_tollgate_ops({"price_per_minute": 10}))
        assert "uci set tollgate.@tollgate[-1].price_per_minute='10'" in rendered

    def test_all_payment_config(self):
        rendered = render_shell(_build_tollgate_ops(FULL_PARAMS))
        assert "mint_url='https://mint.example.com'" in rendered
        assert "lightning_address='user@domain.com'" in rendered
        assert "price_per_minute='5'" in rendered

    def test_payment_uses_typed_section_ref(self):
        rendered = render_shell(_build_tollgate_ops(FULL_PARAMS))
        # UciAdd uses @type[-1] (last-added section), not hardcoded [0]
        assert "@tollgate[-1]" in rendered
        assert "@tollgate[0]" not in rendered
