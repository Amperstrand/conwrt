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
        assert "uci set nodogsplash.@nodogsplash[0].enabled='1' 2>/dev/null || true" in rendered
        assert "uci commit nodogsplash 2>/dev/null || true" in rendered
        assert "/etc/init.d/nodogsplash enable 2>/dev/null || true" in rendered
        assert "/etc/init.d/nodogsplash restart 2>/dev/null || true" in rendered

    def test_default_no_wget(self):
        rendered = render_shell(_build_tollgate_ops(DEFAULT_PARAMS))
        assert "wget" not in rendered
        assert "opkg install" not in rendered

    def test_default_no_tollgate_config(self):
        rendered = render_shell(_build_tollgate_ops(DEFAULT_PARAMS))
        assert "uci set tollgate" not in rendered
        assert "uci commit tollgate" not in rendered


class TestTollgateOpsPayment:
    def test_mint_url(self):
        rendered = render_shell(_build_tollgate_ops(MINT_PARAMS))
        assert "uci set tollgate.@tollgate[0].mint_url='https://mint.example.com' 2>/dev/null || true" in rendered
        assert "uci commit tollgate 2>/dev/null || true" in rendered

    def test_lightning_address(self):
        rendered = render_shell(_build_tollgate_ops({"lightning_address": "pay@node.com"}))
        assert "uci set tollgate.@tollgate[0].lightning_address='pay@node.com' 2>/dev/null || true" in rendered

    def test_price_only(self):
        rendered = render_shell(_build_tollgate_ops({"price_per_minute": 10}))
        assert "uci set tollgate.@tollgate[0].price_per_minute='10' 2>/dev/null || true" in rendered

    def test_all_payment_config(self):
        rendered = render_shell(_build_tollgate_ops(FULL_PARAMS))
        assert "mint_url='https://mint.example.com'" in rendered
        assert "lightning_address='user@domain.com'" in rendered
        assert "price_per_minute='5'" in rendered
