"""Ops characterization + defect-regression tests for tollgate.py.

render_shell(_build_tollgate_ops(...)) is the authoritative output.
The named-section / del_list shapes and the hotplug_interface gate are
the fixes landed with the Rust port (plan.rs TollgateProfile).
"""
import pytest
from profile.ops import render_shell
from shell_safe import ValidationError
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

    def test_guards_only_on_idempotent_del_list(self):
        # the fixed builder's ONLY defensive wrappers are the guarded
        # del_list lines (re-configure idempotency); nothing else
        # swallows errors
        rendered = render_shell(_build_tollgate_ops(DEFAULT_PARAMS))
        guarded = [
            l for l in rendered.splitlines() if "2>/dev/null || true" in l
        ]
        assert guarded, "del_list guards must exist"
        assert all("del_list nodogsplash" in l for l in guarded)


class TestTollgateOpsPayment:
    def test_mint_url(self):
        rendered = render_shell(_build_tollgate_ops(MINT_PARAMS))
        assert "uci set tollgate.payment=tollgate" in rendered
        assert "uci set tollgate.payment.mint_url='https://mint.example.com'" in rendered
        assert "uci commit tollgate" in rendered

    def test_lightning_address(self):
        rendered = render_shell(_build_tollgate_ops({"lightning_address": "pay@node.com"}))
        assert "uci set tollgate.payment.lightning_address='pay@node.com'" in rendered

    def test_price_only(self):
        rendered = render_shell(_build_tollgate_ops({"price_per_minute": 10}))
        assert "uci set tollgate.payment.price_per_minute='10'" in rendered

    def test_all_payment_config(self):
        rendered = render_shell(_build_tollgate_ops(FULL_PARAMS))
        assert "mint_url='https://mint.example.com'" in rendered
        assert "lightning_address='user@domain.com'" in rendered
        assert "price_per_minute='5'" in rendered


class TestTollgateIdempotencyFixes:
    """Regression tests for the re-configure defects fixed with the port."""

    def test_payment_section_is_named_not_anonymous(self):
        # 1.x `uci add tollgate tollgate` appended a NEW anonymous section
        # on every re-configure; the named section replaces in place.
        rendered = render_shell(_build_tollgate_ops(MINT_PARAMS))
        assert "uci add tollgate" not in rendered
        assert "@tollgate[-1]" not in rendered
        assert "uci set tollgate.payment=tollgate" in rendered

    def test_users_to_router_deduped_before_add(self):
        # plain add_list accumulated duplicate allow rules per re-run;
        # each rule is del_list'd (guarded) before add_list.
        rendered = render_shell(_build_tollgate_ops(DEFAULT_PARAMS))
        for rule in ("allow tcp port 2121", "allow tcp port 2050"):
            assert (
                f"uci -q del_list nodogsplash.@nodogsplash[0].users_to_router='{rule}' "
                f"2>/dev/null || true" in rendered
            )
            assert f"uci add_list nodogsplash.@nodogsplash[0].users_to_router='{rule}'" in rendered
        assert "users_to_router='allow tcp port 22'" not in rendered  # ssh off by default

    def test_lan_ssh_rule_conditional(self):
        rendered = render_shell(_build_tollgate_ops({"allow_lan_ssh": True}))
        assert "users_to_router='allow tcp port 22'" in rendered


class TestTollgateHotplugGate:
    """hotplug_interface executes inside the installed ifup script —
    hostile values are command injection at router runtime."""

    def test_default_wwan_ok(self):
        rendered = render_shell(_build_tollgate_ops(DEFAULT_PARAMS))
        assert '[ "$INTERFACE" = "wwan" ]' in rendered

    def test_hostile_interface_rejected(self):
        for evil in ("wwan$(reboot)", "a'; rm -rf /; '", "if; reboot", "x\ny"):
            with pytest.raises(ValidationError):
                _build_tollgate_ops({"hotplug_interface": evil})

    def test_valid_interface_variants_accepted(self):
        for ok in ("wwan", "wan", "usbwan", "wwan2", "br-lan"):
            rendered = render_shell(_build_tollgate_ops({"hotplug_interface": ok}))
            assert f'[ "$INTERFACE" = "{ok}" ]' in rendered


class TestTollgatePricing:
    def test_explicit_price(self):
        rendered = render_shell(_build_tollgate_ops({"price_sats_per_mib": 8}))
        assert "( 8 * SS + 1048575 )" in rendered
        assert "8 sat/MiB" in rendered

    def test_fx_derivation_deterministic_with_explicit_fx(self):
        rendered = render_shell(_build_tollgate_ops({
            "upstream_usd_per_gb": 0.83, "markup": 2.0, "fx_sats_per_usd": 2500,
        }))
        # 0.83/1024*2500*2.0 = 4.052… -> ceil 5
        assert "( 5 * SS + 1048575 )" in rendered
        assert "5 sat/MiB" in rendered

    def test_no_pricing_without_inputs(self):
        rendered = render_shell(_build_tollgate_ops(DEFAULT_PARAMS))
        assert "price_per_step" not in rendered

    def test_markup_must_be_positive_when_deriving(self):
        with pytest.raises(ValueError, match="markup"):
            _build_tollgate_ops({
                "upstream_usd_per_gb": 1.0, "markup": 0.0, "fx_sats_per_usd": 2500,
            })
