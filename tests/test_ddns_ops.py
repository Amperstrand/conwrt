"""Characterization tests for ddns.py ops pipeline (#5).

render_shell(_build_ddns_ops(...)) is the authoritative output. If ops
change, these tests must be updated to match.
"""
import pytest

from profile.ops import render_shell
from use_cases import get as get_use_case
from use_cases.ddns import _build_ddns_ops


DEFAULT_PARAMS = {"domain": "home.example.org", "password": "tok123"}

EXPECTED_DEFAULT = (
    "# --- Dynamic DNS (cloudflare) ---\n"
    "uci -q delete ddns.myddns >/dev/null 2>&1 || true\n"
    "uci set ddns.myddns=service\n"
    "uci set ddns.myddns.enabled='1'\n"
    "uci set ddns.myddns.domain='home.example.org'\n"
    "uci set ddns.myddns.username=''\n"
    "uci set ddns.myddns.password='tok123'\n"
    "uci set ddns.myddns.use_https='1'\n"
    "uci set ddns.myddns.lookup_host='home.example.org'\n"
    "uci set ddns.myddns.check_interval='300'\n"
    "uci set ddns.myddns.check_unit='seconds'\n"
    "uci set ddns.myddns.force_interval='2592000'\n"
    "uci set ddns.myddns.force_unit='seconds'\n"
    "uci set ddns.myddns.service_name='cloudflare.com/v4'\n"
    "uci commit ddns\n"
    "/etc/init.d/ddns enable\n"
    "/etc/init.d/ddns restart"
)


class TestDdnsOps:
    def test_default_params(self):
        assert render_shell(_build_ddns_ops(DEFAULT_PARAMS)) == EXPECTED_DEFAULT

    def test_custom_provider_takes_update_url(self):
        rendered = render_shell(_build_ddns_ops({
            "provider": "custom", "domain": "a.io", "username": "u",
            "password": "p", "update_url": "https://upd.example.com/nic/update?hostname=",
        }))
        assert "ddns.myddns.update_url='https://upd.example.com/nic/update?hostname='" in rendered
        assert "service_name" not in rendered

    def test_staging_debris_guard_leads(self):
        rendered = render_shell(_build_ddns_ops(DEFAULT_PARAMS))
        assert rendered.index("uci -q delete ddns.myddns") < rendered.index(
            "uci set ddns.myddns.enabled"
        )

    @pytest.mark.parametrize("field", ["domain", "password"])
    @pytest.mark.parametrize("hostile", ["with space", "semi;colon", "quo'te", "in$(j)ect"])
    def test_injection_is_rejected(self, field, hostile):
        params = dict(DEFAULT_PARAMS)
        params[field] = hostile
        with pytest.raises(ValueError):
            _build_ddns_ops(params)

    @pytest.mark.parametrize("interval", ["check_interval", "force_interval"])
    def test_interval_floor(self, interval):
        params = dict(DEFAULT_PARAMS)
        params[interval] = 5
        with pytest.raises(ValueError):
            _build_ddns_ops(params)

    def test_unknown_provider_rejected(self):
        with pytest.raises(ValueError):
            _build_ddns_ops(dict(DEFAULT_PARAMS, provider="nope"))

    def test_registry_shape(self):
        uc = get_use_case("ddns")
        assert uc is not None
        assert uc.packages == ["ddns-scripts", "luci-app-ddns", "curl", "ca-certificates"]
        assert uc.params["domain"].required
