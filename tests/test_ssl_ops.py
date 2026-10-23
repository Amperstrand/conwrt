"""ssl use-case tests: build smoke, branch flags, and the provider gate.

The provider gate is a 1.x security fix landed with the Rust ssl port
(2026-10-23): ssl.py declared `choices=("lancert","qip","manual")` on the
provider ParamDef but `_resolve_params` never enforced it — and the value
was interpolated into a rendered comment line, where a newline injected
live shell. The Rust twin applies the same choice gate
(`SslProfile::validate`, plan.rs).
"""

from __future__ import annotations

import pytest

from use_cases import registry


def _ssl():
    return registry()["ssl"]


def test_default_build_smoke():
    script = _ssl().build_configure({})
    assert "uci set uhttpd.main.cert='/etc/tollgate/ssl/server.crt'" in script
    assert "uci set uhttpd.main.key='/etc/tollgate/ssl/server.key'" in script
    assert "uci add_list uhttpd.main.listen_https='0.0.0.0:443'" in script
    assert "uci commit uhttpd" in script
    assert "/etc/init.d/uhttpd restart" in script
    assert "users_to_router='allow tcp port 443'" in script


@pytest.mark.parametrize(
    "hostile",
    ["lancert\nreboot", "qip; poweroff", "$(reboot)", "", "letsencrypt"],
)
def test_provider_gate_rejects_non_choices(hostile):
    with pytest.raises(ValueError, match="must be one of"):
        _ssl().build_configure({"provider": hostile})


@pytest.mark.parametrize("provider", ["lancert", "qip", "manual"])
def test_valid_providers_pass(provider):
    script = _ssl().build_configure({"provider": provider})
    assert f"via {provider} ---" in script


def test_uhttpd_branch_off_drops_https_block_only():
    script = _ssl().build_configure({"enable_uhttpd_https": False})
    assert "uhttpd" not in script
    assert "nodogsplash" in script


def test_nds_branch_off_drops_nodogsplash_line_only():
    script = _ssl().build_configure({"open_port_443_nds": False})
    assert "uci commit uhttpd" in script
    assert "/etc/init.d/uhttpd restart" in script
    assert "nodogsplash" not in script
