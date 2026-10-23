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
    assert "uci add_list uhttpd.main.listen_https='[::]:443'" in script
    assert "uci commit uhttpd" in script
    assert "/etc/init.d/uhttpd restart" in script
    assert "users_to_router='allow tcp port 443'" in script


def test_listen_https_reset_is_idempotent():
    """Regression (Codex #486 round 1): the old &&-chained reset silently
    no-opped when listen_https was absent — `uci -q delete` exits
    nonzero on a missing option, so the chain stopped and neither
    listener was added. The reset must delete guarded, then add both."""
    script = _ssl().build_configure({})
    assert "uci -q delete uhttpd.main.listen_https || true" in script
    assert "listen_https &&" not in script


def test_uhttpd_wiring_guards_on_certs_present():
    """Regression (Codex #486 round 2): pointing uhttpd at cert files
    that do not exist yet (they land post-flash via
    deploy_ssl_post_flash) makes uhttpd drop the HTTPS listener or
    exit — the wiring must be guarded on both files existing, with a
    loud skip message otherwise."""
    script = _ssl().build_configure({})
    assert (
        "if [ -f /etc/tollgate/ssl/server.crt ] && "
        "[ -f /etc/tollgate/ssl/server.key ]; then" in script
    )
    assert "certs not present yet" in script


def test_nodogsplash_branch_propagates_failures():
    """Regression (Codex #486 round 2): the old trailing `|| true`
    masked real failures (missing section, failed commit/restart) as
    success. The branch must be an explicit existence guard whose body
    propagates errors."""
    script = _ssl().build_configure({})
    assert "if uci -q show nodogsplash >/dev/null 2>&1; then" in script
    assert "nodogsplash restart || true" not in script


def test_nodogsplash_allow_entry_is_reapply_idempotent():
    """Regression (Codex #486 round 4): uci lists are append-only — a
    bare add_list accumulates a duplicate 'allow tcp port 443' entry
    on every re-run. The exact value must be deleted (guarded) before
    it is added."""
    script = _ssl().build_configure({})
    assert (
        "uci -q del_list nodogsplash.@nodogsplash[0].users_to_router="
        "'allow tcp port 443' || true" in script
    )
    add = script.count(
        "uci add_list nodogsplash.@nodogsplash[0].users_to_router='allow tcp port 443'"
    )
    assert add == 1


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
