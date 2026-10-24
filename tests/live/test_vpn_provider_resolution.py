"""Provider-resolution → op-build e2e tests — parameterized, credential-gated.

Complements ``test_vpn_live_apis.py`` (endpoint JSON contracts): this
module runs the actual BUILDERS end-to-end with real credentials and
asserts the full generated payload is valid, deployable shell — plus,
for build-time resolvers, that the RESOLVED values feed cleanly into
the Rust 2.x planner CLI (the cross-language §4 boundary).

Two provider classes, per the credential matrix:

* **Build-time resolvers** (the host fetches everything; the device
  gets a static config): the NordVPN family. With a token these tests
  resolve REAL credentials + endpoints and build the real payload.
* **Runtime-API scripts** (the generated script curls the provider
  from the device): PIA WireGuard, PIA OpenVPN, Mullvad, IVPN,
  Surfshark. Build-time testing needs only the credential SHAPE —
  these render with whatever credentials are provided and validate the
  payload; device-side live runs additionally need a bench router.

Parameterized and env-driven so any runner (prta scenario harness,
cron, a bare ``pytest`` invocation) can execute them without opencode:

============  ==========================  ==================================
Provider      Env vars                    Unlocks
============  ==========================  ==================================
vpn-nordvpn   CONWRT_LIVE_NORDVPN_TOKEN   real NordLynx resolution + payload
(+ openvpn)                               + Rust planner hand-off
vpn-pia       CONWRT_LIVE_PIA_USER/PASS   real payload render (runtime API)
vpn-pia-      CONWRT_LIVE_PIA_USER/PASS   real p-number rendering checks
  openvpn
vpn-mullvad   CONWRT_LIVE_MULLVAD_TOKEN   real payload render (runtime API)
vpn-ivpn      CONWRT_LIVE_IVPN_ACCOUNT    real payload render (runtime API)
vpn-surfshark CONWRT_LIVE_SURFSHARK_USER/PASS  real payload render
============  ==========================  ==================================

Without a provider's credentials its tests SKIP with the env var
named — set the vars later and rerun; nothing else changes. Secrets
come from the environment ONLY (never config.toml, never committed).
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from profile.apply import _CONTROL_FLOW_RE, _HEREDOC_RE, _MULTI_LINE_BLOCK_RE, _shell_lines_without_comments
from profile.ops import render_shell
from use_cases import registry
from use_cases.vpn_providers import nordvpn as nv

pytestmark = pytest.mark.live

REPO_ROOT = Path(__file__).resolve().parents[2]


def _transport_payload(script: str) -> str:
    """The exact payload ``_run_step_script`` would send for this script."""
    if _HEREDOC_RE.search(script):
        return "set -e\n" + script.strip() + "\n"
    if _CONTROL_FLOW_RE.search(script):
        if _MULTI_LINE_BLOCK_RE.search(script):
            return "set -e\n" + script.strip() + "\n"
        return " && ".join(_shell_lines_without_comments(script)) + "\n"
    return " && ".join(_shell_lines_without_comments(script))


def _assert_deployable(script: str, label: str) -> None:
    """Full payload is valid shell through BOTH transport forms."""
    for name, payload in (("verbatim", script), ("transported", _transport_payload(script))):
        r = subprocess.run(["sh", "-n"], input=payload, capture_output=True, text=True)
        assert r.returncode == 0, f"{label} [{name}] not valid shell: {r.stderr}"


def _env(*names: str) -> dict[str, str]:
    return {n.split("=")[0]: v for n in names for v in [os.environ.get(n)] if v}  # noqa: SIM118


# ---------------------------------------------------------------- NordVPN
# The build-time resolver family: a token unlocks REAL resolution and,
# through the same values, the Rust §4 planner hand-off.

NORD_TOKEN = os.environ.get("CONWRT_LIVE_NORDVPN_TOKEN", "")


@pytest.mark.skipif(not NORD_TOKEN, reason="set CONWRT_LIVE_NORDVPN_TOKEN to run real NordLynx resolution")
class TestNordvpnBuildTimeResolution:
    """Real token → real credentials/endpoint → real payload → Rust planner.

    These exercise the exact host-side flow 1.x performs for a flash
    build, then prove the §4 boundary: the resolved statics plan and
    render cleanly through the Rust CLI.
    """

    def test_resolve_and_build_nordlynx(self):
        import base64

        basic = base64.b64encode(f"token:{NORD_TOKEN}".encode()).decode()
        creds = nv._fetch_credentials(basic)
        priv = creds["nordlynx_private_key"]
        assert priv and "=" in priv or len(priv) >= 40, f"unexpected key shape: {priv!r}"

        # pin the resolution the builder will use: the recommendations
        # API may return a DIFFERENT server on each call (Codex #529),
        # so resolve once and freeze it for the build via monkeypatching
        resolved = nv._resolve_endpoint("DE", NORD_TOKEN)
        host, port, pub = resolved
        assert host and port and pub, f"endpoint resolution failed: {host} {port} {pub!r}"

        original = nv._resolve_endpoint
        nv._resolve_endpoint = lambda *a, **k: resolved
        try:
            script = registry()["vpn-nordvpn"].build_configure({
                "access_token": NORD_TOKEN, "server": "DE",
            })
        finally:
            nv._resolve_endpoint = original
        _assert_deployable(script, "vpn-nordvpn(nordlynx)")
        # the resolved values actually landed in the payload
        assert priv in script and pub in script and host in script

    def test_resolved_statics_feed_the_rust_planner(self):
        """The §4 boundary: resolved values → `conwrt plan` renders a plan.

        Dry-run only — no device, no mutation.
        """
        import base64
        import tempfile

        basic = base64.b64encode(f"token:{NORD_TOKEN}".encode()).decode()
        priv = nv._fetch_credentials(basic)["nordlynx_private_key"]
        host, port, pub = nv._resolve_endpoint("DE", NORD_TOKEN)
        route_ip = host if all(p.isdigit() for p in host.split(".")) and len(host.split(".")) == 4 else nv._route_target(host, NORD_TOKEN)

        r = subprocess.run(
            ["cargo", "run", "--quiet", "-p", "conwrt-cli", "--", "plan",
             "--profile", "vpn-nordvpn",
             "--model-id", "dlink-covr-x1860-a1",
             "--nord-private-key", priv,
             "--nord-server-public-key", pub,
             "--nord-endpoint-host", host,
             "--nord-route-target", route_ip],
            capture_output=True, text=True, timeout=600,
            cwd=str(REPO_ROOT),
        )
        assert r.returncode == 0, f"rust planner refused real statics: {r.stderr[-400:]}"
        assert "vpn-nordvpn" in r.stdout
        assert "wireguard" in r.stdout
        # secrets never echo into the plan output header lines
        assert priv not in r.stdout.split("\n")[0]

    def test_resolve_and_build_openvpn_variant(self):
        """Service credentials + server resolved for real, payload built,
        and the SAME resolved statics feed the Rust planner CLI."""
        import base64

        basic = base64.b64encode(f"token:{NORD_TOKEN}".encode()).decode()
        creds = nv._fetch_credentials(basic)
        srv = nv._resolve_server("DE", NORD_TOKEN, nv.NORDVPN_TECH_IDS["openvpn-udp"])
        user, pw = creds["username"], creds["password"]
        station, hostname = srv["station"], srv["hostname"]
        assert user and pw and station and hostname, "incomplete resolution"

        original_srv, original_creds = nv._resolve_server, nv._fetch_credentials
        nv._resolve_server = lambda *a, **k: srv
        nv._fetch_credentials = lambda *a, **k: creds
        try:
            script = registry()["vpn-nordvpn-openvpn"].build_configure({
                "access_token": NORD_TOKEN, "server": "DE",
                "technology": "openvpn-udp",
            })
        finally:
            nv._resolve_server, nv._fetch_credentials = original_srv, original_creds
        assert script.strip(), "openvpn variant produced no script"
        _assert_deployable(script, "vpn-nordvpn-openvpn")
        assert user in script and station in script and hostname in script

        r = subprocess.run(
            ["cargo", "run", "--quiet", "-p", "conwrt-cli", "--", "plan",
             "--profile", "vpn-nordvpn-openvpn",
             "--model-id", "dlink-covr-x1860-a1",
             "--nordovpn-username", user,
             "--nordovpn-password", pw,
             "--nordovpn-station", station,
             "--nordovpn-hostname", hostname],
            capture_output=True, text=True, timeout=600,
            cwd=str(REPO_ROOT),
        )
        assert r.returncode == 0, f"rust planner refused real statics: {r.stderr[-400:]}"
        assert "openvpn" in r.stdout


# ------------------------------------------------------- Runtime-API tier
# The generated script talks to the provider from the device; build time
# only needs the credential shape. Parameterized: one row per provider,
# each skipping with its env var named until credentials exist.

RUNTIME_PROVIDERS = [
    pytest.param(
        "vpn-pia",
        ("CONWRT_LIVE_PIA_USER", "CONWRT_LIVE_PIA_PASS"),
        {"username": None, "password": None, "region": "netherlands",
         "upstream_gateway": "192.168.1.1"},
        id="pia-wireguard",
    ),
    pytest.param(
        "vpn-pia-openvpn",
        ("CONWRT_LIVE_PIA_USER", "CONWRT_LIVE_PIA_PASS"),
        {"username": None, "password": None, "upstream_gateway": "192.168.8.1"},
        id="pia-openvpn",
    ),
    pytest.param(
        "vpn-mullvad",
        ("CONWRT_LIVE_MULLVAD_TOKEN",),
        {"account_token": None, "country": "se", "upstream_gateway": "192.168.1.1"},
        id="mullvad",
    ),
    pytest.param(
        "vpn-ivpn",
        ("CONWRT_LIVE_IVPN_ACCOUNT",),
        {"account_id": None, "upstream_gateway": "192.168.1.1"},
        id="ivpn",
    ),
    pytest.param(
        "vpn-surfshark",
        ("CONWRT_LIVE_SURFSHARK_USER", "CONWRT_LIVE_SURFSHARK_PASS"),
        {"username": None, "password": None, "upstream_gateway": "192.168.1.1"},
        id="surfshark",
    ),
]


@pytest.mark.parametrize("preset,env_names,params", RUNTIME_PROVIDERS)
def test_runtime_api_payload_with_real_credentials(preset, env_names, params):
    missing = [n for n in env_names if not os.environ.get(n)]
    if missing:
        pytest.skip(f"set {'+'.join(missing)} to render {preset} with real credentials")
    # params with a None value fill from the provider's env vars, in order
    env_cycle = iter(env_names)
    resolved = {
        key: (os.environ.get(next(env_cycle)) if value is None else value)
        for key, value in params.items()
    }
    script = registry()[preset].build_configure(resolved)
    assert script.strip(), f"{preset}: unconfigured stub — credentials did not take"
    _assert_deployable(script, preset)
    # the credential must survive the transport verbatim (quoted heredoc)
    cred_keys = ("username", "password", "account_token", "account_id")
    first_cred = next(v for k, v in resolved.items() if k in cred_keys and v)
    assert first_cred in script, f"{preset}: credential not embedded in payload"
