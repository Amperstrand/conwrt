"""Tollgate payment E2E — pay → access on the conwrt VM (issue #41).

Upgraded from the original fakewallet blueprint to SIGNET: we now have a
signet Cashu mint (cashu-cf `cashu-mint-signet`, CoreLightning backend via
clnrest+rune) and a signet CLN node. Signet carries no monetary value but is
a real Lightning network — more realistic than FakeWallet, and drained-test-
funds are merely annoying, not costly.

Two-layer design (mirrors test_wizard_recipes.py):

  Router side (session VM): build tollgate-wrt for linux/amd64, install +
  configure nodogsplash + tollgate pointing at the mint, start the backend.
  Host side: mint real signet ecash (NUT-04 quote → bolt11 → CLN ``xpay`` via
  signet_cln.py → tokens via the ``cashu`` CLI), then pay the router and
  assert access is granted.

Everything is env-gated so the default suite (and CI) skips cleanly:

  CONWRT_TOLLGATE_MINT_URL   mint the router accepts (signet mint URL)
  CONWRT_CLNREST_URL         signet CLN clnrest endpoint (https://host:port)
  CONWRT_CLNREST_RUNE        restricted rune (see signet_cln.py docstring:
                             method/xpay + method/listpays + method/getinfo,
                             rate-limited — NEVER the master rune)
  CONWRT_CASHU_BIN           nutshell CLI path (default: `cashu` on PATH)

Operator checklist to enable (see also signet_cln.py):
  1. cashu-mint-signet URL (cashu-cf repo, wrangler signet env)
  2. On the signet CLN node:
       lightning-cli createrune null \\
         '[["method/xpay"],["method/listpays"],["method/getinfo"],
           ["rate",3,"once"]]'
  3. Store creds in ~/.config/conwrt/signet-cln.json (gitignored location,
     outside the repo) or export the env vars.
  4. pip install cashu (nutshell) somewhere on PATH as `cashu`

Done when: one green test proving pay → access on the VM against the signet
mint, with the CLN leg settled by xpay (issue #41, signet upgrade).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from signet_cln import credentials_available, xpay

pytestmark = [pytest.mark.hardware]

REPO_ROOT = Path(__file__).resolve().parents[2]
TOLLGATE_DIR = REPO_ROOT / "tests" / "integration" / ".tollgate"
TOLLGATE_REPO = os.environ.get(
    "CONWRT_TOLLGATE_REPO", "https://github.com/OpenTollGate/tollgate-module-basic-go.git")
TOLLGATE_REF = os.environ.get("CONWRT_TOLLGATE_REF", "main")

MINT_URL = os.environ.get("CONWRT_TOLLGATE_MINT_URL", "")
CASHU_BIN = os.environ.get("CONWRT_CASHU_BIN", "cashu")

PAYMENT_SATS = 21

if not MINT_URL:
    pytest.skip("CONWRT_TOLLGATE_MINT_URL not set — see module docstring for the "
                "signet mint + CLN rune checklist", allow_module_level=True)


def _ssh(vm, command, timeout=60):
    r = subprocess.run(
        ["ssh",
         "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null",
         "-o", "ConnectTimeout=5",
         "-i", vm["key"],
         "-p", str(vm["port"]),
         f"root@{vm['host']}", command],
        capture_output=True, text=True, timeout=timeout,
    )
    return r


def _router_ip(vm):
    return _ssh(vm, "ip -4 addr show dev eth0 | grep -oE 'inet [0-9.]+' | head -1"
                ).stdout.replace("inet", "").strip()


def _router_port_reachable(vm, port, seconds=30):
    ip = _router_ip(vm)
    for _ in range(seconds // 2):
        r = _ssh(vm, f"netstat -tln 2>/dev/null | grep -q ':{port} ' && echo up || echo down")
        if "up" in r.stdout:
            return ip
        time.sleep(2)
    return None


def _build_tollgate_wrt() -> Path:
    """Cross-compile tollgate-wrt for linux/amd64 (cached by repo+ref)."""
    binary = TOLLGATE_DIR / TOLLGATE_REF / "tollgate-wrt"
    if binary.exists():
        return binary
    go = shutil.which("go") or "/usr/local/go/bin/go"
    if not Path(go).exists():
        pytest.skip("Go toolchain not available to build tollgate-wrt")
    src = TOLLGATE_DIR / f"src-{TOLLGATE_REF}"
    if not (src / ".git").exists():
        subprocess.run(["git", "clone", "--depth", "1", "--branch", TOLLGATE_REF,
                        TOLLGATE_REPO, str(src)], check=True, capture_output=True)
    binary.parent.mkdir(parents=True, exist_ok=True)
    ldflags = (f"-s -w -X 'github.com/OpenTollGate/tollgate-module-basic-go/"
               f"src/cli.Version=conwrt-e2e'")
    subprocess.run(
        [go, "build", "-C", str(src / "src"), "-o", str(binary),
         "-trimpath", f"-ldflags={ldflags}", "main.go"],
        check=True, capture_output=True, timeout=600,
    )
    return binary


def _install_router_side(vm):
    """nodogsplash + tollgate-wrt + config.json on the VM."""
    r = _ssh(vm, "opkg update >/dev/null 2>&1 && opkg install nodogsplash >/dev/null 2>&1 "
                 "&& echo ok || echo no-opkg", timeout=120)
    if "no-opkg" in r.stdout:
        pytest.skip("VM cannot reach opkg repos — extend PREBAKE_PACKAGES with "
                    "nodogsplash and re-prepare the image (see conftest.py)")
    binary = _build_tollgate_wrt()
    subprocess.run(
        ["scp", "-O", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         "-i", vm["key"], "-P", str(vm["port"]), str(binary),
         f"root@{vm['host']}:/usr/bin/tollgate-wrt"],
        check=True, capture_output=True, timeout=120,
    )
    config = {
        "config_version": "v0.0.7",
        "log_level": "info",
        "accepted_mints": [{
            "url": MINT_URL,
            "min_balance": 0,
            "balance_tolerance_percent": 0,
            "payout_interval_seconds": 999999,
            "min_payout_amount": 999999,
            "price_per_step": 1,
            "price_unit": "sats",
            "purchase_min_steps": 0,
        }],
        "profit_share": [
            {"factor": 0.79, "identity": "owner"},
            {"factor": 0.21, "identity": "developer"},
        ],
        "step_size": 22020096,
        "margin": 0.1,
        "metric": "bytes",
        "show_setup": True,
        "reseller_mode": False,
        "auth_delay_seconds": 0,
    }
    _ssh(vm, "mkdir -p /etc/tollgate")
    subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         "-i", vm["key"], "-p", str(vm["port"]), f"root@{vm['host']}",
         "cat > /etc/tollgate/config.json"],
        input=json.dumps(config), text=True, capture_output=True, timeout=30, check=True,
    )
    _ssh(vm, (
        "uci set nodogsplash.@nodogsplash[0].enabled='1'; "
        "uci set nodogsplash.@nodogsplash[0].gatewayname='TollGate E2E'; "
        "uci add_list nodogsplash.@nodogsplash[0].users_to_router='allow tcp port 2121'; "
        "uci add_list nodogsplash.@nodogsplash[0].users_to_router='allow tcp port 2050'; "
        "uci commit nodogsplash; "
        "/etc/init.d/nodogsplash restart 2>/dev/null; "
        "pkill -f tollgate-wrt 2>/dev/null; "
        "(/usr/bin/tollgate-wrt --config /etc/tollgate/config.json "
        "> /tmp/tollgate.log 2>&1 &) ; sleep 3"
    ), timeout=60)
    ip = _router_port_reachable(vm, 2121)
    assert ip, f"tollgate-wrt did not listen on :2121 — /tmp/tollgate.log says: " \
               f"{_ssh(vm, 'tail -5 /tmp/tollgate.log').stdout}"
    return ip


def _mint_signet_tokens(amount_sats: int) -> str:
    """NUT-04 quote → pay bolt11 via signet CLN xpay → mint tokens.

    Returns a Cashu token string ready to hand to the router.
    """
    env = {**os.environ}
    r = subprocess.run(
        [CASHU_BIN, "-h", MINT_URL, "--json", "invoice", str(amount_sats)],
        capture_output=True, text=True, timeout=60, env=env,
    )
    if r.returncode != 0:
        pytest.fail(f"cashu invoice failed (is the mint reachable?): {r.stderr[:300]}")
    out = _parse_jsonish(r.stdout)
    bolt11 = out.get("bolt11") or out.get("payment_request") or out.get("invoice")
    quote_id = out.get("quote") or out.get("quote_id") or out.get("id")
    assert bolt11 and quote_id, f"unexpected cashu invoice output: {r.stdout[:300]}"

    result = xpay(bolt11, maxfee_msat=2100)
    assert result.get("ok"), f"CLN xpay failed: {result}"

    r = subprocess.run(
        [CASHU_BIN, "-h", MINT_URL, "--json", "invoice", str(quote_id)],
        capture_output=True, text=True, timeout=120, env=env,
    )
    assert r.returncode == 0, f"cashu mint (invoice poll) failed: {r.stderr[:300]}"
    token = _extract_token(r.stdout) or _extract_token(_wallet_balance_token())
    assert token, f"no token after minting: {r.stdout[:300]}"
    return token


def _wallet_balance_token() -> str:
    r = subprocess.run(
        [CASHU_BIN, "-h", MINT_URL, "--json", "balance"],
        capture_output=True, text=True, timeout=60,
    )
    return r.stdout


def _parse_jsonish(text: str) -> dict:
    try:
        start = text.index("{")
        end = text.rindex("}") + 1
        return json.loads(text[start:end])
    except (ValueError, json.JSONDecodeError):
        return {}


def _extract_token(text: str) -> str:
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("cashuA") or line.startswith("cashuB"):
            return line
    if '"token"' in text:
        parsed = _parse_jsonish(text)
        return parsed.get("token", "")
    return ""


class TestTollgatePaymentSignet:
    def test_pay_token_grants_access(self, openwrt_vm):
        if not MINT_URL:
            pytest.skip("CONWRT_TOLLGATE_MINT_URL not set (signet mint URL)")
        if not credentials_available():
            pytest.skip("signet CLN credentials not configured (see signet_cln.py)")
        if shutil.which(CASHU_BIN) is None:
            pytest.skip(f"nutshell CLI ({CASHU_BIN}) not on PATH — pip install cashu")

        router_ip = _install_router_side(openwrt_vm)
        token = _mint_signet_tokens(PAYMENT_SATS)

        r = subprocess.run(
            ["curl", "-sf", "--max-time", "20",
             "-X", "POST", f"http://{router_ip}:2121/pay",
             "-H", "Content-Type: application/json",
             "-d", json.dumps({"token": token})],
            capture_output=True, text=True, timeout=30,
        )
        assert r.returncode == 0, f"tollgate /pay rejected the token: {r.stderr[:200]}"

        for _ in range(15):
            nds = _ssh(openwrt_vm, "ndsctl json 2>/dev/null").stdout
            try:
                clients = json.loads(nds).get("clients", {})
            except ValueError:
                clients = {}
            if any(c.get("state") in ("Authenticated", "authed")
                   for c in clients.values()):
                return
            time.sleep(2)
        pytest.fail(f"no authenticated NDS client after payment — ndsctl: {nds[:300]}")
