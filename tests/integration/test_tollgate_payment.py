"""Tollgate payment E2E — pay → access on the conwrt VM (issue #41).

Signet edition: a REAL Cashu mint (cdk-signet-pilot on inr2.cashu.exchange,
CoreLightning backend) and a REAL signet Lightning payment via ``xpay`` — no
fakewallet, no monetary value. The full loop proven by this test:

    NUT-04 mint quote → bolt11 → CLN xpay (restricted rune, tunnel to inr2)
    → ecash token → POST to tollgate-wrt on the VM → proofs swapped at the
    mint → nodogsplash gate opens → client Authenticated (session event 1022)

Router side (session VM): tollgate-wrt built from source for linux/amd64
(CGO_ENABLED=0 — OpenWrt is musl), nodogsplash via opkg, a br-lan bridge, and
a synthetic client (veth pair in a netns) that hits the portal so NDS has a
client session to authorize — the same preauth state a real phone would have.

Host side: nutshell CLI mints the token (fresh wallet per run — the mint
rotates keysets and a stale cached keyset makes the mint reject blind
signatures with 12001); the token's embedded mint URL is rewritten from the
host's view (127.0.0.1:8190, via SSH tunnel) to the router's view
(10.0.2.2:8190, via slirp) — the URL is unsigned metadata.

Everything is env-gated; without credentials the module skips in milliseconds:

  CONWRT_TOLLGATE_ENABLED=1  master switch
  CONWRT_CLNREST_URL/RUNE    or ~/.config/conwrt/signet-cln.json (see
                             signet_cln.py for the restricted-rune recipe:
                             xpay/listpays/getinfo only, rate-limited)
  CONWRT_TOLLGATE_SSH_HOST   SSH to the signet lab (default
                             root@inr2.cashu.exchange) — tunnels mint :8190
                             and clnrest :3011 to host loopback
  CONWRT_CASHU_BIN           nutshell CLI (default:
                             tests/integration/.venv-cashu/bin/cashu)
  CONWRT_TOLLGATE_REF        tollgate-module-basic-go git ref (default main)
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

import pytest

from signet_cln import credentials_available, xpay

pytestmark = [pytest.mark.hardware]

REPO_ROOT = Path(__file__).resolve().parents[2]
TOLLGATE_DIR = REPO_ROOT / "tests" / "integration" / ".tollgate"
TOLLGATE_REPO = os.environ.get(
    "CONWRT_TOLLGATE_REPO", "https://github.com/OpenTollGate/tollgate-module-basic-go.git")
TOLLGATE_REF = os.environ.get("CONWRT_TOLLGATE_REF", "main")
CDK_GO_PIN = os.environ.get("CONWRT_CDK_GO_PIN", "v0.18.0-rc.3")

MINT_HOST_VIEW = os.environ.get("CONWRT_TOLLGATE_MINT_URL", "http://127.0.0.1:8190")
MINT_ROUTER_VIEW = os.environ.get("CONWRT_TOLLGATE_MINT_URL_VM", "http://10.0.2.2:8190")
CASHU_BIN = os.environ.get(
    "CONWRT_CASHU_BIN", str(REPO_ROOT / "tests/integration/.venv-cashu/bin/cashu"))

CLIENT_MAC = "52:54:00:aa:bb:cc"
CLIENT_IP = "10.0.2.99"
PAYMENT_SATS = 4
LAB_SSH = os.environ.get("CONWRT_TOLLGATE_SSH_HOST", "root@inr2.cashu.exchange")
MINT_LAB_PORT = os.environ.get("CONWRT_TOLLGATE_MINT_PORT", "8190")
CLNREST_LAB_PORT = os.environ.get("CONWRT_TOLLGATE_CLNREST_PORT", "3011")


def _restore_vm(vm):
    """Undo every mutation so later tests in the session see a pristine VM:
    network back to eth0-as-LAN, bridge/netns/veth/tollgate/NDS removed."""
    _ssh(vm, (
        "kill $(pidof tollgate-wrt) 2>/dev/null; "
        "/etc/init.d/nodogsplash stop 2>/dev/null; "
        "ip netns del client 2>/dev/null; "
        "for i in $(seq 0 9); do "
        "n=$(uci -q get network.@device[$i].name 2>/dev/null) || break; "
        "[ \"$n\" = 'br-lan' ] && { uci del network.@device[$i]; break; }; done; "
        "uci set network.lan.device='eth0'; "
        "uci -q delete nodogsplash.@nodogsplash[0].gatewayname; "
        "uci commit network; uci commit nodogsplash 2>/dev/null; "
        "rm -rf /etc/tollgate /usr/bin/tollgate-wrt /tmp/token.txt; "
        "(/etc/init.d/network restart >/dev/null 2>&1 &)"
    ), timeout=60)
    for _ in range(15):
        if _ssh(vm, "ip -4 addr show dev eth0 | grep -q inet && echo ok",
                timeout=10).stdout.strip() == "ok":
            return
        time.sleep(3)


@pytest.fixture(scope="module")
def lab_tunnel():
    """Reach the loopback-only signet services: reuse a working tunnel or
    open our own SSH port-forward to the lab (mint :8190, clnrest :3011)."""
    def reachable():
        try:
            with urllib.request.urlopen(MINT_HOST_VIEW + "/v1/info", timeout=3) as r:
                return r.status == 200
        except Exception:
            return False

    if reachable():
        yield None
        return
    proc = subprocess.Popen(
        ["ssh", "-N", "-o", "StrictHostKeyChecking=accept-new",
         "-o", "ServerAliveInterval=15", "-o", "ExitOnForwardFailure=yes",
         "-L", f"127.0.0.1:{MINT_LAB_PORT}:127.0.0.1:{MINT_LAB_PORT}",
         "-L", f"127.0.0.1:{CLNREST_LAB_PORT}:127.0.0.1:{CLNREST_LAB_PORT}",
         LAB_SSH],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(10):
        if reachable():
            break
        time.sleep(1)
    if not reachable():
        proc.terminate()
        pytest.skip("could not reach the signet lab through an SSH tunnel")
    yield proc
    proc.terminate()


def _env_ready() -> bool:
    if not os.environ.get("CONWRT_TOLLGATE_ENABLED"):
        return False
    if not credentials_available():
        return False
    return Path(CASHU_BIN).exists()


if not _env_ready():
    pytest.skip(
        "tollgate signet E2E not enabled: set CONWRT_TOLLGATE_ENABLED=1 plus "
        "signet CLN credentials (see signet_cln.py) and a nutshell install "
        "(tests/integration/.venv-cashu)", allow_module_level=True)


def _ssh(vm, command, timeout=60):
    return subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         "-o", "ConnectTimeout=5", "-i", vm["key"], "-p", str(vm["port"]),
         f"root@{vm['host']}", command],
        capture_output=True, text=True, timeout=timeout,
    )


def _build_tollgate_wrt() -> Path:
    """Clone (cached) + pin cdk-go + static musl-safe amd64 build."""
    go = shutil.which("go") or "/usr/local/go/bin/go"
    if not Path(go).exists():
        pytest.skip("Go toolchain not available to build tollgate-wrt")
    binary = TOLLGATE_DIR / TOLLGATE_REF / "tollgate-wrt"
    if binary.exists():
        return binary
    src = TOLLGATE_DIR / f"src-{TOLLGATE_REF}"
    if not (src / ".git").exists():
        subprocess.run(["git", "clone", "--depth", "5", "--branch", TOLLGATE_REF,
                        TOLLGATE_REPO, str(src)], check=True, capture_output=True)
    env = {**os.environ, "PATH": f"{Path(go).parent}:{os.environ['PATH']}",
           "CGO_ENABLED": "0"}
    subprocess.run([go, "get", "-C", str(src / "src"),
                    f"github.com/cashubtc/cdk-go@{CDK_GO_PIN}"],
                   check=True, capture_output=True, timeout=300, env=env)
    binary.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [go, "build", "-C", str(src / "src"),
         "-o", str(binary), "-trimpath", "main.go"],
        check=True, capture_output=True, timeout=900, env=env,
    )
    assert "statically linked" in subprocess.run(
        ["file", str(binary)], capture_output=True, text=True).stdout, (
        "tollgate-wrt must be statically linked (OpenWrt is musl)")
    return binary


def _setup_router(vm):
    """nodogsplash + br-lan bridge + tollgate-wrt on the session VM."""
    binary = _build_tollgate_wrt()
    r = _ssh(vm, (
        "opkg update >/dev/null 2>&1; "
        "opkg install nodogsplash kmod-veth ip-full >/dev/null 2>&1; "
        "opkg list-installed | grep -q nodogsplash && "
        "opkg list-installed | grep -q ip-full && "
        "opkg list-installed | grep -q kmod-veth && echo nds-ok || echo nds-missing"
    ), timeout=300)
    if "nds-ok" not in r.stdout:
        pytest.skip("VM cannot install nodogsplash via opkg — add it to "
                    "PREBAKE_PACKAGES and re-prepare the image (conftest.py)")

    # Bridge eth0 into br-lan (NDS needs a gateway interface). The DHCP lease
    # moves with the MAC, so the SSH session recovers after the restart.
    _ssh(vm, (
        "uci -q get network.lan.device >/dev/null 2>&1 && "
        "[ \"$(uci -q get network.lan.device)\" = 'br-lan' ] || { "
        "uci add network device; uci set network.@device[-1].name='br-lan'; "
        "uci set network.@device[-1].type='bridge'; "
        "uci add_list network.@device[-1].ports='eth0'; "
        "uci set network.lan.device='br-lan'; uci commit network; "
        "(/etc/init.d/network restart >/dev/null 2>&1 &); }; "
        "sleep 8; ip link show br-lan >/dev/null 2>&1 && echo br-lan-ok || echo br-lan-missing"
    ), timeout=120)
    for _ in range(10):
        if "br-lan-ok" in _ssh(vm, "ip link show br-lan >/dev/null 2>&1 && echo br-lan-ok").stdout:
            break
        time.sleep(3)
    else:
        pytest.fail("br-lan did not come up after the bridge migration")

    _ssh(vm, (
        "uci set nodogsplash.@nodogsplash[0].enabled='1'; "
        "uci set nodogsplash.@nodogsplash[0].gatewayname='TollGate E2E'; "
        "uci set nodogsplash.@nodogsplash[0].gatewayinterface='br-lan'; "
        "uci set nodogsplash.@nodogsplash[0].gatewayport='2050'; "
        "uci add_list nodogsplash.@nodogsplash[0].users_to_router='allow tcp port 2121'; "
        "uci add_list nodogsplash.@nodogsplash[0].users_to_router='allow tcp port 2050'; "
        "uci commit nodogsplash; /etc/init.d/nodogsplash restart; sleep 2"
    ), timeout=60)
    if "nds-listening" not in _ssh(
            vm, "netstat -tln | grep ':2050 ' && echo nds-listening").stdout:
        pytest.fail("nodogsplash not listening on :2050")

    subprocess.run(
        ["scp", "-O", "-q", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         "-i", vm["key"], "-P", str(vm["port"]), str(binary),
         f"root@{vm['host']}:/usr/bin/tollgate-wrt"],
        check=True, capture_output=True, timeout=180,
    )
    config = {
        "config_version": "v0.0.7", "log_level": "info",
        "accepted_mints": [{
            "url": MINT_ROUTER_VIEW, "min_balance": 0,
            "balance_tolerance_percent": 0, "payout_interval_seconds": 999999,
            "min_payout_amount": 999999, "price_per_step": 1,
            "price_unit": "sats", "purchase_min_steps": 0,
        }],
        "profit_share": [{"factor": 0.79, "identity": "owner"},
                         {"factor": 0.21, "identity": "developer"}],
        "step_size": 22020096, "margin": 0.1, "metric": "bytes",
        "show_setup": True, "reseller_mode": False, "auth_delay_seconds": 0,
    }
    write = subprocess.Popen(
        ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         "-i", vm["key"], "-p", str(vm["port"]), f"root@{vm['host']}",
         "mkdir -p /etc/tollgate && cat > /etc/tollgate/config.json"],
        stdin=subprocess.PIPE, text=True)
    write.communicate(json.dumps(config))
    assert write.returncode == 0, "failed to write /etc/tollgate/config.json"

    _ssh(vm, (
        "kill $(pidof tollgate-wrt) 2>/dev/null; sleep 1; "
        "(/usr/bin/tollgate-wrt --config /etc/tollgate/config.json "
        "> /tmp/tollgate.log 2>&1 &); sleep 4"
    ), timeout=60)
    if "tg-listening" not in _ssh(
            vm, "netstat -tln | grep ':2121 ' && echo tg-listening").stdout:
        pytest.fail("tollgate-wrt not listening on :2121 — see /tmp/tollgate.log")


def _setup_client(vm):
    """Synthetic captive-portal client: veth into a netns with our test MAC,
    then one portal hit so NDS registers the preauthenticated client."""
    r = _ssh(vm, (
        "ip link del veth-a 2>/dev/null; "
        "ip netns add client 2>/dev/null; "
        "ip link add veth-a type veth peer name veth-b && "
        "ip link set veth-a master br-lan && ip link set veth-a up && "
        "ip link set veth-b netns client && "
        "ip netns exec client ip link set veth-b address " + CLIENT_MAC + " && "
        "ip netns exec client ip addr add " + CLIENT_IP + "/24 dev veth-b && "
        "ip netns exec client ip link set veth-b up && "
        "ip netns exec client ip route add default via 10.0.2.15 && echo client-ok"
    ), timeout=60)
    if "client-ok" not in r.stdout:
        pytest.skip(f"could not create the netns client: "
                    f"{(r.stdout + r.stderr)[-300:]}")
    r = _ssh(vm, "ip netns exec client wget -q -O- --timeout=5 "
                 "'http://10.0.2.15:2050/' >/dev/null 2>&1; sleep 2; "
                 f"ndsctl clients | grep -q '{CLIENT_MAC}' && echo nds-client || echo no-client",
             timeout=60)
    if "nds-client" not in r.stdout:
        pytest.fail(f"NDS did not register the synthetic client: {r.stdout[:200]}")


def _mint_token() -> str:
    """NUT-04 quote → xpay → nutshell mint+send, fresh wallet, router-view URL."""
    wallet = tempfile.mkdtemp(prefix="conwrt-cashu-")
    env = {**os.environ, "CASHU_DIR": wallet}
    proc = subprocess.Popen(
        [CASHU_BIN, "-h", MINT_HOST_VIEW, "invoice", str(PAYMENT_SATS)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        env=env, bufsize=1,
    )
    bolt = quote_id = None
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        if bolt is None and "lntbs" in line:
            bolt = re.search(r"lntbs[a-z0-9]+", line).group(0)
        m = re.search(r"--id ([0-9a-f-]{36})", line)
        if m:
            quote_id = m.group(1)
        if bolt and quote_id:
            break
    assert bolt and quote_id, "could not parse nutshell invoice output"

    pay = xpay(bolt, maxfee_msat=1000)
    assert pay.get("ok"), f"CLN xpay failed: {pay}"

    try:
        proc.communicate(timeout=180)
    except subprocess.TimeoutExpired:
        proc.kill()
        pytest.fail("nutshell never settled the paid invoice")

    r = subprocess.run([CASHU_BIN, "-h", MINT_HOST_VIEW, "send", str(PAYMENT_SATS),
                        "--legacy"], capture_output=True, text=True, timeout=60, env=env)
    lines = [l for l in r.stdout.strip().splitlines() if l.startswith("cashu")]
    assert lines, f"nutshell send produced no token: {r.stderr[:200]}"
    raw = lines[-1]

    assert raw.startswith("cashuA"), "expected a v3 (cashuA) token"
    payload = raw[len("cashuA"):]
    payload += "=" * (-len(payload) % 4)
    data = json.loads(base64.urlsafe_b64decode(payload))
    for t in data.get("token", []):
        if isinstance(t, dict) and "mint" in t:
            t["mint"] = MINT_ROUTER_VIEW
    return "cashuA" + base64.urlsafe_b64encode(
        json.dumps(data).encode()).rstrip(b"=").decode()


def _pay(vm, token: str):
    """POST the token to tollgate-wrt via nc (busybox wget hides error bodies)."""
    write = subprocess.Popen(
        ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         "-i", vm["key"], "-p", str(vm["port"]), f"root@{vm['host']}",
         "cat > /tmp/token.txt"],
        stdin=subprocess.PIPE, text=True)
    write.communicate(token)
    assert write.returncode == 0
    request = (f"POST /?mac={CLIENT_MAC} HTTP/1.0\r\nHost: router\r\n"
               f"Content-Type: text/plain\r\nContent-Length: {len(token)}\r\n"
               f"Connection: close\r\n\r\n")
    r = _ssh(vm,
             "{ printf '" + request + "'; cat /tmp/token.txt; } "
             "| nc 127.0.0.1 2121 | tail -c 1500", timeout=90)
    return r.stdout


def _session_event(response: str) -> bool:
    try:
        body = response[response.index("{"):]
        event = json.loads(body)
    except (ValueError, json.JSONDecodeError):
        return False
    tags = event.get("tags", [])
    return event.get("kind") == 1022 or any(
        isinstance(t, list) and t and t[0] == "allotment" for t in tags)


class TestTollgatePaymentSignet:
    def test_pay_token_grants_access(self, openwrt_vm, lab_tunnel):
        try:
            _setup_router(openwrt_vm)
            _setup_client(openwrt_vm)
            token = _mint_token()
            response = _pay(openwrt_vm, token)
        except BaseException:
            _restore_vm(openwrt_vm)
            raise
        assert _session_event(response), f"expected a session event: {response[-400:]}"
        state = _ssh(openwrt_vm, "ndsctl clients", timeout=30).stdout
        _restore_vm(openwrt_vm)
        assert CLIENT_MAC in state, f"client missing after payment: {state[:200]}"
        assert "Authenticated" in state, f"client not Authenticated: {state[:200]}"
