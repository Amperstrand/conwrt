"""WireGuard self-hosted E2E: real tunnels between this host and the QEMU OpenWrt VM.

The wireguard-client / wireguard-server use cases ship as rendered PlanOps
characterized hermetically in tests/test_wireguard_*_ops.py. This file is the
missing integration layer: it APPLIES the rendered ops on a real OpenWrt
system (the session VM from conftest.py) and proves a real WireGuard tunnel
against a self-hosted counterpart — every assertion reads live kernel state
(``wg show``, ``ip route``, ping), never mocks.

Topology (QEMU user-mode networking):

  test 1 — host-as-server
      host wg server (root netns, UDP 51900, 10.9.0.1/24)
          ▲  slirp 10.0.2.2 host alias (guest→host UDP, verified working)
      VM client  ← wireguard_client ops (endpoint 10.0.2.2:51900, 10.9.0.2/32)

  test 2 — vm-as-server (mirror)
      VM server  ← wireguard_server ops (listen 51820, 10.9.1.1/24)
          ▲  conftest UDP hostfwd udp::51820-:51820 (host→guest)
      host wg client (10.9.1.2/32, endpoint 127.0.0.1:51820)

  test 3 — pbr smoke (package permitting): enable pbr with a selective
      wg0 policy and assert the non-tunneled path (ping 10.0.2.2) survives.

Host-side wg state lives in dedicated interfaces (conwrtsrv0/conwrtcli0) and
is removed in ``finally`` — no host WireGuard state survives the session.
"""
from __future__ import annotations

import base64
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from profile.ops import Op, render_shell  # noqa: E402
from use_cases.pbr import _build_pbr_ops  # noqa: E402
from use_cases.wireguard_client import _build_wireguard_client_ops  # noqa: E402
from use_cases.wireguard_server import _build_wireguard_server_ops  # noqa: E402
from vm_port import port_from_env  # noqa: E402

pytestmark = [pytest.mark.hardware]

SESSION_PORT = port_from_env("CONWRT_VM_SESSION_PORT", 2222)
SSH_CMD = [
    "ssh", "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR",
    "-i", str(REPO_ROOT / "tests" / "integration" / ".vm_ssh_key"),
    "-p", str(SESSION_PORT), "root@127.0.0.1",
]

HOST_SERVER_PORT = 51900   # host wg server; the VM's endpoint is 10.0.2.2:51900
VM_SERVER_PORT = 51820     # VM wg server (conftest UDP hostfwd lands here)
HOST_SRV_IF = "conwrtsrv0"  # host interface, test 1 (kernel ifnames: <=15 chars)
HOST_CLI_IF = "conwrtcli0"  # host interface, test 2
GUEST_ALIAS = "10.0.2.2"   # QEMU user-net gateway = alias for the host loopback

WG_UCI_SECTIONS = [
    "network.wg0", "network.wg0_peer", "network.wg0_peer1",
    "firewall.wg_client_vpn", "firewall.wg_client_fwd", "firewall.wg_client_killswitch",
    "firewall.wg_server_vpn", "firewall.wg_server_fwd_lan",
    "firewall.wg_server_fwd_wan", "firewall.wg_server_allow",
]


# --- host-side helpers -----------------------------------------------------


def _host(cmd: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)


def _host_out(cmd: str, timeout: int = 30) -> str:
    r = _host(cmd, timeout)
    assert r.returncode == 0, f"host command failed: {cmd}\nstdout:{r.stdout[-400:]}\nstderr:{r.stderr[-400:]}"
    return r.stdout.strip()


# --- VM-side helpers -------------------------------------------------------


def _vm(cmd: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(SSH_CMD + [cmd], capture_output=True, text=True, timeout=timeout)


def _vm_ok(cmd: str, timeout: int = 60) -> str:
    r = _vm(cmd, timeout)
    assert r.returncode == 0, f"vm command failed: {cmd}\nstdout:{r.stdout[-400:]}\nstderr:{r.stderr[-400:]}"
    return r.stdout.strip()


def _wait_vm_ssh(deadline_s: int = 120) -> None:
    """SSH goes away while netifd restarts — poll until dropbear answers again."""
    deadline = time.time() + deadline_s
    while time.time() < deadline:
        try:
            if _vm("true").returncode == 0:
                time.sleep(3)  # let netifd settle before asserting on wg0
                return
        except subprocess.TimeoutExpired:
            pass
        time.sleep(3)
    pytest.fail("VM SSH did not come back after /etc/init.d/network restart")


def _apply_ops_in_vm(ops: list[Op]) -> str:
    """Render PlanOps to shell and execute them inside the VM (real transport).

    This is the same render_shell output `conwrt configure` would push over
    SSH — applied directly so the test owns exactly one script.
    """
    script = render_shell(ops)
    r = subprocess.run(SSH_CMD + ["sh -s"], input=script, capture_output=True,
                       text=True, timeout=180)
    assert r.returncode == 0, f"ops apply failed:\nstdout:{r.stdout[-1500:]}\nstderr:{r.stderr[-800:]}"
    return r.stdout


def _vm_wg_cleanup() -> None:
    """Remove every wg uci section both use cases create; restart network."""
    for section in WG_UCI_SECTIONS:
        _vm(f"uci -q delete {section}")
    _vm("uci commit network; uci commit firewall")
    _vm("/etc/init.d/firewall restart >/dev/null 2>&1; "
        "/etc/init.d/network restart >/dev/null 2>&1; echo restarted", timeout=90)
    _wait_vm_ssh()


def _soft_vm_wg_cleanup() -> None:
    """Teardown path: cleanup must never mask the real test result."""
    try:
        _vm_wg_cleanup()
    except Exception as exc:  # noqa: BLE001 — teardown best-effort by design
        print(f"VM wg cleanup failed (non-fatal): {exc}", flush=True)


# --- WireGuard plumbing (host: kernel module + wg tools; keys via wg genkey) --


def _genkey() -> tuple[str, str]:
    priv = base64.b64encode(secrets.token_bytes(32)).decode()
    pub = subprocess.run(["wg", "pubkey"], input=priv, capture_output=True,
                         text=True, timeout=10).stdout.strip()
    return priv, pub


def _host_wg_up(ifname: str, keydir: str, priv: str, listen_port: int | None,
                addr: str, peer_pub: str, peer_allowed: str,
                endpoint: str | None = None) -> None:
    """Create a host wg interface with one peer (all-or-nothing asserts)."""
    keyfile = Path(keydir) / f"{ifname}.key"
    keyfile.write_text(priv)
    keyfile.chmod(0o600)
    listen = f" listen-port {listen_port}" if listen_port else ""
    peer_cmd = f"wg set {ifname} peer {peer_pub} allowed-ips {peer_allowed}"
    if endpoint:
        peer_cmd += f" endpoint {endpoint}"
    cmds = [
        f"ip link add {ifname} type wireguard",
        f"wg set {ifname} private-key {keyfile}{listen}",
        peer_cmd,
        f"ip addr add {addr} dev {ifname}",
        f"ip link set {ifname} mtu 1420 up",
    ]
    for cmd in cmds:
        r = _host(cmd)
        assert r.returncode == 0, f"host wg setup failed: {cmd}\n{r.stderr}"


def _host_wg_down(ifname: str) -> None:
    _host(f"ip link del {ifname} 2>/dev/null")


def _transfer_counters(out: str, peer_pub: str) -> tuple[int, int]:
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == peer_pub:
            return int(parts[1]), int(parts[2])
    raise pytest.fail(f"no transfer counters for peer {peer_pub} in:\n{out}")


def _wait_handshake(wg_cmd: str, peer_pub: str, runner: Callable[..., str],
                    drive_cmd: str | None = None, timeout_s: int = 90,
                    drive_via_ssh: bool = True) -> int:
    """Poll `wg show <if> latest-handshakes` until the peer's timestamp is set.

    WireGuard only initiates on outbound traffic, so ``drive_cmd`` (a ping to
    the peer's tunnel IP) runs every poll when the peer itself has no
    persistent-keepalive.
    """
    deadline = time.time() + timeout_s
    last = ""
    while time.time() < deadline:
        if drive_cmd:
            if drive_via_ssh:
                _vm(f"{drive_cmd} >/dev/null 2>&1")
            else:
                _host(f"{drive_cmd} >/dev/null 2>&1")
        try:
            last = runner(wg_cmd)
        except (AssertionError, subprocess.SubprocessError):
            last = ""
        for line in last.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] == peer_pub and parts[1].isdigit() and int(parts[1]) > 0:
                return int(parts[1])
        time.sleep(4)
    raise pytest.fail(f"no WireGuard handshake within {timeout_s}s for {peer_pub}\nlast: {last!r}")


# --- test 1: host-as-server, VM applies wireguard_client ops ----------------


def test_host_server_vm_client(openwrt_vm, wireguard_installed):
    vm = wireguard_installed  # guarantees wg + luci-proto-wireguard in the VM
    host_priv, host_pub = _genkey()
    vm_priv, vm_pub = _genkey()

    with tempfile.TemporaryDirectory(prefix="conwrt-wg-e2e-") as keydir:
        _host_wg_up(HOST_SRV_IF, keydir, host_priv, HOST_SERVER_PORT,
                    "10.9.0.1/24", vm_pub, "10.9.0.2/32")
        try:
            ops = _build_wireguard_client_ops({
                "private_key": vm_priv,
                "peer_public_key": host_pub,
                "endpoint_host": GUEST_ALIAS,
                "endpoint_port": HOST_SERVER_PORT,
                "address": "10.9.0.2/32",
                # selective routing: SSH to the VM must stay on eth0, and the
                # kill-switch REJECT rule would defeat the non-tunneled checks
                "allowed_ips": "10.9.0.0/24",
                "kill_switch": False,
            })
            out = _apply_ops_in_vm(ops)
            assert "WireGuard client configured" in out, out[-400:]
            _wait_vm_ssh()

            # 1. UCI state really landed (the layer the use case owns)
            assert vm("uci -q get network.wg0.proto") == "wireguard"
            assert vm("uci -q get network.wg0.addresses") == "10.9.0.2/32"
            assert vm("uci -q get network.wg0_peer.endpoint_host") == GUEST_ALIAS
            assert vm("uci -q get network.wg0_peer.allowed_ips") == "10.9.0.0/24"

            # 2. The kernel accepted the config: wg0 exists with address + peer
            wg_show = vm("wg show wg0")
            assert "interface: wg0" in wg_show, f"wg0 not up: {wg_show}"
            assert host_pub in wg_show, f"peer missing: {wg_show}"
            assert "10.9.0.2/32" in vm("ip addr show wg0")

            # 3. route_allowed_ips=1 installed the selective route via wg0
            route_line = vm("ip route show | grep '10.9.0.0/24' || true")
            assert "wg0" in route_line, f"selective route missing: {route_line!r}"

            # 4. REAL handshake with the host server (10.0.2.2 slirp alias)
            _wait_handshake("wg show wg0 latest-handshakes", host_pub, runner=vm,
                            drive_cmd=f"ping -c 1 -W 2 10.9.0.1")

            # 5. Data path VM → host tunnel IP
            ping_out = vm("ping -c 3 -W 3 10.9.0.1")
            assert "0% packet loss" in ping_out, ping_out

            # 6. Host-side view: handshake, transfer counters, VM→host ping
            _wait_handshake(f"wg show {HOST_SRV_IF} latest-handshakes", vm_pub,
                            runner=_host_out)
            rx, tx = _transfer_counters(_host_out(f"wg show {HOST_SRV_IF} transfer"), vm_pub)
            assert rx > 0 and tx > 0, f"transfer counters empty: rx={rx} tx={tx}"
            host_ping = _host(f"ping -c 3 -W 3 -I {HOST_SRV_IF} 10.9.0.2")
            assert host_ping.returncode == 0, \
                f"host→VM tunnel ping failed:\n{host_ping.stdout}"

            # 7. Best effort: internet egress VM→wg→host→internet
            print(f"egress: {_try_tunnel_egress(vm)}", flush=True)
        finally:
            _host_wg_down(HOST_SRV_IF)
            _soft_vm_wg_cleanup()


def _try_tunnel_egress(vm) -> str:
    """Best-effort internet egress through the tunnel (host NAT required).

    The QEMU host is a shared box — forwarding/NAT may be unavailable or its
    egress filtered, so this only reports; the test verdict rests on the
    tunnel assertions above.
    """
    note = "deferred: "
    ifw = _host_out("cat /proc/sys/net/ipv4/ip_forward")
    if _host("sysctl -wq net.ipv4.ip_forward=1").returncode != 0:
        return note + "cannot enable host ip_forward (container restriction)"
    default = _host_out("ip -4 route show default")
    toks = default.split()
    wan_if = toks[toks.index("dev") + 1] if "dev" in toks else None
    if not wan_if or _host(f"ip link show {wan_if}").returncode != 0:
        _host(f"sysctl -wq net.ipv4.ip_forward={ifw}")
        return note + f"cannot identify default interface from {default!r}"
    rule = f"-s 10.9.0.0/24 -o {wan_if} -j MASQUERADE"
    if _host(f"iptables -t nat -C POSTROUTING {rule} 2>/dev/null"
             f" || iptables -t nat -A POSTROUTING {rule}").returncode != 0:
        _host(f"sysctl -wq net.ipv4.ip_forward={ifw}")
        return note + "iptables NAT unavailable on host"
    try:
        vm("ip route add 9.9.9.9/32 dev wg0 2>/dev/null; echo ok")
        p = _vm("ping -c 3 -W 3 9.9.9.9")
        if p.returncode == 0:
            return f"OK — VM reached 9.9.9.9 through the host wg server via {wan_if}"
        return note + f"NAT up but ping 9.9.9.9 rc={p.returncode}: {p.stdout.strip().splitlines()[-1:]}"
    finally:
        vm("ip route del 9.9.9.9/32 dev wg0 2>/dev/null; echo ok")
        _host(f"iptables -t nat -D POSTROUTING {rule} 2>/dev/null")
        _host(f"sysctl -wq net.ipv4.ip_forward={ifw}")


# --- test 2: VM-as-server (mirror), host connects as client -----------------


def test_vm_server_host_client(openwrt_vm, wireguard_installed):
    fwd_port = openwrt_vm.get("wg_fwd_port")
    if not fwd_port:
        pytest.skip("QEMU UDP hostfwd unavailable (host UDP 51820 busy or "
                    "CONWRT_VM_WG_FWD_PORT points elsewhere) — VM-as-server "
                    "topology needs udp::51820-:51820")
    vm = wireguard_installed
    vm_srv_priv, vm_srv_pub = _genkey()
    host_cli_priv, host_cli_pub = _genkey()

    with tempfile.TemporaryDirectory(prefix="conwrt-wg-e2e-") as keydir:
        _host_wg_up(HOST_CLI_IF, keydir, host_cli_priv, None, "10.9.1.2/24",
                    vm_srv_pub, "10.9.1.0/24", endpoint=f"127.0.0.1:{fwd_port}")
        try:
            ops = _build_wireguard_server_ops({
                "private_key": vm_srv_priv,
                "listen_port": VM_SERVER_PORT,
                "subnet": "10.9.1.1/24",
                "peer1_public_key": host_cli_pub,
                "peer1_allowed_ips": "10.9.1.2/32",
            })
            out = _apply_ops_in_vm(ops)
            assert "WireGuard server configured" in out, out[-400:]
            _wait_vm_ssh()

            # UCI state + kernel view of the server config
            assert vm("uci -q get network.wg0.proto") == "wireguard"
            assert vm("uci -q get network.wg0.listen_port") == str(VM_SERVER_PORT)
            assert vm("uci -q get network.wg0_peer1.public_key") == host_cli_pub
            assert vm("wg show wg0 listen-port") == str(VM_SERVER_PORT)
            assert "10.9.1.1/24" in vm("ip addr show wg0")

            # REAL handshake: host client drives it through the UDP hostfwd
            _wait_handshake(f"wg show {HOST_CLI_IF} latest-handshakes", vm_srv_pub,
                            runner=_host_out, drive_via_ssh=False,
                            drive_cmd=f"ping -c 1 -W 2 -I {HOST_CLI_IF} 10.9.1.1")

            # Data path host → VM tunnel IP
            ping = _host(f"ping -c 3 -W 3 -I {HOST_CLI_IF} 10.9.1.1")
            assert ping.returncode == 0, f"host→VM tunnel ping failed:\n{ping.stdout}"

            # VM-side view: handshake seen by the server + nonzero counters
            _wait_handshake("wg show wg0 latest-handshakes", host_cli_pub, runner=vm)
            rx, tx = _transfer_counters(vm("wg show wg0 transfer"), host_cli_pub)
            assert rx > 0 and tx > 0, f"server transfer counters empty: rx={rx} tx={tx}"
        finally:
            _host_wg_down(HOST_CLI_IF)
            _soft_vm_wg_cleanup()


# --- test 3: pbr smoke — selective route must not break the non-tunneled path


def test_pbr_smoke_selective_route_keeps_non_tunneled_path(openwrt_vm, wireguard_installed):
    vm = wireguard_installed
    r = _vm("apk add pbr 2>&1 | tail -1; test -x /etc/init.d/pbr && echo PBR-OK",
            timeout=240)
    if "PBR-OK" not in (r.stdout or ""):
        pytest.skip(f"pbr package not installable in the VM: {(r.stdout or r.stderr)[-200:]}")

    try:
        ops = _build_pbr_ops({
            "wan_interface": "lan",      # the session VM's only interface
            "lan_interface": "lan",
            "strict_enforcement": False,  # never drop unmatched traffic
        })
        out = _apply_ops_in_vm(ops)
        assert "pbr configured" in out, out[-300:]

        assert vm("uci -q get pbr.config.enabled") == "1"
        assert vm("/etc/init.d/pbr enabled; echo rc=$?").endswith("rc=0")

        # selective policy: only 10.9.0.0/24 (the wg subnet) via wg0 — wg0
        # intentionally absent, so pbr must log'n'skip it, not break routing
        for cmd in [
            "uci set pbr.wg_selective=policy",
            "uci set pbr.wg_selective.name='tunnel-subnet-only'",
            "uci set pbr.wg_selective.dest_addr='10.9.0.0/24'",
            "uci set pbr.wg_selective.interface='wg0'",
            "uci commit pbr",
            "/etc/init.d/pbr restart >/dev/null 2>&1; echo restarted",
        ]:
            vm(cmd)
        assert vm("uci -q get pbr.wg_selective.interface") == "wg0"

        # the assertion that matters: non-tunneled path still passes
        ping_out = vm("ping -c 3 -W 2 10.0.2.2")
        assert "0% packet loss" in ping_out, ping_out
    finally:
        for cmd in [
            "uci -q delete pbr.wg_selective",
            "uci set pbr.config.enabled='0'",
            "uci commit pbr",
            "/etc/init.d/pbr stop >/dev/null 2>&1",
            "/etc/init.d/pbr disable >/dev/null 2>&1",
            "echo cleaned",
        ]:
            vm(cmd, timeout=90)
