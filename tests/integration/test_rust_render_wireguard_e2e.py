"""Rust-rendered WireGuard E2E: the `conwrt-plan-render` output, applied on a real VM.

tests/integration/test_wireguard_e2e.py (#409) proves the PYTHON-rendered
wireguard ops produce a working tunnel on the QEMU OpenWrt VM, and
tests/test_parity_rust_plan.py (#411) proves the Rust renderer emits a
semantically equal command stream for the static parity fixtures. Neither
proves the missing rung: that the RUST-rendered plan applies on a real
OpenWrt system and the tunnel actually WORKS. This file does exactly that:

  1. build `conwrt-plan-render` (the #411 parity binary),
  2. write a per-run fixture json — real Curve25519 keys generated on the
     host, so the host peer can recognize the VM — and render it through
     the RUST pipeline (fixture → Profile → plan_profile → render_shell),
  3. pipe the bin's stdout — unmodified, the exact artifact the Rust side
     ships — into the VM over SSH (`sh -s`),
  4. assert the same real outcomes as #409: kernel WireGuard state, a real
     handshake, 0%-loss pings over the tunnel both ways, nonzero transfer
     counters.

Topology (same as #409, distinct host ports/interfaces so both suites can
run concurrently on this shared host):

  test 1 — host-as-server
      host wg server (root netns, UDP 51901, 10.9.0.1/24)
          ▲  slirp 10.0.2.2 host alias (guest→host UDP, verified working)
      VM client  ← RUST-rendered wireguard-client script
                   (endpoint 10.0.2.2:51901, 10.9.0.2/32)

  test 2 — vm-as-server (mirror)
      VM server  ← RUST-rendered wireguard-server script (51820, 10.9.1.1/24)
          ▲  conftest UDP hostfwd udp::51820-:51820 (host→guest)
      host wg client (10.9.1.2/32, endpoint 127.0.0.1:51820)

Host-side wg state lives in dedicated interfaces (conwrtrsrv0/conwrtrcli0,
distinct from #409's conwrtsrv0/conwrtcli0) and is removed in ``finally``.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

# Reuse the proven, retry-hardened helpers from the Python E2E suite
# (same directory — pytest's prepend import mode puts it on sys.path).
# Only the RENDER step differs: the script under test comes from the
# Rust binary, everything downstream (transport, waits, assertions) is
# the machinery #409 already shook out on real hardware.
from test_wireguard_e2e import (  # noqa: E402
    GUEST_ALIAS,
    SSH_CMD,
    _genkey,
    _host_out,
    _host_wg_down,
    _host_wg_up,
    _soft_vm_wg_cleanup,
    _transfer_counters,
    _wait_handshake,
    _wait_vm_ssh,
)

pytestmark = [pytest.mark.hardware]

HOST_SERVER_PORT = 51901    # host wg server; VM endpoint is 10.0.2.2:51901
                             # (51900 belongs to test_wireguard_e2e — distinct
                             # so both suites can run concurrently here)
HOST_SRV_IF = "conwrtrsrv0"  # host interface, test 1 (<=15 chars, distinct
                              # from #409's conwrtsrv0 for the same reason)
HOST_CLI_IF = "conwrtrcli0"  # host interface, test 2
VM_SERVER_PORT = 51820       # conftest UDP hostfwd lands here


# --- the Rust renderer (built from the repo, same invocation as #411) -------


@pytest.fixture(scope="session")
def rust_plan_render_bin() -> Path:
    """Build `conwrt-plan-render` once per session and return its path.

    The parity-fixture feature is a dependency-level default of the
    conwrt-cli package, so a plain `cargo build -p conwrt-cli` yields the
    same binary the pytest parity harness uses.
    """
    cargo = shutil.which("cargo")
    if cargo is None:
        pytest.skip("cargo toolchain not available — cannot build conwrt-plan-render")
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR", str(REPO_ROOT / "target")))
    bin_path = target_dir / "debug" / "conwrt-plan-render"
    if not bin_path.exists():
        build_cmd = [cargo, "build", "-p", "conwrt-cli", "--bin",
                     "conwrt-plan-render"]
        proc = subprocess.run(build_cmd, cwd=str(REPO_ROOT),
                              capture_output=True, text=True, timeout=1200)
        assert proc.returncode == 0, f"cargo build failed: {proc.stderr[-800:]}"
    assert bin_path.exists(), f"{bin_path} missing after cargo build"
    return bin_path


def _render_via_rust_bin(bin_path: Path, use_case: str, params: dict,
                         workdir: Path) -> str:
    """Write a per-run parity fixture (fresh keys) and render it via the bin.

    The fixture shape is exactly what tests/test_parity_rust_plan.py feeds
    the binary — the only difference is that params carry per-run generated
    keys instead of the static fixtures' placeholders.
    """
    fixture_path = workdir / f"{use_case.replace('-', '_')}_rust_e2e.json"
    fixture_path.write_text(json.dumps({"use_case": use_case, "params": params},
                                       indent=2) + "\n")
    proc = subprocess.run([str(bin_path), str(fixture_path)],
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, (
        f"conwrt-plan-render failed on {fixture_path}:\n{proc.stderr}"
    )
    return proc.stdout


def _apply_rust_script_in_vm(script: str) -> str:
    """Execute the RUST-rendered script in the VM — the acceptance act.

    The script is piped unmodified (shebang/header/`set -e` included) into
    `sh -s` over the conftest SSH transport: the same channel, and the same
    shell semantics, `conwrt configure` would use on a real device.
    """
    proc = subprocess.run(SSH_CMD + ["sh -s"], input=script,
                          capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, (
        f"Rust-rendered script failed to apply:\n"
        f"stdout:{proc.stdout[-1500:]}\nstderr:{proc.stderr[-800:]}"
    )
    return proc.stdout


# --- test 1: host-as-server, VM applies the RUST wireguard-client render ----


def test_rust_rendered_client_against_host_server(openwrt_vm, wireguard_installed,
                                                  rust_plan_render_bin,
                                                  tmp_path_factory):
    vm = wireguard_installed  # guarantees wg + luci-proto-wireguard in the VM
    host_priv, host_pub = _genkey()
    vm_priv, vm_pub = _genkey()
    workdir = tmp_path_factory.mktemp("rust-wg-e2e")

    with tempfile.TemporaryDirectory(prefix="conwrt-wg-e2e-") as keydir:
        _host_wg_up(HOST_SRV_IF, keydir, host_priv, HOST_SERVER_PORT,
                    "10.9.0.1/24", vm_pub, "10.9.0.2/32")
        try:
            script = _render_via_rust_bin(rust_plan_render_bin, "wireguard-client", {
                "private_key": vm_priv,        # host must know the VM's key
                "peer_public_key": host_pub,
                "endpoint_host": GUEST_ALIAS,  # slirp alias for the host
                "endpoint_port": HOST_SERVER_PORT,
                "address": "10.9.0.2/32",
                # selective routing: SSH to the VM must stay on eth0, and the
                # kill-switch REJECT rule would defeat the non-tunneled checks
                "allowed_ips": "10.9.0.0/24",
                "kill_switch": False,
            }, workdir)

            # 0. The artifact under test is genuinely the Rust render, and it
            #    carries the per-run material (not fixture placeholders).
            assert script.startswith("#!/bin/sh"), script[:200]
            assert "# conwrt plan: wireguard-client" in script, script[:400]
            assert f"uci set network.wg0.private_key='{vm_priv}'" in script
            assert f"uci set network.wg0_peer.public_key='{host_pub}'" in script
            assert f"uci set network.wg0_peer.endpoint_host='{GUEST_ALIAS}'" in script
            assert f"uci set network.wg0_peer.endpoint_port='{HOST_SERVER_PORT}'" in script
            # kill_switch=False drops the RULE, not the hygiene: both
            # renderers (verified: Python identical) keep the cleanup
            # loop that greps for the rule name — assert the ADD is
            # absent, the same precise form the plan unit test pins.
            assert "uci set firewall.wg_client_killswitch" not in script, \
                "kill_switch=False must not add the reject rule"

            # 1. APPLY — the Rust output runs, unmodified, inside the VM
            out = _apply_rust_script_in_vm(script)
            marker = f"WireGuard client configured: {GUEST_ALIAS}:{HOST_SERVER_PORT}"
            assert marker in out, out[-400:]
            _wait_vm_ssh()  # network restart inside the script drops SSH 5-20 s

            # 2. UCI state really landed (the layer the plan owns)
            assert vm("uci -q get network.wg0.proto") == "wireguard"
            assert vm("uci -q get network.wg0.addresses") == "10.9.0.2/32"
            assert vm("uci -q get network.wg0_peer.endpoint_host") == GUEST_ALIAS
            assert vm("uci -q get network.wg0_peer.allowed_ips") == "10.9.0.0/24"

            # 3. The kernel accepted the Rust-rendered config: wg0 + peer
            wg_show = vm("wg show wg0")
            assert "interface: wg0" in wg_show, f"wg0 not up: {wg_show}"
            assert host_pub in wg_show, f"peer missing: {wg_show}"
            assert "10.9.0.2/32" in vm("ip addr show wg0")

            # 4. route_allowed_ips=1 installed the selective route via wg0
            route_line = vm("ip route show | grep '10.9.0.0/24' || true")
            assert "wg0" in route_line, f"selective route missing: {route_line!r}"

            # 5. REAL handshake with the host server (10.0.2.2 slirp alias)
            _wait_handshake("wg show wg0 latest-handshakes", host_pub, runner=vm,
                            drive_cmd="ping -c 1 -W 2 10.9.0.1")

            # 6. Data path VM → host tunnel IP
            ping_out = vm("ping -c 3 -W 3 10.9.0.1")
            assert "0% packet loss" in ping_out, ping_out

            # 7. Host-side view: handshake, transfer counters, host→VM ping
            _wait_handshake(f"wg show {HOST_SRV_IF} latest-handshakes", vm_pub,
                            runner=_host_out)
            rx, tx = _transfer_counters(
                _host_out(f"wg show {HOST_SRV_IF} transfer"), vm_pub)
            assert rx > 0 and tx > 0, f"transfer counters empty: rx={rx} tx={tx}"
            host_ping = subprocess.run(
                f"ping -c 3 -W 3 -I {HOST_SRV_IF} 10.9.0.2",
                shell=True, capture_output=True, text=True, timeout=30)
            assert host_ping.returncode == 0, \
                f"host→VM tunnel ping failed:\n{host_ping.stdout}"
        finally:
            _host_wg_down(HOST_SRV_IF)
            _soft_vm_wg_cleanup()


# --- test 2: VM-as-server (mirror), RUST wireguard-server render ------------


def test_rust_rendered_server_vm_as_server(openwrt_vm, wireguard_installed,
                                           rust_plan_render_bin,
                                           tmp_path_factory):
    fwd_port = openwrt_vm.get("wg_fwd_port")
    if not fwd_port:
        pytest.skip("QEMU UDP hostfwd unavailable (host UDP 51820 busy or "
                    "CONWRT_VM_WG_FWD_PORT points elsewhere) — VM-as-server "
                    "topology needs udp::51820-:51820")
    vm = wireguard_installed
    vm_srv_priv, vm_srv_pub = _genkey()
    host_cli_priv, host_cli_pub = _genkey()
    workdir = tmp_path_factory.mktemp("rust-wg-e2e")

    with tempfile.TemporaryDirectory(prefix="conwrt-wg-e2e-") as keydir:
        _host_wg_up(HOST_CLI_IF, keydir, host_cli_priv, None, "10.9.1.2/24",
                    vm_srv_pub, "10.9.1.0/24", endpoint=f"127.0.0.1:{fwd_port}")
        try:
            script = _render_via_rust_bin(rust_plan_render_bin, "wireguard-server", {
                "private_key": vm_srv_priv,
                "listen_port": VM_SERVER_PORT,
                "subnet": "10.9.1.1/24",
                "peer1_public_key": host_cli_pub,
                "peer1_allowed_ips": "10.9.1.2/32",
            }, workdir)

            # 0. Rust render sanity: per-run key material, server sections
            assert script.startswith("#!/bin/sh"), script[:200]
            assert "# conwrt plan: wireguard-server" in script, script[:400]
            assert f"uci set network.wg0.private_key='{vm_srv_priv}'" in script
            assert f"uci set network.wg0_peer1.public_key='{host_cli_pub}'" in script

            # 1. APPLY the Rust output in the VM
            out = _apply_rust_script_in_vm(script)
            marker = f"WireGuard server configured: port {VM_SERVER_PORT}, subnet 10.9.1.1/24"
            assert marker in out, out[-400:]
            _wait_vm_ssh()

            # 2. UCI + kernel view of the server config
            assert vm("uci -q get network.wg0.proto") == "wireguard"
            assert vm("uci -q get network.wg0.listen_port") == str(VM_SERVER_PORT)
            assert vm("uci -q get network.wg0_peer1.public_key") == host_cli_pub
            assert vm("wg show wg0 listen-port") == str(VM_SERVER_PORT)
            assert "10.9.1.1/24" in vm("ip addr show wg0")

            # 3. REAL handshake: host client drives it through the UDP hostfwd
            _wait_handshake(f"wg show {HOST_CLI_IF} latest-handshakes", vm_srv_pub,
                            runner=_host_out, drive_via_ssh=False,
                            drive_cmd=f"ping -c 1 -W 2 -I {HOST_CLI_IF} 10.9.1.1")

            # 4. Data path host → VM tunnel IP
            ping = subprocess.run(
                f"ping -c 3 -W 3 -I {HOST_CLI_IF} 10.9.1.1",
                shell=True, capture_output=True, text=True, timeout=30)
            assert ping.returncode == 0, f"host→VM tunnel ping failed:\n{ping.stdout}"

            # 5. VM-side view: handshake seen by the server + nonzero counters
            _wait_handshake("wg show wg0 latest-handshakes", host_cli_pub, runner=vm)
            rx, tx = _transfer_counters(vm("wg show wg0 transfer"), host_cli_pub)
            assert rx > 0 and tx > 0, f"server transfer counters empty: rx={rx} tx={tx}"
        finally:
            _host_wg_down(HOST_CLI_IF)
            _soft_vm_wg_cleanup()
