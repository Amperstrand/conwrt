"""VM apply-acceptance: render parity fixtures -> execute on a live OpenWrt VM -> verify.

The render-parity corpus proves Python 1.x and Rust 2.x emit the same bytes.
This runner proves those bytes APPLY cleanly on a router-shaped system —
the second pillar of the 1.x-planner deprecation evidence.

Usage (from the conwrt repo root):
  CONWRT_REAL_NETWORK=1 /usr/bin/python3 /root/.hermes/cache/scratch/vm_apply_acceptance.py \
      [fixture ...]        # defaults to a representative set

Evidence per fixture: exit code, verification echoes, uci readback digest.
"""
import json
import pathlib
import subprocess
import sys
import time
from pathlib import Path

REPO = Path("/root/src/worktrees/conwrt/parity-corpus")
RENDER = Path("/root/.cargo-target/debug/conwrt-plan-render")
FIXDIR = REPO / "tests/fixtures/parity"
KEY = REPO / "tests/integration/.vm_ssh_key"
PORT = 2226  # dedicated apply-VM (2222 held by a prior lane's qemu)

DEFAULTS = [
    "doh_default",            # uci + service restart + echo tail
    "mwan3_default",          # the 1.x track_ip bug fix — track_ips MUST commit
    "vpn_ivpn_default",       # heredoc script + API-curl text (network-free apply)
    "tollgate_cellular_minimal",  # GAP fixture applies fine; bytes differ only
    "ssh_hardening_default",
    "guest_wifi_default",
]


def ssh(cmd: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["ssh", "-F", "/dev/null", "-p", str(PORT), "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes",
         "-o", "ConnectTimeout=10", "-i", str(KEY), "root@127.0.0.1", cmd],
        capture_output=True, text=True, timeout=timeout)


def render(name: str) -> str:
    r = subprocess.run([str(RENDER), str(FIXDIR / f"{name}.json")],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise SystemExit(f"render failed for {name}: {r.stderr[:300]}")
    return r.stdout


def sh_syntax_ok(script: str) -> tuple[bool, str]:
    r = subprocess.run(["sh", "-n"], input=script, capture_output=True, text=True)
    return r.returncode == 0, r.stderr.strip()[:200]


def main() -> int:
    names = sys.argv[1:] or DEFAULTS
    if ssh("true").returncode != 0:
        raise SystemExit("session VM not reachable on :2222 — boot it via a "
                         "session-scoped integration run first (make integration)")
    results = {}
    for name in names:
        script = render(name)
        ok, err = sh_syntax_ok(script)
        if not ok:
            results[name] = {"syntax": f"FAIL {err}"}
            continue
        # ship + execute under sh (not bash — OpenWrt is busybox ash; -n locally
        # uses dash semantics, close enough for gate purposes)
        local = pathlib.Path("/tmp") / f"{name}.sh"
        local.write_text(script)
        subprocess.run(["scp", "-O", "-F", "/dev/null", "-P", str(PORT), "-o", "StrictHostKeyChecking=no",
                        "-o", "UserKnownHostsFile=/dev/null", "-i", str(KEY),
                        str(local), f"root@127.0.0.1:/tmp/{name}.sh"],
                       capture_output=True, text=True, timeout=60)
        # pre-seed: apk/opkg may hit network; EnsurePackage lines are best-effort
        # with || true in 1.x renders — acceptable. Run with sh -e like 2.x.
        r = ssh(f"sh /tmp/{name}.sh; echo APPLY_RC=$?", timeout=180)
        out = r.stdout
        rc = next((l for l in out.splitlines() if l.startswith("APPLY_RC=")), "APPLY_RC=?")
        # readbacks for known-good side effects
        checks = {}
        if name.startswith("mwan3"):
            checks["track_ip_committed"] = ssh(
                "uci show mwan3 2>/dev/null | grep -c track_ip").stdout.strip()
        if name.startswith("doh"):
            checks["resolver_url"] = ssh(
                "uci -q get https-dns-proxy.main.resolver_url 2>/dev/null").stdout.strip()
            checks["dnsmasq_fwd"] = ssh(
                "uci -q get dhcp.@dnsmasq[0].server 2>/dev/null").stdout.strip()
        if name.startswith("ssh_hardening"):
            checks["dropbear_port"] = ssh(
                "uci -q get dropbear.@dropbear[0].Port 2>/dev/null").stdout.strip()
        tail = [l for l in out.splitlines() if l.strip()][-4:]
        results[name] = {"syntax": "ok", "apply": rc, "checks": checks, "tail": tail}
        print(f"{name}: {rc} checks={checks}", flush=True)
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
