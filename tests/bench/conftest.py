"""Bench fixtures: router access, isolated conwrt config, CPU sampler, results.

Everything is env-driven so the same suite runs on any bench router:

  CONWRT_BENCH_ROUTER   router IP (default 192.168.1.1) — unset skips the suite
  CONWRT_BENCH_MODEL    conwrt model id (default: auto-detect via board.json)
  CONWRT_BENCH_IFACE    host ethernet interface (default enp5s0)
  CONWRT_BENCH_TOKEN    NordVPN access token (default: read from CONWRT_CONFIG)
  CONWRT_BENCH_SERVER   iperf3 server (default inr2.cashu.exchange)
  CONWRT_BENCH_SECONDS  seconds per iperf direction (default 10)
  CONWRT_BENCH_AP_SSID/KEY  VPN-exit AP params to include in scenarios

Results land in test-results/vpn-bench-<ts>/ (gitignored): results.json,
summary.md, and a per-scenario exit/endpoint record.

The user's repo config.toml is NEVER modified: each scenario switch runs
`conwrt configure` with CONWRT_CONFIG pointed at a generated temp config.
"""
from __future__ import annotations

from typing import Iterator

import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scenarios import Scenario, default_scenarios  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tests"))
from venues import Venue, venues_from_env  # noqa: E402

ROUTER = os.environ.get("CONWRT_BENCH_ROUTER", "192.168.1.1")
IFACE = os.environ.get("CONWRT_BENCH_IFACE", "enp5s0")
IPERF_SERVER = os.environ.get("CONWRT_BENCH_SERVER", "inr2.cashu.exchange")
IPERF_SECONDS = int(os.environ.get("CONWRT_BENCH_SECONDS", "10"))
RESULTS_ROOT = REPO / "test-results"

SSH = ["ssh", "-o", "ConnectTimeout=12", "-o", "StrictHostKeyChecking=no",
       "-o", "UserKnownHostsFile=/dev/null", f"root@{ROUTER}"]


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "bench: VPN performance benchmark on a physical router (minutes per scenario)",
    )
    config.addinivalue_line(
        "markers", "nordlynx: NordLynx (WireGuard) scenarios",
    )
    config.addinivalue_line(
        "markers", "openvpn: OpenVPN scenarios",
    )
    config.addinivalue_line(
        "markers", "ipsec: IKEv2/IPsec scenarios (need a baked image)",
    )


def ssh_run(cmd: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(SSH + [cmd], capture_output=True, text=True,
                          timeout=timeout, check=False)


def _router_alive() -> bool:
    """Up as OpenWrt (ROUTER) or waiting in U-Boot recovery — either is a
    flashable starting state for bake-per-scenario."""
    for ip in (ROUTER, "192.168.0.1"):
        r = subprocess.run(["ping", "-c1", "-W2", ip], capture_output=True)
        if r.returncode == 0:
            return True
    return False


def bench_venue(venues: list[Venue] | None = None) -> tuple[str | None, str]:
    """(router_ip_override, venue_label) from CONWRT_VENUES, else (None, "").

    Exactly one non-qemu venue feeds the bench router axis (its address
    resolved from the lab registry when direct:); qemu-session venues are
    not bench routers (flash-capable venue required — plan §4/§5); multiple
    hardware venues would need a per-venue scenario loop (post-step).
    """
    vs = venues if venues is not None else venues_from_env()
    hw = [v for v in vs if v.kind != "qemu-session"]
    if not hw:
        return None, ""
    if len(hw) > 1:
        raise ValueError(
            "bench venue axis takes ONE hardware venue per run "
            f"(got: {', '.join(v.key for v in hw)}); loop runs per venue")
    v = hw[0]
    if v.kind == "direct":
        from venues import direct_device
        return direct_device(v.place or "")["host"], v.key
    return None, v.key  # labgrid: exporter-proxied — bench keeps its own ROUTER


def pytest_collection_modifyitems(config, items):
    if _router_alive():
        return
    skip = pytest.mark.skip(reason=f"router {ROUTER} not reachable")
    for item in items:
        if "router" in item.fixturenames or "apply_scenario" in item.fixturenames:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def router() -> dict[str, object]:
    venue_ip, venue_label = bench_venue()
    if venue_ip:
        globals()["ROUTER"] = venue_ip
        globals()["SSH"] = SSH[:-1] + [f"root@{venue_ip}"]
    r = ssh_run(". /etc/openwrt_release; echo $DISTRIB_RELEASE; "
                "cat /tmp/sysinfo/board_name; grep -c ^processor /proc/cpuinfo")
    assert r.returncode == 0, f"router {ROUTER} unreachable over SSH"
    rel, board, cores = r.stdout.split()
    return {"ip": ROUTER, "iface": IFACE, "release": rel,
            "board": board, "cores": int(cores), "venue": venue_label}


@pytest.fixture(scope="session")
def results(router: dict) -> Iterator[dict]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out_dir = RESULTS_ROOT / f"vpn-bench-{stamp}"
    doc = {
        "meta": {
            "router": router["ip"], "board": router["board"],
            "release": router["release"], "cores": router["cores"],
            "venue": router.get("venue", ""),
            "iperf_server": IPERF_SERVER, "iperf_seconds": IPERF_SECONDS,
            "started": datetime.now(timezone.utc).isoformat(),
        },
        "scenarios": {}, "inventory": {},
    }
    yield doc
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "results.json").write_text(json.dumps(doc, indent=2))
    venue_tag = f", venue `{router['venue']}`" if router.get("venue") else ""
    lines = ["# VPN bench", "",
             f"router `{router['board']}` @ {router['release']} "
             f"({router['cores']} hw threads){venue_tag}, "
             f"iperf server {IPERF_SERVER}, "
             f"{IPERF_SECONDS}s per direction", "",
             "| scenario | down Mbit/s | up Mbit/s | CPU% down | CPU% up | exit |",
             "|---|---|---|---|---|---|"]
    for name, s in doc["scenarios"].items():
        lines.append(f"| {name} | {s.get('down_mbits', '?')} | {s.get('up_mbits', '?')} "
                     f"| {s.get('cpu_down', '?')} | {s.get('cpu_up', '?')} "
                     f"| {s.get('exit', '?')} |")
    (out_dir / "summary.md").write_text("\n".join(lines) + "\n")
    print(f"\n[vpn-bench] results → {out_dir}")


class CpuSampler(threading.Thread):
    """Sample aggregate router CPU busy% from /proc/stat once per second."""

    def __init__(self):
        super().__init__(daemon=True)
        self.samples: list[float] = []
        self._halt = threading.Event()

    @staticmethod
    def _read() -> tuple[int, int] | None:
        r = ssh_run("head -n1 /proc/stat", timeout=15)
        m = re.match(r"cpu\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", r.stdout)
        if not m:
            return None
        v = [int(x) for x in m.groups()]
        return v[3], sum(v)

    def run(self) -> None:
        prev = self._read()
        while not self._halt.is_set():
            time.sleep(1.0)
            cur = self._read()
            if not prev or not cur or cur[1] == prev[1]:
                continue
            idle_d, total_d = cur[0] - prev[0], cur[1] - prev[1]
            self.samples.append(round(100 * (1 - idle_d / total_d), 1))
            prev = cur

    def __enter__(self) -> "CpuSampler":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self._halt.set()
        self.join(timeout=15)

    @property
    def max_busy(self) -> float:
        return max(self.samples) if self.samples else -1.0


def _write_bench_config(scenario: Scenario) -> Path:
    """Generate an isolated conwrt config for one scenario."""
    import tempfile

    token = scenario.params["access_token"]
    ap = ""
    if scenario.params.get("ap_ssid"):
        ap = f'ap_ssid = "{scenario.params["ap_ssid"]}"\n'
        ap += f'ap_key = "{scenario.params.get("ap_key", "")}"\n'
    extra = ""
    for key in ("technology", "openvpn_cipher"):
        if scenario.params.get(key):
            extra += f'{key} = "{scenario.params[key]}"\n'
    hw = ""
    if "hw_accel" in scenario.params:
        hw = f'hw_accel = {"true" if scenario.params["hw_accel"] else "false"}\n'
    cfg = f"""[ssh]
keys = ["/home/ubuntu/.ssh/id_ed25519.pub"]

[password]
mode = "key-only"

[network]
lan_ip_mode = "keep"

[use_cases]
enabled = ["{scenario.use_case}"]

[use_cases.{scenario.use_case}]
access_token = "{token}"
server = "DE"
{extra}{ap}{hw}kill_switch = true
"""
    fd, path = tempfile.mkstemp(suffix=".toml", prefix="conwrt-bench-")
    os.close(fd)
    Path(path).write_text(cfg)
    return Path(path)


VERIFY_PROBES = {
    "wireguard": "wg show wg0 2>/dev/null | grep -q 'latest handshake'",
    "openvpn": "ip -4 addr show tun0 2>/dev/null | grep -q inet",
    "ipsec": "swanctl --list-sas 2>/dev/null | grep -q INSTALLED",
}


_IMAGE_CACHE: dict[str, str] = {}


def _bench_model_id() -> str:
    """The bench model id (env or the x1860 default) — one source for
    image requests AND flashing, so CONWRT_BENCH_MODEL is honored
    throughout the flow. The manager resolves the canonical ASU
    profile from the model registry (openwrt.profile)."""
    return os.environ.get("CONWRT_BENCH_MODEL", "dlink-covr-x1860-a1")


def _request_image(scenario: Scenario) -> str:
    """Request (and cache) the ASU image for a scenario; returns its path."""
    if scenario.name in _IMAGE_CACHE:
        return _IMAGE_CACHE[scenario.name]
    cfg_path = _write_bench_config(scenario)
    env = {**os.environ, "CONWRT_CONFIG": str(cfg_path)}
    try:
        r = subprocess.run(
            ["python3", "scripts/firmware-manager.py", "request",
             "--profile", _bench_model_id()],
            cwd=str(REPO), capture_output=True, text=True, env=env,
            timeout=900, check=False,
        )
        image = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else ""
        if r.returncode != 0 or not image or not Path(image).is_file():
            pytest.fail(f"ASU image request failed for {scenario.name}: "
                        f"{r.stdout[-200:]} {r.stderr[-200:]}")
        _IMAGE_CACHE[scenario.name] = image
        return image
    finally:
        cfg_path.unlink(missing_ok=True)


def _image_variant(image: str) -> str:
    """Pick recovery.bin vs sysupgrade.bin from an ASU build directory.

    The build dir holds both; U-Boot recovery needs the recovery image, a
    running OpenWrt takes the sysupgrade one.
    """
    path = Path(image)
    directory = path.parent if path.is_file() else path
    alive = ssh_run("echo ok", timeout=15).returncode == 0
    want = "*sysupgrade.bin" if alive else "*recovery.bin"
    matches = sorted(directory.glob(want))
    return str(matches[0]) if matches else image


def _flash(image: str) -> bool:
    """Flash via conwrt (auto-detects sysupgrade vs recovery state)."""
    variant = _image_variant(image)
    r = subprocess.run(
        ["python3", "scripts/conwrt.py", "flash", "--model-id",
         _bench_model_id(), "--image", variant, "--interface", IFACE,
         "--no-voice"],
        cwd=str(REPO), capture_output=True, text=True, timeout=1800,
        check=False,
    )
    return r.returncode == 0


def _wait_ssh(timeout: int = 720) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if ssh_run("echo ok", timeout=20).returncode == 0:
            return True
        time.sleep(15)
    return False


def _apply(scenario: Scenario) -> bool:
    """Put the router on the scenario's baked image (bake-per-scenario).

    Fresh boots are the stable path on this hardware: every flash+firstboot
    of 2026-10-08 worked, while runtime service churn (configure-mode
    network restarts) wedged the box three times. The bench therefore
    never runtime-switches; each scenario is a flash away.
    """
    if not _router_alive() and not _wait_ssh(timeout=60):
        pytest.exit(f"router {ROUTER} unreachable — aborting bench run "
                    "(circuit breaker; evidence in results)", returncode=3)
    image = _request_image(scenario)
    if not _flash(image):
        return False
    if not _wait_ssh():
        return False
    return True


def _wait_tunnel(scenario: Scenario, timeout: int = 480) -> bool:
    probe = VERIFY_PROBES[scenario.verify]
    deadline = time.time() + timeout
    while time.time() < deadline:
        if ssh_run(probe, timeout=30).returncode == 0:
            return True
        time.sleep(15)
    return False


def _exit_ip() -> str:
    r = ssh_run("wget -qO- --timeout=12 'http://ip-api.com/line/"
                "?fields=query,country,isp' 2>/dev/null", timeout=30)
    return r.stdout.strip().replace("\n", " ")


@pytest.fixture()
def apply_scenario(request, results):
    """Apply the parameterized scenario, verify the tunnel, record exit."""
    scenario = request.param

    def _run() -> dict:
        entry = results["scenarios"].setdefault(scenario.name, {"name": scenario.name})
        if entry.get("_applied"):
            return entry
        if not _apply(scenario):
            entry["error"] = "conwrt configure failed"
            pytest.fail(f"scenario {scenario.name}: configure failed")
        if not _wait_tunnel(scenario):
            entry["error"] = "tunnel did not come up"
            pytest.fail(f"scenario {scenario.name}: tunnel verification failed")
        entry["_applied"] = True
        time.sleep(8)  # settle routes/DNS
        entry["exit"] = _exit_ip()
        return entry

    return _run


def iperf(direction: str) -> tuple[float, float]:
    """One iperf3 run; returns (mbits, cpu_busy_max)."""
    flag = "-R" if direction == "down" else ""
    with CpuSampler() as sampler:
        r = ssh_run(
            f"iperf3 -c {IPERF_SERVER} -t {IPERF_SECONDS} {flag} 2>/dev/null "
            "| grep 'receiver\\|sender' | tail -1",
            timeout=IPERF_SECONDS + 90,
        )
    m = re.search(r"([\d.]+)\s+Mbits/sec", r.stdout)
    return (float(m.group(1)) if m else -1.0), sampler.max_busy


def pytest_generate_tests(metafunc):
    if "apply_scenario" in metafunc.fixturenames:
        from scenarios import ipsec_scenarios
        only = [s for s in os.environ.get("CONWRT_BENCH_ONLY", "").split(",") if s]
        scen = list(default_scenarios())
        if os.environ.get("CONWRT_BENCH_IPSEC") == "1":
            scen += ipsec_scenarios()
        if only:
            scen = [s for s in scen if s.name in only]
        metafunc.parametrize("apply_scenario", scen, indirect=True,
                             ids=[s.name for s in scen])
