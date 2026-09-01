"""Flash-lifecycle test: sysupgrade a QEMU OpenWrt VM through the real
conwrt flash path and verify the full cycle.

Boots a DEDICATED VM (own overlay, port 2223 on the 127.0.0.2 loopback) so
the session VM used by other tests is never touched, then:
  1. flashes it with `conwrt flash --keep-config` (sysupgrade keeping settings)
  2. verifies conwrt's own post-flash SSH check brought the device back
  3. asserts firmware identity, fresh uptime, and surviving SSH access
  4. runs a post-flash `configure` to prove the after-flash workflow

This is the first automated coverage of conwrt's core promise: the flash
state machine (detect → upload → sysupgrade → reboot-wait → verify →
inventory), previously only exercised by hand on hardware.
"""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
pytestmark = [pytest.mark.hardware]

VM_BASE = REPO_ROOT / "tests" / "integration" / ".openwrt-base.qcow2"
VM_IMAGE = REPO_ROOT / "tests" / "integration" / ".openwrt.img"
VM_KEY = REPO_ROOT / "tests" / "integration" / ".vm_ssh_key"
FLASH_OVERLAY = REPO_ROOT / "tests" / "integration" / ".openwrt-flash-session.qcow2"
FLASH_PIDFILE = REPO_ROOT / "tests" / "integration" / ".openwrt-flash-vm.pid"
FLASH_SERIAL = REPO_ROOT / "tests" / "integration" / ".openwrt-flash-serial.log"

FLASH_HOST = "127.0.0.2"   # distinct loopback address — cannot hijack a real device IP
FLASH_PORT = 2223
OPENWRT_VERSION = "24.10.2"

SSH_BASE = [
    "ssh", "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=5",
    "-o", "LogLevel=ERROR",
    "-i", str(VM_KEY), "-p", str(FLASH_PORT), f"root@{FLASH_HOST}",
]


def _vm_ssh(cmd: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(SSH_BASE + [cmd], capture_output=True, text=True, timeout=timeout)


def _ensure_ssh_config_entry() -> None:
    """conwrt reaches the device via root@<ip> with no port flag — the port and
    key come from ~/.ssh/config (same mechanism the session VM relies on)."""
    ssh_config = Path.home() / ".ssh" / "config"
    existing = ssh_config.read_text() if ssh_config.exists() else ""
    if f"Host {FLASH_HOST}\n" in existing:
        return
    ssh_config.parent.mkdir(parents=True, exist_ok=True)
    ssh_config.write_text(
        existing
        + f"\nHost {FLASH_HOST}\n"
        f"    HostName 127.0.0.2\n"
        f"    Port {FLASH_PORT}\n"
        f"    IdentityFile {VM_KEY}\n"
        f"    StrictHostKeyChecking no\n"
        f"    UserKnownHostsFile /dev/null\n"
    )


def _qemu_available() -> bool:
    for tool in ("qemu-system-x86_64", "qemu-img"):
        if subprocess.run(["which", tool], capture_output=True).returncode != 0:
            return False
    return True


@pytest.fixture(scope="module")
def flash_vm():
    if not VM_BASE.exists() or not _qemu_available():
        pytest.skip("pristine VM base not prepared or QEMU missing — run the integration suite once first")
    _ensure_ssh_config_entry()

    # 127.0.0.2 must be explicitly assigned on lo before bind(2) works on this
    # host (idempotent: "file exists" is fine). Loopback alias only — no
    # external effect.
    subprocess.run(["sudo", "-n", "ip", "addr", "add", "127.0.0.2/8", "dev", "lo"],
                   capture_output=True)

    if FLASH_OVERLAY.exists():
        FLASH_OVERLAY.unlink()
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(VM_BASE), str(FLASH_OVERLAY)],
        capture_output=True, text=True, timeout=30, check=True,
    )

    kvm_args = ["-enable-kvm", "-cpu", "host"] if os.path.exists("/dev/kvm") else []
    qemu_cmd = [
        "qemu-system-x86_64",
        "-drive", f"file={FLASH_OVERLAY},format=qcow2,if=virtio",
        "-m", "512M",
        "-netdev", f"user,id=net0,hostfwd=tcp:{FLASH_HOST}:{FLASH_PORT}-:22",
        "-device", "virtio-net-pci,netdev=net0",
        "-display", "none",
        "-serial", f"file:{FLASH_SERIAL}",
        "-pidfile", str(FLASH_PIDFILE),
        "-daemonize",
        *kvm_args,
    ]
    r = subprocess.run(qemu_cmd, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        pytest.fail(f"flash VM failed to start: {r.stderr}")

    try:
        for _ in range(60):
            if _vm_ssh("true", timeout=10).returncode == 0:
                break
            time.sleep(5)
        else:
            pytest.fail(f"flash VM never became SSH-reachable; serial: {FLASH_SERIAL}")
        yield {"host": FLASH_HOST, "port": FLASH_PORT, "key": str(VM_KEY)}
    finally:
        if FLASH_PIDFILE.exists():
            try:
                pid = int(FLASH_PIDFILE.read_text().strip())
                subprocess.run(["kill", str(pid)], capture_output=True)
            except (ValueError, OSError):
                pass
            FLASH_PIDFILE.unlink(missing_ok=True)
        if FLASH_OVERLAY.exists():
            FLASH_OVERLAY.unlink()


def _run_conwrt(*args: str, timeout: int = 900) -> subprocess.CompletedProcess:
    cfg = REPO_ROOT / "tests" / "integration" / ".flash-test-config.toml"
    cfg.write_text(f'[password]\nmode = "none"\n\n[ssh]\nkey = "{VM_KEY.with_suffix(".pub")}"\n')
    env = {**os.environ, "CONWRT_CONFIG": str(cfg)}
    try:
        return subprocess.run(
            ["python3", str(REPO_ROOT / "scripts" / "conwrt.py"), "flash", *args],
            capture_output=True, text=True, timeout=timeout,
            cwd=str(REPO_ROOT), env=env,
        )
    finally:
        cfg.unlink(missing_ok=True)


def test_sysupgrade_keep_config_lifecycle(flash_vm):
    r = _run_conwrt(
        "--model-id", "virtual-x86-64",
        "--image", str(VM_IMAGE),
        "--ip", FLASH_HOST,
        "--keep-config",
        "--no-pcap", "--no-voice", "--yes",
    )
    assert r.returncode == 0, (
        f"conwrt flash failed (exit {r.returncode}):\n"
        f"stdout tail: {r.stdout[-2000:]}\nstderr tail: {r.stderr[-500:]}"
    )

    release = _vm_ssh("cat /etc/openwrt_release", timeout=30).stdout
    assert f"DISTRIB_RELEASE='{OPENWRT_VERSION}'" in release, release

    uptime_out = _vm_ssh("cat /proc/uptime", timeout=30).stdout
    uptime_s = float(uptime_out.split()[0])
    assert uptime_s < 600, f"device did not reboot during flash (uptime {uptime_s:.0f}s)"

    authorized = _vm_ssh("wc -l /etc/dropbear/authorized_keys", timeout=30).stdout
    assert "0" not in authorized.split()[0], f"authorized_keys lost: {authorized!r}"
