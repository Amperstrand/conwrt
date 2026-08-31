"""QEMU OpenWrt VM fixtures for integration testing.

Boots a real OpenWrt x86_64 VM in QEMU (with KVM if available) and provides
SSH access for conwrt configure + verification tests.

Requires: qemu-system-x86_64, losetup, mount
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
VM_IMAGE = REPO_ROOT / "tests" / "integration" / ".openwrt.img"
VM_BASE = REPO_ROOT / "tests" / "integration" / ".openwrt-base.qcow2"
VM_OVERLAY = REPO_ROOT / "tests" / "integration" / ".openwrt-session.qcow2"
SSH_PORT = 2222
SSH_HOST = "127.0.0.1"
OPENWRT_VERSION = "24.10.2"
IMAGE_URL = f"https://downloads.openwrt.org/releases/{OPENWRT_VERSION}/targets/x86/64/openwrt-{OPENWRT_VERSION}-x86-64-generic-ext4-combined.img.gz"
PACKAGES_URL = f"https://downloads.openwrt.org/releases/{OPENWRT_VERSION}/packages/x86_64/packages"
SSH_KEY = REPO_ROOT / "tests" / "integration" / ".vm_ssh_key"
SERIAL_LOG = REPO_ROOT / "tests" / "integration" / ".serial.log"
PREBAKE_PACKAGES = ["sqm-scripts", "luci-app-sqm", "iperf3", "libiperf3", "libatomic1",
                    "wireguard-tools", "luci-proto-wireguard", "qrencode"]


def _available(cmd: str) -> bool:
    return subprocess.run(["which", cmd], capture_output=True).returncode == 0


def _ssh(command: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["ssh",
         "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null",
         "-o", "ConnectTimeout=5",
         "-i", str(SSH_KEY),
         "-p", str(SSH_PORT),
         f"root@{SSH_HOST}", command],
        capture_output=True, text=True, timeout=timeout,
    )


def _prepare_image(image_path: Path) -> None:
    """Inject SSH key and configure eth0 as LAN DHCP so QEMU NAT can reach it.

    OpenWrt's default config puts eth0 in the WAN zone (firewall blocks SSH)
    and sets LAN to a static 192.168.1.1 bridge that QEMU user-mode NAT can't
    route to. We rewrite the network config so the single eth0 acts as LAN
    with DHCP (QEMU provides 10.0.2.15), and disable the firewall entirely
    so dropbear is reachable on port 22 via the hostfwd port forward.
    """
    if SSH_KEY.exists():
        return
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(SSH_KEY)],
                   capture_output=True, check=True)
    pubkey = (SSH_KEY.with_suffix(".pub")).read_text().strip()

    r = subprocess.run(
        ["bash", "-c", f"""
        set -e
        LOOP=$(sudo losetup -fP --show {image_path})
        sudo mkdir -p /mnt/owrt
        sudo mount ${{LOOP}}p2 /mnt/owrt || sudo mount ${{LOOP}}p1 /mnt/owrt

        sudo mkdir -p /mnt/owrt/etc/dropbear
        echo '{pubkey}' | sudo tee -a /mnt/owrt/etc/dropbear/authorized_keys > /dev/null
        sudo chmod 600 /mnt/owrt/etc/dropbear/authorized_keys

        # Replace network config: eth0 as LAN with DHCP
        sudo tee /mnt/owrt/etc/config/network > /dev/null <<'NETCFG'
config interface 'loopback'
        option device 'lo'
        option proto 'static'
        option ipaddr '127.0.0.1'
        option netmask '255.0.0.0'

config interface 'lan'
        option device 'eth0'
        option proto 'dhcp'
NETCFG

        # Replace firewall: open zone accepting everything
        sudo tee /mnt/owrt/etc/config/firewall > /dev/null <<'FWCFG'
config defaults
        option input 'ACCEPT'
        option output 'ACCEPT'
        option forward 'ACCEPT'

config zone
        option name 'lan'
        option input 'ACCEPT'
        option output 'ACCEPT'
        option forward 'ACCEPT'
        option device 'eth0'

config zone
        option name 'wan'
        option input 'ACCEPT'
        option output 'ACCEPT'
        option forward 'ACCEPT'
        option masq '1'
        option mtu_fix '1'
FWCFG

        # Allow root login with password and keys in dropbear
        sudo tee /mnt/owrt/etc/config/dropbear > /dev/null <<'DROPBEAR'
config dropbear
        option PasswordAuth 'on'
        option RootPasswordAuth 'on'
        option Port '22'
        option Interface 'lan'
DROPBEAR

        sudo mkdir -p /mnt/owrt/etc/uci-defaults
        sudo tee /mnt/owrt/etc/uci-defaults/99-install-sqm > /dev/null <<'INSTALL'
#!/bin/sh
opkg update >/dev/null 2>&1
opkg install sqm-scripts luci-app-sqm >/dev/null 2>&1 || true
exit 0
INSTALL
        sudo chmod +x /mnt/owrt/etc/uci-defaults/99-install-sqm

        # Pre-bake: inject .ipk files into image — QEMU guest can't reach opkg repos
        sudo mkdir -p /mnt/owrt/tmp/prebake
        for pkg in {" ".join(PREBAKE_PACKAGES)}; do
            ipk=$(ls /tmp/conwrt-prebake/$pkg*.ipk 2>/dev/null | head -1)
            if [ -n "$ipk" ]; then
                sudo cp "$ipk" /mnt/owrt/tmp/prebake/
            fi
        done
        if sudo ls /mnt/owrt/tmp/prebake/*.ipk >/dev/null 2>&1; then
            sudo tee /mnt/owrt/etc/uci-defaults/98-prebake-packages > /dev/null <<'PREBAKE'
#!/bin/sh
cd /tmp/prebake 2>/dev/null || exit 0
opkg install *.ipk 2>/dev/null || true
rm -rf /tmp/prebake
exit 0
PREBAKE
            sudo chmod +x /mnt/owrt/etc/uci-defaults/98-prebake-packages
        fi

        sudo umount /mnt/owrt
        sudo losetup -d $LOOP
        """],
        capture_output=True, text=True, timeout=60,
    )
    if r.returncode != 0:
        pytest.fail(f"Image preparation failed: {r.stderr}")


def _download_prebake_packages() -> None:
    prebake_dir = Path("/tmp/conwrt-prebake")
    prebake_dir.mkdir(parents=True, exist_ok=True)
    if any(prebake_dir.glob("*.ipk")):
        return
    print("Downloading pre-bake packages...", flush=True)
    listing = subprocess.run(
        ["curl", "-sfL", PACKAGES_URL + "/"],
        capture_output=True, text=True, timeout=30,
    )
    if listing.returncode != 0:
        print(f"  Warning: could not fetch package listing: {listing.stderr}")
        return
    import re
    available = set(re.findall(r'href="([^"]+\.ipk)"', listing.stdout))
    for pkg in PREBAKE_PACKAGES:
        match = next((a for a in available if a.startswith(pkg + "_")), None)
        if not match:
            print(f"  Warning: {pkg} not found in package repo")
            continue
        subprocess.run(
            ["curl", "-sfL", "-o", str(prebake_dir / match), f"{PACKAGES_URL}/{match}"],
            capture_output=True, timeout=30,
        )
    print(f"  Pre-baked {len(list(prebake_dir.glob('*.ipk')))} packages", flush=True)


@pytest.fixture(scope="session")
def openwrt_vm():
    if not _available("qemu-system-x86_64") or not _available("qemu-img"):
        pytest.skip("qemu-system-x86_64 / qemu-img not installed")

    if not VM_IMAGE.exists():
        print("Downloading OpenWrt x86_64 image...", flush=True)
        VM_IMAGE.parent.mkdir(parents=True, exist_ok=True)
        gz_path = VM_IMAGE.with_suffix(".img.gz")
        r = subprocess.run(
            ["curl", "-fL", "--retry", "3", "--retry-delay", "2",
             "-o", str(gz_path), IMAGE_URL],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            pytest.fail(f"curl download failed: {r.stderr}")
        # gunzip exit 2 = warning (e.g. "trailing garbage ignored"), not a real failure
        r = subprocess.run(["gunzip", "-f", str(gz_path)], capture_output=True, text=True)
        if r.returncode not in (0, 2) or not VM_IMAGE.exists():
            pytest.fail(f"gunzip failed (exit {r.returncode}): {r.stderr}")
        print(f"OpenWrt image ready: {VM_IMAGE} ({VM_IMAGE.stat().st_size} bytes)", flush=True)
        _download_prebake_packages()
        _prepare_image(VM_IMAGE)

    kvm_args = ["-enable-kvm", "-cpu", "host"] if os.path.exists("/dev/kvm") else []

    # Pristine raw image → one-time qcow2 base → fresh per-session overlay.
    # The overlay (deleted at teardown) absorbs all mutations, so every session
    # boots a clean VM and the base is never dirtied (pattern proven in PRTA).
    if not VM_BASE.exists():
        print("Converting pristine image to qcow2 base (one-time)...", flush=True)
        r = subprocess.run(
            ["qemu-img", "convert", "-f", "raw", "-O", "qcow2", str(VM_IMAGE), str(VM_BASE)],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            pytest.fail(f"qemu-img convert failed: {r.stderr}")
    if VM_OVERLAY.exists():
        VM_OVERLAY.unlink()
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(VM_BASE), str(VM_OVERLAY)],
        capture_output=True, text=True, timeout=30, check=True,
    )

    qemu_cmd = [
        "qemu-system-x86_64",
        "-drive", f"file={VM_OVERLAY},format=qcow2,if=virtio",
        "-m", "512M",
        "-netdev", f"user,id=net0,hostfwd=tcp::{SSH_PORT}-:22",
        "-device", "virtio-net-pci,netdev=net0",
        "-display", "none",
        "-serial", f"file:{SERIAL_LOG}",
        "-daemonize",
        *kvm_args,
    ]

    print("Booting OpenWrt VM...", flush=True)
    r = subprocess.run(qemu_cmd, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        pytest.fail(f"QEMU failed to start: {r.stderr}")

    print("Waiting for SSH (up to 5 min)...", flush=True)
    for i in range(60):
        r = _ssh("true")
        if r.returncode == 0:
            print(f"SSH ready after ~{i * 5}s", flush=True)
            break
        time.sleep(5)
    else:
        serial_tail = ""
        if SERIAL_LOG.exists():
            serial_tail = SERIAL_LOG.read_text()[-2000:]
        pytest.fail(
            f"OpenWrt VM did not become reachable via SSH after 5 minutes.\n"
            f"Serial log tail:\n{serial_tail}"
        )

    ssh_dir = Path.home() / ".ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    ssh_config = ssh_dir / "config"
    existing = ssh_config.read_text() if ssh_config.exists() else ""
    if f"Host {SSH_HOST}" not in existing:
        ssh_config.write_text(
            existing
            + f"\nHost {SSH_HOST}\n"
            f"    Port {SSH_PORT}\n"
            f"    IdentityFile {SSH_KEY}\n"
            f"    StrictHostKeyChecking no\n"
            f"    UserKnownHostsFile /dev/null\n"
        )

    yield {"host": SSH_HOST, "port": SSH_PORT, "key": str(SSH_KEY)}

    _capture_evidence()
    subprocess.run(["pkill", "-f", "qemu-system-x86_64.*openwrt"],
                   capture_output=True)
    if VM_OVERLAY.exists():
        VM_OVERLAY.unlink()


def _capture_evidence() -> None:
    """Snapshot VM state into $CONWRT_EVIDENCE_DIR (set by scripts/local-tests.sh).

    Local-only debugging aid: serial log, UCI state, and firmware identity for
    every run — written before the VM is killed at session teardown."""
    ev = os.environ.get("CONWRT_EVIDENCE_DIR")
    if not ev:
        return
    try:
        ev_dir = Path(ev)
        ev_dir.mkdir(parents=True, exist_ok=True)
        if SERIAL_LOG.exists():
            shutil.copy(SERIAL_LOG, ev_dir / "serial.log")
        r = _ssh("uci show 2>/dev/null", timeout=20)
        (ev_dir / "uci-show.txt").write_text(r.stdout or "")
        r = _ssh("cat /etc/openwrt_release 2>/dev/null", timeout=10)
        (ev_dir / "openwrt-release.txt").write_text(r.stdout or "")
    except Exception as exc:  # noqa: BLE001 — evidence capture must never fail a run
        print(f"Evidence capture failed (non-fatal): {exc}", flush=True)


@pytest.fixture(scope="session")
def ssh_cmd(openwrt_vm):
    def _run(command: str, timeout: int = 30) -> str:
        return _ssh(command, timeout=timeout).stdout
    return _run
