"""QEMU OpenWrt VM fixtures for integration testing.

Boots a real OpenWrt x86_64 VM in QEMU (with KVM if available) and provides
SSH access for conwrt configure + verification tests.

Requires: qemu-system-x86_64, losetup, mount
"""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
VM_IMAGE = REPO_ROOT / "tests" / "integration" / ".openwrt.img"
SSH_PORT = 2222
SSH_HOST = "127.0.0.1"
OPENWRT_VERSION = "24.10.2"
IMAGE_URL = f"https://downloads.openwrt.org/releases/{OPENWRT_VERSION}/targets/x86/64/openwrt-{OPENWRT_VERSION}-x86-64-generic-ext4-combined.img.gz"
SSH_KEY = REPO_ROOT / "tests" / "integration" / ".vm_ssh_key"
SERIAL_LOG = REPO_ROOT / "tests" / "integration" / ".serial.log"


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

        sudo umount /mnt/owrt
        sudo losetup -d $LOOP
        """],
        capture_output=True, text=True, timeout=60,
    )
    if r.returncode != 0:
        pytest.fail(f"Image preparation failed: {r.stderr}")


@pytest.fixture(scope="session")
def openwrt_vm():
    if not _available("qemu-system-x86_64"):
        pytest.skip("qemu-system-x86_64 not installed")

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
        _prepare_image(VM_IMAGE)

    kvm_args = ["-enable-kvm", "-cpu", "host"] if os.path.exists("/dev/kvm") else []

    qemu_cmd = [
        "qemu-system-x86_64",
        "-drive", f"file={VM_IMAGE},format=raw,if=virtio",
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

    subprocess.run(["pkill", "-f", "qemu-system-x86_64.*openwrt"],
                   capture_output=True)


@pytest.fixture(scope="session")
def ssh_cmd(openwrt_vm):
    def _run(command: str, timeout: int = 30) -> str:
        return _ssh(command, timeout=timeout).stdout
    return _run
