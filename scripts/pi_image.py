#!/usr/bin/env python3
"""Provision an OS image onto a disk attached to a Raspberry Pi, over SSH.

Designed for headless lab Pis managed by conwrt: the Pi runs an OS with SSH
access (e.g. Raspberry Pi OS or Ubuntu on a boot stick), a target disk is
attached to it, and this tool:

1. pre-flights the target (exists, is a disk, big enough, nothing mounted),
2. transfers a compressed OS image (local file served over LAN HTTP, or a URL),
3. verifies the sha256 checksum,
4. streams it onto the disk (xz-decompressed dd),
5. injects cloud-init headless config (user, ssh key, hostname, DHCP).

Requires SSH on the target: the conwrt netboot rescue shell only runs telnetd,
so a rescue-shell flash is a manual procedure — see
recipes/raspberry-pi/netboot-rescue.md. For a bootable-USB stick on the
workstation, use the Rescue Kit flash script instead.

Usage:
    pi_image.py provision --host 192.168.1.240 --device /dev/sdb \
        --image ubuntu.img.xz --sha256 <hash> --hostname pi4 \
        --user ubuntu --ssh-key ~/.ssh/id_ed25519.pub \
        --expect-serial 10000000abcd1234

Wipes the target disk. Never points --device at the Pi's boot medium.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import subprocess
import sys
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ssh_utils import run_ssh  # noqa: E402

MIN_DEVICE_GB = 8
DD_BLOCK = "4M"


# ---------------------------------------------------------------------------
# Pure helpers (unit-testable)
# ---------------------------------------------------------------------------

def _is_mounted(entry: dict) -> bool:
    """lsblk emits mountpoints as a string, a list (possibly of nulls), or null."""
    mp = entry.get("mountpoints")
    if not mp:
        return False
    if isinstance(mp, str):
        return bool(mp)
    return any(bool(m) for m in mp)


def _subtree_mounted(entry: dict) -> bool:
    """Recursively inspect the disk AND every descendant (parts, lvm, crypt).

    A dm-crypt/LVM rootfs mounts as a GRANDCHILD of the physical disk; a
    one-level children check sees the running system disk as 'unmounted'.
    """
    if _is_mounted(entry):
        return True
    return any(_subtree_mounted(c) for c in (entry.get("children") or []))


def pick_target_device(lsblk_json: str, min_gb: int = MIN_DEVICE_GB,
                       allow_mounted: bool = False) -> str:
    """Choose the target disk from `lsblk -b -J -o ...` output.

    Returns the device path (e.g. /dev/sda). Refuses anything that is not a
    whole disk, is too small, or has mounted partitions.
    """
    data = json.loads(lsblk_json)
    devices = data.get("blockdevices", [])
    candidates: list[tuple[str, int, str]] = []
    for dev in devices:
        if dev.get("type") != "disk":
            continue
        size = int(dev.get("size", 0))
        name = f"/dev/{dev['name']}"
        mounted = _subtree_mounted(dev)
        if mounted and not allow_mounted:
            continue
        if size >= min_gb * (1 << 30):
            candidates.append((name, size, dev.get("model") or ""))
    if len(candidates) == 1:
        return candidates[0][0]
    if not candidates:
        raise SystemExit(
            f"no eligible disk >= {min_gb}GB found (unmounted whole disks only)")
    detail = ", ".join(f"{n} ({s // (1 << 30)}GB, {m})" for n, s, m in candidates)
    raise SystemExit(f"multiple eligible disks — pick explicitly: {detail}")


def boot_partition(device: str) -> str:
    """First partition path, handling both /dev/sda and /dev/mmcblk0 styles."""
    return device + ("p1" if device[-1].isdigit() else "1")


def render_meta_data(hostname: str) -> str:
    return f"instance-id: {hostname}\nlocal-hostname: {hostname}\n"


def render_user_data(user: str, hostname: str, ssh_keys: list[str],
                     sudo_nopass: bool = True,
                     password: str | None = None) -> str:
    """Render #cloud-config user-data.

    Forces ssh on at boot (runcmd) — some raspi images ship sshd disabled and
    would lock out a headless box. `password` (if set) is the account's
    break-glass password; callers must record it in a credentials file.
    """
    sudo_rule = "ALL=(ALL) NOPASSWD:ALL" if sudo_nopass else "ALL=(ALL):ALL"
    stanza = [
        f"  - name: {user}",
        "    groups: [adm, sudo]",
        "    shell: /bin/bash",
        f"    sudo: {sudo_rule}",
        "    lock_passwd: true",
    ]
    if password:
        stanza.append(f"    password: {password}")
    stanza.append("    ssh_authorized_keys:")
    stanza += [f"      - {key}" for key in ssh_keys]
    return (
        "#cloud-config\n"
        f"hostname: {hostname}\n"
        "manage_etc_hosts: true\n"
        "users:\n"
        + "\n".join(stanza) + "\n"
        "ssh_pwauth: false\n"
        "chpasswd:\n"
        "  expire: false\n"
        "runcmd:\n"
        "  - systemctl enable --now ssh || systemctl enable --now sshd || true\n"
    )


def render_network_config() -> str:
    return (
        "version: 2\n"
        "ethernets:\n"
        "  eth0:\n"
        "    dhcp4: true\n"
        "    optional: true\n"
    )


def parse_cpuinfo_serial(cpuinfo_text: str) -> str | None:
    """Serial line from /proc/cpuinfo ('Serial\t\t: 1000...') or None."""
    for line in cpuinfo_text.splitlines():
        if line.strip().lower().startswith("serial"):
            fields = line.split(":", 1)
            if len(fields) == 2 and fields[1].strip():
                return fields[1].strip()
    return None


def parse_iface_macs(sysfs_listing: str) -> list[str]:
    """Non-empty lines of `for f in /sys/class/net/*/address; do cat $f; done`."""
    return [ln.strip().lower() for ln in sysfs_listing.splitlines() if ln.strip()]


def verify_specimen(remote_serial: str | None, remote_macs: list[str],
                    expect_mac: str | None = None,
                    expect_serial: str | None = None) -> None:
    """AGENTS.md 'Verify the SPECIMEN, Not Just the Model' gate (AGENTS.md:36-42).

    The destructive provision path must confirm it is talking to the expected
    physical Pi — DHCP address reuse or identical bench units otherwise put a
    valid-looking /dev/sda on the wrong machine. At least one expectation is
    required; when both are given, both must match.
    """
    if not expect_mac and not expect_serial:
        raise SystemExit(
            "refusing: specimen gate requires --expect-mac and/or "
            "--expect-serial (AGENTS.md: verify the specimen, not just the "
            "model — DHCP reuse makes an IP insufficient identity)")
    if expect_serial:
        if not remote_serial:
            raise SystemExit("refusing: target reports no board serial — "
                             "cannot verify --expect-serial")
        if remote_serial.lower() != expect_serial.strip().lower():
            raise SystemExit(
                f"refusing: serial mismatch (target {remote_serial} != "
                f"expected {expect_serial}) — wrong Pi, STOP")
    if expect_mac:
        want = expect_mac.strip().lower()
        if not remote_macs or want not in remote_macs:
            found = ", ".join(remote_macs) or "none"
            raise SystemExit(
                f"refusing: MAC {want} not present on target "
                f"(found: {found}) — wrong Pi, STOP")


def remote_specimen(host: str) -> tuple[str | None, list[str]]:
    """Read live identity evidence from the Pi over SSH."""
    _, serial_out, _ = _ssh(host, "cat /proc/cpuinfo")
    _, macs_out, _ = _ssh(host,
                          "for f in /sys/class/net/*/address; do cat $f; done")
    return parse_cpuinfo_serial(serial_out), parse_iface_macs(macs_out)


def sha256_of(path: Path, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while block := fh.read(chunk):
            digest.update(block)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def _ssh(host: str, command: str, timeout: int = 60,
         input_text: str | None = None) -> tuple[int, str, str]:
    proc = run_ssh(host, command, timeout=timeout, input=input_text)
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def local_ip_for(host: str) -> str:
    """Local source IP the workstation would use to reach `host`."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect((host, 22))
        return probe.getsockname()[0]
    finally:
        probe.close()


class _QuietHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(Path(kwargs.pop("directory"))),
                        **kwargs)

    def log_message(self, *args):  # silence request log
        pass


def serve_file(path: Path, port: int = 0) -> tuple[HTTPServer, int]:
    directory = str(path.parent)

    def handler(*a, **kw):
        return _QuietHandler(*a, directory=directory, **kw)

    server = HTTPServer(("0.0.0.0", port), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port


def preflight(host: str, device: str, min_gb: int) -> str:
    """Verify the target is eligible and return the device path to write.

    For ``--device auto`` the resolved ``/dev/...`` path is returned so the
    caller never passes the literal string "auto" to ``dd``.
    """
    rc, out, err = _ssh(host, "lsblk -b -J -o NAME,SIZE,TYPE,MOUNTPOINTS,MODEL")
    if rc != 0:
        raise SystemExit(f"cannot lsblk {host}: {err}")
    target = pick_target_device(out, min_gb=min_gb) \
        if device == "auto" else _check_explicit(out, device, min_gb)
    if target != device and device != "auto":
        raise SystemExit(f"refusing: {device} not eligible (choose {target})")
    print(f"target: {target}")
    return target


def _check_explicit(lsblk_json: str, device: str, min_gb: int) -> str:
    data = json.loads(lsblk_json)
    for dev in data.get("blockdevices", []):
        if f"/dev/{dev['name']}" == device:
            if dev.get("type") != "disk":
                raise SystemExit(f"refusing: {device} is not a whole disk")
            if int(dev.get("size", 0)) < min_gb * (1 << 30):
                raise SystemExit(f"refusing: {device} smaller than {min_gb}GB")
            if _subtree_mounted(dev):
                raise SystemExit(f"refusing: {device} has mounted partitions")
            return device
    raise SystemExit(f"refusing: {device} not found on host")


def transfer_image(host: str, image: Path, sha256: str | None,
                   remote_path: str) -> None:
    ip = local_ip_for(host)
    server, port = serve_file(image)
    url = f"http://{ip}:{port}/{image.name}"
    print(f"transferring {image.name} ({image.stat().st_size // (1 << 20)}MB) "
          f"to {host} over LAN http ...")
    try:
        rc, _, err = _ssh(host, f"wget -q -O {remote_path} {url}", timeout=3600)
        if rc != 0:
            raise SystemExit(f"transfer failed: {err}")
    finally:
        server.shutdown()
    if sha256:
        rc, out, _ = _ssh(host, f"sha256sum {remote_path}")
        actual = out.split()[0] if out.split() else ""
        if actual != sha256:
            raise SystemExit(f"checksum MISMATCH: {actual} != {sha256}")
        print("checksum ok")


def reread_pt_cmd(device: str) -> str:
    """Ask the kernel to drop the stale partition table after a whole-disk dd."""
    return (f"partprobe {device} 2>/dev/null || "
            f"blockdev --rereadpt {device} 2>/dev/null || true")


def wait_for_part_cmd(part: str, tries: int = 10) -> str:
    """Bounded wait for the boot-partition node to (re)appear."""
    return (f"i=0; while [ $i -lt {tries} ] && [ ! -b {part} ]; do "
            f"sleep 1; i=$((i+1)); done; test -b {part}")


def reread_partition_table(host: str, device: str, part: str) -> None:
    """Re-read the partition table and wait for the boot node before mounting.

    After overwriting a whole disk Linux can keep the previous table until
    rescanned: on a blank target the partition may not exist yet, on a
    previously partitioned one it can point at the old offset.
    """
    rc, _, err = _ssh(host, reread_pt_cmd(device))
    if rc != 0:
        raise SystemExit(f"partition reread failed on {device}: {err}")
    rc, _, _ = _ssh(host, wait_for_part_cmd(part))
    if rc != 0:
        raise SystemExit(
            f"boot partition {part} did not appear after rereading the "
            f"partition table on {device}")


def validate_archive(host: str, remote_path: str) -> None:
    """Verify the downloaded archive is intact xz data BEFORE dd touches the disk.

    Without this, a corrupt download (especially with --sha256 omitted) lets
    xz die mid-stream while dd happily consumes the partial output — the
    pipeline reports dd's status and a truncated image is declared written.
    """
    rc, _, err = _ssh(host, f"xz -t {remote_path}", timeout=300)
    if rc != 0:
        raise SystemExit(
            f"image archive failed xz integrity check on {host}: "
            f"{err.strip() or 'corrupt or not xz data'}")


def write_image(host: str, remote_path: str, device: str) -> None:
    rc, _, err = _ssh(
        host,
        f"xz -d -c {remote_path} | dd of={device} bs={DD_BLOCK} && sync",
        timeout=1800)
    if rc != 0:
        raise SystemExit(f"write failed: {err}")
    print(f"image written to {device}")


def inject_cloud_init(host: str, device: str, user: str, hostname: str,
                      ssh_keys: list[str], password: str | None = None) -> None:
    part = boot_partition(device)
    mount_cmd = (f"mkdir -p /mnt/pi-img && mount -t vfat {part} /mnt/pi-img")
    rc, _, err = _ssh(host, mount_cmd)
    if rc != 0:
        raise SystemExit(
            f"cannot mount {part} as vfat ({err.strip()}). If this is the "
            "rescue shell, the vfat kernel modules are missing — push "
            "fat.ko/vfat.ko/nls_*.ko for the rescue kernel and insmod them, "
            "or run the injection from a booted OS.")
    files = {
        "meta-data": render_meta_data(hostname),
        "user-data": render_user_data(user, hostname, ssh_keys, password=password),
        "network-config": render_network_config(),
    }
    for name, content in files.items():
        rc, _, err = _ssh(host,
                          f"cat > /mnt/pi-img/{name}", input_text=content)
        if rc != 0:
            raise SystemExit(f"cannot write {name}: {err}")
    _ssh(host, "umount /mnt/pi-img && sync")
    print(f"cloud-init injected (user={user}, hostname={hostname})")


def cmd_provision(args: argparse.Namespace) -> int:
    import secrets
    image = Path(args.image).expanduser().resolve()
    if not image.is_file():
        raise SystemExit(f"image not found: {image}")
    ssh_keys = [Path(k).expanduser().read_text().strip()
                for k in args.ssh_key]

    password = args.password or secrets.token_urlsafe(12)
    target = preflight(args.host, args.device, args.min_gb)
    serial, macs = remote_specimen(args.host)
    verify_specimen(serial, macs,
                    expect_mac=args.expect_mac,
                    expect_serial=args.expect_serial)
    print(f"specimen ok: serial={serial or 'n/a'}, "
          f"macs={', '.join(macs) or 'n/a'}")
    remote_path = f"/tmp/{image.name}"
    transfer_image(args.host, image, args.sha256, remote_path)
    validate_archive(args.host, remote_path)
    write_image(args.host, remote_path, target)
    _ssh(args.host, f"rm -f {remote_path}")
    if not args.no_inject:
        reread_partition_table(args.host, target, boot_partition(target))
        inject_cloud_init(args.host, target, args.user,
                          args.hostname, ssh_keys, password)
        creds = Path(str(image) + ".credentials.txt")
        creds.write_text(
            f"host={args.hostname}\nuser={args.user}\npassword={password}\n"
            f"break-glass: console login, or rescue shell + mount rootfs\n")
        print(f"credentials written to {creds} — store this file, "
              "it is the only record of the password")
    print("done. reboot the Pi to boot the new OS "
          "(netboot server must be disarmed for USB boot to be reached).")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("provision", help="flash + configure a Pi-attached disk")
    sp.add_argument("--host", required=True, help="Pi IP reachable via root SSH")
    sp.add_argument("--device", required=True,
                    help="target disk on the Pi (e.g. /dev/sda) or 'auto'")
    sp.add_argument("--image", required=True, help="local .img.xz file")
    sp.add_argument("--sha256", default=None, help="expected image checksum")
    sp.add_argument("--expect-mac", default=None,
                    help="specimen gate: MAC that must be present on the "
                         "target Pi (AGENTS.md MAC/serial rule)")
    sp.add_argument("--expect-serial", default=None,
                    help="specimen gate: /proc/cpuinfo Serial that must "
                         "match the target Pi")
    sp.add_argument("--password", default=None,
                    help="break-glass console password (default: generated, "
                         "recorded in <image>.credentials.txt)")
    sp.add_argument("--hostname", default="pi4")
    sp.add_argument("--user", default="ubuntu")
    sp.add_argument("--ssh-key", action="append", default=[],
                    help="public key file(s) to authorize (repeatable)")
    sp.add_argument("--min-gb", type=int, default=MIN_DEVICE_GB)
    sp.add_argument("--no-inject", action="store_true",
                    help="skip cloud-init injection")
    sp.set_defaults(func=cmd_provision)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
