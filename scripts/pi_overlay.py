#!/usr/bin/env python3
"""Generate a buildroot files/ overlay for a RAM-netbooted OpenWrt Pi.

Everything here was verified live on a Pi 4B running OpenWrt 25.12.5 built
from source with CONFIG_TARGET_ROOTFS_INITRAMFS=y (see
recipes/raspberry-pi/netboot-full-os.md). The overlay exists because a bare
initramfs image boots a USELESS box for lab work: static LAN address, rogue
DHCP server, no SSH access, and dropbear 2025.89 quirks that silently refuse
key auth.

What the generated overlay fixes:

- network: the interface comes up as a DHCP CLIENT (uci name "lan" so the
  stock firewall's lan zone — keyed by network name — accepts inbound SSH).
  A stock image would serve DHCP on the bench LAN from 192.168.1.1.
- dhcp: dnsmasq runs DNS-only, no pools — a netbooted test box must never
  compete with the lab's real DHCP server.
- dropbear: key auth via /etc/dropbear/authorized_keys (dropbear 2025.89
  REFUSES the ~/.ssh path) plus the legacy ~/.ssh copy for older dropbear.
- perms: an uci-defaults script enforces mode 700/600 at every boot — the
  buildroot files/ copy preserves the build user's umask (775 dirs), and
  dropbear rejects group-writable paths even when owned by root.
- password: optional root password set at boot (BusyBox passwd; initramfs
  boots are always "first boot", so uci-defaults run every time).
- host keys: optional static dropbear host keys — a RAM box regenerates
  keys each boot, churning every client's known_hosts. Bake once, extract
  from a running instance or generate ahead.

Usage:
    pi_overlay.py init --output ~/pi-overlay --authorized-key ~/.ssh/id_ed25519.pub
    pi_overlay.py init --output DIR --authorized-key KEY \\
        [--root-password PASS] [--host-key-dir DIR] [--interface eth0]

Then build with the overlay in the buildroot root:
    cp -r ~/pi-overlay/* ~/owrt-build/files/
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path


def render_network_config(interface: str = "eth0") -> str:
    return (
        'config interface "loopback"\n'
        '\toption device "lo"\n'
        '\toption proto "static"\n'
        '\toption ipaddr "127.0.0.1"\n'
        '\toption netmask "255.0.0.0"\n'
        '\n'
        'config interface "lan"\n'
        f'\toption device "{interface}"\n'
        '\toption proto "dhcp"\n'
    )


def render_dhcp_config() -> str:
    return (
        'config dnsmasq\n'
        '\toption domainneeded "1"\n'
        '\toption boguspriv "1"\n'
        '\toption localise_queries "1"\n'
        '\toption rebind_protection "1"\n'
        '\toption rebind_localhost "1"\n'
        '\toption local "/lan/"\n'
        '\toption domain "lan"\n'
        '\toption expandhosts "1"\n'
        '\toption authoritative "1"\n'
        '\toption readethers "1"\n'
        '\toption leasefile "/tmp/dhcp.leases"\n'
        '\toption resolvfile "/tmp/resolv.conf.d/resolv.conf.auto"\n'
        '\toption nonwildcard "1"\n'
        '\toption localservice "1"\n'
        '\toption ednspacket_max "1232"\n'
    )


def render_dropbear_config() -> str:
    return (
        'config dropbear\n'
        '\toption PasswordAuth "on"\n'
        '\toption RootPasswordAuth "on"\n'
        '\toption Port "22"\n'
    )


def render_perms_fix() -> str:
    return (
        "#!/bin/sh\n"
        "chmod 700 /root\n"
        "chmod 700 /root/.ssh 2>/dev/null\n"
        "chmod 600 /root/.ssh/authorized_keys 2>/dev/null\n"
        "chmod 700 /etc/dropbear\n"
        "chmod 600 /etc/dropbear/authorized_keys 2>/dev/null\n"
        "exit 0\n"
    )


def render_password_setup(password: str) -> str:
    return (
        "#!/bin/sh\n"
        f"printf '%s\\n%s\\n' '{password}' '{password}' | passwd root "
        ">/dev/null 2>&1\n"
        "exit 0\n"
    )


def render_nodogsplash_config(interface: str = "eth0") -> str:
    # nodogsplash's stock config wants br-lan as its gateway interface; this
    # overlay deliberately runs the interface unbridged, so point NDS at it
    # or its init refuses to start ("Interface br-lan not detected").
    return (
        'config nodogsplash\n'
        f'\toption gatewayinterface \'{interface}\'\n'
        '\toption gatewayname \'TollGate\'\n'
        '\toption maxclients \'20\'\n'
        '\toption preauthidletimeout \'10\'\n'
        '\toption authidletimeout \'480\'\n'
    )


HOST_KEY_FILES = ("dropbear_ed25519_host_key", "dropbear_rsa_host_key")


def write_overlay(out_dir: Path, authorized_key: Path,
                  root_password: str | None = None,
                  host_key_dir: Path | None = None,
                  interface: str = "eth0",
                  nodogsplash: bool = False) -> list[Path]:
    """Materialise the overlay under out_dir. Returns files written."""
    key_text = authorized_key.read_text(encoding="utf-8").strip()
    if not key_text.startswith(("ssh-", "ecdsa-")):
        raise ValueError(f"{authorized_key} does not look like a public key")

    (out_dir / "etc/config").mkdir(parents=True, exist_ok=True)
    (out_dir / "etc/dropbear").mkdir(parents=True, exist_ok=True)
    (out_dir / "etc/uci-defaults").mkdir(parents=True, exist_ok=True)
    (out_dir / "root/.ssh").mkdir(parents=True, exist_ok=True)

    written: list[Path] = []

    def put(rel: str, content: str, mode: int) -> None:
        p = out_dir / rel
        p.write_text(content, encoding="utf-8")
        p.chmod(mode)
        written.append(p)

    put("etc/config/network", render_network_config(interface), 0o644)
    put("etc/config/dhcp", render_dhcp_config(), 0o644)
    put("etc/config/dropbear", render_dropbear_config(), 0o644)
    put("etc/uci-defaults/98-conwrt-perms", render_perms_fix(), 0o755)
    put("etc/dropbear/authorized_keys", key_text + "\n", 0o600)
    put("root/.ssh/authorized_keys", key_text + "\n", 0o600)
    if nodogsplash:
        put("etc/config/nodogsplash", render_nodogsplash_config(interface),
            0o644)

    if root_password:
        put("etc/uci-defaults/99-conwrt-password",
            render_password_setup(root_password), 0o755)
    if host_key_dir:
        for name in HOST_KEY_FILES:
            src = host_key_dir / name
            if not src.is_file():
                raise ValueError(f"host key not found: {src}")
            dst = out_dir / "etc/dropbear" / name
            shutil.copyfile(src, dst)
            dst.chmod(0o600)
            written.append(dst)
    return written


def cmd_init(args: argparse.Namespace) -> int:
    out_dir = Path(args.output).expanduser().resolve()
    key = Path(args.authorized_key).expanduser().resolve()
    hk_dir = Path(args.host_key_dir).expanduser() if args.host_key_dir else None
    if out_dir.exists() and any(out_dir.iterdir()):
        print(f"{out_dir} is not empty — refusing to overwrite", file=sys.stderr)
        return 1
    try:
        written = write_overlay(out_dir, key, args.root_password, hk_dir,
                                args.interface, args.nodogsplash)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"overlay written to {out_dir} ({len(written)} files):")
    for p in written:
        print(f"  {p.relative_to(out_dir)}")
    print("\nnext: cp -r " + str(out_dir) + "/* <buildroot>/files/ && make -j$(nproc)")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("init", help="generate a buildroot files/ overlay")
    sp.add_argument("--output", required=True, help="empty target directory")
    sp.add_argument("--authorized-key", required=True,
                    help="SSH public key to bake in")
    sp.add_argument("--root-password", default=None,
                    help="root password to set at boot (bench/lab use)")
    sp.add_argument("--host-key-dir", default=None,
                    help="dir with dropbear_*_host_key files to bake "
                         "(stops known_hosts churn across RAM reboots)")
    sp.add_argument("--interface", default="eth0",
                    help="interface for the DHCP-client lan (default: eth0)")
    sp.add_argument("--nodogsplash", action="store_true",
                    help="also generate /etc/config/nodogsplash with the "
                         "gateway interface matching --interface (stock NDS "
                         "wants br-lan and refuses to start without it)")
    sp.set_defaults(func=cmd_init)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
