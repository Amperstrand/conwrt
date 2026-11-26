"""Post-flash overlay generation for sysupgrade -f.

Generates a tarball containing UCI config that gets applied to the
permanent firmware during sysupgrade, preventing rogue DHCP before
the device has a chance to serve a single lease.
"""
from __future__ import annotations

import ipaddress
import io
import os
import tarfile
import tempfile
from typing import Optional


def _validate_lan_ip(lan_ip: str) -> None:
    """Reject anything that is not a plain IPv4 literal.

    The value is interpolated into a uci-defaults shell script; anything
    that is not a bare IPv4 address is an injection risk and a
    reachability bug (the AGENTS single-quote/IP lesson).
    """
    try:
        addr = ipaddress.ip_address(lan_ip)
    except ValueError:
        raise ValueError(f"lan_ip must be an IPv4 literal, got: {lan_ip!r}") from None
    if addr.version != 4:
        raise ValueError(f"lan_ip must be IPv4 (use a separate overlay for ip6addr), got: {lan_ip!r}")


def _lan_ip_uci_default_script(lan_ip: str) -> bytes:
    # Delta-only uci-defaults script: runs at first boot AFTER the image's
    # default network config exists, sets only ipaddr — no full
    # etc/config/network replacement (device names vary per model; a whole
    # -file replacement is the reachability-bug class this avoids).
    # OpenWrt runs+deletes /etc/uci-defaults/* on first boot; scripts in a
    # sysupgrade -f restore archive are honored.
    return (
        f"uci set network.lan.ipaddr='{lan_ip}'\n"
        f"uci commit network\n"
    ).encode()


def _dhcp_lan_ignore_config() -> bytes:
    # conwrt#307: the rogue-DHCP triple, not ignore alone — odhcpd keeps
    # advertising RA/DHCPv6 on a shared segment without ra/dhcpv6 disabled
    # (same shape as the builder's _DHCP_DISABLE_SCRIPT and the bench
    # utilities' read-back-gated triple).
    return b"""config dnsmasq
\toption domainneeded '1'
\toption localise_queries '1'
\toption rebind_protection '1'
\toption rebind_localhost '1'
\toption local '/lan/'
\toption domain 'lan'
\toption expandhosts '1'
\toption readethers '1'
\toption leasefile '/tmp/dhcp.leases'
\toption resolvfile '/tmp/resolv.conf.d/resolv.conf.auto'
\toption ednspacket_max '1232'

config dhcp 'lan'
\toption interface 'lan'
\toption ignore '1'
\toption ra 'disabled'
\toption dhcpv6 'disabled'

config dhcp 'wan'
\toption interface 'wan'
\toption ignore '1'

config odhcpd 'odhcpd'
\toption maindhcp '0'
\toption leasefile '/tmp/hosts/odhcpd'
\toption leasetrigger '/usr/sbin/odhcpd-update'
\toption loglevel '4'
"""


def resolve_overlay_identity(
    lan_ip: Optional[str] = None,
    authorized_keys: Optional[str] = None,
    cfg: Optional["object"] = None,
) -> tuple[Optional[str], Optional[str]]:
    """THE single decision place for overlay identity (#828).

    Precedence (explicit flag > config):
    - lan_ip: an explicit argument wins; else the config's static LAN IP
      — but ONLY when ``lan_ip_mode == "static"`` (the mac-hash default
      is deliberately NOT baked into a first-boot overlay: a MAC-derived
      address belongs to the device-side derivators, not a static pin).
    - authorized_keys: an explicit argument (key text or file path) wins;
      else the config's public key text; else the file at
      ``ssh_public_key_path``.

    Returns (lan_ip, authorized_keys_text) — either may be None (that
    overlay feature then rides the defaults). An invalid explicit IP
    raises (same guard as build_overlay_tarball).
    """
    if cfg is None:
        from config import load_config  # noqa: PLC0415 — lazy: config IO only when needed
        try:
            cfg = load_config()
        except Exception:  # no config / unparsable: flags only (host-side best effort)
            cfg = None

    resolved_ip = lan_ip
    if resolved_ip is None and cfg is not None:
        if getattr(cfg, "lan_ip_mode", "") == "static" and getattr(cfg, "lan_ip", ""):
            resolved_ip = cfg.lan_ip

    resolved_keys = authorized_keys
    if resolved_keys is None and cfg is not None:
        text = getattr(cfg, "ssh_public_key_text", "")
        if not text:
            path = getattr(cfg, "ssh_public_key_path", "")
            if path:
                try:
                    with open(os.path.expanduser(path)) as fh:
                        text = fh.read().strip()
                except OSError:
                    text = ""
        resolved_keys = text or None
    elif resolved_keys and not resolved_keys.startswith("ssh-") and os.path.isfile(
            os.path.expanduser(resolved_keys)):
        # a path was passed as the explicit argument: read the key text
        with open(os.path.expanduser(resolved_keys)) as fh:
            resolved_keys = fh.read().strip()

    if resolved_ip is not None:
        _validate_lan_ip(resolved_ip)
    return resolved_ip, resolved_keys


def build_overlay_tarball(
    disable_dhcp: bool = True,
    authorized_keys: Optional[str] = None,
    lan_ip: Optional[str] = None,
    lan_election: bool = False,
) -> str:
    """Build a sysupgrade -f compatible overlay tarball.

    Returns the path to the temporary tarball file.
    Caller is responsible for cleanup.
    """
    if lan_ip is not None:
        _validate_lan_ip(lan_ip)
    if lan_election and lan_ip is not None:
        raise ValueError(
            "lan_election and lan_ip are mutually exclusive: the election "
            "derives the role at first boot, a static lan_ip fixes it ahead "
            "of time — pick one per unit")

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        if disable_dhcp:
            data = _dhcp_lan_ignore_config()
            info = tarfile.TarInfo(name="etc/config/dhcp")
            info.size = len(data)
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))

        if lan_election:
            from profile.lan_election import election_installer
            data = election_installer()
            info = tarfile.TarInfo(name="etc/uci-defaults/96-conwrt-lan-election")
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))

        if lan_ip is not None:
            data = _lan_ip_uci_default_script(lan_ip)
            info = tarfile.TarInfo(name="etc/uci-defaults/99-conwrt-lan-ip")
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))

        if authorized_keys:
            key_data = authorized_keys.encode("utf-8")
            info = tarfile.TarInfo(name="etc/dropbear/authorized_keys")
            info.size = len(key_data)
            info.mode = 0o600
            tar.addfile(info, io.BytesIO(key_data))

    fd, path = tempfile.mkstemp(suffix=".tar.gz", prefix="conwrt-overlay-")
    with os.fdopen(fd, "wb") as f:
        f.write(buf.getvalue())
    return path
