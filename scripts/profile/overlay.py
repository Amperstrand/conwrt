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


def build_overlay_tarball(
    disable_dhcp: bool = True,
    authorized_keys: Optional[str] = None,
    lan_ip: Optional[str] = None,
    lan_election: bool = False,
    election_iface: str = "eth0",
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
            from profile.lan_election import election_script
            data = election_script(iface=election_iface)
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
