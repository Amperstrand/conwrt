"""Post-flash overlay generation for sysupgrade -f.

Generates a tarball containing UCI config that gets applied to the
permanent firmware during sysupgrade, preventing rogue DHCP before
the device has a chance to serve a single lease.
"""
from __future__ import annotations

import io
import os
import tarfile
import tempfile
from typing import Optional


def _dhcp_lan_ignore_config() -> bytes:
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
) -> str:
    """Build a sysupgrade -f compatible overlay tarball.

    Returns the path to the temporary tarball file.
    Caller is responsible for cleanup.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        if disable_dhcp:
            data = _dhcp_lan_ignore_config()
            info = tarfile.TarInfo(name="etc/config/dhcp")
            info.size = len(data)
            info.mode = 0o644
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
