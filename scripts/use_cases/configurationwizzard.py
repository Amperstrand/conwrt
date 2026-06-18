"""configurationwizzard — net4sats admin UI + captive portal deployment.

Builds and deploys the configurationwizzard Preact app to a running router:
- Admin panel → /www/net4sats/ (served by uhttpd on port 80)
- Captive portal → /etc/tollgate/net4sats-captive-portal-site/ (served by NDS on port 2050)
- rpcd plugin for backend API bridge
- uhttpd config for net4sats instance

The portal is served directly by nodogsplash, so unauthenticated clients
see it immediately when they connect. Payment API calls go to port 2121
(tollgate) with CORS handling cross-origin from :2050 → :2121.
"""
from __future__ import annotations

import os
import subprocess
from typing import Any, Callable

from profile.ops import Comment, Op, ShellCommand, ServiceAction, render_shell

from . import ParamDef, UseCase, register

_REPO = "net4sats/configurationwizzard"


def deploy_configurationwizzard(
    ip: str,
    ssh_key: str = "",
    source_dir: str = "",
    log: Callable[[str], None] | None = None,
) -> bool:
    """Build and deploy configurationwizzard to a running router.

    Host-side operation: builds the Preact app, SCPs to router,
    installs rpcd plugin, configures uhttpd.

    Args:
        ip: Router IP address.
        ssh_key: Path to SSH private key.
        source_dir: Local path to configurationwizzard repo (auto-detected if empty).
        log: Optional logging callback.

    Returns:
        True on success.
    """
    from ssh_utils import ssh_cmd

    def _log(msg: str) -> None:
        if log:
            log(msg)

    # Find source directory
    if not source_dir:
        candidates = [
            os.path.expanduser("~/src/configurationwizzard"),
            os.path.expanduser("~/configurationwizzard"),
        ]
        for c in candidates:
            if os.path.isdir(os.path.join(c, "package.json")):
                source_dir = c
                break
        if not source_dir:
            _log("configurationwizzard repo not found. Clone it first:")
            _log(f"  git clone https://github.com/{_REPO}.git")
            return False

    # Build
    _log("Building configurationwizzard...")
    build_result = subprocess.run(
        ["npm", "run", "build"],
        cwd=source_dir,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if build_result.returncode != 0:
        _log(f"Build failed: {build_result.stderr[:200]}")
        return False
    _log("Build complete.")

    dist = os.path.join(source_dir, "dist")
    key_arg = ["-i", ssh_key] if ssh_key else []
    ssh_opts = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null"]

    def _ssh(cmd: str) -> bool:
        full = ssh_cmd(ip, cmd, key=ssh_key or None)
        r = subprocess.run(full, capture_output=True, text=True, timeout=30)
        return r.returncode == 0

    def _scp(local: str, remote: str) -> bool:
        args = ["scp", "-O"] + key_arg + ssh_opts + ["-r", local, f"root@{ip}:{remote}"]
        r = subprocess.run(args, capture_output=True, text=True, timeout=60)
        return r.returncode == 0

    # Deploy admin → /www/net4sats/
    _log("Deploying admin panel...")
    _ssh("mkdir -p /www/net4sats")
    _scp(os.path.join(dist, "admin") + "/.", "/www/net4sats/")

    # Deploy portal → NDS htdocs (via tollgate captive portal site)
    _log("Deploying captive portal...")
    _ssh("mkdir -p /etc/tollgate/net4sats-captive-portal-site")
    _scp(os.path.join(dist, "portal") + "/.", "/etc/tollgate/net4sats-captive-portal-site/")
    _ssh("rm -rf /etc/nodogsplash/htdocs && ln -s /etc/tollgate/net4sats-captive-portal-site /etc/nodogsplash/htdocs")

    # Install rpcd plugin
    _log("Installing rpcd plugin...")
    _ssh("mkdir -p /usr/libexec/rpcd /usr/share/rpcd/acl.d")
    _scp(os.path.join(source_dir, "openwrt/rpcd/tollgate"), "/usr/libexec/rpcd/tollgate")
    _ssh("chmod +x /usr/libexec/rpcd/tollgate")
    _scp(os.path.join(source_dir, "openwrt/rpcd/tollgate_acl.json"), "/usr/share/rpcd/acl.d/tollgate.json")

    # Configure uhttpd
    _log("Configuring uhttpd...")
    _scp(os.path.join(source_dir, "openwrt/files/etc/config/uhttpd_net4sats"), "/etc/config/uhttpd_net4sats")

    # Restart services
    _log("Restarting services...")
    _ssh("/etc/init.d/rpcd restart")
    _ssh("/etc/init.d/uhttpd restart")
    _ssh("/etc/init.d/nodogsplash restart 2>/dev/null; true")

    _log("ConfigurationWizzard deployed.")
    _log(f"  Admin:  http://{ip}/")
    _log(f"  Portal: http://{ip}:2050/ (via NDS)")
    _log(f"  LuCI:   http://{ip}:8080/")
    return True


def _build_cw_ops(params: dict[str, Any]) -> list[Op]:
    return [
        Comment(text="--- configurationwizzard: deployed via deploy_configurationwizzard() ---"),
        Comment(text="Admin: http://router/ (uhttpd port 80)"),
        Comment(text="Portal: served by NDS on port 2050"),
        Comment(text="rpcd plugin bridges ubus → tollgate CLI"),
    ]


register(UseCase(
    name="configurationwizzard",
    description=(
        "net4sats admin UI + captive portal (Preact). "
        "Builds and deploys portal to NDS htdocs, admin to /www/net4sats/, "
        "installs rpcd plugin for backend API bridge. "
        "Run deploy_configurationwizzard() post-flash to build + deploy."
    ),
    packages=[],
    params={
        "source_dir": ParamDef(
            type=str, default="",
            description="Local path to configurationwizzard repo (auto-detected if empty)",
        ),
    },
    build_configure_ops=_build_cw_ops,
    build_configure=lambda p: render_shell(_build_cw_ops(p)),
    test_status="tested",
    tested_notes="Full E2E on COVR-X1860: captive portal, Lightning payment, internet access",
    configure_via="ssh",
    post_install_notes=(
        "Run deploy_configurationwizzard(ip=...) after flashing to build + deploy. "
        "Portal served by NDS on port 2050 (captive portal detection). "
        "Admin served by uhttpd on port 80. "
        "Payment API on port 2121 (tollgate). CORS handles cross-origin. "
        "Pair with 'tollgate' and 'ssl' use cases for full setup."
    ),
))
