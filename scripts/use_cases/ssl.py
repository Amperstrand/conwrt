"""ssl — trusted HTTPS certificates for LAN devices.

Downloads real Let's Encrypt certificates for private IP addresses
using free DNS+cert providers (lancert.dev, qip.sh). Installs certs
on the router for uhttpd (admin HTTPS) and any SNI-capable service
(e.g. tollgate payment API).

Works without owning a domain, without running a DNS server, and
without installing a custom CA on client devices.
"""
from __future__ import annotations

import os
import subprocess
from typing import Any, Callable
from urllib.request import urlretrieve

from profile.ops import (
    BlankLine,
    Comment,
    Op,
    ShellCommand,
    render_shell,
)
from shell_safe import require_choice

from . import ParamDef, UseCase, register

_LANCERT_BASE = "https://lancert.dev/certs"
_QIP_BASE = "https://qip.sh/cert"

_QIP_ZONE_MAP: dict[str, str] = {
    "192.": "v",
    "10.": "x",
    "172.": "p",
    "100.": "c",
}


def _qip_zone_for_ip(ip: str) -> str:
    for prefix, zone in _QIP_ZONE_MAP.items():
        if ip.startswith(prefix):
            return zone
    return "v"


def download_lancert_cert(lan_ip: str, dest_dir: str) -> tuple[str, str, str]:
    """Download cert from lancert.dev for a LAN IP.

    Returns (cert_path, key_path, hostname).
    """
    hostname = lan_ip.replace(".", "-") + ".lancert.dev"
    os.makedirs(dest_dir, exist_ok=True)
    cert_path = os.path.join(dest_dir, "server.crt")
    key_path = os.path.join(dest_dir, "server.key")

    urlretrieve(f"{_LANCERT_BASE}/{lan_ip}/fullchain.pem", cert_path)
    urlretrieve(f"{_LANCERT_BASE}/{lan_ip}/privkey.pem", key_path)

    print(f"  [ssl] Lancert cert for {hostname} downloaded")
    return cert_path, key_path, hostname


def download_qip_cert(lan_ip: str, dest_dir: str) -> tuple[str, str, str]:
    """Download wildcard cert from qip.sh for the IP's subnet zone.

    Returns (cert_path, key_path, hostname).
    """
    zone = _qip_zone_for_ip(lan_ip)
    combined_path = os.path.join(dest_dir, f"{zone}.qip.sh.pem")
    os.makedirs(dest_dir, exist_ok=True)

    urlretrieve(f"{_QIP_BASE}/{zone}.qip.sh.pem", combined_path)

    # Split combined PEM into cert + key
    cert_path = os.path.join(dest_dir, "v.qip.sh.crt")
    key_path = os.path.join(dest_dir, "v.qip.sh.key")

    import re
    with open(combined_path) as f:
        content = f.read()

    cert_match = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", content, re.DOTALL)
    key_match = re.search(r"-----BEGIN .*PRIVATE KEY-----.*?-----END .*PRIVATE KEY-----", content, re.DOTALL)

    if cert_match:
        with open(cert_path, "w") as f:
            f.write("\n".join(cert_match) + "\n")
    if key_match:
        with open(key_path, "w") as f:
            f.write(key_match.group() + "\n")

    os.remove(combined_path)

    print(f"  [ssl] qip.sh wildcard cert (*.{zone}.qip.sh) downloaded")
    return cert_path, key_path, f"*.{zone}.qip.sh"


def deploy_ssl_post_flash(
    ip: str,
    ssh_key: str = "",
    provider: str = "lancert",
    lan_ip: str = "",
    cert_file: str = "",
    key_file: str = "",
    log: Callable[[str], None] | None = None,
) -> bool:
    """Download and install SSL certificates on a running router.

    Host-side operation: downloads certs, SCPs to router.

    Args:
        ip: Router IP address.
        ssh_key: Path to SSH private key.
        provider: 'lancert', 'qip', or 'manual'.
        lan_ip: Router LAN IP (auto-detected if empty).
        cert_file: Local cert file (for 'manual' provider).
        key_file: Local key file (for 'manual' provider).
        log: Optional logging callback.

    Returns:
        True on success.
    """
    from ssh_utils import ssh_cmd

    def _log(msg: str) -> None:
        if log:
            log(msg)

    # Auto-detect LAN IP
    if not lan_ip:
        _log("Detecting LAN IP from router...")
        detect = ssh_cmd(ip, "uci get network.lan.ipaddr", key=ssh_key or None)
        result = subprocess.run(detect, capture_output=True, text=True, timeout=15)
        if result.returncode != 0 or not result.stdout.strip():
            _log(f"Failed to detect LAN IP: {result.stderr.strip()}")
            return False
        lan_ip = result.stdout.strip()
        _log(f"Detected LAN IP: {lan_ip}")

    # Download certs (host-side)
    dest = os.path.join(os.environ.get("TMPDIR", "/tmp"), "conwrt-ssl")
    if provider == "lancert":
        cert_path, key_path, hostname = download_lancert_cert(lan_ip, dest)
    elif provider == "qip":
        cert_path, key_path, hostname = download_qip_cert(lan_ip, dest)
    elif provider == "manual":
        if not cert_file or not key_file:
            _log("manual provider requires cert_file and key_file")
            return False
        cert_path, key_path = cert_file, key_file
        hostname = "manual"
    else:
        _log(f"Unknown provider: {provider}")
        return False

    _log(f"Cert ready: {hostname}")

    # SCP certs to router
    _log(f"Transferring certs to router at {ip}...")
    remote_dir = "/etc/tollgate/ssl"
    for local_path, remote_name in [(cert_path, os.path.basename(cert_path)), (key_path, os.path.basename(key_path))]:
        scp_args: list[str] = ["scp", "-O"]
        if ssh_key:
            scp_args += ["-i", ssh_key]
        scp_args += [
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            local_path,
            f"root@{ip}:{remote_dir}/{remote_name}",
        ]
        # Ensure remote dir exists
        mkdir_cmd = ssh_cmd(ip, f"mkdir -p {remote_dir}", key=ssh_key or None)
        subprocess.run(mkdir_cmd, capture_output=True, text=True, timeout=10)

        scp_result = subprocess.run(scp_args, capture_output=True, text=True, timeout=30)
        if scp_result.returncode != 0:
            _log(f"SCP failed for {remote_name}: {scp_result.stderr.strip()}")
            return False

    # Also install as default cert (server.crt/server.key) for uhttpd
    copy_cmd = ssh_cmd(
        ip,
        f"cp {remote_dir}/{os.path.basename(cert_path)} {remote_dir}/server.crt 2>/dev/null; "
        f"cp {remote_dir}/{os.path.basename(key_path)} {remote_dir}/server.key 2>/dev/null; "
        "echo done",
        key=ssh_key or None,
    )
    subprocess.run(copy_cmd, capture_output=True, text=True, timeout=10)

    _log(f"SSL certs installed at {remote_dir}/")
    return True


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    # Enforce the ParamDef choices here too: build_configure() bypasses
    # apply_defaults(), and the provider is interpolated into a rendered
    # comment line — a newline value injected live shell (mwan3/#448
    # class; the Rust port applies the same gate, plan.rs
    # SslProfile::validate).
    provider = require_choice(
        str(params.get("provider", "lancert")), ("lancert", "qip", "manual"), "provider"
    )
    return {
        "provider": provider,
        "enable_uhttpd_https": params.get("enable_uhttpd_https", True),
        "open_port_443_nds": params.get("open_port_443_nds", True),
    }


def _build_ssl_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)

    ops: list[Op] = [
        Comment(text=f"--- SSL: trusted HTTPS via {r['provider']} ---"),
    ]

    if r["enable_uhttpd_https"]:
        ops.append(Comment(text="-- uhttpd HTTPS (admin interface) --"))
        # Certs land post-flash (host-side download + SCP via
        # deploy_ssl_post_flash). Wire uhttpd only once both files
        # exist: pointed at missing certs, uhttpd drops the HTTPS
        # listener or exits — so a cert-less router must not take the
        # wiring yet. Inside the guard the listen_https reset stays
        # idempotent: `uci -q delete` exits nonzero when the option is
        # absent, so the delete is guarded and both listeners always
        # land.
        ops.append(ShellCommand(command=(
            "if [ -f /etc/tollgate/ssl/server.crt ] && "
            "[ -f /etc/tollgate/ssl/server.key ]; then\n"
            "uci set uhttpd.main.cert='/etc/tollgate/ssl/server.crt'\n"
            "uci set uhttpd.main.key='/etc/tollgate/ssl/server.key'\n"
            "uci -q delete uhttpd.main.listen_https || true\n"
            "uci add_list uhttpd.main.listen_https='0.0.0.0:443'\n"
            "uci add_list uhttpd.main.listen_https='[::]:443'\n"
            "uci commit uhttpd\n"
            "/etc/init.d/uhttpd restart\n"
            "echo 'ssl: uhttpd HTTPS wired on :443'\n"
            "else\n"
            "echo 'ssl: /etc/tollgate/ssl certs not present yet — skipping uhttpd HTTPS wiring (deploy certs, then re-run)' >&2\n"
            "fi"
        )))

    if r["open_port_443_nds"]:
        ops.append(Comment(text="-- Allow port 443 through nodogsplash --"))
        # Explicit existence guard with a propagating body: a trailing
        # `|| true` would mask real failures (missing anonymous section,
        # failed commit, failed restart) as success alongside the
        # intended package-absent no-op. Absent nodogsplash skips the
        # branch; present-but-failing aborts loudly under set -e.
        ops.append(ShellCommand(command=(
            "if uci -q show nodogsplash >/dev/null 2>&1; then\n"
            "uci add_list nodogsplash.@nodogsplash[0].users_to_router='allow tcp port 443'\n"
            "uci commit nodogsplash\n"
            "/etc/init.d/nodogsplash restart\n"
            "echo 'ssl: nodogsplash allows tcp/443 to the router'\n"
            "fi"
        )))

    ops.append(BlankLine())
    return ops


register(UseCase(
    name="ssl",
    description=(
        "Trusted HTTPS certificates for LAN devices. Downloads real Let's "
        "Encrypt certs from lancert.dev or qip.sh — no domain ownership "
        "required. Configures uhttpd HTTPS and opens port 443."
    ),
    packages=[
        "libustream-wolfssl",
        "ca-bundle",
    ],
    params={
        "provider": ParamDef(
            type=str, default="lancert",
            description="Cert provider: 'lancert' (per-IP), 'qip' (wildcard per subnet), or 'manual'",
            choices=("lancert", "qip", "manual"),
        ),
        "enable_uhttpd_https": ParamDef(
            type=bool, default=True,
            description="Configure uhttpd to serve HTTPS on port 443",
        ),
        "open_port_443_nds": ParamDef(
            type=bool, default=True,
            description="Allow unauthenticated clients to reach port 443 through nodogsplash",
        ),
        "cert_file": ParamDef(
            type=str, default="",
            description="Local cert file path (required for provider='manual')",
        ),
        "key_file": ParamDef(
            type=str, default="",
            description="Local key file path (required for provider='manual')",
        ),
    },
    build_configure_ops=_build_ssl_ops,
    build_configure=lambda p: render_shell(_build_ssl_ops(p)),
    test_status="tested",
    tested_notes="Cert download + uhttpd config verified on COVR-X1860. Lancert/qip providers tested.",
    configure_via="ssh",
    post_install_notes=(
        "SSL certs are installed at /etc/tollgate/ssl/. "
        "Tollgate (if installed) will automatically use them for HTTPS on port 2121. "
        "uhttpd serves HTTPS on port 443 for LuCI admin. "
        "Certs expire in 90 days — re-run 'conwrt configure' to renew."
    ),
))
