"""OpenTollGate — Bitcoin Lightning payment gateway for selling internet access."""
from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Callable
from urllib.request import urlretrieve

from flash.context import sha256_file as _sha256_file
from profile.ops import BlankLine, Comment, Op, ServiceAction, ShellCommand, UciAdd, UciAddList, UciCommit, UciSet, render_shell

from . import ParamDef, UseCase, register

_REPO = "OpenTollGate/tollgate-module-basic-go"
_WORKFLOW = "Build and Publish"



def resolve_ipk_gh(
    version: str = "",
    arch: str = "",
    expected_sha: str = "",
    dest: str = "",
) -> str:
    """Download a tollgate ipk from GitHub CI artifacts.

    Uses ``gh`` CLI to find the matching CI run and downloads the
    matching artifact.  Returns the local path to the downloaded ipk file.

    This runs on the **host**, not on the router.
    """
    if not arch:
        raise ValueError("arch is required (e.g. aarch64_cortex-a53)")

    if not version:
        raise ValueError(
            "version is required — specify a commit hash (e.g. '8ec5342') "
            "or CI run number (e.g. '1176'). 'latest' is not accepted."
        )

    if not dest:
        dest = os.path.join(os.environ.get("TMPDIR", "/tmp"), "conwrt-tollgate")
    os.makedirs(dest, exist_ok=True)

    run_query = (
        f"gh run list --repo {_REPO} --workflow {_WORKFLOW!r}"
        f" --branch main --status success --limit 50"
        f" --json databaseId,runNumber,headSha --jq '.[]'"
    )

    result = subprocess.run(run_query, shell=True, capture_output=True, text=True, check=True)
    runs = json.loads(result.stdout)

    # Match by CI run number or by commit hash
    run_info = None
    for r in runs:
        if str(r["runNumber"]) == str(version) or r["headSha"].startswith(version):
            run_info = r
            break

    if run_info is None:
        raise ValueError(
            f"No CI run matching version {version!r}. "
            f"Use 'gh run list --repo {_REPO} --workflow {_WORKFLOW!r} --limit 10' to see available runs."
        )

    run_id = run_info["databaseId"]
    run_number = run_info["runNumber"]
    short_sha = run_info["headSha"][:7]

    art_cmd = (
        f"gh run view {run_id} --repo {_REPO} --json artifacts"
        f" --jq '.artifacts[].name'"
    )
    art_result = subprocess.run(art_cmd, shell=True, capture_output=True, text=True, check=True)
    artifact_names = art_result.stdout.strip().splitlines()

    target_name = f"_{arch}.ipk"
    matching = [n for n in artifact_names if n.endswith(target_name)]
    if not matching:
        plain = f"tollgate-wrt_main.{run_number}.{short_sha}{target_name}"
        matching = [n for n in artifact_names if n == plain]

    if not matching:
        raise ValueError(
            f"No ipk artifact for arch={arch} in run #{run_number}. "
            + f"Available: {', '.join(artifact_names)}"
        )

    artifact_name = matching[0]

    print("  [tollgate] Resolved via GitHub CI:")
    print(f"    run:      #{run_number}")
    print(f"    commit:   {short_sha}")
    print(f"    artifact: {artifact_name}")

    dl_cmd = (
        f"gh run download {run_id} --repo {_REPO}"
        f" -n {artifact_name!r} -D {dest!r}"
    )
    subprocess.run(dl_cmd, shell=True, check=True)

    ipk_path = os.path.join(dest, artifact_name)
    if not os.path.exists(ipk_path):
        for root, _dirs, files in os.walk(dest):
            for f in files:
                if f.endswith(".ipk") and arch.replace("-", "_") in f:
                    ipk_path = os.path.join(root, f)
                    break

    if not os.path.exists(ipk_path):
        raise FileNotFoundError(f"ipk not found after download in {dest}")

    actual_sha = _sha256_file(ipk_path)
    print(f"    sha256:   {actual_sha[:16]}...")

    if expected_sha and actual_sha != expected_sha:
        os.remove(ipk_path)
        raise RuntimeError(
            f"SHA-256 mismatch (operator check) for {artifact_name}: "
            f"expected {expected_sha}, got {actual_sha}"
        )

    return ipk_path


def resolve_ipk_nostr(
    arch: str,
    channel: str = "dev",
    version: str = "",
    trusted_pubkey: str = "",
    expected_sha: str = "",
    dest: str = "",
    timeout: float = 15.0,
) -> str:
    """Download a tollgate ipk from nostr relays via Blossom URLs.

    Queries nostr relays for signed release events from the trusted publisher,
    picks the matching release, downloads the ipk, and verifies its SHA-256.

    Returns the local path to the downloaded ipk file.

    This runs on the **host**, not on the router.
    """
    from nostr_fetch import DEFAULT_RELAYS, TRUSTED_PUBKEY, query_releases

    if not version:
        raise ValueError(
            "version is required — specify a version string (e.g. 'main.104.8ec5342') "
            "or commit hash (e.g. '8ec5342'). 'latest' is not accepted."
        )

    pubkey = trusted_pubkey or TRUSTED_PUBKEY

    if not dest:
        dest = os.path.join(os.environ.get("TMPDIR", "/tmp"), "conwrt-tollgate")
    os.makedirs(dest, exist_ok=True)

    releases = query_releases(
        relay_urls=DEFAULT_RELAYS,
        trusted_pubkey=pubkey,
        package_name="tollgate-wrt",
        architecture=arch,
        release_channel=channel,
        timeout=timeout,
    )

    if not releases:
        raise RuntimeError(
            f"No nostr releases found for tollgate-wrt arch={arch} channel={channel} "
            f"pubkey={pubkey[:12]}..."
        )

    # Match by version string or by commit hash suffix
    event = None
    for r in releases:
        v = r.get("version", "")
        if v == version or v.endswith(version):
            event = r
            break

    if event is None:
        available = ", ".join(r.get("version", "?") for r in releases[:10])
        raise RuntimeError(
            f"tollgate-wrt version {version!r} not found on nostr. "
            f"Available: {available}"
        )

    # Verify publisher
    event_pubkey = event.get("pubkey", "")
    if event_pubkey != pubkey:
        raise RuntimeError(
            f"Publisher mismatch: event signed by {event_pubkey[:12]}... "
            f"but expected {pubkey[:12]}..."
        )

    url = event.get("url", "")
    release_sha = event.get("x", "")

    if not url:
        raise RuntimeError("Nostr release event has no download URL")

    local_name = url.rsplit("/", 1)[-1]
    if not local_name.endswith(".ipk"):
        local_name = f"tollgate-wrt_{arch}.ipk"
    local_path = os.path.join(dest, local_name)

    print("  [tollgate] Resolved via nostr:")
    print(f"    version:  {event.get('version', '?')}")
    print(f"    pubkey:   {event_pubkey[:12]}...{event_pubkey[-8:]}")
    print(f"    sha256:   {release_sha[:16]}...")
    print(f"    url:      {url[:60]}...")

    urlretrieve(url, local_path)

    # Verify SHA-256 from event
    actual_sha = _sha256_file(local_path)
    if release_sha and actual_sha != release_sha:
        os.remove(local_path)
        raise RuntimeError(
            f"SHA-256 mismatch for {local_name}: "
            f"expected {release_sha}, got {actual_sha}"
        )

    # Verify SHA-256 from operator (if provided)
    if expected_sha and actual_sha != expected_sha:
        os.remove(local_path)
        raise RuntimeError(
            f"SHA-256 mismatch (operator check) for {local_name}: "
            f"expected {expected_sha}, got {actual_sha}"
        )

    return local_path


def resolve_ipk_auto(
    arch: str = "",
    channel: str = "dev",
    version: str = "",
    trusted_pubkey: str = "",
    expected_sha: str = "",
    dest: str = "",
    source: str = "nostr",
) -> str:
    """Resolve tollgate ipk from nostr or GitHub.

    Args:
        arch: Target ipk architecture (e.g. aarch64_cortex-a53).
        channel: Release channel for nostr lookup.
        version: Version string (e.g. 'main.104.8ec5342') or commit hash (e.g. '8ec5342').
        trusted_pubkey: Nostr pubkey of trusted publisher (default: hardcoded TRUSTED_PUBKEY).
        expected_sha: If set, verify downloaded file matches this SHA-256.
        dest: Local directory to download into.
        source: 'nostr' or 'github'.

    Returns:
        Local path to the downloaded ipk file.
    """
    if not version:
        raise ValueError(
            "version is required — specify a version string or commit hash. "
            "'latest' is not accepted."
        )

    if source == "github":
        return resolve_ipk_gh(version=version, arch=arch, expected_sha=expected_sha, dest=dest)
    else:
        if not arch:
            raise ValueError("arch is required for nostr source")
        return resolve_ipk_nostr(
            arch=arch, channel=channel, version=version,
            trusted_pubkey=trusted_pubkey, expected_sha=expected_sha, dest=dest,
        )


def deploy_tollgate_post_flash(
    ip: str,
    ssh_key: str = "",
    arch: str = "",
    channel: str = "dev",
    version: str = "",
    trusted_pubkey: str = "",
    expected_sha: str = "",
    source: str = "nostr",
    log: Callable[[str], None] | None = None,
) -> bool:
    """Deploy tollgate ipk to a running router after flashing.

    This is the main host-side entry point for post-flash tollgate deployment.
    It resolves the ipk, downloads it, transfers it via SCP, and installs it.

    Args:
        ip: Router IP address.
        ssh_key: Path to SSH private key (optional).
        arch: Target architecture. Auto-detected from router if empty.
        channel: Release channel for nostr lookup.
        version: Version string or commit hash (required).
        trusted_pubkey: Nostr pubkey of trusted publisher.
        expected_sha: If set, verify downloaded file matches this SHA-256.
        source: 'nostr' or 'github'.
        log: Optional logging callback.

    Returns:
        True on success, False on failure.
    """
    from ssh_utils import ssh_cmd

    def _log(msg: str) -> None:
        if log:
            log(msg)

    # Auto-detect arch from router if not provided
    if not arch:
        _log("Detecting architecture from router...")
        detect_cmd = ssh_cmd(ip, "grep DISTRIB_ARCH /etc/openwrt_release | cut -d\"'\" -f2", key=ssh_key or None)
        result = subprocess.run(detect_cmd, capture_output=True, text=True, timeout=15)
        if result.returncode != 0 or not result.stdout.strip():
            _log(f"Failed to detect architecture: {result.stderr.strip()}")
            return False
        arch = result.stdout.strip()
        _log(f"Detected architecture: {arch}")

    # Download ipk to host
    _log(f"Resolving tollgate ipk (source={source}, arch={arch}, version={version})...")
    try:
        ipk_path = resolve_ipk_auto(
            arch=arch, channel=channel, version=version,
            trusted_pubkey=trusted_pubkey, expected_sha=expected_sha,
            source=source,
        )
    except (ValueError, OSError, RuntimeError) as exc:
        _log(f"Failed to resolve ipk: {exc}")
        return False
    _log(f"Downloaded ipk to {ipk_path}")

    ext = os.path.splitext(ipk_path)[1] or ".ipk"
    remote_pkg = f"/tmp/tollgate-wrt{ext}"
    _log(f"Transferring tollgate package to router at {ip}...")
    scp_args: list[str] = ["scp", "-O"]
    if ssh_key:
        scp_args += ["-i", ssh_key]
    scp_args += [
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        ipk_path,
        f"root@{ip}:{remote_pkg}",
    ]
    scp_result = subprocess.run(scp_args, capture_output=True, text=True, timeout=30)
    if scp_result.returncode != 0:
        _log(f"SCP failed: {scp_result.stderr.strip()}")
        return False

    if ext == ".apk":
        # --allow-untrusted: tollgate packages are unsigned (TODO: sign releases).
        install_remote = f"apk add --allow-untrusted {remote_pkg} && /etc/init.d/tollgate-wrt enable"
    else:
        install_remote = f"opkg install {remote_pkg} && /etc/init.d/tollgate-wrt enable"
    _log(f"Installing tollgate on router ({ext})...")
    install_cmd = ssh_cmd(ip, install_remote, key=ssh_key or None)
    install_result = subprocess.run(install_cmd, capture_output=True, text=True, timeout=30)
    if install_result.returncode != 0:
        _log(f"Install failed: {install_result.stderr.strip()}")
        return False

    # Cleanup local ipk
    try:
        os.remove(ipk_path)
    except OSError:
        pass

    _log("TollGate deployed successfully.")
    return True


def _resolve_params(params: dict[str, Any]) -> dict[str, Any]:
    return {
        "mint_url": str(params.get("mint_url", "")),
        "lightning_address": str(params.get("lightning_address", "")),
        "price_per_minute": int(params.get("price_per_minute", 1)),
        "gateway_name": str(params.get("gateway_name", "")),
        "gateway_domain": str(params.get("gateway_domain", "")),
        "clientid": str(params.get("clientid", "mac")),
        "install_hotplug": params.get("install_hotplug", True),
        "hotplug_interface": str(params.get("hotplug_interface", "wwan")),
    }


_HOTPLUG_SCRIPT = """\
#!/bin/sh
[ "$ACTION" = "ifup" ] || exit 0
[ "$INTERFACE" = "{iface}" ] || exit 0
logger -t tollgate-hotplug "{iface} up \\u2014 restarting tollgate"
/etc/init.d/tollgate-wrt restart &
"""


def _build_tollgate_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    mint_url = r["mint_url"]
    lightning_address = r["lightning_address"]
    price_per_minute = r["price_per_minute"]
    gateway_name = r["gateway_name"]
    gateway_domain = r["gateway_domain"]
    clientid = r["clientid"]
    install_hotplug = r["install_hotplug"]
    hotplug_iface = r["hotplug_interface"]

    ops: list[Op] = []

    ops.append(Comment(text="--- TollGate: nodogsplash captive portal ---"))
    ops.append(UciSet(config="nodogsplash", section="@nodogsplash[0]", values={"enabled": "1"}))

    nds_values: dict[str, str] = {}
    if gateway_name:
        nds_values["gatewayname"] = gateway_name
    if gateway_domain:
        nds_values["gatewaydomainname"] = gateway_domain
    if clientid:
        nds_values["clientid"] = clientid
    if nds_values:
        ops.append(UciSet(config="nodogsplash", section="@nodogsplash[0]", values=nds_values))

    ops.append(UciAddList(config="nodogsplash", section="@nodogsplash[0]",
                          option="users_to_router", value="allow tcp port 2121"))
    ops.append(UciAddList(config="nodogsplash", section="@nodogsplash[0]",
                          option="users_to_router", value="allow tcp port 2050"))
    ops.append(UciCommit(config="nodogsplash"))
    ops.append(ServiceAction(name="nodogsplash", action="enable"))
    ops.append(ServiceAction(name="nodogsplash", action="restart"))

    if install_hotplug:
        ops.append(BlankLine())
        ops.append(Comment(text=f"--- TollGate: hotplug ({hotplug_iface} ifup \\u2192 tollgate restart) ---"))
        script = _HOTPLUG_SCRIPT.format(iface=hotplug_iface)
        escaped = script.replace("'", "'\\''")
        ops.append(ShellCommand(
            command=f"mkdir -p /etc/hotplug.d/iface && "
                    f"printf '%s' '{escaped}' > /etc/hotplug.d/iface/95-tollgate-restart && "
                    f"chmod +x /etc/hotplug.d/iface/95-tollgate-restart"
        ))

    if mint_url or lightning_address or price_per_minute != 1:
        ops.append(BlankLine())
        ops.append(Comment(text="--- TollGate: payment configuration ---"))
        ops.append(ShellCommand("touch /etc/config/tollgate"))
        values: dict[str, str] = {}
        if mint_url:
            values["mint_url"] = mint_url
        if lightning_address:
            values["lightning_address"] = lightning_address
        if price_per_minute != 1:
            values["price_per_minute"] = str(price_per_minute)
        ops.append(UciAdd(config="tollgate", type="tollgate", values=values))
        ops.append(UciCommit(config="tollgate"))

    ops.append(BlankLine())
    ops.append(Comment(text="--- TollGate: ipk installed separately via deploy_tollgate_post_flash() ---"))

    return ops


register(UseCase(
    name="tollgate",
    description=(
        "OpenTollGate Bitcoin/Lightning payment gateway. "
        "Downloads ipk via nostr (Blossom) with GitHub CI fallback, "
        "deploys post-flash via SCP + opkg. "
        "Configures nodogsplash captive portal, hotplug for WiFi STA, "
        "and optional gateway branding."
    ),
    packages=[
        "nodogsplash",
        "libustream-wolfssl",
        "ca-bundle",
        "ca-certificates",
    ],
    params={
        "version": ParamDef(type=str, default="",
            description="TollGate version: commit hash (e.g. 'd68c099') or full version (e.g. 'main.117.d68c099'). Required."),
        "trusted_pubkey": ParamDef(type=str, default="",
            description="Nostr pubkey of trusted publisher (default: hardcoded TollGate maintainer key)"),
        "expected_sha": ParamDef(type=str, default="",
            description="Expected SHA-256 of the ipk file (fails download if mismatch)"),
        "arch": ParamDef(type=str, default="",
            description="Target architecture override (auto-detected from model if empty)"),
        "source": ParamDef(type=str, default="nostr",
            description="Download source: 'nostr' (Blossom via NIP-94) or 'github' (CI artifacts)",
            choices=("nostr", "github")),
        "channel": ParamDef(type=str, default="dev",
            description="Release channel: 'stable', 'beta', 'alpha', 'dev'",
            choices=("stable", "beta", "alpha", "dev")),
        "mint_url": ParamDef(type=str, default="",
            description="Cashu mint URL"),
        "lightning_address": ParamDef(type=str, default="",
            description="Lightning address for payouts"),
        "price_per_minute": ParamDef(type=int, default=1,
            description="Price in sats per minute"),
        "gateway_name": ParamDef(type=str, default="",
            description="Nodogsplash gateway name shown to clients (e.g. 'net4sats')"),
        "gateway_domain": ParamDef(type=str, default="",
            description="Nodogsplash gateway domain (e.g. 'net4sats.lan')"),
        "clientid": ParamDef(type=str, default="mac",
            description="Client identification method: 'mac', 'token', or 'ip'",
            choices=("mac", "token", "ip")),
        "install_hotplug": ParamDef(type=bool, default=True,
            description="Install hotplug script to restart tollgate when WiFi STA comes up"),
        "hotplug_interface": ParamDef(type=str, default="wwan",
            description="Network interface name that triggers tollgate restart (default: wwan)"),
    },
    build_configure=lambda p: render_shell(_build_tollgate_ops(p)),
    build_configure_ops=_build_tollgate_ops,
    test_status="tested",
    tested_notes="ops characterization + resolve tests + transport parity + physical router verification",
    configure_via="ssh",
    post_install_notes=(
        "TollGate ipk is installed via deploy_tollgate_post_flash(). "
        "Nodogsplash is configured as the captive portal. "
        "Hotplug script restarts tollgate when WiFi STA connects. "
        "Pair with the 'ssl' use case for trusted HTTPS on the payment API."
    ),
))
