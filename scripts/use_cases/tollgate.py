"""OpenTollGate — Bitcoin Lightning payment gateway for selling internet access."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from typing import Any, Callable
from urllib.request import urlretrieve

from profile.ops import Comment, Op, ShellCommand, render_shell

from . import ParamDef, UseCase, register

_REPO = "OpenTollGate/tollgate-module-basic-go"
_WORKFLOW = "Build and Publish"

_ARCH_MAP: dict[str, str] = {
    "mediatek/filogic": "aarch64_cortex-a53",
    "ipq40xx/generic": "arm_cortex-a7",
    "bcm27xx/bcm2711": "aarch64_cortex-a72",
    "bcm27xx/bcm2709": "arm_cortex-a7",
    "ramips/mt7621": "mipsel_24kc",
    "ath79/generic": "mips_24kc",
    "ath79/nand": "mips_24kc",
    "x86/64": "x86_64",
}


def arch_from_target(target: str) -> str:
    """Map an OpenWrt target (e.g. ``mediatek/filogic``) to ipk architecture."""
    return _ARCH_MAP.get(target, "")


def _sha256_file(path: str) -> str:
    """Compute SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve_ipk_gh(
    version: str = "latest",
    arch: str = "",
    dest: str = "",
) -> str:
    """Download a tollgate ipk from GitHub CI artifacts.

    Uses ``gh`` CLI to find the latest successful CI run and downloads the
    matching artifact.  Returns the local path to the downloaded ipk file.

    This runs on the **host**, not on the router.
    """
    if not arch:
        raise ValueError("arch is required (e.g. aarch64_cortex-a53)")

    if not dest:
        dest = os.path.join(os.environ.get("TMPDIR", "/tmp"), "conwrt-tollgate")
    os.makedirs(dest, exist_ok=True)

    if version == "latest":
        run_query = (
            f"gh run list --repo {_REPO} --workflow {_WORKFLOW!r}"
            f" --branch main --status success --limit 1"
            f" --json databaseId,runNumber,headSha --jq '.[0]'"
        )
    else:
        run_query = (
            f"gh run list --repo {_REPO} --workflow {_WORKFLOW!r}"
            f" --branch main --status success --limit 50"
            f" --json databaseId,runNumber,headSha"
        )

    result = subprocess.run(run_query, shell=True, capture_output=True, text=True, check=True)
    runs = json.loads(result.stdout)

    if version == "latest":
        run_info = runs
    else:
        run_info = next(
            (r for r in runs if str(r["runNumber"]) == str(version)),
            None,
        )
        if run_info is None:
            raise ValueError(f"CI run #{version} not found")

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
                    return os.path.join(root, f)
        raise FileNotFoundError(f"ipk not found after download in {dest}")

    return ipk_path


def resolve_ipk_nostr(
    arch: str,
    channel: str = "stable",
    version: str = "latest",
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

    if not dest:
        dest = os.path.join(os.environ.get("TMPDIR", "/tmp"), "conwrt-tollgate")
    os.makedirs(dest, exist_ok=True)

    releases = query_releases(
        relay_urls=DEFAULT_RELAYS,
        trusted_pubkey=TRUSTED_PUBKEY,
        package_name="tollgate-wrt",
        architecture=arch,
        release_channel=channel,
        timeout=timeout,
    )

    if not releases:
        raise RuntimeError(
            f"No nostr releases found for tollgate-wrt arch={arch} channel={channel}"
        )

    if version == "latest":
        event = releases[0]
    else:
        event = next(
            (r for r in releases if r.get("version") == version),
            None,
        )
        if event is None:
            available = ", ".join(r.get("version", "?") for r in releases[:10])
            raise RuntimeError(
                f"tollgate-wrt version {version!r} not found on nostr. "
                f"Available: {available}"
            )

    url = event.get("url", "")
    expected_sha = event.get("x", "")

    if not url:
        raise RuntimeError("Nostr release event has no download URL")

    local_name = url.rsplit("/", 1)[-1]
    if not local_name.endswith(".ipk"):
        local_name = f"tollgate-wrt_{arch}.ipk"
    local_path = os.path.join(dest, local_name)

    urlretrieve(url, local_path)

    if expected_sha:
        actual_sha = _sha256_file(local_path)
        if actual_sha != expected_sha:
            os.remove(local_path)
            raise RuntimeError(
                f"SHA-256 mismatch for {local_name}: "
                f"expected {expected_sha}, got {actual_sha}"
            )

    return local_path


def resolve_ipk_auto(
    arch: str = "",
    channel: str = "stable",
    version: str = "latest",
    dest: str = "",
    source: str = "auto",
) -> str:
    """Resolve tollgate ipk from nostr, GitHub, or auto (nostr→gh fallback).

    Args:
        arch: Target ipk architecture (e.g. aarch64_cortex-a53).
        channel: Release channel for nostr lookup.
        version: 'latest' or specific version string.
        dest: Local directory to download into.
        source: 'nostr', 'github', or 'auto' (try nostr, fall back to github).

    Returns:
        Local path to the downloaded ipk file.
    """
    if source == "github":
        return resolve_ipk_gh(version=version, arch=arch, dest=dest)
    elif source == "nostr":
        if not arch:
            raise ValueError("arch is required for nostr source")
        return resolve_ipk_nostr(arch=arch, channel=channel, version=version, dest=dest)
    else:
        # auto: try nostr first, fall back to github
        if not arch:
            return resolve_ipk_gh(version=version, arch=arch, dest=dest)
        try:
            return resolve_ipk_nostr(arch=arch, channel=channel, version=version, dest=dest)
        except Exception:
            return resolve_ipk_gh(version=version, arch=arch, dest=dest)


def deploy_tollgate_post_flash(
    ip: str,
    ssh_key: str = "",
    arch: str = "",
    channel: str = "stable",
    version: str = "latest",
    source: str = "auto",
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
        version: 'latest' or specific version.
        source: 'auto', 'nostr', or 'github'.
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
    _log(f"Resolving tollgate ipk (source={source}, arch={arch})...")
    try:
        ipk_path = resolve_ipk_auto(arch=arch, channel=channel, version=version, source=source)
    except Exception as exc:
        _log(f"Failed to resolve ipk: {exc}")
        return False
    _log(f"Downloaded ipk to {ipk_path}")

    # SCP to router (use -O for dropbear compatibility)
    _log(f"Transferring ipk to router at {ip}...")
    scp_args: list[str] = ["scp", "-O"]
    if ssh_key:
        scp_args += ["-i", ssh_key]
    scp_args += [
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        ipk_path,
        f"root@{ip}:/tmp/tollgate-wrt.ipk",
    ]
    scp_result = subprocess.run(scp_args, capture_output=True, text=True, timeout=30)
    if scp_result.returncode != 0:
        _log(f"SCP failed: {scp_result.stderr.strip()}")
        return False

    # Install on router
    _log("Installing tollgate ipk on router...")
    install_cmd = ssh_cmd(
        ip,
        "opkg install /tmp/tollgate-wrt.ipk && /etc/init.d/tollgate-wrt enable",
        key=ssh_key or None,
    )
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
    }


def _build_tollgate_ops(params: dict[str, Any]) -> list[Op]:
    r = _resolve_params(params)
    mint_url = r["mint_url"]
    lightning_address = r["lightning_address"]
    price_per_minute = r["price_per_minute"]

    ops: list[Op] = []

    # Enable nodogsplash
    ops.append(Comment(text="--- TollGate: nodogsplash captive portal ---"))
    ops.append(ShellCommand("uci set nodogsplash.@nodogsplash[0].enabled='1' 2>/dev/null || true"))
    ops.append(ShellCommand("uci commit nodogsplash 2>/dev/null || true"))
    ops.append(ShellCommand("/etc/init.d/nodogsplash enable 2>/dev/null || true"))
    ops.append(ShellCommand("/etc/init.d/nodogsplash restart 2>/dev/null || true"))

    # Configure tollgate UCI if any settings provided
    _has_config = bool(mint_url or lightning_address or price_per_minute != 1)
    if _has_config:
        ops.append(Comment(text="--- TollGate: payment configuration ---"))
        ops.append(ShellCommand("touch /etc/config/tollgate 2>/dev/null || true"))
        ops.append(ShellCommand("uci add tollgate tollgate 2>/dev/null || true"))
        if mint_url:
            ops.append(ShellCommand(f"uci set tollgate.@tollgate[0].mint_url='{mint_url}' 2>/dev/null || true"))
        if lightning_address:
            ops.append(ShellCommand(f"uci set tollgate.@tollgate[0].lightning_address='{lightning_address}' 2>/dev/null || true"))
        if price_per_minute != 1:
            ops.append(ShellCommand(f"uci set tollgate.@tollgate[0].price_per_minute='{price_per_minute}' 2>/dev/null || true"))
        ops.append(ShellCommand("uci commit tollgate 2>/dev/null || true"))

    ops.append(Comment(text="--- TollGate: ipk installed separately via deploy_tollgate_post_flash() ---"))

    return ops


register(UseCase(
    name="tollgate",
    description=(
        "OpenTollGate Bitcoin/Lightning payment gateway. "
        "Downloads ipk via nostr (Blossom) with GitHub CI fallback, "
        "deploys post-flash via SCP + opkg."
    ),
    packages=[
        "nodogsplash",
        "libustream-wolfssl",
        "ca-bundle",
        "ca-certificates",
    ],
    params={
        "version": ParamDef(type=str, default="latest",
            description="TollGate version: 'latest' (main branch CI), or specific run number like '76'"),
        "ipk_url": ParamDef(type=str, default="",
            description="Direct URL to ipk file (overrides version lookup, for offline/custom builds)"),
        "arch": ParamDef(type=str, default="",
            description="Target architecture override (auto-detected from model if empty)"),
        "source": ParamDef(type=str, default="auto",
            description="Download source: 'auto' (nostr→gh fallback), 'nostr', or 'github'",
            choices=("auto", "nostr", "github")),
        "channel": ParamDef(type=str, default="stable",
            description="Release channel: 'stable', 'beta', 'alpha', 'dev'",
            choices=("stable", "beta", "alpha", "dev")),
        "mint_url": ParamDef(type=str, default="",
            description="Cashu mint URL"),
        "lightning_address": ParamDef(type=str, default="",
            description="Lightning address for payouts"),
        "price_per_minute": ParamDef(type=int, default=1,
            description="Price in sats per minute"),
    },
    build_configure=lambda p: render_shell(_build_tollgate_ops(p)),
    build_configure_ops=_build_tollgate_ops,
    test_status="untested",
    tested_notes="post-flash ipk deploy",
    configure_via="ssh",
))
