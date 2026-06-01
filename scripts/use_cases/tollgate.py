"""OpenTollGate — Bitcoin Lightning payment gateway for selling internet access."""
from __future__ import annotations

import json
import os
import subprocess
import textwrap
from typing import Any

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


def resolve_ipk(
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


def _build_tollgate(params: dict[str, Any]) -> str:
    deploy_mode = params.get("deploy_mode", "post-flash")
    ipk_url = params.get("ipk_url", "")
    mint_url = params.get("mint_url", "")
    lightning_address = params.get("lightning_address", "")
    price_per_minute = params.get("price_per_minute", 1)

    if deploy_mode == "bake" and ipk_url:
        config_lines: list[str] = []
        if mint_url:
            config_lines.append(
                f"uci set tollgate.@tollgate[0].mint_url='{mint_url}' 2>/dev/null || true"
            )
        if lightning_address:
            config_lines.append(
                f"uci set tollgate.@tollgate[0].lightning_address='{lightning_address}' 2>/dev/null || true"
            )
        if price_per_minute != 1:
            config_lines.append(
                f"uci set tollgate.@tollgate[0].price_per_minute='{price_per_minute}' 2>/dev/null || true"
            )

        config_block = ""
        if config_lines:
            config_block = "\n".join([""] + config_lines + [
                "uci commit tollgate 2>/dev/null || true",
            ])

        return textwrap.dedent(f"""\
            # --- TollGate install (bake mode) ---
            # Wait for internet (max 60s)
            _i=0
            while [ $_i -lt 30 ]; do
                ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 && break
                sleep 2
                _i=$((_i + 1))
            done
            if ! ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
                echo "TollGate: no internet, skipping ipk install" >&2
                exit 0
            fi
            # Download and install ipk
            wget -O /tmp/tollgate-wrt.ipk '{ipk_url}' 2>/dev/null && \\
              opkg install /tmp/tollgate-wrt.ipk && \\
              rm -f /tmp/tollgate-wrt.ipk
            # Configure nodogsplash
            uci set nodogsplash.@nodogsplash[0].enabled='1' 2>/dev/null || true
            uci commit nodogsplash 2>/dev/null || true
            /etc/init.d/nodogsplash enable 2>/dev/null || true
            /etc/init.d/nodogsplash restart 2>/dev/null || true
            # Configure tollgate
            touch /etc/config/tollgate 2>/dev/null || true
            uci add tollgate tollgate 2>/dev/null || true{config_block}
            /etc/init.d/tollgate-wrt enable 2>/dev/null || true
            /etc/init.d/tollgate-wrt restart 2>/dev/null || true
            echo "TollGate: ipk installed and configured (bake mode)"
        """)
    else:
        if deploy_mode == "bake" and not ipk_url:
            note = "# bake mode requested but no ipk_url — falling back to post-flash deploy"
        else:
            note = "# ipk will be deployed post-flash via SSH (SCP + opkg)"

        config_lines = []
        if mint_url:
            config_lines.append(
                f"uci set tollgate.@tollgate[0].mint_url='{mint_url}' 2>/dev/null || true"
            )
        if lightning_address:
            config_lines.append(
                f"uci set tollgate.@tollgate[0].lightning_address='{lightning_address}' 2>/dev/null || true"
            )
        if price_per_minute != 1:
            config_lines.append(
                f"uci set tollgate.@tollgate[0].price_per_minute='{price_per_minute}' 2>/dev/null || true"
            )

        config_block = ""
        if config_lines:
            config_block = "\n".join([
                "",
                "touch /etc/config/tollgate 2>/dev/null || true",
                "uci add tollgate tollgate 2>/dev/null || true",
            ] + config_lines + [
                "uci commit tollgate 2>/dev/null || true",
            ])

        return textwrap.dedent(f"""\
            # --- TollGate base setup ---
            {note}
            uci set nodogsplash.@nodogsplash[0].enabled='1' 2>/dev/null || true
            uci commit nodogsplash 2>/dev/null || true
            /etc/init.d/nodogsplash enable 2>/dev/null || true
            /etc/init.d/nodogsplash restart 2>/dev/null || true{config_block}
            echo "TollGate: nodogsplash configured, awaiting ipk deploy"
        """)


register(UseCase(
    name="tollgate",
    description="OpenTollGate Bitcoin/Lightning payment gateway (post-flash deploy)",
    packages=[
        "nodogsplash",
        "libustream-wolfssl",
        "ca-bundle",
        "ca-certificates",
    ],
    params={
        "deploy_mode": ParamDef(type=str, default="post-flash",
            description="How to install tollgate: 'post-flash' (SCP+opkg via SSH) or 'bake' (wget+opkg in first-boot script)"),
        "version": ParamDef(type=str, default="latest",
            description="TollGate version: 'latest' (main branch CI), or specific run number like '76'"),
        "ipk_url": ParamDef(type=str, default="",
            description="Direct URL to ipk file (overrides version lookup, for offline/custom builds)"),
        "arch": ParamDef(type=str, default="",
            description="Target architecture override (auto-detected from model if empty)"),
        "mint_url": ParamDef(type=str, default="",
            description="Cashu mint URL"),
        "lightning_address": ParamDef(type=str, default="",
            description="Lightning address for payouts"),
        "price_per_minute": ParamDef(type=int, default=1,
            description="Price in sats per minute"),
    },
    build_configure=_build_tollgate,
    test_status="untested",
    tested_notes="post-flash ipk deploy",
    configure_via="ssh",
))
