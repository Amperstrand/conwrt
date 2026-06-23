#!/usr/bin/env python3
"""target — derive a per-router "target profile" from a model + OpenWrt version.

The single source of truth for the router dimension that every renderer
(shell, markdown, web) and every deploy path must consume:

  - CPU architecture           (→ which tollgate ipk/apk to install)
  - package manager            (opkg on OpenWrt ≤24.x, apk on ≥25.x)
  - stock firmware image URL   (→ what to flash)

Keeping this here means ``opkg`` vs ``apk``, ``mipsel_24kc`` vs
``aarch64_cortex-a53``, and the downloads.openwrt.org URL are derived in ONE
place instead of being scattered across use cases and renderers.
"""
from __future__ import annotations

from typing import Any

# OpenWrt target → package architecture.
# Canonical home; ``use_cases/tollgate`` re-exports ``arch_from_target`` for
# backward compatibility, but new code should import it from here.
ARCH_BY_TARGET: dict[str, str] = {
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
    """Map an OpenWrt target (e.g. ``mediatek/filogic``) to its package architecture.

    Returns "" for unknown targets so callers can decide whether to auto-detect.
    """
    return ARCH_BY_TARGET.get(target, "")


def package_manager(version: str) -> str:
    """Return the package manager for an OpenWrt version string.

    OpenWrt switched from opkg to apk in 25.x. Anything with major ≥ 25 is apk;
    anything else (24.10.x, 23.05.x, SNAPSHOT pre-25) is treated as opkg.

    >>> package_manager("24.10.7")
    'opkg'
    >>> package_manager("25.12.0")
    'apk'
    >>> package_manager("SNAPSHOT")
    'opkg'
    """
    head = (version or "").split("-")[0].split(".")[0]
    try:
        return "apk" if int(head) >= 25 else "opkg"
    except ValueError:
        return "opkg"


def firmware_image_url(
    model: dict[str, Any],
    version: str | None = None,
    kind: str = "sysupgrade",
) -> str:
    """Build the stock OpenWrt image URL for a model + version + image kind.

    Mirrors the downloads.openwrt.org layout::

        https://downloads.openwrt.org/releases/{version}/targets/{target}/
            openwrt-{version}-{target-dashes}-{profile}-squashfs-{kind}.bin

    Args:
        model: A conwrt model dict (needs ``openwrt.target/profile``).
        version: OpenWrt version; defaults to ``model["openwrt"]["version"]``.
        kind: Image kind — ``sysupgrade``, ``factory``, or ``recovery``
              (recovery is not published for every device).

    Raises:
        KeyError: if the model lacks the required openwrt fields.
    """
    ow = model["openwrt"]
    ver = version or ow["version"]
    target = ow["target"]                       # e.g. "mediatek/filogic"
    profile = ow["profile"]                     # e.g. "glinet_gl-mt6000"
    target_dash = target.replace("/", "-")      # "mediatek-filogic"
    filename = f"openwrt-{ver}-{target_dash}-{profile}-squashfs-{kind}.bin"
    return f"https://downloads.openwrt.org/releases/{ver}/targets/{target}/{filename}"


def derive_target_profile(
    model: dict[str, Any],
    version: str | None = None,
    image_kind: str = "sysupgrade",
) -> dict[str, str]:
    """Bundle every per-router derivative a renderer/deployer needs.

    Keys: ``model_id``, ``target``, ``arch``, ``pkg_manager``, ``version``,
    ``image_kind``, ``firmware_url``, ``default_ip``.
    """
    ow = model["openwrt"]
    ver = version or ow["version"]
    return {
        "model_id": model.get("id", ""),
        "target": ow["target"],
        "arch": arch_from_target(ow["target"]),
        "pkg_manager": package_manager(ver),
        "version": ver,
        "image_kind": image_kind,
        "firmware_url": firmware_image_url(model, ver, image_kind),
        "default_ip": ow.get("default_ip", "192.168.1.1"),
    }
