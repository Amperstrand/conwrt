"""Single source of the OpenWrt version the integration suite tests against.

Every test in tests/integration/ imports from HERE — no local
`OPENWRT_VERSION = "…"` literals (scripts/check_version_pins.py enforces
it). The layering of version truth across the org is documented in
docs/version-pins-ssot.md:

  species qualification  → models/*.json `openwrt.version`
  specimen reality       → ~/conwrt-bench registry/inventory.jsonl
  harness test image     → THIS module (per-repo, one definition)
  planner floors/warns   → crates/conwrt-core/src/plan.rs

Override for a local run: CONWRT_TEST_OPENWRT_VERSION (full X.Y.Z). The
QEMU oracle defaults to the 25.12 family — 24.10 is past end-of-support
(2026-09) and carries unpatched kernel CVEs (CVE-2026-98432; see #607
for the staged deprecation).
"""
from __future__ import annotations

import os

OPENWRT_VERSION = os.environ.get("CONWRT_TEST_OPENWRT_VERSION", "25.12.5")

#: x86/64 combined image the QEMU oracle boots.
IMAGE_URL = (
    "https://downloads.openwrt.org/releases/"
    f"{OPENWRT_VERSION}/targets/x86/64/"
    f"openwrt-{OPENWRT_VERSION}-x86-64-generic-ext4-combined.img.gz"
)

#: package feed matching the image (arch: x86_64).
PACKAGES_URL = (
    "https://downloads.openwrt.org/releases/"
    f"{OPENWRT_VERSION}/packages/x86_64/packages"
)

#: package manager on this family (25.x = apk; 24.10 = opkg). Derived
#: from the major so tests branch on fact, not on another literal.
PKG_MANAGER = "opkg" if OPENWRT_VERSION.split(".")[0] == "24" else "apk"
