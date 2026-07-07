# OpenWrt Version Testing Strategy

## Current Releases (July 2026)

| Version | Package Manager | Kernel | MPTCP | Status | Use For |
|---------|----------------|--------|-------|--------|---------|
| **24.10.x** (e.g. 24.10.2) | `opkg` | 6.6 | `CONFIG_MPTCP=n` | EOL Sept 2026 | Legacy production, migration testing |
| **25.12.x** (e.g. 25.12.5) | `apk` | 6.12.71 | `CONFIG_MPTCP=y` | Current stable | Production, MPTCP bonding, all use cases |
| **SNAPSHOT** | `apk` | 6.18+ | `CONFIG_MPTCP=y` | Bleeding edge | Catch breaking changes, latest packages |

> **OpenWrt 24.10 goes end-of-life September 2026.** Migrate to 25.12 before then.

## Key Changes from 24.10 to 25.12

- **Package manager**: `opkg` → `apk` (apk is faster, better dependency resolution)
- **MPTCP**: Disabled → Enabled by default (CONFIG_MPTCP=y since Oct 2024, PR openwrt/openwrt#16786)
- **Kernel**: 6.6 → 6.12.71 (newer hardware support, better DSA, BPF improvements)
- **Config migration**: Most UCI config is transparent; a few edge cases need manual fixup
- **Interface renames**: Some devices (BPI-R4) renamed interfaces to match physical labels

## How to Test Each Version

### OpenWrt 24.10.x (Legacy Stable — EOL Sept 2026)

```bash
wget 'https://downloads.openwrt.org/releases/24.10.2/targets/x86/64/openwrt-24.10.2-x86-64-generic-squashfs-combined.img.gz'
gunzip openwrt-24.10.2-x86-64-generic-squashfs-combined.img.gz

python3 conwrt/run_use_case_tests.py \
  --openwrt-img /tmp/openwrt.img \
  --openwrt-version 24
```

- Package manager: `opkg update && opkg install <pkg>`
- mwan3 works with `iptables-nft` compat packages
- pbr works natively (nftables)
- **MPTCP bonding does NOT work** (CONFIG_MPTCP=n)

### OpenWrt 25.12.x (Current Stable)

```bash
wget 'https://downloads.openwrt.org/releases/25.12.5/targets/x86/64/openwrt-25.12.5-x86-64-generic-squashfs-combined.img.gz'
gunzip openwrt-25.12.5-x86-64-generic-squashfs-combined.img.gz

python3 conwrt/run_use_case_tests.py \
  --openwrt-img /tmp/openwrt-2512.img \
  --openwrt-version 25
```

- Package manager: `apk update && apk add <pkg>`
- **MPTCP bonding WORKS** (CONFIG_MPTCP=y, kernel 6.12.71)
- All use cases should work

### OpenWrt SNAPSHOT

```bash
wget 'https://downloads.openwrt.org/snapshots/targets/x86/64/openwrt-x86-64-generic-squashfs-combined.img.gz'

python3 conwrt/run_use_case_tests.py \
  --openwrt-img /tmp/openwrt-snapshot.img \
  --openwrt-version snapshot
```

- Package manager: `apk`
- Kernel 6.18+ — may have breaking changes
- MPTCP bonding works
- **Expect some use cases to fail** due to upstream changes

## Version-Specific Use Case Behavior

| Use Case | 24.10.x | 25.12.x | SNAPSHOT | Notes |
|----------|---------|---------|----------|-------|
| sqm | opkg | apk | apk | Same config, different pkg manager |
| doh | opkg | apk | apk | Same |
| wireguard-client/server | opkg | apk | apk | Same |
| mwan3 | opkg + iptables-nft | apk + ? | apk + ? | Needs iptables-nft compat on fw4 |
| pbr | opkg | apk | apk | nftables-native, no compat needed |
| mptcp-bonding | **FAIL** (no MPTCP) | **WORKS** | **WORKS** | CONFIG_MPTCP=y since Oct 2024 |
| travelmate/guest-wifi | opkg | apk | apk | WiFi required (QEMU can't test) |
| tollgate-security | opkg | apk | apk | WiFi required for full test |

## Publishing Results with Version Tags

```bash
python3 conwrt/publish_results.py \
  --results-dir /tmp/conwrt-results \
  --run-id conwrt-sqm-25-$(date +%s) \
  --openwrt-version 25 \
  --router dlink-covr-x1860-a1 \
  --use-case sqm \
  --passed 1 --failed 0
```

The `--openwrt-version` flag adds a `t=openwrt-25` tag to the Nostr event,
making it filterable on the dashboard.

## Dashboard Version Filtering

The dashboard at tests.tollgate.me supports:

1. **Version filter dropdown** — filter runs by OpenWrt version (All/24/25/SNAPSHOT)
2. **Matrix view** (conwrt tab) — use_case × version grid showing pass/fail
3. **Version badge** — each run card shows an "OWrt 24/25/snapshot" chip

## CI Strategy

For automated CI on SHC:

1. **Always test 25.12** — current stable, all use cases including MPTCP
2. **Weekly SNAPSHOT test** — catch breaking changes early
3. **24.10 only for migration testing** — EOL Sept 2026, sunset after

```bash
for version in 25 snapshot; do
    download_image $version
    boot_qemu $version
    python3 conwrt/run_use_case_tests.py \
      --openwrt-img /tmp/openwrt.img \
      --openwrt-version $version \
      --nsec ~/.config/prta/nsec
done
```
