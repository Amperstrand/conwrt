# Role: fips (stable)

The **stable** FIPS role — builds the FIPS mesh daemon from the `master` branch
of [github.com/jmcorgan/fips](https://github.com/jmcorgan/fips).

## What this role installs

A complete FIPS node: mesh daemon (`fips`), CLI tools (`fipsctl`, `fipstop`),
gateway service (`fips-gateway`), init scripts, firewall rules, DNS forwarding,
and 802.11s mesh / open-AP setup helpers.

See [`packaging/README.md`](packaging/README.md) for the full file manifest.

## When to use this role

- Production deployments
- Routers that should run a tested, stable FIPS release
- Any node that is not specifically experimenting with unreleased features

For experimental features from the `next` branch, use the
[`fips-next`](../fips-next/README.md) role instead.

## Building the .ipk

### Standalone (no SDK required)

```bash
# Point --source at your local FIPS repo checkout
./packaging/build-ipk.sh --arch aarch64 --source /path/to/fips
```

The `--source` flag is required when building from conwrt (the FIPS source
tree is not nested inside this repo). The `--branch` flag defaults to
whatever branch is currently checked out in the source repo.

### Via OpenWrt SDK

Copy or symlink `packaging/` into the SDK's `package/` tree:

```bash
ln -s /path/to/conwrt/roles/fips/packaging /path/to/sdk/package/fips
make package/fips/compile V=s
```

The Makefile pins `PKG_SOURCE_VERSION:=master`.

## Installing on a router

Use the top-level [conwrt-flash.sh](../../conwrt-flash.sh):

```bash
./conwrt-flash.sh --role fips --router-ip 192.168.1.1 \
    --firmware dist/fips_0.1.0_aarch64_cortex-a53.ipk
```

Or manually:

```bash
scp -O dist/fips_*.ipk root@192.168.1.1:/tmp/
ssh root@192.168.1.1 opkg install /tmp/fips_*.ipk
```

## Post-install setup

After the package is installed, the daemon starts automatically. Depending on
your topology, run one of the setup helpers:

| Topology | Helper | Notes |
|---|---|---|
| Router-to-router backhaul | `fips-mesh-setup radio0` | Creates open 802.11s mesh |
| Phone/laptop access | `fips-ap-setup radio1` | Creates open "!FIPS" SSID |
| Outbound LAN gateway | `/etc/init.d/fips-gateway enable && /etc/init.d/fips-gateway start` | Bridges LAN onto mesh |
