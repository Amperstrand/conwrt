# Role: fips-next (experimental)

The **experimental** FIPS role — builds the FIPS mesh daemon from the `next`
branch of [github.com/jmcorgan/fips](https://github.com/jmcorgan/fips).

## How this differs from `fips` (stable)

| Aspect | `fips` (stable) | `fips-next` (this role) |
|---|---|---|
| Source branch | `master` | `next` |
| Makefile `PKG_SOURCE_VERSION` | `master` | `next` |
| Identity | Ephemeral by default | Persistent by default |
| Nostr rendezvous | Commented (off) | Enabled |
| mDNS/DNS-SD (lan) | Commented (off) | Enabled |
| UDP/TCP `advertise_on_nostr` | Commented (off) | Enabled |
| Stability | Production-tested | May have breaking changes |

The two roles share 95% of their files. Only the build source branch, the
default `fips.yaml` configuration, and the Makefile's `PKG_SOURCE_VERSION`
differ.

## When to use this role

- Testing unreleased features before they land in `master`
- Feedback to FIPS developers on new transport/config options
- Staging nodes that mirror what will become the next stable release

For production, use the [`fips`](../fips/README.md) role.

## Building the .ipk

```bash
# The build script defaults to the 'next' branch for this role
./packaging/build-ipk.sh --arch aarch64 --source /path/to/fips
```

The `--branch next` default is baked in. You can still override it
explicitly with `--branch <name>`.

## Installing on a router

```bash
./conwrt-flash.sh --role fips-next --router-ip 192.168.1.1 \
    --firmware dist/fips_0.1.0_aarch64_cortex-a53.ipk
```

## Rolling back to stable

Install the stable `.ipk` over the next `.ipk`:

```bash
ssh root@192.168.1.1 opkg install --force-reinstall /tmp/fips_stable.ipk
```

The persistent identity key (`/etc/fips/fips.key`) is preserved across
upgrades and downgrades.
