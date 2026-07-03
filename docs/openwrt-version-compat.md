# OpenWRT 24 / 25 Compatibility Notes

Reference for flow and use-case authors targeting both OpenWRT release lines.

## Version Map

| Release line | Latest stable | Package manager | Package format |
|---|---|---|---|
| 24.10.x | 24.10.7 | opkg | `.ipk` |
| 25.12.x | 25.12.5 | apk (apk-tools) | `.apk` |

OpenWRT 25.x does NOT ship opkg. OpenWRT 24.x does NOT ship apk. A router
running 25.x has no `opkg` binary, and vice versa. Detect at runtime:

```python
pm = "apk" if router.ssh("command -v apk") else "opkg"
```

## Artifact URLs in Flows

`Step.artifact_urls` supports two keying strategies:

1. **Arch-keyed** (for arch-dependent packages like `tollgate-wrt`):
   ```python
   artifact_urls={
       "mipsel_24kc": "...ipk",
       "aarch64_cortex-a53": "...apk",
   }
   ```
   The renderer (`flows/render.py:_install_package`) looks up by `target["arch"]`.

2. **Format-keyed** (for arch-independent packages, `PKGARCH:=all`):
   ```python
   artifact_urls={
       "ipk": "...ipk",
       "apk": "...apk",
   }
   ```
   The renderer falls back to format keys (`"ipk"` or `"apk"`) when the arch
   lookup returns empty. This covers packages like `configurationwizzard`
   that build one file per format, valid on all architectures.

If a URL value is empty, the renderer emits a `# no artifact URL` comment
and skips the install step. Use this for formats not yet published.

## mDNS (.local resolution)

The `umdns` package is available on both 24.x (`.ipk`) and 25.x (`.apk`) but
is NOT installed in the base image. Install it explicitly when a flow needs
`.local` hostname resolution:

- opkg: `opkg update && opkg install umdns`
- apk: `apk update && apk add umdns`

After install, `umdns` announces and resolves `<hostname>.local` via
multicast DNS (RFC 6762) on port 5353.

## Hostname Configuration for Branded Gateways

Three separate UCI values must be set for `net4sats.lan` / `net4sats.local`
to work end-to-end:

| UCI path | Purpose |
|---|---|
| `system.@system[0].hostname` | Kernel hostname (`/proc/sys/kernel/hostname`) |
| `dhcp.@dnsmasq[0].domain` + `address=/net4sats.lan/<router-ip>` | dnsmasq resolves `net4sats.lan` for DHCP clients |
| `nodogsplash.@nodogsplash[0].gatewayname` | Display name shown in the captive portal |
| `nodogsplash.@nodogsplash[0].gatewaydomainname` | NDS injects this as the DNS name clients use for portal redirect |

The conwrt `net4sats` flow currently sets only `gatewayname`. The system
hostname, dnsmasq domain, and gatewaydomainname must be added for full
`.lan` / `.local` resolution.
