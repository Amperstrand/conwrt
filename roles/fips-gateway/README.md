# Role: fips-gateway (outbound LAN gateway)

A FIPS node configured to act as an **outbound LAN gateway** — it bridges LAN
clients onto the FIPS mesh, giving them transparent access to mesh resources.

## What this role does differently

The gateway role ships the same FIPS package as [`fips`](../fips/README.md)
(stable), but pre-configured for gateway operation:

| Setting | `fips` (stable) | `fips-gateway` (this role) |
|---|---|---|
| `gateway.enabled` | `true` (config present) | `true` (config present) |
| fips-gateway service | Enabled in postinst | Enabled + started in postinst |
| `proxy_ndp` sysctl | Applied on first boot | Applied on first boot |
| IPv6 forwarding | Applied on first boot | Applied on first boot |
| Package description | "FIPS Mesh Network Daemon" | "FIPS Mesh Network Daemon (Gateway Role)" |

The gateway role is functionally identical to the stable role with the gateway
service explicitly enabled. It exists as a separate role so operators can
distinguish gateway nodes from mesh-only nodes at the packaging layer.

## What the gateway does

When `fips-gateway` starts:

1. **Applies sysctls** — `proxy_ndp=1`, IPv6 forwarding=1
2. **Swaps dnsmasq** — redirects `.fips` DNS queries to the gateway DNS
   listener (port 5353) instead of the daemon (port 5354), so LAN clients
   get virtual IPs instead of raw mesh addresses
3. **Adds a global IPv6 prefix** to `br-lan` so Android/Chrome clients send
   AAAA queries
4. **Advertises the virtual IP pool** via Router Advertisement so LAN clients
   learn the route automatically
5. **Starts `fips-gateway`** — the gateway daemon that manages virtual IP
   allocation and NAT/proxy for LAN clients

## When to use this role

- A router that sits between a LAN (phones, laptops) and the FIPS mesh
- A router that should give LAN clients transparent mesh access
- Any node where you want `fips-gateway` running by default

## Building

```bash
./packaging/build-ipk.sh --arch aarch64 --source /path/to/fips
```

## Installing

```bash
./conwrt-flash.sh --role fips-gateway --router-ip 192.168.1.1 \
    --firmware dist/fips_0.1.0_aarch64_cortex-a53.ipk
```

## Gateway-specific files

These files are shipped in all FIPS packages but are central to the gateway role:

| File | Purpose |
|---|---|
| `/etc/init.d/fips-gateway` | procd service — applies sysctls, configures dnsmasq, starts gateway |
| `/etc/sysctl.d/fips-gateway.conf` | `proxy_ndp=1`, IPv6 forwarding=1 |
| `/etc/sysctl.d/fips-bridge.conf` | `br_netfilter` settings for Ethernet transport |
| `/usr/bin/fips-gateway` | The gateway daemon binary |

## Verifying the gateway is running

```bash
# Check the service
ssh root@192.168.1.1 '/etc/init.d/fips-gateway status'

# Check the gateway daemon
ssh root@192.168.1.1 'pgrep -a fips-gateway'

# Check virtual IP pool
ssh root@192.168.1.1 'ip -6 route show | grep fd01'

# Check DNS forwarding
ssh root@192.168.1.1 'cat /etc/dnsmasq.d/fips.conf'
```
