# Fake WAN: giving a bench device internet through the host (reversible recipe)

For devices with no configured WAN (freshly flashed, DUT bays, adoption
testing) that need package installs (`apk`/`opkg`) or online
verification. Everything here is reversible and must be fully torn down
at the end of the session — record every rule you add.

Tested on the COVR-X1860 A1 bench specimen @ OpenWrt 25.12.6 (apk era),
2026-10-22.

Placeholders (bench-specific values live in the operator's private
inventory project, never in this repo): `<fake-wan-subnet>` (a /24
reserved for fake-WAN use), `<fake-wan-host>` (the host's address in
it), `<fake-wan-device>` (the device's address in it), `<bench-iface>`
(host interface carrying the device's L2), `<uplink-iface>` (the host's
internet uplink), `<tag>` (an iptables comment tag unique to the
session).

## Recipe

Host side (the device's L2 segment rides the host's bench interface,
`<bench-iface>`; uplink `<uplink-iface>`):

```bash
# 1. Subnet alias on the bench interface (pick one reserved for fake-WAN,
#    e.g. <fake-wan-subnet>). NOTE: NetworkManager wipes raw iproute2
#    addresses on any interface event (carrier flap, DHCP renew) —
#    re-arm after device-side network restarts, or add it via NM.
ip addr add <fake-wan-host>/24 dev <bench-iface>

# 2. Forwarding (often already on, e.g. docker hosts) — record original:
sysctl net.ipv4.ip_forward

# 3. NAT + forward rules, SCOPED to the fake-WAN subnet and tagged for
#    clean removal (never broader rules, never the default route):
iptables -t nat -A POSTROUTING -s <fake-wan-subnet> -o <uplink-iface> \
  -m comment --comment <tag> -j MASQUERADE
iptables -I FORWARD -s <fake-wan-subnet> -o <uplink-iface> \
  -m comment --comment <tag> -j ACCEPT
iptables -I FORWARD -d <fake-wan-subnet> -i <uplink-iface> -m conntrack \
  --ctstate ESTABLISHED,RELATED -m comment --comment <tag> -j ACCEPT
# (ufw/DROP-INPUT hosts: also a scoped INPUT accept for any listener
# ports you test, e.g. a temporary WireGuard UDP endpoint)
```

Device side (runtime-only — do NOT touch `network.lan`/`dhcp.*`; commit
nothing; all of it dies at reboot and is removed at teardown):

```sh
ip addr add <fake-wan-device>/24 dev br-lan     # second address on the live mgmt bridge
ip route add default via <fake-wan-host> dev br-lan
cp /tmp/resolv.conf /tmp/resolv.conf.<tag>.bak
echo "nameserver 9.9.9.9" > /tmp/resolv.conf   # dnsmasq forwards upstream from here
```

Verify: `ping <fake-wan-host>` from the device, then `apk update` /
`opkg update`.

## Teardown (all of it, before you walk away)

Reverse each item by its tag/backup: delete the three iptables rules by
comment tag, drop the alias, restore `/tmp/resolv.conf` from the
backup, delete the device's runtime address + default route, and diff
the device uci state against its session baseline (must be empty).

## Findings paid for on 2026-10-22 (the traps)

1. **`/etc/init.d/network restart` on the device wipes the runtime
   route** — any plan that restarts network (wireguard, guest-wifi)
   silently drops the fake WAN mid-apply. Re-arm the runtime route
   after every apply that restarts network, before asserting
   connectivity.
2. **NetworkManager wipes raw host aliases on interface events** — the
   device-side carrier flaps from those same restarts can take the
   host's fake-WAN alias with them. Re-check `ip addr` before blaming
   the device (a "slow apk" that is really a dead alias costs minutes).
3. **wireguard endpoint on the fake WAN needs `nohostroute='1'`** (or a
   netifd-known route to the endpoint subnet): `proto_add_host_dependency`
   fails when the endpoint subnet exists only in runtime state netifd
   doesn't manage, and netifd tears wg0 down immediately (`Interface
   'wg0' is now down`, no error in logread). With the shim a real
   handshake against a temporary host `wg` listener works end-to-end.
4. **`apk add` can fail while an orphaned `apk update` (from a killed
   session) holds the database lock** — check `ps | grep apk` when apk
   behaves oddly, and never gate success on a piped exit code
   (`cmd | tail -1; echo $?` reports tail's).
