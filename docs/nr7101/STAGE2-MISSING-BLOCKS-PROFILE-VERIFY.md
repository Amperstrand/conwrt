# Stage 2 was never run on this unit — so a profile could not be verified here

Field record, 2026-11-27. Read-only inventory of the same NR7101 (MAC
`d4:1a:d1:d2:1a:78`, OpenWrt 25.12.4) that reached Gate 0.

## Measured state

| Stage-2 piece (CELLULAR-GUIDE §0.1) | State on this unit |
|---|---|
| `wwandctl` / `wwand` | absent |
| `quectel-CM` | absent |
| `conwrt` CLI | absent |
| `uci show network` wwand/wwmodem sections | none |
| `/usr/share/ucode/wwand/` tree (incl. the REQUIRED `datapath_rmnet_nss.uc`) | absent |
| vendor `qmi_wwan_q` / `rmnet` kmods | not loaded |
| `wwan0` / `usb0` data interface | absent (`wwan0` exists but is `DOWN`, no IP) |
| default route | none (`network.wan` is `proto dhcp` on a device literally named `wan`, which does not exist → ubus `NO_DEVICE`) |

The modem is healthy and fully enumerable (`cdc-wdm0`, `ttyUSB0-3`,
`qmi_wwan`+`option` loaded) and the eUICC answers ES10 through
`LPAC_APDU=at LPAC_APDU_AT_DEVICE=/dev/ttyUSB2`. So **card provisioning works
on this image; attaching the resulting profile does not** — the data stack is
simply not installed.

## Why this matters before spending a paid profile

The whole point of the free rehearsal in Stage 4 is to prove
`card → transport → TLS → authentication → download → install → enable →
attach to a real production network`. On this unit the last link does not
exist yet, so:

- a successful download/install would still land in `wwan0 DOWN` with no
  default route, and
- the "attach to a real network" half of the verification **cannot be
  observed** — which is exactly the half a paid profile is bought for.

Do Stage 2 first, then spend the code. Ordering the other way turns a
single-use download into an unverifiable one.

## The clock/WAN prerequisite, and what it actually costs

Gate 0's recorded blocker was "router needs internet + correct clock for the
SM-DP+ download". Measured fix, no router WAN needed: give the router a
temporary default route to a host that NATs, then sync NTP.

```sh
# on the host (Linux, ip_forward + masquerade for the router's LAN subnet)
sudo sysctl -qw net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -o <uplink> -j MASQUERADE
sudo iptables -I FORWARD -i <lan-iface> -o <uplink> -j ACCEPT
sudo iptables -I FORWARD -i <uplink> -o <lan-iface> -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# on the router
ip route replace default via <host-lan-ip> dev br-lan
echo 'nameserver <upstream-dns>' > /tmp/resolv.conf.d/resolv.conf.auto   # resolv.conf.auto is a symlink; write the .d file
kill -HUP "$(cat /var/run/dnsmasq/dnsmasq.pid)"; sleep 1
ping -c2 1.1.1.1 && nslookup time.cloudflare.com
```

Two traps worth recording:

- **`ntpd -n -q -p <server>` alone does not set the clock here** — it printed
  `Alarm clock` and left the date unchanged (busybox `date` was ~6 months
  behind, which is outside `ntpd`'s step threshold). Set it once with
  `date -u -s '<host UTC>'`, then let the running `sysntpd` instance keep it
  disciplined. Verified: router date matched host UTC within 2 s, and was
  still correct an hour later.
- **`date -u -s` rejects ISO-8601 with a `T`** on busybox (`invalid date`).
  Use `date -u -s 'YYYY-MM-DD HH:MM:SS'`.

With NAT in place the router also reached `downloads.openwrt.org`, so `apk`
works for anything that does not need the cellular link.
