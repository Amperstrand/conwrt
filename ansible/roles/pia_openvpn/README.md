# pia_openvpn

Configure a Private Internet Access (PIA) **OpenVPN** full-tunnel client on an
OpenWrt router.

This role is the Ansible companion to the `openvpn-pia` use-case preset
(`scripts/use_cases/openvpn_pia.py`). See `docs/vpn-setup-library.md` for the
provider-agnostic design.

## Requirements

- A router running OpenWrt with SSH access (tested: GL.iNet GL-MT3000, OpenWrt 25.12.5).
- A PIA account. `pia_username` is the **p-number** (e.g. `p1234567`), not an email.
- `gather_facts: false` (OpenWrt images generally have no Python; the role uses
  `ansible.builtin.raw` for every remote action).

> **Transfer caveat:** OpenWrt's dropbear has no SFTP server. The role avoids the
> `copy`/`template` modules entirely (they need Python on the target) and streams
> files with `raw` heredocs, so it works on a stock image.

## Role variables

| Variable | Default | Notes |
|----------|---------|-------|
| `pia_username` | `""` | **required** — PIA p-number |
| `pia_password` | `""` | **required** — use `ansible-vault` |
| `pia_remote_hosts` | 10 US `host:port` endpoints | `remote-random` failover pool |
| `pia_dns_servers` | `10.0.0.241/242/243` | PIA in-tunnel resolvers |
| `pia_ca_url` | pia-foss `ca.rsa.4096.crt` | RSA-4096 CA |
| `pia_interface` | `tun0` | |
| `pia_kill_switch` | `true` | remove LAN→WAN forwarding |
| `pia_ipv6_disable` | `true` | kernel + LAN |
| `pia_phase` | `validation` | `validation` (fail open) or `enforced` (fail closed) |
| `pia_fail_open_timeout` | `180` | seconds before failing open during validation |
| `pia_require_stable_seconds` | `86400` | healthy seconds before auto-enforcing |

## Behaviour

The role installs OpenVPN, writes the credentials/profile, locks DNS to PIA's
in-tunnel resolvers, disables IPv6, sets up the firewall zone, deploys the
functional health probe + watchdog, and verifies the tunnel before finishing.

- **validation** phase: if the tunnel cannot recover within `pia_fail_open_timeout`,
  the watchdog restores the WAN fallback + normal DNS and re-enforces once healthy.
- The watchdog auto-advances to **enforced** (strict kill switch) after
  `pia_require_stable_seconds` of cumulative healthy operation.

## Example

```bash
ansible-playbook -i inventory.ini ansible/playbooks/pia-openvpn.yml \
  -e pia_username=p1234567 -e @vault.yml
```

## Verify / operate on the router

```sh
pia-status          # HEALTHY / DEGRADED / DOWN + server, phase, counters
pia-health           # exit 0 healthy
tail -f /tmp/pia-watchdog.log
```

## Rollback

The role keeps the previous UCI files in `/root/vpnbak` after the first run
(see `docs/vpn-setup-library.md`). To disable the tunnel:

```sh
uci set openvpn.pia.enabled=0; uci commit openvpn
uci set pia.settings.enabled=0; uci commit pia
/etc/init.d/openvpn restart
```
