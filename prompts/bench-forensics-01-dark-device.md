# Bench Forensics 01 — Dark Device on a Bench Port

Use this template when a device on the bench should be reachable but isn't
(wrong verdict risk!), or when identifying an unknown powered device. Full
methodology: `docs/DARK-DEVICE-PLAYBOOK.md`. Tooling:
`scripts/bench_discover.py` (plan mode is always hardware-safe).

## Inputs to gather first

1. **Port + VLAN**: which switch port, which access VLAN, PoE delivering?
2. **Any frame EVER seen from it**: tcpdump during a PoE cycle, switch FDB,
   `ip neigh` — a single source MAC is worth everything (EUI-64 door).
3. **Its own records**: inventory entries (past IPs, passwords, keys),
   model JSON, recipes, past session notes.
4. **Probe host's own subnets** — the switch's interfaces are sweep candidates.

## Rules

- NO negative result is reported unless a positive control passed through
  the same path this session.
- IPv6 before "dead": derive `fe80::<EUI-64(MAC)>`, ping6 it on the access
  VLAN, check `ip neigh` (STALE ≠ dead, `router` flag = odhcpd alive).
- Passive windows are 2-5 minutes, on the VLAN interface (never `-i any`
  with VLAN filters).
- DHCP bait only proves DHCP-client-ness; zero DISCOVERs = operator-configured
  device → prefer operator-chosen subnets.
- Credentials: fleet-history ladder first (inventory/recipes/sessions), then
  defaults, then fleet keys. Brute force with generic lists ONLY with
  explicit operator approval. If password works but keys never do: check
  `ls -ld /etc/dropbear` ownership/group-writability.
- Transport: to zone-scoped v6 you MUST run the client on the on-link host
  (`dbclient ... root@fe80::...%switch.100X`, scripts via `sh -s` stdin).
- If zero frames EVER including bootloader phase across a fresh PoE cycle →
  stop, it's serial-gated. Do not burn hours on IP-level theories.

## Session flow

1. `python3 scripts/bench_discover.py plan --mac <MAC> --iface switch.100X
   --control-ip <known-good> [--probe-subnets <probe host subnets>]`
2. Review the ladder; correct the sweep order from archaeology.
3. `run` mode (operator-approved): control gate first, then v6, then v4
   sweeps, then banners. Collect the JSON record.
4. On first positive: banner-grab, credential ladder (operator-executed),
   then diagnose from shell: `uci show network dropbear dhcp`, `ip addr`,
   `logread | grep -i <daemon>` — the device's own syslog names silent
   failures (e.g. dropbear refusing bad /etc/dropbear perms).
5. Fix minimally, readback-verify any `uci commit`, reboot-verify, append
   inventory, and update the model JSON if the lesson is species-level.
