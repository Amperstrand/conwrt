# Network Segmentation (moved to the private registry)

The production/lab network design, enforcement rules, and incident record
for the Amperstrand bench live in the **private** conwrt-bench repository
(`docs/NETWORK-SEGMENTATION.md` there) — unit IPs, topology, and hostnames
are operator-private per the conwrt species-level policy and must not be
published in this repo.

Species-level guidance that belongs here:

- Exactly one DHCP/RA authority per broadcast domain; fresh OpenWrt is an
  armed rogue (`dhcp.lan.ignore='1'`, `ra='disabled'`, `dhcpv6='disabled'`
  before any DUT shares a segment).
- Tests needing a DHCP server get an isolated VLAN, never a shared segment.
- See AGENTS.md "Rogue-DHCP Discipline" for the full rule set.
